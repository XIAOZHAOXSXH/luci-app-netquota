-- Administrator-only GL guest onboarding. Never called by the guest CGI.
local M = {}
local C = require('netquota.config')
local N = require('netquota.network')
local fs = require('nixio.fs')
local nixio = require('nixio')
local json = require('luci.jsonc')
local ROOT = '/etc/netquota/tls'
local JOB = '/var/run/netquota-apply.json'
local function quote(s) return "'"..tostring(s):gsub("'", "'\"'\"'").."'" end
local function run(argv)
  local words={}; for _,v in ipairs(argv) do words[#words+1]=quote(v) end
  local f=assert(io.popen('LC_ALL=C '..table.concat(words,' ')..' </dev/null 2>&1; printf "\\nNQ_EXIT:%s\\n" "$?"','r'))
  local output=f:read('*a'); f:close()
  local body,code=output:match('^(.*)\nNQ_EXIT:(%d+)\n$')
  assert(code,'无法读取系统命令结果')
  return body,tonumber(code)
end
local function read(path,limit)
  local f=io.open(path,'rb'); if not f then return nil end
  local data=f:read((limit or 65536)+1); f:close()
  if data and #data<=(limit or 65536) then return data end
end
local function write(path,data)
  local f=assert(nixio.open(path,'w','0600'),'无法创建配置文件')
  assert(fs.chmod(path,'0600'))
  local offset=1
  while offset<=#data do local n=assert(f:write(data:sub(offset))); assert(n>0); offset=offset+n end
  f:close()
end
local function cursor() return require('uci').cursor() end
local function clean(c,name)
  local changes=c:changes(name)
  assert(not changes or next(changes)==nil,'该配置存在尚未保存的改动，请先在其他页面保存或撤销：'..name)
end
local function locked(fn)
  local f=assert(nixio.open('/var/lock/netquota-deploy.lock','w','0600'))
  assert(f:lock('tlock'),'另一个部署操作正在进行，请稍后重试')
  local ok,result=pcall(fn)
  f:lock('ulock'); f:close()
  if not ok then error(result,0) end
  return result
end
local function call(object,method)
  local out,rc=run({'/bin/ubus','call',object,method or 'status','{}'})
  return rc==0 and json.parse(out) or nil
end
function M.default_routes(text)
  local routes,seen={},{}
  for line in tostring(text or ''):gmatch('[^\r\n]+') do
    local dev=line:match('^default%s+') and line:match('%sdev%s+(%S+)')
    if dev and C.is_interface_name(dev) and dev~='lo' and dev~='br-lan' and not seen[dev] then
      routes[#routes+1]={device=dev,metric=tonumber(line:match('metric%s+(%d+)')) or 0}
      seen[dev]=true
    end
  end
  table.sort(routes,function(a,b) return a.metric<b.metric end)
  return routes
end
function M.prefix(mask)
  if not C.is_ipv4(mask) then return nil end
  local n=C.ipv4_to_int(mask)
  for bits=0,32 do if n==4294967296-2^(32-bits) then return bits end end
end
local function discover(c)
  local board=call('system','board') or {}
  local supported=tostring(board.board_name or ''):match('^glinet,')~=nil
  local candidates={}
  local guest=c:get_all('network','guest') or {}
  local dev=guest.device or guest.ifname
  local address=guest.ipaddr
  local prefix=M.prefix(guest.netmask or '255.255.255.0')
  local valid=supported and C.is_interface_name(dev) and C.is_ipv4(address) and prefix and
    guest.proto=='static' and dev~='br-lan' and dev~='lo' and not N.is_protected_interface(dev,{})
  if valid then
    local bridge=false
    c:foreach('network','device',function(s)
      if s.name==dev and s.type=='bridge' then bridge=true end
    end)
    valid=bridge or guest.type=='bridge'
  end
  if valid then
    c:foreach('wireless','wifi-iface',function(s)
      -- The factory guest flag and exact guest network are both required.
      if s.guest=='1' and s.network=='guest' and (s.mode=='ap' or s.mode==nil) and C.is_interface_name(s.device) then
        candidates[#candidates+1]={id=s['.name'],ssid=s.ssid or s['.name'],radio=s.device,
          enabled=s.disabled~='1' and guest.disabled~='1',device=dev,address=address,
          cidr=address..'/'..prefix,network='guest',encryption=s.encryption or 'none'}
      end
    end)
  end
  local text=run({'/sbin/ip','-4','route','show','default'})
  local routes=M.default_routes(text)
  local uplinks={}
  local dump=call('network.interface','dump') or {}
  for _,item in ipairs(dump.interface or {}) do
    if item.up and item.interface~='lan' and item.interface~='guest' and C.is_interface_name(item.l3_device) then
      uplinks[item.l3_device]=item.interface
    end
  end
  for _,item in ipairs(routes) do item.network=uplinks[item.device] or item.device end
  return {supported=supported,model=board.model,candidates=candidates,uplinks=routes,
    guest_status=call('network.interface.guest') or {up=false}}
end
local function cert_info(cfg,cert,key)
  cert,key=cert or cfg.cert_path,key or cfg.key_path
  local result={ready=false,source=cfg.tls_source or 'unknown',browser_trust='unverified'}
  if not read(cert,32768) or not read(key,16384) then result.message='尚未配置门户证书和私钥'; return result end
  local out,rc=run({'/usr/bin/openssl','x509','-in',cert,'-noout','-subject','-issuer','-dates','-fingerprint','-sha256'})
  if rc~=0 then result.message='证书格式无效，请上传 PEM 证书'; return result end
  result.details=out
  local _,expires=run({'/usr/bin/openssl','x509','-in',cert,'-noout','-checkend','60'})
  if expires~=0 then result.message='证书已到期或即将到期'; return result end
  local _,valid_time=run({'/usr/bin/openssl','verify','-partial_chain','-CAfile',cert,cert})
  if valid_time~=0 then result.message='证书时间或证书链无效，请检查路由器时间和证书链'; return result end
  local host=cfg.portal_hostname~='' and cfg.portal_hostname or cfg.guest_address
  local match_text,matches=run({'/usr/bin/openssl','x509','-in',cert,'-noout',C.is_ipv4(host) and '-checkip' or '-checkhost',host})
  -- OpenSSL 1.1.1q exits zero even when -checkhost/-checkip reports a mismatch.
  if matches~=0 or not match_text:find(' does match certificate',1,true) then
    result.message='证书与认证地址不匹配：'..host; return result
  end
  local pub,prc=run({'/usr/bin/openssl','x509','-in',cert,'-noout','-pubkey'})
  local keypub,krc=run({'/usr/bin/openssl','pkey','-in',key,'-passin','pass:','-pubout'})
  if prc~=0 or krc~=0 or pub~=keypub then result.message='证书与私钥不匹配，或私钥带有密码'; return result end
  result.ready=true
  result.message=result.source=='generated' and '测试证书已就绪；终端仍需手动信任或在浏览器确认' or '证书和私钥校验通过；是否受信任由客户端决定'
  return result
end
M.certificate_info=cert_info
local function get_job()
  local job=json.parse(read(JOB,4096) or '') or {state='idle'}
  if job.state=='applying' and os.time()-(job.updated_at or 0)>90 then
    return {state='failed',message='应用任务超时，请重新检查后重试',updated_at=job.updated_at}
  end
  return job
end
local function put_job(state,message)
  write(JOB..'.tmp',json.stringify({state=state,message=message,updated_at=os.time()}))
  assert(fs.rename(JOB..'.tmp',JOB))
end
local function idle()
  local job=get_job()
  assert(job.state~='applying' or os.time()-(job.updated_at or 0)>90,'正在应用设置，请等待完成后再操作')
end
local function queue()
  put_job('applying','正在应用设置，请稍候')
  local _,rc=run({'/bin/sh','-c','/usr/libexec/netquota/apply </dev/null >/var/run/netquota-apply.log 2>&1 &'})
  assert(rc==0,'无法启动应用任务')
end
function M.status()
  local c=cursor(); local cfg=C.load()
  local d=discover(c)
  local https=c:get('uhttpd','main','listen_https')
  if type(https)=='table' then https=https[1] end
  d.admin_https_port=tonumber(tostring(https or ''):match(':(%d+)$'))
  d.enabled=cfg.enabled
  d.selected={wifi_section=cfg.wifi_section,egress=cfg.egress,portal_hostname=cfg.portal_hostname,
    portal_mode=cfg.portal_mode,address=cfg.guest_address,device=cfg.guest,url=C.portal_origin(cfg)..'/'}
  d.certificate=cert_info(cfg)
  local requested=C.from_table(cfg); requested.enabled=true
  local probe=N.new(requested):probe()
  d.checks={}
  local function check(label,ok,message) d.checks[#d.checks+1]={label=label,ok=ok==true,message=message} end
  check('GL 原厂访客网络',#d.candidates>0,'请选择原厂访客 Wi-Fi；管理网络不会被接管')
  local selected
  for _,item in ipairs(d.candidates) do if item.id==cfg.wifi_section then selected=item end end
  check('接管网络设置已保存',selected~=nil and selected.device==cfg.guest and selected.address==cfg.guest_address,
    '请先选择访客 Wi-Fi 和上网出口，点击“保存网络设置”')
  check('访客网络已启动',d.guest_status.up==true and selected~=nil and selected.enabled,'请先开启所选访客 Wi-Fi')
  local route_match=false
  for _,r in ipairs(d.uplinks) do for _,e in ipairs(cfg.egress) do if e==r.device then route_match=true end end end
  check('上网出口匹配',route_match,'当前实际出口：'..(#d.uplinks>0 and d.uplinks[1].device or '未连接外网'))
  if cfg.portal_mode=='https' then check('HTTPS 证书和私钥',d.certificate.ready,d.certificate.message)
  else check('HTTP 模式免证书',true,'HTTP 未加密，账号与会话不受 TLS 保护') end
  check('时间已同步',require('netquota.time').trusted(),'请先让路由器联网并完成时间同步')
  local accel=run({'/bin/sh','-c','uci -q show mtkhnat; uci -q show firewall'})
  check('硬件和软件加速已关闭',#N.parse_acceleration(accel)==0,'请在 GL 原厂界面关闭网络加速')
  local messages={}
  for _,message in ipairs(probe.errors or {}) do
    if message:find('TLS material',1,true) then message='请配置门户证书和私钥'
    elseif message:find('Guest interface',1,true) then message='访客网络地址尚未就绪'
    elseif message:find('Acceleration',1,true) then message='请关闭网络加速'
    elseif message:find('chrony',1,true) then message='请等待路由器时间同步' end
    messages[#messages+1]=message
  end
  check('网络就绪检查',probe.ok,table.concat(messages,'；'))
  d.can_enable=true
  for _,item in ipairs(d.checks) do if not item.ok then d.can_enable=false end end
  d.job=get_job()
  local runtime=json.parse(read('/var/run/netquota-status.json',8192) or '') or {}
  d.runtime=runtime
  d.active=cfg.enabled and runtime.state=='ready' and runtime.ok==true and d.can_enable
  return d
end
local function select_guest(c,id)
  assert(type(id)=='string' and id:match('^[%w_]+$'),'请选择访客 Wi-Fi')
  local d=discover(c)
  for _,item in ipairs(d.candidates) do if item.id==id then return item,d end end
  error('所选 Wi-Fi 不是可接管的 GL 原厂访客网络',0)
end
local function require_disabled(cfg) assert(not cfg.enabled,'请先停止接管，再修改网络或证书') end
-- Protocol changes retire bearer tokens from the other transport. No account,
-- period or byte counter is reset. The stopped service has already checkpointed.
function M.revoke_protocol_sessions(cfg)
  local core=require('netquota.core')
  local db=require('netquota.db')
  local service=assert(core.open({config=cfg,db_path=cfg.db_path,admin=true}))
  local ok,result=pcall(function()
    assert(service:lock())
    local success,err=db.transaction(service.db,function()
      local now=os.time()
      assert(db.exec(service.db,"UPDATE network_sessions SET state='revoked',revoked_at=?,revoke_reason='portal_protocol_changed' WHERE state='online'",{now}))
      assert(db.exec(service.db,"UPDATE portal_sessions SET revoked_at=?,revoke_reason='portal_protocol_changed' WHERE revoked_at IS NULL",{now}))
      return true
    end)
    assert(success,err and err.message or '无法撤销旧协议会话')
    return true
  end)
  service:unlock(); service:close()
  assert(ok,result)
end
function M.certificate_pem(raw)
  assert(type(raw)=='string' and #raw<=32768,'证书文件不能超过 32KB')
  local blocks={}
  local rest=raw:gsub('(%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-[%s%w+/=]+%-%-%-%-%-END CERTIFICATE%-%-%-%-%-)',function(block)
    blocks[#blocks+1]=block; return ''
  end)
  assert(#blocks>0 and rest:match('^%s*$'),'证书文件只能包含 PEM 证书链，不能包含私钥或其他内容')
  return table.concat(blocks,'\n')..'\n'
end
function M.save(args)
  return locked(function()
    idle(); local c=cursor(); clean(c,'netquota'); clean(c,'dhcp')
    local cfg=C.load(); require_disabled(cfg)
    local mode=args.portal_mode or cfg.portal_mode
    assert(mode=='http' or mode=='https','请选择 HTTP 或 HTTPS')
    local item,d=select_guest(c,args.wifi_section)
    assert(type(args.egress)=='string' and C.is_interface_name(args.egress),'请选择当前上网出口')
    local valid=false; for _,r in ipairs(d.uplinks) do if r.device==args.egress then valid=true end end
    assert(valid,'所选出口不是当前默认路由出口，请刷新后重试')
    local host=args.portal_hostname or ''
    assert(type(host)=='string' and (host=='' or C.is_hostname(host)),'认证域名格式无效，请仅填写域名，不包含 https:// 或端口')
    host=host:lower()
    local nextcfg=C.from_table(cfg)
    nextcfg.guest,nextcfg.guest_address,nextcfg.guest_cidr=item.device,item.address,item.cidr
    nextcfg.egress={args.egress}; nextcfg.portal_hostname=host; nextcfg.portal_mode=mode
  assert(not N.is_protected_interface(item.device,nextcfg),'不能接管管理或出口接口')
    assert(not C.cidr_contains(item.cidr,cfg.management_address),'访客网段与管理地址重叠')
    local existing=c:get_all('dhcp','netquota_portal')
    assert(not existing or existing.netquota_owned=='1','存在同名外部 DNS 配置，拒绝覆盖')
    local original=assert(read('/etc/config/netquota')); local olddns=assert(read('/etc/config/dhcp'))
    if mode~=cfg.portal_mode then M.revoke_protocol_sessions(cfg) end
    local ok,err=pcall(function()
      if host~='' then
        c:set('dhcp','netquota_portal','domain'); c:set('dhcp','netquota_portal','name',host)
        c:set('dhcp','netquota_portal','ip',item.address); c:set('dhcp','netquota_portal','netquota_owned','1')
      elseif existing then c:delete('dhcp','netquota_portal') end
      assert(c:commit('dhcp'),'DNS 配置保存失败')
      if not c:get('netquota','main') then c:set('netquota','main','netquota') end
      for k,v in pairs({guest=item.device,guest_address=item.address,guest_cidr=item.cidr,
          egress={args.egress},wifi_section=item.id,portal_hostname=host,portal_mode=mode}) do c:set('netquota','main',k,v) end
      assert(c:commit('netquota'),'接管配置保存失败')
    end)
    if not ok then
      c:revert('netquota'); c:revert('dhcp')
      write('/etc/config/netquota',original); write('/etc/config/dhcp',olddns)
      error(err,0)
    end
    queue()
    return {message='访客网络与出口已保存',applying=true}
  end)
end
function M.enable_guest(args)
  return locked(function()
    idle(); local c=cursor(); clean(c,'wireless'); clean(c,'network')
    require_disabled(C.load())
    local item=select_guest(c,args.wifi_section)
    if item.enabled then return {message='所选访客 Wi-Fi 已经开启，无需重载无线'} end
    c:set('wireless',item.id,'disabled','0'); c:set('network','guest','disabled','0')
    assert(c:commit('wireless')); assert(c:commit('network'))
    queue()
    -- Radio-specific reload; existing LAN SSIDs are not edited. GL may briefly
    -- reconnect the selected radio while applying its virtual guest AP.
    local _,rc=run({'/bin/sh','-c','/sbin/wifi reload '..quote(item.radio)..' </dev/null >/var/run/netquota-wifi.log 2>&1 &'})
    assert(rc==0,'无法重新载入访客无线')
    return {message='已开启访客 Wi-Fi，同频无线可能短暂重连',applying=true}
  end)
end
function M.capture(args)
  return locked(function()
    idle(); assert(type(args.enabled)=='boolean','接管开关必须为布尔值')
    local c=cursor(); clean(c,'netquota'); local cfg=C.load()
    if args.enabled then
      local d=M.status(); assert(d.can_enable,'尚未通过上线检查，请先处理页面列出的项目')
      select_guest(c,cfg.wifi_section)
      local guarded=C.from_table(cfg); guarded.enabled=true
      N.new(guarded):freeze()
    elseif cfg.enabled then N.new(cfg):freeze() end
    c:set('netquota','main','enabled',args.enabled and '1' or '0')
    assert(c:commit('netquota'),'接管开关保存失败')
    queue()
    return {message=args.enabled and '正在启用认证与流量配额' or '正在停止接管，访客将恢复普通上网',applying=true}
  end)
end
local function bundle()
  assert(fs.mkdirr(ROOT)); assert(fs.chmod(ROOT,'0700'))
  local path=ROOT..'/bundle-'..assert(require('netquota.crypto').random_hex(8))
  assert(fs.mkdir(path,'0700')); assert(fs.chmod(path,'0700'))
  write(path..'/.netquota-owned','netquota-tls-bundle\n')
  return path
end
local function remove_bundle(path)
  if type(path)~='string' or not path:match('^/etc/netquota/tls/bundle%-%x+$') or
    read(path..'/.netquota-owned',64)~='netquota-tls-bundle\n' then return end
  os.remove(path..'/cert.pem'); os.remove(path..'/key.pem'); os.remove(path..'/.netquota-owned'); fs.rmdir(path)
end
local function install_cert(cfg,path,source)
  local result=cert_info(cfg,path..'/cert.pem',path..'/key.pem')
  assert(result.ready,result.message)
  local c=cursor(); clean(c,'netquota')
  if cfg.portal_mode~='https' then M.revoke_protocol_sessions(cfg) end
  local old=cfg.cert_path:match('^(.*)/cert%.pem$')
  c:set('netquota','main','cert_path',path..'/cert.pem')
  c:set('netquota','main','key_path',path..'/key.pem')
  c:set('netquota','main','tls_source',source)
  c:set('netquota','main','portal_mode','https')
  assert(c:commit('netquota'),'无法保存证书配置')
  if old~=path then remove_bundle(old) end
  return {message=source=='generated' and '测试证书已生成，已选择 HTTPS；终端仍需手动信任' or '证书和私钥已保存，已选择 HTTPS'}
end
local function certificate(args,generate)
  return locked(function()
    idle(); local c=cursor(); clean(c,'netquota'); local cfg=C.load(); require_disabled(cfg)
    assert(cfg.wifi_section~='','请先选择并保存访客网络')
    assert(require('netquota.time').trusted(),'请先完成路由器时间同步')
    local path=bundle()
    local ok,result=pcall(function()
      if generate then
        local host=cfg.portal_hostname~='' and cfg.portal_hostname or cfg.guest_address
        local _,rc=run({'/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','365',
          '-subj','/CN=NetQuota Guest Portal','-addext','subjectAltName='..(C.is_ipv4(host) and 'IP:' or 'DNS:')..host,
          '-keyout',path..'/key.pem','-out',path..'/cert.pem'})
        assert(rc==0,'生成证书失败，请检查 OpenSSL 是否可用')
        assert(fs.chmod(path..'/cert.pem','0600')); assert(fs.chmod(path..'/key.pem','0600'))
      else
        local cert=M.certificate_pem(args.certificate_pem)
        assert(type(args.private_key_pem)=='string' and #args.private_key_pem<=16384 and
          not args.private_key_pem:find('ENCRYPTED',1,true),'请上传不超过 16KB 且不带密码的 PEM 私钥')
        write(path..'/cert.pem',cert); write(path..'/key.pem',args.private_key_pem)
      end
      return install_cert(cfg,path,generate and 'generated' or 'imported')
    end)
    if not ok then remove_bundle(path); error(result,0) end
    return result
  end)
end
function M.generate(args) return certificate(args,true) end
function M.import(args) return certificate(args,false) end
function M.public_certificate()
  local pem=read(C.load().cert_path,32768)
  assert(pem and pem:find('-----BEGIN CERTIFICATE-----',1,true),'暂无可下载的证书')
  return {certificate_pem=M.certificate_pem(pem),filename='netquota-portal.crt'}
end
function M.apply()
  local ok,err=pcall(function()
    locked(function()
      local _,rc=run({'/etc/init.d/dnsmasq','reload'})
      assert(rc==0,'DNS 服务重载失败')
      local _,restart=run({'/etc/init.d/netquota','restart'})
      assert(restart==0,'服务重启失败，请查看系统信息')
      local cfg=C.load()
      for i=1,12 do
        local runtime=json.parse(read('/var/run/netquota-status.json',8192) or '') or {}
        if (cfg.enabled and runtime.state=='ready' and runtime.ok) or (not cfg.enabled and runtime.state=='disabled') then
          put_job('done',cfg.enabled and '访客认证和配额已启用' or '设置已应用，接管已关闭'); return
        end
        nixio.nanosleep(1)
      end
      error('服务未就绪，网络保持守卫，请查看上线检查',0)
    end)
  end)
  if not ok then put_job('failed',tostring(err)) end
  return ok
end
return M

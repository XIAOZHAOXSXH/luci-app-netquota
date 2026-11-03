-- Read-only discovery plus real OpenSSL fixtures; never writes router UCI.
local D=require('netquota.deployment')
local C=require('netquota.config')
local N=require('nixio')
local fs=require('nixio.fs')
local function check(name,fn) fn(); print('PASS '..name) end
check('hostname input excludes schemes, ports, control characters and IPs',function()
  for _,s in ipairs({'portal.example.com','login.example.cn','nq.home.arpa'}) do assert(C.is_hostname(s),s) end
  for _,s in ipairs({'','x','.x.com','x..com','x.com.','-x.com','x-.com','https://x.com','x.com:2051',
      '192.168.9.1','a\nx.com','x.com;reboot','x.com/xx','x.com$(reboot)'}) do assert(not C.is_hostname(s),s) end
  assert(C.portal_origin({guest_address='192.168.9.1',https_port=2051,portal_hostname='portal.example.com',portal_mode='https'})=='https://portal.example.com:2051')
  assert(C.portal_origin(C.defaults())=='http://192.168.9.1:2050')
  assert(not pcall(C.from_table,{portal_mode='ftp'}))
end)
check('default route selects lowest metric and rejects malformed device names',function()
  local routes=D.default_routes('default via 1.1.1.1 dev eth0 metric 100\ndefault via 2.2.2.2 dev apclix0 metric 20\ndefault dev br-lan\n')
  assert(#routes==2 and routes[1].device=='apclix0' and routes[2].device=='eth0')
  assert(#D.default_routes('default dev lo\nnotdefault dev eth0\n')==0)
  assert(D.prefix('255.255.255.0')==24 and D.prefix('255.255.0.0')==16 and not D.prefix('255.0.255.0'))
end)
check('public certificate export cannot include an appended private key',function()
  local pem='-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n'
  assert(D.certificate_pem(pem..pem)==pem..pem)
  assert(not pcall(D.certificate_pem,pem..'-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----'))
  assert(not pcall(D.certificate_pem,'not a certificate'))
end)
local path='/tmp/netquota-deployment-test-'..N.getpid()
assert(not fs.access(path)); assert(fs.mkdir(path,'0700'))
local function run(cmd)
  local rc=os.execute(cmd..' </dev/null >/dev/null 2>&1'); assert(rc==0,cmd)
end
local ok,err=xpcall(function()
  run('openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=NetQuota-test -addext subjectAltName=IP:192.168.9.1 -keyout '..path..'/key.pem -out '..path..'/cert.pem')
  local cfg={portal_hostname='',guest_address='192.168.9.1',tls_source='generated',cert_path=path..'/cert.pem',key_path=path..'/key.pem'}
  check('generated IP certificate, expiry and key pair validated by real OpenSSL',function()
    local info=D.certificate_info(cfg); assert(info.ready,info.message)
    assert(info.browser_trust=='unverified' and info.details:find('Fingerprint',1,true))
  end)
  check('wrong SAN and absent/malformed keys cannot pass',function()
    cfg.portal_hostname='portal.example.com'; assert(not D.certificate_info(cfg).ready)
    cfg.portal_hostname=''; cfg.guest_address='192.168.8.1'; assert(not D.certificate_info(cfg).ready)
    cfg.guest_address='192.168.9.1'; cfg.key_path=path..'/missing.pem'; assert(not D.certificate_info(cfg).ready)
    local f=assert(io.open(path..'/bad.pem','w')); f:write('malformed secret marker'); f:close()
    cfg.key_path=path..'/bad.pem'; local info=D.certificate_info(cfg)
    assert(not info.ready and not info.message:find('malformed secret marker',1,true))
  end)
  run('openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=NetQuota-other -addext subjectAltName=DNS:portal.example.com -keyout '..path..'/other-key.pem -out '..path..'/other-cert.pem')
  check('valid key belonging to another certificate rejected',function()
    cfg.key_path=path..'/other-key.pem'; assert(not D.certificate_info(cfg).ready)
  end)
  check('domain certificate accepted only for its hostname',function()
    cfg.cert_path=path..'/other-cert.pem'; cfg.portal_hostname='portal.example.com'
    assert(D.certificate_info(cfg).ready)
    cfg.portal_hostname='other.example.com'; assert(not D.certificate_info(cfg).ready)
  end)
end,debug.traceback)
for _,name in ipairs({'cert.pem','key.pem','other-cert.pem','other-key.pem','bad.pem'}) do os.remove(path..'/'..name) end
fs.rmdir(path)
assert(ok,err)
check('protocol switch revokes existing sessions without clearing usage or passwords',function()
  local dbpath='/tmp/netquota-protocol-switch-'..N.getpid()..'.db'
  local core=require('netquota.core')
  local svc=assert(core.open({db_path=dbpath,admin=true}))
  local a=svc:request('create_account',{username='protocol_test',password='Protocol-test-123',quota_bytes=100000})
  assert(a.ok)
  local login=svc:portal_login('protocol_test','Protocol-test-123','192.168.9.2','02:00:00:00:00:02')
  assert(login.ok)
  local account=svc:request('get_account',{id=a.data.id}).data
  assert(svc:checkpoint({{user_id=a.data.id,period_id=account.period_id,upload_bytes=400,download_bytes=600}}).ok)
  svc:close()
  D.revoke_protocol_sessions({db_path=dbpath,enabled=false,portal_mode='http'})
  svc=assert(core.open({db_path=dbpath,admin=true}))
  assert(not svc:get_my_account(login.data.session_token,'192.168.9.2','02:00:00:00:00:02').ok)
  local after=svc:request('get_account',{id=a.data.id}).data
  assert(after.total_bytes==1000 and after.session_count==0)
  assert(svc:portal_login('protocol_test','Protocol-test-123','192.168.9.2','02:00:00:00:00:02').ok)
  svc:close()
  for _,suffix in ipairs({'','-wal','-shm'}) do os.remove(dbpath..suffix) end
end)
print('deployment validation: PASS')
check('configuring a certificate automatically selects HTTPS in a sandbox UCI config',function()
  local uci=require('uci'); local original_cursor=uci.cursor
  local base='/tmp/netquota-autotls-'..N.getpid()
  assert(not fs.access(base)); assert(fs.mkdir(base,'0700'))
  assert(fs.mkdir(base..'/config','0700')); assert(fs.mkdir(base..'/save','0700'))
  local file=assert(io.open(base..'/config/netquota','w'))
  file:write('config netquota "main"\n option enabled "0"\n option portal_mode "http"\n option wifi_section "guest5g"\n option db_path "'..base..'/ledger.db"\n');file:close()
  uci.cursor=function() return original_cursor(base..'/config',base..'/save') end
  local generated
  local success,problem=xpcall(function()
    assert(C.load().portal_mode=='http')
    D.generate({})
    generated=C.load()
    assert(generated.portal_mode=='https' and D.certificate_info(generated).ready)
    assert(C.portal_origin(generated)=='https://192.168.9.1:2051')
  end,debug.traceback)
  local state=original_cursor(base..'/config',base..'/save')
  local cert=state:get('netquota','main','cert_path')
  uci.cursor=original_cursor
  if cert then
    local dir=cert:match('^(/etc/netquota/tls/bundle%-%x+)/cert%.pem$')
    assert(dir)
    os.remove(dir..'/cert.pem');os.remove(dir..'/key.pem');os.remove(dir..'/.netquota-owned');fs.rmdir(dir)
  end
  for _,name in ipairs({'ledger.db','ledger.db-wal','ledger.db-shm','config/netquota','save/netquota'}) do os.remove(base..'/'..name) end
  fs.rmdir(base..'/config');fs.rmdir(base..'/save');fs.rmdir(base)
  assert(success,problem)
end)

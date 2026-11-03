-- SPDX-License-Identifier: GPL-2.0-only
-- Owns only inet netquota and inet netquota_guard. fw3 filtering still applies.
local M = {}
local C = require('netquota.config')
local NFT, MAX = '/usr/sbin/nft', 9007199254740991
local function number(n) return string.format('%.0f', n) end
local function quote(s) return "'" .. tostring(s):gsub("'", "'\"'\"'") .. "'" end
local function nq(s) return '"' .. s .. '"' end
local function run(argv)
  local words = {}
  for _, a in ipairs(argv) do words[#words+1] = quote(a) end
  local f = assert(io.popen(table.concat(words, ' ') ..
    ' 2>&1; printf "\\nNQ_EXIT:%s\\n" "$?"', 'r'), 'cannot execute command')
  local output = f:read('*a') or ''; f:close()
  local body, code = output:match('^(.*)\nNQ_EXIT:(%d+)\n$')
  assert(code, 'command did not return exit status'); code = tonumber(code)
  return body, code == 0 and '' or body, code
end
local protected = {lo=true, lan=true, ['br-lan']=true}
function M.is_protected_interface(dev, cfg)
  if not C.is_interface_name(dev) or protected[dev] then return true end
  if dev:match('^eth%d') or dev:match('^wan') or dev:match('^wwan') or
     dev:match('^apcli') or dev:match('^tun') or dev:match('^tap') or
     dev:match('^wg') or dev:match('^ppp') then return true end
  for _, e in ipairs((cfg or {}).egress or {}) do if e == dev then return true end end
  return false
end
local function check_cfg(cfg)
  cfg = C.from_table(cfg)
  assert(not M.is_protected_interface(cfg.guest, cfg), 'refusing management/uplink capture')
  assert(not C.cidr_contains(cfg.guest_cidr, cfg.management_address or '192.168.8.1'),
    'guest subnet overlaps management address')
  return cfg
end
function M.parse_acceleration(text)
  local errors = {}
  for line in tostring(text or ''):gmatch('[^\r\n]+') do
    if line:match('mtkhnat%.global%.enable=["\']?1') or
       line:match('%.flow_offloading=["\']?1') or
       line:match('%.flow_offloading_hw=["\']?1') then errors[#errors+1] = 'Acceleration enabled: '..line end
  end
  return errors
end
local function input_rules(cfg, emit)
  local g = nq(cfg.guest)
  emit('  iifname '..g..' meta nfproto ipv4 udp dport { 67, 68 } accept')
  emit('  iifname '..g..' meta nfproto ipv6 drop')
  emit('  iifname '..g..' ip saddr != '..cfg.guest_cidr..' drop')
  emit('  iifname '..g..' udp dport 53 accept')
  emit('  iifname '..g..' tcp dport 53 accept')
  local ports=cfg.portal_mode=='https' and (cfg.http_port..', '..cfg.https_port) or tostring(cfg.http_port)
  emit('  iifname '..g..' ip daddr '..cfg.guest_address..' tcp dport { '..ports..' } accept')
  emit('  iifname '..g..' drop')
end
function M.guard_rules(cfg)
  cfg = check_cfg(cfg)
  local out = {'table inet netquota_guard {',
    ' chain nq_guard { type filter hook forward priority -30; policy accept;',
    '  iifname '..nq(cfg.guest)..' drop', '  oifname '..nq(cfg.guest)..' drop', ' }',
    ' chain nq_input { type filter hook input priority -30; policy accept;'}
  input_rules(cfg, function(s) out[#out+1] = s end)
  out[#out+1] = ' }'; out[#out+1] = '}'
  return table.concat(out, '\n')..'\n'
end
function M.normalize_input(a, b)
  if type(a) == 'table' and a.accounts then return a.accounts, b end
  return a or {}, b
end
-- This pure builder returns a table declaration, with no unconditional delete.
function M.rules(cfg, input_accounts, flat_sessions)
  cfg = check_cfg(cfg)
  local accounts, extra = M.normalize_input(input_accounts, flat_sessions)
  local norm, by_id, seen_period, seen_ip = {}, {}, {}, {}
  for _, a in ipairs(accounts) do
    assert(C.is_identifier(a.id) and C.is_identifier(a.period_id), 'invalid account/period ID')
    assert(C.is_quota(a.quota_bytes), 'invalid quota')
    local up, down = tonumber(a.upload_bytes or 0), tonumber(a.download_bytes or 0)
    local used = tonumber(a.quota_used_bytes or (up + down))
    assert(C.is_counter(up) and C.is_counter(down) and C.is_counter(used), 'invalid counters')
    assert(up + down <= MAX, 'counter sum too large')
    local pid = tostring(a.period_id)
    assert(not seen_period[pid], 'duplicate period ID'); seen_period[pid] = true
    local copy = {id=tostring(a.id), pid=pid, quota=tonumber(a.quota_bytes), up=up,
      down=down, used=math.max(used, up + down), sessions={}, exhausted=a.exhausted}
    norm[#norm+1] = copy; by_id[copy.id] = copy
    local function add(s)
      if s.status and s.status ~= 'online' then return end
      local ip, mac = s.ipv4_address or s.ip, C.normalize_mac(s.mac_address or s.mac)
      assert(C.is_ipv4(ip) and C.cidr_contains(cfg.guest_cidr, ip), 'client outside guest subnet')
      assert(ip ~= cfg.guest_address and C.is_mac(mac), 'invalid client identity')
      assert(not seen_ip[ip], 'duplicate client address'); seen_ip[ip] = true
      copy.sessions[#copy.sessions+1] = {ip=ip, mac=mac}
    end
    copy.add = add
    for _, s in ipairs(a.sessions or {}) do add(s) end
  end
  for _, s in ipairs(extra or {}) do
    local a = by_id[tostring(s.user_id or s.account_id)]
    assert(a, 'session has unknown account'); a.add(s)
  end
  local out = {'table inet netquota {'}
  local function emit(s) out[#out+1] = s end
  -- One kernel object is the account's total budget, shared by every session and
  -- both directions. A request and its reply are different packets: both count.
  -- Direction counters follow the quota expression and count admitted packets only.
  for _, a in ipairs(norm) do
    -- The kernel rejects an initial consumed value above the quota after an
    -- administrator lowers the quota below existing usage. Saturate this
    -- object; direction counters and the SQLite ledger retain the full usage.
    emit(' quota q_'..a.pid..' { until '..number(a.quota)..' bytes used '..number(math.min(a.used,a.quota))..' bytes }')
    emit(' counter u_'..a.pid..' { packets 0 bytes '..number(a.up)..' }')
    emit(' counter d_'..a.pid..' { packets 0 bytes '..number(a.down)..' }')
  end
  local g = nq(cfg.guest)
  emit(' chain nq_forward { type filter hook forward priority -20; policy accept;')
  emit('  iifname '..g..' meta nfproto ipv6 drop'); emit('  oifname '..g..' meta nfproto ipv6 drop')
  for _, a in ipairs(norm) do
    if not a.exhausted and a.used < a.quota then
      for _, s in ipairs(a.sessions) do
        for _, e in ipairs(cfg.egress) do
          -- Bind upload to the server-observed IP/MAC pair. A changed address or
          -- randomized MAC requires reauthentication; IP alone is not identity.
          emit('  iifname '..g..' oifname '..nq(e)..' ip saddr '..s.ip..' ether saddr '..s.mac..
            ' quota name "q_'..a.pid..'" counter name "u_'..a.pid..'" accept')
          emit('  iifname '..nq(e)..' oifname '..g..' ip daddr '..s.ip..
            ' quota name "q_'..a.pid..'" counter name "d_'..a.pid..'" accept')
        end
      end
    end
  end
  -- Unconditional fallbacks: an exhausted account's quota no longer matches, so without
  -- these the packets would fall through to the chain policy (accept) and keep flowing.
  emit('  iifname '..g..' drop'); emit('  oifname '..g..' drop'); emit(' }')
  emit(' chain nq_input { type filter hook input priority -20; policy accept;')
  input_rules(cfg, emit); emit(' }')
  emit('}')
  return table.concat(out, '\n')..'\n'
end
local units = {bytes=1, kbytes=1024, mbytes=1048576, gbytes=1073741824, tbytes=1099511627776}
local function sized(n, u)
  assert(units[u], 'unknown nft unit')
  local result = tonumber(n) and tonumber(n)*units[u]
  assert(result and result >= 0 and result <= MAX and result == math.floor(result), 'invalid nft byte count')
  return result
end
local function until_mode(body)
  -- nft 0.9.6 omits the default "until" keyword when listing quota objects.
  local canonical=body:gsub('^%s*until%s+','')
  return canonical:match('^%s*%d+%s+%a+') ~= nil
end
function M.parse_state(text)
  assert(type(text) == 'string' and text:match('table%s+inet%s+netquota%s*{'), 'unexpected nft table output')
  local state, seen = {}, {}
  local function entry(pid)
    if not state[pid] then state[pid] = {period_id=tonumber(pid) or pid} end
    return state[pid]
  end
  for kind, name, body in text:gmatch('(%a+)%s+([%w_]+)%s*{([^{}]*)}') do
    if kind == 'counter' then
      local dir, pid = name:match('^([ud])_(%w+)$'); assert(dir, 'unexpected nft counter')
      local bytes = body:match('packets%s+%d+%s+bytes%s+(%d+)'); assert(bytes, 'malformed nft counter')
      entry(pid)[dir == 'u' and 'upload_bytes' or 'download_bytes'] = sized(bytes, 'bytes')
      seen[pid..dir] = true
    elseif kind == 'quota' then
      -- Per-direction quota objects: qu_<pid> (upload) and qd_<pid> (download).
      local dir, pid = name:match('^(q[u])_(%w+)$'); dir = dir and dir:sub(2)
      if not dir then dir, pid = name:match('^(q[d])_(%w+)$'); dir = dir and dir:sub(2) end
      if not dir then
        -- Legacy single shared object q_<pid>: record its used bytes as the total.
        pid = name:match('^q_(%w+)$'); assert(pid, 'unexpected nft quota')
        assert(until_mode(body), 'unexpected quota mode')
        local used, unit = body:match('used%s+(%d+)%s+(%a+)')
        entry(pid).quota_used_bytes = used and sized(used,unit) or 0
        seen[pid..'q'] = true
      else
        local used, unit = body:match('used%s+(%d+)%s+(%a+)')
        assert(until_mode(body), 'unexpected quota mode')
        local e = entry(pid)
        e[dir == 'u' and 'up_quota_used_bytes' or 'down_quota_used_bytes'] = used and sized(used,unit) or 0
        seen[pid..'q'..dir] = true
      end
    end
  end
  local result = {}
  for pid, e in pairs(state) do
    assert(seen[pid..'u'] and seen[pid..'d'], 'incomplete nft account state')
    if seen[pid..'qu'] and seen[pid..'qd'] then
      -- Per-direction objects: the shared monthly total is their sum. Never report less
      -- than the counters prove, so a partial quota read cannot under-report usage.
      local sum = e.up_quota_used_bytes + e.down_quota_used_bytes
      e.quota_used_bytes = math.max(sum, e.upload_bytes + e.download_bytes)
    else
      assert(seen[pid..'q'], 'incomplete nft account state')
      e.quota_used_bytes = math.max(e.quota_used_bytes, e.upload_bytes + e.download_bytes)
    end
    result[#result+1] = e
  end
  table.sort(result, function(a,b) return tostring(a.period_id) < tostring(b.period_id) end)
  return result
end
function M.new(cfg, deps)
  cfg, deps = C.from_table(cfg or {}), deps or {}
  local self, cmd = {cfg=cfg}, deps.run or run
  local function exists(name)
    local out, err, code = cmd({NFT,'list','table','inet',name})
    if code == 0 then return true end
    if tostring(err or out):find('No such file') then return false end
    error('cannot inspect nft table: '..tostring(err or out),0)
  end
  local function apply(script)
    -- This vendor firmware has no /dev/stdin; nft -f - does not work.
    local n, fs = require('nixio'), require('nixio.fs')
    fs.mkdirr('/var/run/netquota'); assert(fs.chmod('/var/run/netquota','0700'), 'cannot protect runtime directory')
    local path = '/var/run/netquota/nft-'..tostring(n.getpid())..'.nft'
    local f = assert(n.open(path,'w','0600'), 'cannot create nft input')
    local offset = 1
    while offset <= #script do
      local count = assert(f:write(script:sub(offset)), 'cannot write nft input')
      assert(count > 0, 'short nft write'); offset = offset+count
    end
    f:close()
    local out, err, code = cmd({NFT,'-c','-f',path})
    if code == 0 then out,err,code = cmd({NFT,'-f',path}) end
    os.remove(path)
    assert(code == 0, 'nft transaction failed: '..tostring(err ~= '' and err or out))
  end
  local IPT='/usr/sbin/iptables'
  local TAG='netquota-owned-captive'
  local function ipt(args)
    local argv={IPT,'-w','-t','nat'}
    for _,a in ipairs(args) do argv[#argv+1]=a end
    return cmd(argv)
  end
  local function captive_exists()
    local _,_,code=ipt({'-nL','NQ_CAPTIVE'})
    if code~=0 then return false end
    local _,_,owned=ipt({'-C','NQ_CAPTIVE','-m','comment','--comment',TAG,'-j','RETURN'})
    assert(owned==0,'refusing foreign NQ_CAPTIVE chain')
    return true
  end
  function self:cleanup_captive()
    if not captive_exists() then return true end
    while true do
      local _,_,code=ipt({'-C','PREROUTING','-m','comment','--comment',TAG,'-j','NQ_CAPTIVE'})
      if code~=0 then break end
      local out,err,rc=ipt({'-D','PREROUTING','-m','comment','--comment',TAG,'-j','NQ_CAPTIVE'})
      assert(rc==0,tostring(err or out))
    end
    local out,err,rc=ipt({'-F','NQ_CAPTIVE'}); assert(rc==0,tostring(err or out))
    out,err,rc=ipt({'-X','NQ_CAPTIVE'}); assert(rc==0,tostring(err or out))
    return true
  end
  function self:install_captive(snapshot)
    check_cfg(cfg)
    local exists=captive_exists()
    local accounts=M.normalize_input(snapshot)
    local lines={'*nat',':NQ_CAPTIVE - [0:0]','-F NQ_CAPTIVE'}
    for _,a in ipairs(accounts) do
      local used=math.max(tonumber(a.quota_used_bytes or 0),
        tonumber(a.upload_bytes or 0)+tonumber(a.download_bytes or 0))
      if not a.exhausted and used<tonumber(a.quota_bytes) then
        for _,s in ipairs(a.sessions or {}) do
          local ip=s.ipv4_address; local mac=C.normalize_mac(s.mac_address)
          assert(C.is_ipv4(ip) and C.cidr_contains(cfg.guest_cidr,ip) and C.is_mac(mac),'invalid captive identity')
          lines[#lines+1]='-A NQ_CAPTIVE -i '..cfg.guest..' -p tcp --dport 80 -s '..ip..
            ' -m mac --mac-source '..mac..' -j RETURN'
        end
      end
    end
    lines[#lines+1]='-A NQ_CAPTIVE -i '..cfg.guest..' -p tcp --dport 80 -j REDIRECT --to-ports '..cfg.http_port
    lines[#lines+1]='-A NQ_CAPTIVE -m comment --comment '..TAG..' -j RETURN'
    local _,_,hook=ipt({'-C','PREROUTING','-m','comment','--comment',TAG,'-j','NQ_CAPTIVE'})
    if hook~=0 then lines[#lines+1]='-I PREROUTING 1 -m comment --comment '..TAG..' -j NQ_CAPTIVE' end
    lines[#lines+1]='COMMIT'
    local n,fs=require('nixio'),require('nixio.fs')
    fs.mkdirr('/var/run/netquota'); assert(fs.chmod('/var/run/netquota','0700'))
    local path='/var/run/netquota/iptables-'..n.getpid()..'.restore'
    local f=assert(n.open(path,'w','0600'))
    local data=table.concat(lines,'\n')..'\n'
    local offset=1
    while offset<=#data do local count=assert(f:write(data:sub(offset))); assert(count>0); offset=offset+count end
    f:close()
    local out,err,rc=cmd({'/bin/sh','-c','/usr/sbin/iptables-restore --noflush < '..quote(path)})
    os.remove(path)
    assert(rc==0,'cannot install owned captive rules: '..tostring(err~='' and err or out))
    return true
  end
  function self:freeze()
    local body = M.guard_rules(cfg)
    apply((exists('netquota_guard') and 'delete table inet netquota_guard\n' or '')..body)
    return true
  end
  function self:thaw()
    if exists('netquota_guard') then apply('delete table inet netquota_guard\n') end
    return true
  end
  function self:cleanup()
    self:cleanup_captive()
    local script = ''
    for _, t in ipairs({'netquota','netquota_guard'}) do
      if exists(t) then script = script..'delete table inet '..t..'\n' end
    end
    if script ~= '' then apply(script) end
    return true
  end
  function self:snapshot()
    local out,err,code = cmd({NFT,'-nn','list','table','inet','netquota'})
    if code ~= 0 and tostring(err or out):find('No such file') then return {} end
    assert(code == 0, 'cannot read nft counters: '..tostring(err or out))
    return M.parse_state(out)
  end
  function self:install(a,b)
    if not cfg.enabled then return self:cleanup() end
    local body = M.rules(cfg,a,b)
    assert(exists('netquota_guard'), 'refusing unguarded table replacement')
    apply((exists('netquota') and 'delete table inet netquota\n' or '')..body)
    self:install_captive(a)
    return true
  end
  function self:rules(a,b) return M.rules(cfg,a,b) end
  function self:probe()
    local errors,warnings = {},{}
    local function err(s) errors[#errors+1] = s end
    local time=require('netquota.time').status()
    if not time.trusted then
      if cfg.enabled then err(time.reason) else warnings[#warnings+1]=time.reason end
    end
    if M.is_protected_interface(cfg.guest,cfg) then err('Refusing management/uplink capture') end
    if C.cidr_contains(cfg.guest_cidr,cfg.management_address or '192.168.8.1') then err('Guest overlaps management') end
    local out,why,code = cmd({NFT,'--version'})
    if code ~= 0 or not tostring(out):find('nftables') then err('nftables unavailable: '..tostring(why)) end
    local addr,_,ac = cmd({'/sbin/ip','-4','-o','addr','show','dev',cfg.guest})
    if ac ~= 0 or not tostring(addr):find('inet '..cfg.guest_address:gsub('%.','%%.')..'/') then
      if cfg.enabled then err('Guest interface/address is not ready') else warnings[#warnings+1] = 'Guest network is not ready' end
    end
    local accel = cmd({'/bin/sh','-c','uci -q show mtkhnat; uci -q show firewall'})
    for _, message in ipairs(M.parse_acceleration(accel)) do err(message) end
    for _, field in ipairs(cfg.portal_mode=='https' and {'cert_path','key_path'} or {}) do
      local f = io.open(cfg[field],'rb')
      if f then f:close() elseif cfg.enabled then err('TLS material missing: '..cfg[field])
      else warnings[#warnings+1] = 'TLS material missing: '..cfg[field] end
    end
    warnings[#warnings+1] = 'Acceleration configuration checked; forwarding visibility requires independent traffic validation'
    return {ok=#errors==0,errors=errors,warnings=warnings,enabled=cfg.enabled,
      admin_allowed=not cfg.enabled or #errors==0,runtime_acceleration_verified=false}
  end
  function self:peer(ip)
    assert(cfg.enabled, 'Guest capture disabled')
    assert(C.is_ipv4(ip) and C.cidr_contains(cfg.guest_cidr,ip) and ip ~= cfg.guest_address,
      'Client is outside guest network')
    local out,why,code = cmd({'/sbin/ip','-4','neigh','show','dev',cfg.guest,'to',ip})
    assert(code == 0, 'Neighbour lookup failed: '..tostring(why))
    for line in tostring(out):gmatch('[^\r\n]+') do
      if line:match('^(%d+%.%d+%.%d+%.%d+)') == ip and not line:find('FAILED') and not line:find('INCOMPLETE') then
        local mac = C.normalize_mac(line:match('lladdr%s+(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)'))
        if C.is_mac(mac) then return {ip=ip,mac=mac} end
      end
    end
    error('Client has no resolved guest neighbour',0)
  end
  return self
end
return M

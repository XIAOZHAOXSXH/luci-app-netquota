-- Real packets through the production rule builder; router-lab.sh owns topology.
io.stdout:setvbuf('no')
local N=require('netquota.network')
local function command(cmd)
 local p=assert(io.popen(cmd..' 2>&1; printf "\\nRESULT:%s\\n" "$?"'))
 local data=p:read('*a'); p:close()
 local out,rc=data:match('^(.*)\nRESULT:(%d+)\n$')
 assert(rc,'no command result'); return tonumber(rc),out
end
local function shell(cmd) local rc,out=command(cmd); assert(rc==0,tostring(out)); return out end
local cfg={enabled=true,guest='nqtbr0',guest_address='198.18.77.1',
 guest_cidr='198.18.77.0/24',management_address='192.168.8.1',egress={'nqtw0'}}
local function client(ip,mac) return {ipv4_address=ip,mac_address=mac} end
local accounts={
 {id=1,period_id=900001,quota_bytes=16000,upload_bytes=0,download_bytes=0,
  sessions={client('198.18.77.2','02:00:00:77:00:02'),client('198.18.77.3','02:00:00:77:00:03')}},
 {id=2,period_id=900002,quota_bytes=1000000,upload_bytes=0,download_bytes=0,
  sessions={client('198.18.77.4','02:00:00:77:00:04')}}}
local net=N.new(cfg)
local function readings()
 local out={}; for _,r in ipairs(net:snapshot()) do out[r.period_id]=r end; return out
end
local function ping(ns,n,size)
 return command('ip netns exec '..ns..' ping -c '..n..' -s '..size..' -W 1 198.18.78.2')
end
local function ping_ok(ns,n,size) local rc,out=ping(ns,n,size); assert(rc==0,out) end
local function check(name,fn) fn(); print('PASS '..name) end
local ok,err=xpcall(function()
 net:freeze(); net:install({accounts=accounts}); net:thaw()
 command('nft delete table inet netquota_lab_guard')
 check('two clients, both directions, one budget',function()
  ping_ok('nqta',2,1000); ping_ok('nqtb',2,1000)
  local a=readings()[900001]
  assert(a.upload_bytes==4112 and a.download_bytes==4112,'expected four 1028-byte packets each way')
  assert(a.quota_used_bytes==8224,'quota must equal upload plus download')
 end)
 check('unknown and forged client addresses rejected',function()
  shell('ip netns exec nqtc ip addr add 198.18.77.50/24 dev nqtc1')
  assert(command('ip netns exec nqtc ping -c 1 -W 1 -I 198.18.77.50 198.18.78.2')~=0)
  shell('ip netns exec nqtc ip addr del 198.18.77.50/24 dev nqtc1')
  shell('ip netns exec nqtc ip addr add 198.18.77.2/24 dev nqtc1')
  local before=readings()[900001].quota_used_bytes
  command('ip netns exec nqtc ping -c 1 -W 1 -I 198.18.77.2 198.18.78.2')
  assert(readings()[900001].quota_used_bytes==before,'forged MAC/IP reached quota')
  shell('ip netns exec nqtc ip addr del 198.18.77.2/24 dev nqtc1')
  command('ip neigh del 198.18.77.2 dev nqtbr0')
 end)
 check('exhaustion blocks both terminals before daemon polling',function()
  ping('nqta',12,1000)
  assert(ping('nqta',1,100)~=0); assert(ping('nqtb',1,100)~=0)
  local a=readings()[900001]; assert(a.quota_used_bytes>=16000)
  local up,down=a.upload_bytes,a.download_bytes
  ping('nqtb',2,1000); a=readings()[900001]
  assert(a.upload_bytes==up and a.download_bytes==down,'dropped traffic was billed')
 end)
 check('another account remains online',function() ping_ok('nqtc',2,500) end)
 check('IPv6 cannot bypass authentication',function()
  assert(command('ip netns exec nqtc ping -6 -c 1 -W 1 2001:db8:78::2')~=0)
 end)
 check('guarded rebuild preserves counters and exhaustion',function()
  net:freeze(); local r=readings()
  for _,a in ipairs(accounts) do
   local p=r[a.period_id]; a.upload_bytes,a.download_bytes,a.quota_used_bytes=p.upload_bytes,p.download_bytes,p.quota_used_bytes
  end
  net:install({accounts=accounts}); net:thaw()
  local after=readings()
  for id,p in pairs(r) do assert(after[id].upload_bytes==p.upload_bytes and after[id].download_bytes==p.download_bytes) end
  assert(ping('nqta',1,100)~=0); ping_ok('nqtc',1,100)
 end)
 check('an established paced TCP transfer stops at the shared quota',function()
  net:freeze()
  local old=readings()[900002]
  accounts[2].upload_bytes,accounts[2].download_bytes,accounts[2].quota_used_bytes=old.upload_bytes,old.download_bytes,old.quota_used_bytes
  accounts[1]={id=1,period_id=900003,quota_bytes=60000,upload_bytes=0,download_bytes=0,
    sessions={client('198.18.77.2','02:00:00:77:00:02')}}
  net:install({accounts=accounts}); net:thaw()
  local server=shell('ip netns exec nqts iperf3 -s -1 -B 198.18.78.2 -p 5219 >/tmp/netquota-lab/tcp-server.log 2>&1 & echo $!'):match('(%d+)')
  shell('sleep 1')
  local sender=shell('ip netns exec nqta iperf3 -c 198.18.78.2 -p 5219 -b 100K -l 1024 -t 20 >/tmp/netquota-lab/tcp-client.log 2>&1 & echo $!'):match('(%d+)')
  assert(server and sender)
  local success,problem=pcall(function()
   shell('sleep 2')
   local first=readings()[900003]
   assert(first.upload_bytes>0 and first.quota_used_bytes<60000,'TCP did not establish under quota')
   local last
   for i=1,10 do
    last=readings()[900003]
    if last.quota_used_bytes>=60000 then break end
    shell('sleep 1')
   end
   assert(last.quota_used_bytes>=60000,'paced transfer did not exhaust quota')
   shell('sleep 2')
   local after=readings()[900003]
   assert(after.upload_bytes==last.upload_bytes and after.download_bytes==last.download_bytes,
     'established TCP connection continued passing')
   ping_ok('nqtc',1,100)
  end)
  command('kill '..sender..' '..server)
  assert(success,problem)
 end)
end,debug.traceback)
if not ok then local _,state=command('nft -nn list table inet netquota'); io.stderr:write(state..'\n') end
pcall(net.freeze,net)
local cleaned,cleanup_err=pcall(net.cleanup,net)
assert(cleaned,cleanup_err); assert(ok,err)
print('forwarding integration: PASS')

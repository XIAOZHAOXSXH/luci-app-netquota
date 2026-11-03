local N = require('netquota.network')
local cfg = {guest='br-guest',guest_address='192.168.9.1',guest_cidr='192.168.9.0/24',
 management_address='192.168.8.1',egress={'eth0'}}
local a = {id=1,period_id=7,quota_bytes=10000,upload_bytes=1000,download_bytes=2000,
 quota_used_bytes=3000,sessions={{ip='192.168.9.2',mac='02:00:00:00:00:02'},
 {ip='192.168.9.3',mac='02:00:00:00:00:03'}}}
local function contains(s,v) return s:find(v,1,true)~=nil end
local text=N.rules(cfg,{a})
local _,count=text:gsub(' quota q_7 {','')
assert(count==1,'account must have one shared budget')
assert(not contains(text,'quota qu_') and not contains(text,'quota qd_'))
assert(contains(text,'until 10000 bytes used 3000 bytes'))
local _,uses=text:gsub('quota name "q_7"','')
assert(uses==4,'two clients in both directions share the object')
assert(contains(text,'quota name "q_7" counter name "u_7" accept'))
assert(contains(text,'quota name "q_7" counter name "d_7" accept'))
assert(contains(text,'ether saddr 02:00:00:00:00:02'))
assert(contains(text,'iifname "br-guest" meta nfproto ipv6 drop'))
assert(contains(text,'oifname "br-guest" meta nfproto ipv6 drop'))
assert(contains(text,'iifname "br-guest" drop'))
assert(contains(text,'oifname "br-guest" drop'))
assert(not contains(text,'hook prerouting'))
local fixture=[[table inet netquota {
 quota q_7 { until 10 kbytes used 4 kbytes }
 counter u_7 { packets 2 bytes 2000 }
 counter d_7 { packets 2 bytes 2096 }
}]]
local state=N.parse_state(fixture)
assert(#state==1 and state[1].period_id==7)
assert(state[1].upload_bytes==2000 and state[1].download_bytes==2096)
assert(state[1].quota_used_bytes==4096)
assert(N.parse_state(fixture:gsub('until ',''))[1].quota_used_bytes==4096)
assert(not pcall(N.parse_state,fixture:gsub('until','over')))
local reduced=N.rules(cfg,{{id=9,period_id=9,quota_bytes=1,upload_bytes=400,download_bytes=600,
  quota_used_bytes=1000,exhausted=true,sessions={}}})
assert(contains(reduced,'until 1 bytes used 1 bytes'),'saturate consumed quota for kernel restore')
assert(contains(reduced,'counter u_9 { packets 0 bytes 400 }') and contains(reduced,'counter d_9 { packets 0 bytes 600 }'))
local lowered=N.parse_state([[table inet netquota {
 quota q_9 { 1 bytes used 1 bytes }
 counter u_9 { packets 1 bytes 400 }
 counter d_9 { packets 1 bytes 600 }
}]])[1]
assert(lowered.quota_used_bytes==1000,'full ledger usage survives lowering the quota')
a.sessions[2].ip=a.sessions[1].ip
assert(not pcall(N.rules,cfg,{a}),'duplicate IP')
a.sessions[2].ip='192.168.8.50'
assert(not pcall(N.rules,cfg,{a}),'management address')
a.sessions[2].ip='192.168.9.3'
for _,dev in ipairs({'br-lan','lo','eth0','wg0'}) do
 local copy={}; for k,v in pairs(cfg) do copy[k]=v end; copy.guest=dev
 assert(not pcall(N.rules,copy,{a}),'protected interface '..dev)
end
print('rule generation and parsing: PASS')
local time=require('netquota.time')
local now=1793665035
local report='82E2A54D,130.226.165.77,2,1793665035.0,0,0,0,0,0,0,0,0,1024,Normal'
assert(time.parse(report,now).trusted)
assert(not time.parse(report:gsub('Normal','Not synchronised'),now).trusted)
assert(not time.parse(report,now+86401).trusted)
assert(not time.parse(report,now-301).trusted)
assert(not time.parse('',now).trusted)
print('trusted time status: PASS')

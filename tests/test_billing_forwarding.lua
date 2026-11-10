-- Real packets + production domain/rule builders. Only the lab table names differ.
-- router-lab.sh provides isolated, non-WAN topology; live Guest rules stay untouched.
io.stdout:setvbuf('no')
local N=require('netquota.network')
local core=require('netquota.core')
local dbmod=require('netquota.db')
local db='/tmp/netquota-billing-forwarding.db'
local cfg={enabled=true,guest='nqtbr0',guest_address='198.18.77.1',
  guest_cidr='198.18.77.0/24',management_address='192.168.8.1',egress={'nqtw0'}}
local function command(cmd)
  local p=assert(io.popen(cmd..' 2>&1; printf "\nRESULT:%s\n" "$?"'))
  local data=p:read('*a'); p:close()
  local out,rc=data:match('^(.*)\nRESULT:(%d+)\n$')
  return tonumber(assert(rc)),out
end
local function shell(cmd) local rc,out=command(cmd); assert(rc==0,out); return out end
local function apply(text)
  local path='/tmp/netquota-lab/billing.nft'
  local f=assert(io.open(path,'w')); f:write(text); f:close()
  shell('nft -f '..path)
end
local function present(name) return command('nft list table inet '..name)==0 end
local function remove(name) if present(name) then shell('nft delete table inet '..name) end end
local net={}
function net:freeze()
  local prefix=present('netquota_billing_guard') and 'delete table inet netquota_billing_guard\n' or ''
  apply(prefix..N.guard_rules(cfg):gsub('inet netquota_guard','inet netquota_billing_guard'))
  return true
end
function net:thaw() remove('netquota_billing_guard'); return true end
function net:snapshot()
  if not present('netquota_billing_lab') then return {} end
  return N.parse_state((shell('nft -nn list table inet netquota_billing_lab'):gsub('inet netquota_billing_lab','inet netquota')))
end
function net:install(snap)
  local prefix=present('netquota_billing_lab') and 'delete table inet netquota_billing_lab\n' or ''
  apply(prefix..N.rules(cfg,snap):gsub('inet netquota {','inet netquota_billing_lab {'))
  return true
end
local service
local function request(method,args)
  local r=service:request(method,args or {}); assert(r.ok,r.error and r.error.message); return r.data
end
local function ping(ns,count)
  return command('ip netns exec '..ns..' ping -c '..count..' -s 1000 -W 1 198.18.78.2')
end
local ok,err=xpcall(function()
  assert(not present('netquota_billing_lab') and not present('netquota_billing_guard'),'lab table collision')
  for _,suffix in ipairs({'','-wal','-shm'}) do os.remove(db..suffix) end
  service=assert(core.open{db_path=db,admin=true,config=cfg,network=net,log=false})
  local a=request('create_account',{username='billing_lab',password='Billing-lab-123',quota_bytes=12336})
  local b=request('create_account',{username='billing_other',password='Billing-lab-456',quota_bytes=1000000})
  request('update_settings',{traffic_multiplier_percent=150})
  request('portal_login',{username='billing_lab',password='Billing-lab-123',ip='198.18.77.2',mac='02:00:00:77:00:02'})
  request('portal_login',{username='billing_lab',password='Billing-lab-123',ip='198.18.77.3',mac='02:00:00:77:00:03'})
  request('portal_login',{username='billing_other',password='Billing-lab-456',ip='198.18.77.4',mac='02:00:00:77:00:04'})
  remove('netquota_lab_guard')
  assert(service:snapshot().accounts[1].real_quota_bytes==8224,'1.5x kernel budget')
  assert(ping('nqta',1)==0 and ping('nqtb',1)==0,'both terminals work under quota')
  request('tick')
  local first=request('get_account',{id=a.id})
  assert(first.total_bytes==4112 and first.billed_bytes==6168,'real packets billed at 1.5x')
  print('PASS 1.5x billing with two terminals and both directions')
  -- No daemon checkpoint during these packets: the kernel must enforce the limit.
  ping('nqta',5)
  assert(ping('nqta',1)~=0 and ping('nqtb',1)~=0,'both terminals blocked by kernel')
  assert(ping('nqtc',1)==0,'independent account stays online')
  local raw=net:snapshot()
  local reached
  for _,r in ipairs(raw) do if r.period_id==a.period_id then reached=r end end
  assert(reached and reached.quota_used_bytes>=8224,'converted quota exhausted')
  print('PASS converted shared quota stops traffic before polling; another account works')
  request('tick')
  local exhausted=request('get_account',{id=a.id})
  assert(exhausted.exhausted and exhausted.billed_bytes>=12336,'domain and kernel agree on exhaustion')
  request('update_settings',{traffic_multiplier_percent=100})
  assert(request('get_account',{id=a.id}).billed_bytes==exhausted.billed_bytes,'lowering rate never refunds usage')
  assert(ping('nqtb',1)~=0,'exhausted account stays blocked after changing rate')
  request('update_account',{id=a.id,quota_bytes=50000})
  request('portal_login',{username='billing_lab',password='Billing-lab-123',ip='198.18.77.2',mac='02:00:00:77:00:02'})
  assert(ping('nqta',1)==0,'quota increase restores access without clearing usage')
  print('PASS exhaustion, rate changes and increased quota reconcile without clearing usage')
end,debug.traceback)
if service then service:close() end
remove('netquota_billing_lab'); remove('netquota_billing_guard')
for _,suffix in ipairs({'','-wal','-shm'}) do os.remove(db..suffix) end
assert(ok,err)
print('billing forwarding integration: PASS')

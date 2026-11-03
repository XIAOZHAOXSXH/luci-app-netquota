-- Real HTTP handler + real SQLite/crypto/domain; only peer lookup is injected.
local portal=require('netquota.portal')
local core=require('netquota.core')
local json=require('luci.jsonc')
local db='/tmp/netquota-http-tests.db'
for _,suffix in ipairs({'','-wal','-shm'}) do os.remove(db..suffix) end
local cfg={enabled=true,guest_address='192.168.9.1',http_port=2050,https_port=2051,portal_mode='https',db_path=db}
local admin=assert(core.open{db_path=db,admin=true})
assert(admin:request('create_account',{username='http_alice',password='Alice-test-123',quota_bytes=50000000000,reset_day=15}).ok)
assert(admin:request('create_account',{username='http_bob',password='Bob-test-123',quota_bytes=50000000000,reset_day=25}).ok)
admin:close()
local network={}
function network:peer(ip)
 assert(ip=='192.168.9.2','unknown peer')
 return {ip=ip,mac='02:00:00:00:00:02'}
end
function network:probe() return {ok=true} end
local function request(method,path,body,extra)
 local raw=body and json.stringify(body) or ''
 local env={HTTPS='on',REMOTE_ADDR='192.168.9.2',CONTENT_LENGTH=tostring(#raw),
  CONTENT_TYPE='application/json',HTTP_ORIGIN='https://192.168.9.1:2051'}
 for key,value in pairs(extra or {}) do env[key]=value end
 local pieces={}; local original=io.write
 io.write=function(s) pieces[#pieces+1]=s end
 local ok,err=pcall(portal.main,{method=method,script_name='/cgi-bin/api'..path,env=env,config=cfg,
  network=network,stdin={read=function(_,n) return raw:sub(1,n) end},
  open_service=function(c) return assert(core.open{db_path=c.db_path,admin=false}) end})
 io.write=original; assert(ok,err)
 local response=table.concat(pieces)
 local header,payload=response:match('^(.-)\r\n\r\n(.*)$'); assert(header and payload,response)
 return tonumber(header:match('Status: (%d+)')),assert(json.parse(payload)),header,payload
end
local function expect(code,method,path,body,env)
 local actual,data,headers,payload=request(method,path,body,env)
 assert(actual==code,'expected '..code..', got '..actual..' '..payload)
 return data,headers,payload
end
expect(403,'POST','/login',{username='http_alice',password='Alice-test-123'},{HTTPS='off'})
expect(403,'POST','/login',{}, {HTTP_ORIGIN='https://attacker.invalid'})
expect(400,'POST','/login',{}, {QUERY_STRING='password=forbidden'})
expect(400,'POST','/login',{}, {CONTENT_TYPE='text/plain'})
expect(401,'POST','/login',{username='http_alice',password='wrong'})
expect(401,'POST','/login',{username='not_an_account',password='wrong'})
local data,header,payload=expect(200,'POST','/login',{username='http_alice',password='Alice-test-123'})
local token=assert(header:match('nq_session=(%x+)')); assert(#token==64)
assert(header:find('HttpOnly',1,true) and header:find('Secure',1,true) and header:find('SameSite=Strict',1,true))
assert(not payload:find(token,1,true),'cookie token leaked into JS-visible body')
assert(#data.data.csrf_token==64)
local csrf=data.data.csrf_token
local env={HTTP_COOKIE='nq_session='..token}
data=expect(200,'GET','/account',nil,env); assert(data.data.account.username=='http_alice')
expect(401,'GET','/account',nil,{HTTP_COOKIE='nq_session='..string.rep('0',64)})
expect(403,'POST','/password',{old_password='Alice-test-123',new_password='Changed-123',confirm_password='Changed-123'},env)
env.HTTP_X_CSRF_TOKEN=string.rep('0',64)
expect(403,'POST','/password',{old_password='Alice-test-123',new_password='Changed-123',confirm_password='Changed-123'},env)
env.HTTP_X_CSRF_TOKEN=csrf
expect(200,'POST','/password',{user_id=2,old_password='Alice-test-123',new_password='Changed-123',confirm_password='Changed-123'},env)
expect(401,'GET','/account',nil,env)
expect(401,'POST','/login',{username='http_alice',password='Alice-test-123'})
expect(200,'POST','/login',{username='http_alice',password='Changed-123'})
local bob_https,bob_header=expect(200,'POST','/login',{username='http_bob',password='Bob-test-123'})
local bob_token=assert(bob_header:match('nq_session=(%x+)'))
-- HTTP is an explicit separate transport, including a different cookie name.
cfg.portal_mode='http'
local plain_env={HTTPS='off',HTTP_ORIGIN='http://192.168.9.1:2050'}
local plain,plain_header,plain_payload=expect(200,'POST','/login',{username='http_bob',password='Bob-test-123'},plain_env)
local plain_token=assert(plain_header:match('nq_session_http=(%x+)'))
assert(not plain_header:find('; Secure',1,true) and plain_header:find('HttpOnly',1,true))
assert(not plain_payload:find(plain_token,1,true))
plain_env.HTTP_COOKIE='nq_session_http='..plain_token
expect(200,'GET','/account',nil,plain_env)
expect(401,'GET','/account',nil,{HTTPS='off',HTTP_COOKIE='nq_session='..bob_token})
cfg.portal_mode='https'
expect(401,'GET','/account',nil,{HTTP_COOKIE='nq_session_http='..plain_token})
cfg.portal_mode='http'
expect(403,'POST','/logout',{csrf_token=plain.data.csrf_token},{HTTPS='off',HTTP_ORIGIN='http://attacker.invalid',HTTP_COOKIE=plain_env.HTTP_COOKIE})
local _,cleared=expect(200,'POST','/logout',{csrf_token=plain.data.csrf_token},plain_env)
assert(cleared:find('nq_session_http=;',1,true) and not cleared:find('; Secure',1,true))
expect(401,'GET','/account',nil,plain_env)
local status=expect(200,'GET','/status',nil,{HTTPS='off'})
assert(status.data.config.protocol=='http' and status.data.config.tls_trust=='not_applicable')
cfg.portal_mode='https'
expect(401,'GET','/account',nil,{HTTP_COOKIE='nq_session_http='..plain_token})
expect(403,'POST','/login',{username='http_bob',password='Bob-test-123'},plain_env)
local out={};local saved_write=io.write
io.write=function(s)out[#out+1]=s end
portal.main_entry({config={portal_mode='http',guest_address='192.168.9.1',http_port=2050},env={HTTP_HOST='external.example',REQUEST_METHOD='GET'}})
io.write=saved_write
assert(table.concat(out):find('Location: http://192.168.9.1:2050/',1,true),'HTTP interception must canonicalise the origin')
for i=1,5 do request('POST','/login',{username='http_alice',password='wrong'}) end
expect(429,'POST','/login',{username='http_alice',password='wrong'})
for _,suffix in ipairs({'','-wal','-shm'}) do os.remove(db..suffix) end
print('HTTP/HTTPS portal, cookie isolation, CSRF, origin, revocation and throttling: PASS')

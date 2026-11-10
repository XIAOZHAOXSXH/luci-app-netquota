-- SPDX-License-Identifier: GPL-2.0-only
-- Independent guest authentication domain; never exposes administrative RPC.
local M = {}
local json = require('luci.jsonc')
local COOKIE = 'nq_session'
local function cookie_name(cfg) return cfg.portal_mode~='https' and 'nq_session_http' or COOKIE end
local function cookie_flags(cfg) return (cfg.portal_mode=='https' and '; Secure' or '')..'; HttpOnly; SameSite=Strict' end
local function clear_cookie(cfg) return cookie_name(cfg)..'=; Path=/; Max-Age=0'..cookie_flags(cfg) end
local CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "..
  "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
local fields = {'id','username','quota_bytes','upload_bytes','download_bytes','total_bytes',
  'billed_bytes','traffic_multiplier_percent','remaining_bytes','usage_percent','exhausted','effective_reset_day','period_start_at',
  'period_end_at','next_reset_at','session_count'}
local function public_account(raw)
  raw = raw and (raw.account or raw) or {}
  local out = {}
  for _, key in ipairs(fields) do out[key] = raw[key] end
  out.used_bytes = raw.billed_bytes or raw.total_bytes or 0
  return out
end
local function origin(cfg) return require('netquota.config').portal_origin(cfg) end
local function response(status, body, cookie)
  local payload = require('netquota.util').json_encode(body)
  local reasons={[200]='OK',[400]='Bad Request',[401]='Unauthorized',[403]='Forbidden',
    [404]='Not Found',[405]='Method Not Allowed',[429]='Too Many Requests',[503]='Service Unavailable'}
  local headers = {'Status: '..status..' '..assert(reasons[status]), 'Content-Type: application/json; charset=utf-8',
    'Cache-Control: no-store', 'X-Content-Type-Options: nosniff', 'X-Frame-Options: DENY',
    'Referrer-Policy: no-referrer', 'Content-Security-Policy: '..CSP}
  if cookie then headers[#headers+1] = 'Set-Cookie: '..cookie end
  headers[#headers+1] = 'Content-Length: '..#payload
  io.write(table.concat(headers,'\r\n')..'\r\n\r\n'..payload)
  return true
end
local function failure(status, code, message)
  return response(status,{ok=false,error={code=code,message=message}})
end
local function cookie_token(header,cfg)
  for key,value in tostring(header or ''):gmatch('([^;=%s]+)=([^;]*)') do
    if key == (cfg and cookie_name(cfg) or COOKIE) and #value == 64 and value:match('^%x+$') then return value end
  end
end
local function open_service(cfg, net)
  return require('netquota.core').open({db_path=cfg.db_path,config=cfg,network=net,admin=false,
    clock_trusted=require('netquota.time').trusted()})
end
local function body_of(ctx)
  local size = tostring(ctx.env.CONTENT_LENGTH or '')
  assert(size:match('^%d+$'), 'invalid body length')
  size = tonumber(size)
  assert(size > 0 and size <= 8192, 'body too large')
  local ct = tostring(ctx.env.CONTENT_TYPE or ''):lower()
  assert(ct:match('^application/json%s*;?'), 'invalid content type')
  local raw = assert(ctx.stdin:read(size), 'missing body')
  assert(#raw == size, 'short body')
  local value = json.parse(raw)
  assert(type(value) == 'table', 'invalid JSON object')
  return value
end
local function core_error(result)
  local code = tostring(result and result.error and result.error.code or 'INTERNAL'):lower()
  local status, message = 400, '提交的内容无效'
  if code == 'auth_failed' or code == 'password_mismatch' then status,message=401,'账号或密码错误'
  elseif code == 'session_invalid' then status,message=401,'登录会话已失效，请重新登录'
  elseif code == 'csrf_invalid' then status,message=403,'安全校验失败，请重新登录'
  elseif code == 'rate_limited' then status,message=429,'尝试过于频繁，请稍后再试'
  elseif code == 'network' or code == 'unavailable' or code == 'internal' or code == 'clock' then
    status,message=503,'认证服务暂不可用，请稍后再试'
  end
  return failure(status,code,message)
end
local function handle(ctx)
  local env,cfg = ctx.env,ctx.config
  if cfg.portal_mode=='https' and env.HTTPS ~= 'on' and env.HTTPS ~= '1' then
    return failure(403,'https_required','必须通过 HTTPS 访问认证服务')
  end
  if not cfg.enabled then return failure(503,'service_unavailable','访客认证尚未启用') end
  local method,path = ctx.method,ctx.path
  if method ~= 'GET' and method ~= 'POST' then return failure(405,'method_not_allowed','请求方法无效') end
  if method == 'POST' then
    if env.HTTP_ORIGIN ~= origin(cfg) or
      (env.HTTP_SEC_FETCH_SITE and env.HTTP_SEC_FETCH_SITE ~= '' and env.HTTP_SEC_FETCH_SITE ~= 'same-origin') then
      return failure(403,'origin_rejected','请求来源无效')
    end
    if env.QUERY_STRING and env.QUERY_STRING ~= '' then return failure(400,'query_credentials','请使用安全表单提交') end
  end
  local net = ctx.network or require('netquota.network').new(cfg)
  local service = (ctx.open_service or open_service)(cfg,net)
  assert(service,'service unavailable'); ctx.service=service
  local token = cookie_token(env.HTTP_COOKIE,cfg)
  local function peer() return net:peer(env.REMOTE_ADDR or '') end
  local function account()
    if not token then return nil end
    local p = peer()
    local result = service:get_my_account(token,p.ip,p.mac)
    if result.ok then return public_account(result.data) end
  end
  if method == 'GET' and (path == '/cgi-bin/api' or path == '/cgi-bin/api/status') then
    return response(200,{ok=true,data={config={portal_origin=origin(cfg),service='ready',
      protocol=cfg.portal_mode or 'http',tls_trust=cfg.portal_mode=='https' and 'unverified' or 'not_applicable',
      tls_note=cfg.portal_mode=='https' and '请确认浏览器信任管理员部署的证书' or 'HTTP 不加密传输，请仅使用专用上网账号',version=require('netquota.util').VERSION},
      session=token and {account=account()} or nil}})
  elseif method == 'GET' and path == '/cgi-bin/api/account' then
    local a=account()
    if not a then return failure(401,'unauthenticated','登录会话已失效') end
    return response(200,{ok=true,data={account=a}})
  elseif method ~= 'POST' then return failure(404,'not_found','未找到') end
  local ok,body=pcall(body_of,ctx)
  if not ok then return failure(400,'invalid_request','请求内容无效或超过 8 KB') end
  local p=peer()
  if path == '/cgi-bin/api/login' or path == '/cgi-bin/api' then
    local probe=net:probe()
    if not probe.ok then return failure(503,'service_unavailable','认证网络未通过就绪检查') end
    if type(body.username) ~= 'string' or type(body.password) ~= 'string' then
      return failure(400,'invalid_request','请输入账号和密码')
    end
    local result=service:portal_login(body.username,body.password,p.ip,p.mac)
    if not result.ok then return core_error(result) end
    local d=result.data
    assert(type(d.session_token)=='string' and #d.session_token==64 and d.session_token:match('^%x+$'),'invalid token')
    local age=math.max(0,math.floor(d.expires_at-(ctx.clock or os.time)()))
    local cookie=cookie_name(cfg)..'='..d.session_token..'; Path=/; Max-Age='..string.format('%.0f',age)..cookie_flags(cfg)
    return response(200,{ok=true,data={account=public_account(d.account),csrf_token=d.csrf_token,
      expires_at=d.expires_at,network_authorized=d.network_authorized,
      notice=not d.network_authorized and '本周期流量已用尽，仍可查看用量和修改密码。' or nil}},cookie)
  end
  if not token then return failure(401,'unauthenticated','请先登录') end
  local csrf=env.HTTP_X_CSRF_TOKEN or body.csrf_token
  if type(csrf)~='string' or #csrf~=64 then return failure(403,'csrf_failed','安全校验失败，请重新登录') end
  local result
  if path == '/cgi-bin/api/password' then
    result=service:change_my_password(token,csrf,body.old_password,body.new_password,body.confirm_password,p.ip,p.mac)
    if not result.ok then return core_error(result) end
    return response(200,{ok=true,data={sessions_revoked=true,usage_preserved=true,
      message='密码已修改，全部终端需重新登录；已用流量保持不变。'}},clear_cookie(cfg))
  elseif path == '/cgi-bin/api/logout' then
    result=service:logout(token,csrf,p.ip,p.mac)
    if not result.ok then return core_error(result) end
    return response(200,{ok=true,data={message='已退出登录。'}},clear_cookie(cfg))
  end
  return failure(404,'not_found','未找到')
end
function M.main(opts)
  opts=opts or {}
  local ctx={env=opts.env or {},config=opts.config or require('netquota.config').load(),
    stdin=opts.stdin or io.stdin,network=opts.network,open_service=opts.open_service,clock=opts.clock}
  ctx.method=opts.method or ctx.env.REQUEST_METHOD or 'GET'
  ctx.path=opts.script_name or ((ctx.env.SCRIPT_NAME or '/cgi-bin/api')..(ctx.env.PATH_INFO or ''))
  local ok,result=pcall(handle,ctx)
  if ctx.service and ctx.service.close then pcall(ctx.service.close,ctx.service) end
  if not ok then return failure(503,'service_unavailable','认证服务暂不可用，请稍后再试') end
  return result
end
function M.main_redirect(opts)
  local cfg=(opts or {}).config or require('netquota.config').load()
  local target=origin(cfg)..'/'
  io.write('Status: 302 Found\r\nLocation: '..target..
    '\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n请访问安全认证页面。')
  return true
end
function M.main_entry(opts)
  opts=opts or {}
  local cfg=opts.config or require('netquota.config').load()
  local env=opts.env or {HTTP_HOST=os.getenv('HTTP_HOST'),HTTPS=os.getenv('HTTPS'),REQUEST_METHOD=os.getenv('REQUEST_METHOD')}
  local origin_url=origin(cfg)
  local expected=origin_url:match('^https?://(.+)$')
  local tls=env.HTTPS=='on' or env.HTTPS=='1'
  if tostring(env.HTTP_HOST or ''):lower()~=expected:lower() or tls~=(cfg.portal_mode=='https') then
    return M.main_redirect({config=cfg})
  end
  local method=env.REQUEST_METHOD or 'GET'
  if method~='GET' and method~='HEAD' then
    io.write('Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nMethod not allowed.'); return
  end
  local f=assert(io.open('/usr/share/netquota/portal/index.html','rb'))
  local html=f:read('*a'); f:close()
  io.write('Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Length: '..#html..'\r\n\r\n')
  if method~='HEAD' then io.write(html) end
  return true
end
M._internal={portal_origin_of=origin,account_view=public_account,cookie_token=cookie_token}
return M

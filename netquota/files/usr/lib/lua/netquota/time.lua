-- Trust the target firmware's existing chrony synchronisation, not just a
-- plausible wall clock. No network requests or clock changes are made here.
local M={}
function M.parse(report,now)
  local fields={}
  for field in tostring(report or ''):gmatch('[^,\r\n]+') do fields[#fields+1]=field end
  local stratum,reference=tonumber(fields[3]),tonumber(fields[4])
  local leap=fields[#fields]
  leap=leap and leap:match('^%s*(.-)%s*$')
  local trusted=(leap=='Normal' or leap=='Insert second' or leap=='Delete second') and
    stratum and stratum>=1 and stratum<=15 and reference and reference>=1704067200 and
    now>=reference-300 and now-reference<=86400
  local result={trusted=trusted==true,provider='chrony',last_reference_at=reference}
  if not trusted then result.reason='Clock is not recently synchronised by chrony' end
  return result
end
function M.status()
  local file=io.open('/usr/bin/chronyc','r')
  if not file then return {trusted=false,reason='chronyc is unavailable; trusted time cannot be verified'} end
  file:close()
  local process=io.popen('/usr/bin/chronyc -n -c tracking 2>/dev/null','r')
  if not process then return {trusted=false,reason='Cannot read chrony status'} end
  local report=process:read('*a'); process:close()
  return M.parse(report,os.time())
end
function M.trusted() return M.status().trusted end
return M

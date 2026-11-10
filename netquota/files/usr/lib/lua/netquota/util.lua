-- NetQuota domain utilities: errors, strict validation, safe numeric math, JSON helpers.
-- This module contains no I/O and no secrets handling; it is safe to require from any
-- domain consumer (admin rpcd, CLI, portal handler, tests).

local util = {}
util.VERSION = "0.6.0"

util.MAX_SAFE = 9007199254740991   -- 2^53 - 1
util.MAX_QUOTA = util.MAX_SAFE
util.TWO32 = 4294967296
util.TWO16 = 65536

util.USERNAME_PATTERN = "^[A-Za-z0-9_-]+$"
util.USERNAME_MIN = 3
util.USERNAME_MAX = 24
util.PASSWORD_MIN = 8
util.PASSWORD_MAX = 128
util.RESET_DAY_MIN = 1
util.RESET_DAY_MAX = 31

util.DEFAULT_TIMEZONE = "Asia/Shanghai"
util.DEFAULT_RESET_DAY = 1
util.DEFAULT_DB_PATH = "/etc/netquota/netquota.db"
util.DEFAULT_LOCK_PATH = "/var/lock/netquota.lock"
util.DEFAULT_SESSION_TTL = 3600

----------------------------------------------------------------------------
-- Error envelopes
----------------------------------------------------------------------------

-- Machine readable error codes used by the admin/portal envelopes.
util.CODES = {
  INVALID_ARGUMENT = "INVALID_ARGUMENT",
  NOT_FOUND = "NOT_FOUND",
  CONFLICT = "CONFLICT",
  EXHAUSTED = "EXHAUSTED",
  AUTH_FAILED = "AUTH_FAILED",
  RATE_LIMITED = "RATE_LIMITED",
  SESSION_INVALID = "SESSION_INVALID",
  CSRF_INVALID = "CSRF_INVALID",
  PASSWORD_MISMATCH = "PASSWORD_MISMATCH",
  SEQUENCE = "SEQUENCE",
  BUSY = "BUSY",
  INTERNAL = "INTERNAL",
  UNAVAILABLE = "UNAVAILABLE",
  CLOCK = "CLOCK",
  NETWORK = "NETWORK",
  UNSUPPORTED = "UNSUPPORTED",
}

-- Builds the canonical failure payload: {ok=false, error={code=..., message=...}}
function util.error(code, message)
  return { ok = false, error = { code = code or util.CODES.INTERNAL, message = message or "internal error" } }
end

-- Builds the canonical success payload: {ok=true, data=...}
function util.ok(data)
  return { ok = true, data = data }
end

-- Convenience: merge an error envelope with extra machine-readable detail fields that are
-- safe to disclose (never includes secrets, hashes or tokens).
function util.error_detail(code, message, detail)
  local envelope = util.error(code, message)
  if type(detail) == "table" then
    for k, v in pairs(detail) do
      if k ~= "code" and k ~= "message" then envelope.error[k] = v end
    end
  end
  return envelope
end

----------------------------------------------------------------------------
-- Strict scalar validation
----------------------------------------------------------------------------

local function is_plain_integer(v)
  local t = type(v)
  return t == "number" and v == v and v ~= math.huge and v ~= -math.huge and v == math.floor(v)
end
util.is_plain_integer = is_plain_integer

-- Strictly accepts a JSON/Lua integer value inside [min,max]. Floats, strings, booleans,
-- NaN and infinities are rejected: callers must never coerce user input.
function util.integer(v, min, max, field)
  if not is_plain_integer(v) then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, string.format("%s must be an integer", tostring(field or "value")))
  end
  if min and v < min then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, tostring(field or "value") .. " must be >= " .. util.json_int(min))
  end
  if max and v > max then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, tostring(field or "value") .. " must be <= " .. util.json_int(max))
  end
  return v
end

-- Ids and byte counters additionally must be inside the IEEE-754 safe integer range.
function util.safe_integer(v, min, max, field)
  if not is_plain_integer(v) then return nil, util.error(util.CODES.INVALID_ARGUMENT, string.format("%s must be an integer", tostring(field or "value"))) end
  if v > util.MAX_SAFE or v < -util.MAX_SAFE then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, tostring(field or "value") .. " must be within +/-" .. util.json_int(util.MAX_SAFE))
  end
  return util.integer(v, min, max, field)
end

-- Returns true when v is a usable non-empty string and its byte length is inside [min,max].
function util.string_len(v, min, max)
  if type(v) ~= "string" then return false, 0 end
  local n = #v
  if min and n < min then return false, n end
  if max and n > max then return false, n end
  return true, n
end

-- Validates a username: 3..24 bytes of [A-Za-z0-9_-].
function util.username(v)
  if type(v) ~= "string" then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, "username must be a string")
  end
  local ok, n = util.string_len(v, util.USERNAME_MIN, util.USERNAME_MAX)
  if not ok then
    return nil, util.error(util.CODES.INVALID_ARGUMENT,
      string.format("username must be %d-%d characters", util.USERNAME_MIN, util.USERNAME_MAX))
  end
  if not v:match(util.USERNAME_PATTERN) then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, "username may only contain letters, digits, '_' and '-'")
  end
  local _ = n
  return v
end

-- Validates password strength constraints only; values are never echoed or logged.
function util.password(v, field)
  if type(v) ~= "string" then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, string.format("%s must be a string", field or "password"))
  end
  local ok, n = util.string_len(v, util.PASSWORD_MIN, util.PASSWORD_MAX)
  if not ok then
    return nil, util.error(util.CODES.INVALID_ARGUMENT,
      string.format("%s must be %d-%d bytes", field or "password", util.PASSWORD_MIN, util.PASSWORD_MAX))
  end
  if v:find("%z") then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, "password must not contain NUL bytes")
  end
  if not util.utf8_valid(v) then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, string.format("%s contains invalid UTF-8", field or "password"))
  end
  return v
end

-- Strict validation for a reset day: integer 1..31.
function util.reset_day(v, field)
  if util.is_null(v) then return nil end
  return util.integer(v, util.RESET_DAY_MIN, util.RESET_DAY_MAX, field or "reset_day")
end

function util.is_null(v)
  if v == nil then return true end
  local ok, json = pcall(require, "cjson")
  return ok and v == json.null
end

----------------------------------------------------------------------------
-- IP / MAC validation
----------------------------------------------------------------------------

-- Strict dotted-quad IPv4; rejects leading zeros and out-of-range octets.
function util.ipv4(v)
  if type(v) ~= "string" then return nil, util.error(util.CODES.INVALID_ARGUMENT, "ipv4 must be a string") end
  if #v < 7 or #v > 15 then return nil, util.error(util.CODES.INVALID_ARGUMENT, "ipv4 must be a dotted quad") end
  local parts = {}
  local count = 0
  for part in v:gmatch("[^.]+") do
    count = count + 1
    if count > 4 then break end
    parts[count] = part
  end
  if count ~= 4 or select(2, v:gsub("%.", "")) ~= 3 then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, "ipv4 must be a dotted quad")
  end
  for i = 1, 4 do
    local p = parts[i]
    if not p:match("^%d%d?%d?$") then return nil, util.error(util.CODES.INVALID_ARGUMENT, "ipv4 octet must be numeric") end
    if #p > 1 and p:sub(1, 1) == "0" then return nil, util.error(util.CODES.INVALID_ARGUMENT, "ipv4 octet has leading zero") end
    local n = tonumber(p)
    if not n or n < 0 or n > 255 then return nil, util.error(util.CODES.INVALID_ARGUMENT, "ipv4 octet out of range") end
  end
  return parts[1] .. "." .. parts[2] .. "." .. parts[3] .. "." .. parts[4]
end

-- Normalizes a MAC to lowercase colon form aa:bb:cc:dd:ee:ff; accepts '-' or ':' separators.
function util.mac(v)
  if type(v) ~= "string" then return nil, util.error(util.CODES.INVALID_ARGUMENT, "mac must be a string") end
  local hex = v:gsub("[-:]", "")
  if #hex ~= 12 or not hex:match("^%x+$") then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, "mac must be aa:bb:cc:dd:ee:ff")
  end
  local lo = hex:lower()
  local out = {}
  for i = 1, 12, 2 do out[#out + 1] = lo:sub(i, i + 1) end
  return table.concat(out, ":")
end

----------------------------------------------------------------------------
-- UTF-8 helpers (password byte validation only; no normalisation is applied)
----------------------------------------------------------------------------

function util.utf8_valid(s)
  local i, n = 1, #s
  while i <= n do
    local c = s:byte(i)
    local len
    if c < 0x80 then len = 1
    elseif c >= 0xC2 and c <= 0xDF then len = 2
    elseif c >= 0xE0 and c <= 0xEF then len = 3
    elseif c >= 0xF0 and c <= 0xF4 then len = 4
    else return false end
    if i + len - 1 > n then return false end
    for k = 1, len - 1 do
      local cc = s:byte(i + k)
      if cc < 0x80 or cc > 0xBF then return false end
    end
    i = i + len
  end
  return true
end

----------------------------------------------------------------------------
-- Case-insensitive uniqueness key for usernames
----------------------------------------------------------------------------

function util.username_key(v)
  if type(v) ~= "string" then return nil end
  return v:lower()
end

----------------------------------------------------------------------------
-- 64-bit safe byte arithmetic (LuaJIT/5.1 numbers may be int32 on some builds).
-- Counters can exceed 2^31, so sums are kept within the IEEE-754 safe range and are
-- checked before any use as a quota comparison.
----------------------------------------------------------------------------

-- Sums two non-negative safe integers; returns nil on overflow of the safe range.
function util.add_safe(a, b)
  if not is_plain_integer(a) or not is_plain_integer(b) then return nil end
  local sum = a + b
  if sum > util.MAX_SAFE then return nil end
  return sum
end

----------------------------------------------------------------------------
-- Safe JSON number formatting for responses (integers stay integers).
----------------------------------------------------------------------------

-- Formats an integer for JSON as a plain decimal digit string (no exponent, no ".0").
function util.json_int(v)
  if not is_plain_integer(v) then return "0" end
  if v == 0 then return "0" end
  local neg = v < 0
  if neg then v = -v end
  local digits = {}
  while v > 0 do
    local rem = v % 10
    digits[#digits + 1] = string.char(48 + rem)
    v = (v - rem) / 10
  end
  local out = {}
  for i = #digits, 1, -1 do out[#out + 1] = digits[i] end
  local s = table.concat(out)
  if neg then s = "-" .. s end
  return s
end

----------------------------------------------------------------------------
-- Deep-copy helpers / table utilities
----------------------------------------------------------------------------

function util.copy(t)
  if type(t) ~= "table" then return t end
  local out = {}
  for k, v in pairs(t) do
    if type(v) == "table" then out[k] = util.copy(v) else out[k] = v end
  end
  return out
end

-- Rejects unknown keys in an input table against a whitelist; returns error envelope on the
-- first unexpected key. Security-critical writes call this before any SQL is prepared.
function util.reject_unknown(args, allowed, what)
  if args == nil then return true end
  if type(args) ~= "table" then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, string.format("%s must be an object", what or "arguments"))
  end
  for k in pairs(args) do
    local key = k
    if type(key) ~= "string" or not allowed[key] then
      return nil, util.error(util.CODES.INVALID_ARGUMENT, string.format("unexpected field %s", tostring(key)))
    end
  end
  return true
end

-- Table of valid keys built from a list.
function util.allowed_keys(list)
  local set = {}
  for _, k in ipairs(list) do set[k] = true end
  return set
end

----------------------------------------------------------------------------
-- Percentage helper (integer floor, clamped to 0..100 .. no upper clamp for over-quota)
----------------------------------------------------------------------------

-- usage_percent = floor(total / quota * 100), guarded for quota < 1.
function util.usage_percent(total, quota)
  if not is_plain_integer(total) or not is_plain_integer(quota) or quota <= 0 then return 0 end
  if total <= 0 then return 0 end
  -- total and quota are safe integers; compute in two steps to avoid intermediate overflow.
  local whole = math.floor(total / quota)
  if whole >= 100 then return whole * 100 end
  local rem = total - whole * quota
  return whole * 100 + math.floor((rem * 100) / quota)
end

----------------------------------------------------------------------------
-- Time helper for monotonic sequence number of an hour bucket used by rate limiting.
----------------------------------------------------------------------------

function util.bucket(now, width)
  if not is_plain_integer(now) then return 0 end
  width = width or 1
  return now - (now % width)
end

-- lua-cjson 2.1 limits numeric output to 14 significant digits. Preserve the
-- complete safe-integer byte range at the HTTP/rpcd boundary instead.
function util.json_encode(value)
  local json = require("cjson")
  local array_keys = { items = true, sessions = true, errors = true, warnings = true,
    staged = true, readings = true, results = true, accounts = true,
    candidates = true, uplinks = true, checks = true, egress = true }
  local function encode(v, key)
    if v == nil or v == json.null then return "null" end
    local kind = type(v)
    if kind == "boolean" then return v and "true" or "false" end
    if kind == "string" then return json.encode(v) end
    if kind == "number" then
      if v ~= v or v == math.huge or v == -math.huge then error("non-finite JSON number") end
      if util.is_plain_integer(v) then return util.json_int(v) end
      return string.format("%.17g", v)
    end
    if kind ~= "table" then error("unsupported JSON value") end
    local count, max, sequence = 0, 0, true
    for k in pairs(v) do
      count = count + 1
      if type(k) ~= "number" or k < 1 or k ~= math.floor(k) then sequence = false
      elseif k > max then max = k end
    end
    if (count > 0 and sequence and max == count) or (count == 0 and array_keys[key]) then
      local out = {}
      for i = 1, max do out[i] = encode(v[i]) end
      return "[" .. table.concat(out, ",") .. "]"
    end
    local out, keys = {}, {}
    for k in pairs(v) do
      if type(k) ~= "string" then error("JSON object key must be a string") end
      keys[#keys + 1] = k
    end
    table.sort(keys)
    for _, k in ipairs(keys) do out[#out + 1] = json.encode(k) .. ":" .. encode(v[k], k) end
    return "{" .. table.concat(out, ",") .. "}"
  end
  return encode(value)
end

return util

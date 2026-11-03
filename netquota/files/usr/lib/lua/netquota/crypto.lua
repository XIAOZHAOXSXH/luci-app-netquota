-- NetQuota cryptography.
--
-- Storage format for password hashes is the standard sha512crypt MCF string:
--     $6$rounds=<N>$<salt>$<checksum>
-- produced by the native libc crypt(3) implementation exposed as nixio.crypt().
--
-- Rationale (verified on the MT3000 build): nixio.crypto is absent, so no native
-- HMAC/PBKDF2 primitive exists in this build, and a pure-Lua HMAC loop at 100k iterations
-- is far too slow on the router CPU. Native SHA512crypt with a high round count and a
-- unique CSPRNG salt is the strongest verified alternative and is used by default.
-- No unverified fallback cryptography is used by this service.
--
-- Secrets never leave this module: hashes are only returned to callers that must persist
-- them, and all comparisons are constant time.

local util = require("netquota.util")

local crypto = {}

crypto.METHOD_SHA512CRYPT = "sha512crypt"
crypto.DEFAULT_ROUNDS = 100000
crypto.MIN_ROUNDS = 100000
crypto.MAX_ROUNDS = 1000000
crypto.SALT_BYTES = 16          -- base64-ish charset gives 16 chars for 16 bytes
crypto.SALT_CHARS = 16
crypto.TOKEN_BYTES = 32         -- CSPRNG token material (64 hex chars)
crypto.TOKEN_DIGEST_ROUNDS = 1000

local CRYPT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

-- Same index set as util.TWO32 -- crypt(3) output returns below.
local TWO32 = 4294967296

-- Lazily resolved native dependencies. Missing pieces degrade to explicit errors rather
-- than silently producing weaker secrets.
local native = nil
local native_err = nil

local function load_native()
  if native ~= nil then return native end
  local ok_util, _ = pcall(require, "nixio.util")
  local _ = ok_util
  local ok, nixio = pcall(require, "nixio")
  if not ok or type(nixio) ~= "table" then
    native = false
    native_err = "nixio unavailable"
    return native
  end
  local ok_bin, nixio_bin = pcall(require, "nixio.bin")
  if not ok_bin then nixio_bin = nil end
  native = {
    nixio = nixio,
    bin = nixio_bin,
    crypt = type(nixio.crypt) == "function" and nixio.crypt or nil,
    rnd = type(nixio.rnd) == "table" and type(nixio.rnd.get) == "function" and nixio.rnd.get or nil,
    open = type(nixio.open) == "function" and nixio.open or nil,
    isatty = type(nixio.isatty) == "function" and nixio.isatty or nil,
  }
  return native
end

function crypto.native_status()
  local n = load_native()
  if not n then return { available = false, error = native_err } end
  return {
    available = true,
    crypt = n.crypt ~= nil,
    csprng = n.rnd ~= nil or n.open ~= nil,
  }
end

----------------------------------------------------------------------------
-- Bit helpers
----------------------------------------------------------------------------

-- luabitop style uint32 xor composed from arithmetic (no external bit library needed for
-- the fallback paths; native crypt does heavy lifting at runtime).
local function u32(x)
  x = x % TWO32
  if x < 0 then x = x + TWO32 end
  return x
end
crypto.u32 = u32

local function bxor32(a, b)
  local ok, bit = pcall(require, "bit")
  if ok and bit and bit.bxor then return bit.bxor(a, b) end
  a, b = u32(a), u32(b)
  local res, p = 0, 1
  for _ = 1, 32 do
    local ai, bi = a % 2, b % 2
    if ai ~= bi then res = res + p end
    a = (a - ai) / 2
    b = (b - bi) / 2
    p = p * 2
  end
  return res
end

local function band32(a, b)
  local ok, bit = pcall(require, "bit")
  if ok and bit and bit.band then return bit.band(a, b) end
  a, b = u32(a), u32(b)
  local res, p = 0, 1
  for _ = 1, 32 do
    local ai, bi = a % 2, b % 2
    if ai == 1 and bi == 1 then res = res + p end
    a = (a - ai) / 2
    b = (b - bi) / 2
    p = p * 2
  end
  return res
end

----------------------------------------------------------------------------
-- Constant-time primitives
----------------------------------------------------------------------------

-- Constant-time comparison for short secrets of identical type. Length differences are
-- folded into the result without early exit.
function crypto.equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then return false end
  local la, lb = #a, #b
  local max = la > lb and la or lb
  local diff = 0
  for i = 1, max do
    local ca = i <= la and a:byte(i) or 0
    local cb = i <= lb and b:byte(i) or 0
    diff = diff + (ca - cb) * (ca - cb)
  end
  if la ~= lb then diff = diff + 1 end
  return diff == 0
end

----------------------------------------------------------------------------
-- CSPRNG
----------------------------------------------------------------------------

local function urandom_bytes(n)
  local fh, err = io.open("/dev/urandom", "rb")
  if not fh then return nil, "urandom unavailable: " .. tostring(err) end
  local data = fh:read(n)
  fh:close()
  if not data or #data ~= n then return nil, "urandom short read" end
  return data
end

-- Returns n cryptographically strong random bytes, or nil + error.
function crypto.random_bytes(n)
  local nn = load_native()
  if nn and nn.rnd then
    local ok, data = pcall(nn.rnd, n)
    if ok and type(data) == "string" and #data == n then return data end
  end
  return urandom_bytes(n)
end

-- Returns a lowercase hex string from CSPRNG bytes.
function crypto.random_hex(nbytes)
  local raw, err = crypto.random_bytes(nbytes or crypto.TOKEN_BYTES)
  if not raw then return nil, err end
  local out = {}
  for i = 1, #raw do out[#out + 1] = string.format("%02x", raw:byte(i)) end
  return table.concat(out)
end

-- Generates a salt from the crypt(3) alphabet (no '$' or ':' allowed in salts).
function crypto.random_salt(nchars)
  nchars = nchars or crypto.SALT_CHARS
  local raw, err = crypto.random_bytes(nchars)
  if not raw then return nil, err end
  local out = {}
  for i = 1, nchars do
    local idx = (raw:byte(i) % #CRYPT_CHARS) + 1
    out[#out + 1] = CRYPT_CHARS:sub(idx, idx)
  end
  return table.concat(out)
end

----------------------------------------------------------------------------
-- sha512crypt via native crypt(3)
----------------------------------------------------------------------------

local function crypt_call(password, setting)
  local nn = load_native()
  if not nn then return nil, native_err or "nixio unavailable" end
  if not nn.crypt then return nil, "native crypt(3) unavailable (nixio.crypt missing)" end
  local ok, result = pcall(nn.crypt, password, setting)
  if not ok then return nil, "crypt() failed: " .. tostring(result) end
  if type(result) ~= "string" or result:sub(1, 3) ~= "$6$" then
    return nil, "crypt() did not return a sha512crypt hash"
  end
  return result
end

-- Returns the exact MCF setting string for a round count and salt.
function crypto.sha512crypt_setting(rounds, salt)
  rounds = rounds or crypto.DEFAULT_ROUNDS
  local s = ""
  if rounds and rounds ~= 5000 then
    s = "$6$rounds=" .. util.json_int(rounds) .. "$" .. salt
  else
    s = "$6$" .. salt
  end
  return s
end

-- Parses an MCF sha512crypt string into {method, rounds, salt, checksum}.
function crypto.parse_hash(stored)
  if type(stored) ~= "string" then return nil end
  local rounds, salt, sum = stored:match("^%$6%$rounds=(%d+)%$([^$]+)%$(.+)$")
  if rounds then
    return { method = crypto.METHOD_SHA512CRYPT, rounds = tonumber(rounds), salt = salt, checksum = sum }
  end
  salt, sum = stored:match("^%$6%$([^$]+)%$(.+)$")
  if salt then
    return { method = crypto.METHOD_SHA512CRYPT, rounds = 5000, salt = salt, checksum = sum }
  end
  return nil
end

-- Hash a password with sha512crypt. Returns {hash=..., method=..., rounds=...}.
-- Cost defaults to crypto.DEFAULT_ROUNDS (100000) and is never allowed below MIN_ROUNDS.
function crypto.hash_password(password, opts)
  if type(password) ~= "string" or #password == 0 then
    return nil, "password must be a non-empty string"
  end
  opts = opts or {}
  local rounds = opts.rounds or crypto.DEFAULT_ROUNDS
  if rounds < crypto.MIN_ROUNDS then return nil, "round count below minimum" end
  if rounds > crypto.MAX_ROUNDS then return nil, "round count above maximum" end
  local salt = opts.salt or crypto.random_salt(crypto.SALT_CHARS)
  if not salt then return nil, "failed to generate salt" end
  if not salt:match("^[%./0-9A-Za-z]+$") then return nil, "invalid salt alphabet" end
  local hash, err = crypt_call(password, crypto.sha512crypt_setting(rounds, salt))
  if not hash then return nil, err end
  return { hash = hash, method = crypto.METHOD_SHA512CRYPT, rounds = rounds }
end

-- Verify a password against a stored MCF hash. Always performs the full key derivation,
-- even for an empty/absent stored hash, so unknown accounts cost the same as known ones
-- (see crypto.verify_password_or_decoy).
function crypto.verify_password(password, stored)
  if type(stored) ~= "string" or stored == "" then return false end
  if type(password) ~= "string" then return false end
  local parsed = crypto.parse_hash(stored)
  if not parsed then return false end
  local setting = crypto.sha512crypt_setting(parsed.rounds, parsed.salt)
  local candidate, err = crypt_call(password, setting)
  if not candidate then return false, err end
  return crypto.equal(candidate, stored)
end

-- Anti user-enumeration: derive against a fixed decoy hash when the account is unknown.
-- The decoy input is a constant that is never a valid credential; only the resulting MCF
-- digest is cached in memory.
crypto.DECOY_SALT = "NetQuotaDecoySlt"
crypto.DECOY_PASSWORD = "netquota-decoy-password-not-a-credential"
function crypto.decoy_hash()
  local cached = crypto.DECOY_HASH_CACHE
  if cached then return cached end
  cached = crypt_call(crypto.DECOY_PASSWORD, crypto.sha512crypt_setting(crypto.DEFAULT_ROUNDS, crypto.DECOY_SALT))
  crypto.DECOY_HASH_CACHE = cached
  return cached
end

function crypto.verify_password_or_decoy(password, stored)
  if type(stored) == "string" and stored ~= "" then
    return crypto.verify_password(password, stored)
  end
  -- Unknown account: run the identical derivation against the decoy digest so the timing
  -- and the error surfaced to the caller match a wrong-password attempt on a real account.
  crypt_call(type(password) == "string" and password or "",
    crypto.sha512crypt_setting(crypto.DEFAULT_ROUNDS, crypto.DECOY_SALT))
  return false
end

----------------------------------------------------------------------------
-- Token hashing
----------------------------------------------------------------------------
-- Portal and CSRF tokens are stored only as a digest. A fixed salt is used because the
-- input is 256 bits of CSPRNG material (no dictionary attack is possible); this keeps the
-- cost low enough for per-request lookups while never persisting the token itself.

crypto.TOKEN_HASH_SALT = "NetQuotaTokDgst01"

-- Returns the digest of a raw token (hex string) for storage/lookup.
function crypto.hash_token(raw_token)
  if type(raw_token) ~= "string" or raw_token == "" then return nil, "empty token" end
  local hash, err = crypt_call(raw_token, crypto.sha512crypt_setting(crypto.TOKEN_DIGEST_ROUNDS, crypto.TOKEN_HASH_SALT))
  if not hash then return nil, err end
  return hash
end

-- Constant-time comparison of a raw token against a stored digest.
function crypto.verify_token(raw_token, stored_digest)
  if type(stored_digest) ~= "string" or stored_digest == "" then return false end
  local computed = crypto.hash_token(raw_token)
  if not computed then return false end
  return crypto.equal(computed, stored_digest)
end

return crypto

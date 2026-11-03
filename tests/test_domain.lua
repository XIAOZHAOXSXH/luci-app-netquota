io.stdout:setvbuf("no")
-- NetQuota domain test suite.
--
-- Runs against the real domain modules and a real SQLite database under /tmp:
--   LUA_PATH='/tmp/netquota-domain-test/?.lua;/tmp/netquota-domain-test/?/init.lua;;' \
--     lua /tmp/netquota-domain-test/test_domain.lua
--
-- Every test uses its own temporary database file (removed on exit) and an injected clock,
-- so no router configuration, network object or system time is touched. The tests exercise
-- leap-year/day-31 anchoring, staged and inherited reset days, "pending null" semantics,
-- account isolation, password changes versus the usage ledger, strict numeric validation,
-- SQL-injection-shaped input, credential hashing/verification, clock rollback, monotonic
-- checkpoints with stale-period refusal, brute-force limits, CSRF and self-service identity.

local function setup_module_path()
  -- When run from the repository checkout (no LUA_PATH), fall back to the source tree so the
  -- suite can also be executed locally next to the code.
  local here = (arg and arg[0]) or ""
  local dir = here:match("^(.*)[/\\][^/\\]+$")
  if not dir then return end
  local candidate = dir .. "/../netquota/files/usr/lib/lua/?.lua"
  if not package.path:find(candidate, 1, true) then
    package.path = candidate .. ";" .. package.path
  end
end
setup_module_path()

local util = require("netquota.util")
local calendar = require("netquota.calendar")
local crypto = require("netquota.crypto")
local dbmod = require("netquota.db")
local core = require("netquota.core")

----------------------------------------------------------------------------
-- Harness
----------------------------------------------------------------------------

local TMP_DB = os.getenv("NETQUOTA_TEST_DB") or "/tmp/netquota_domain_tests.db"
local results = { passed = 0, failed = 0, errors = {} }
local current_test = nil

local function remove_db_files(path)
  for _, suffix in ipairs({ "", "-wal", "-shm", "-journal" }) do
    os.remove(path .. suffix)
  end
end

local function check(cond, message)
  if cond then
    results.passed = results.passed + 1
    return true
  end
  results.failed = results.failed + 1
  results.errors[#results.errors + 1] = string.format("[%s] %s", tostring(current_test), tostring(message))
  return false
end

local function check_equal(actual, expected, message)
  local ok = actual == expected
  if not ok then
    return check(false, string.format("%s (expected %s, got %s)", tostring(message),
      tostring(expected), tostring(actual)))
  end
  return check(true, message)
end

local function check_error(envelope, code, message)
  local ok = type(envelope) == "table" and envelope.ok == false and type(envelope.error) == "table"
  if ok and code then ok = envelope.error.code == code end
  if not ok then
    local got = type(envelope) == "table" and type(envelope.error) == "table"
      and tostring(envelope.error.code) or tostring(envelope)
    return check(false, string.format("%s (expected error %s, got %s)", tostring(message), tostring(code), got))
  end
  return check(true, message)
end

local function test(name, fn)
  current_test = name
  local before = results.failed
  local ok, err = pcall(fn)
  if not ok then
    results.failed = results.failed + 1
    results.errors[#results.errors + 1] = string.format("[%s] uncaught error: %s", name, tostring(err))
  end
  local status = results.failed == before and "PASS" or "FAIL"
  io.write(string.format("%-58s %s\n", name, status))
end

-- Injected clock so period boundaries are exact and reproducible.
local clock = { t = 0 }
local function set_now(t) clock.t = t end
local function now() return clock.t end

local function local_epoch(y, m, d, hh, mm, ss, tz)
  return calendar.local_to_epoch(tz or "Asia/Shanghai", y, m, d, hh or 0, mm or 0, ss or 0)
end

local function new_service(opts)
  opts = opts or {}
  opts.db_path = opts.db_path or TMP_DB
  opts.clock = opts.clock or now
  opts.admin = true
  opts.log = false
  local service, err = core.open(opts)
  if not service then
    error("core.open failed: " .. tostring(err and err.error and err.error.message or err))
  end
  return service
end

local function rq(service, method, args)
  return service:request(method, args)
end

----------------------------------------------------------------------------
-- 0. Environment / crypto capability
----------------------------------------------------------------------------

remove_db_files(TMP_DB)
set_now(local_epoch(2026, 11, 3, 12, 0, 0))

test("crypto: native status and constant-time compare", function()
  local status = crypto.native_status()
  check(type(status) == "table", "native_status returns a table")
  check(status.crypt == true, "native crypt(3)/sha512crypt available")
  check(crypto.native_status().csprng == true, "CSPRNG available")
  check(crypto.equal("abc", "abc") == true, "constant-time equal matches")
  check(crypto.equal("abc", "abd") == false, "constant-time equal rejects difference")
  check(crypto.equal("abc", "abcd") == false, "constant-time equal rejects length mismatch")
  check(crypto.equal(nil, nil) == false, "non-string compared as unequal")
end)

test("crypto: CSPRNG tokens are 64 hex chars and unique", function()
  local a = crypto.random_hex(32)
  local b = crypto.random_hex(32)
  check(type(a) == "string" and #a == 64, "token is 64 hex characters")
  check(a:match("^[0-9a-f]+$") ~= nil, "token is lowercase hex")
  check(a ~= b, "two tokens differ")
  local salt1 = crypto.random_salt()
  local salt2 = crypto.random_salt()
  check(#salt1 == crypto.SALT_CHARS, "salt has expected length")
  check(salt1 ~= salt2, "salts are unique")
  check(salt1:find("$", 1, true) == nil, "salt never contains '$'")
end)

test("crypto: password hash never contains the password", function()
  local password = "correct horse battery"
  local out, err = crypto.hash_password(password)
  check(out ~= nil, "hash_password succeeds: " .. tostring(err))
  if not out then return end
  check(out.hash:sub(1, 3) == "$6$", "hash is sha512crypt MCF")
  check(out.hash:find("rounds=", 1, true) ~= nil, "hash records the round count")
  check(out.hash:find(password, 1, true) == nil, "hash does not embed the password")
  local rounds = tonumber(out.hash:match("rounds=(%d+)"))
  check(rounds ~= nil and rounds >= 100000, "round count is at least 100000")
end)

test("crypto: credential hash verification (round trip)", function()
  local password = "S3cret-passphrase"
  local out = crypto.hash_password(password, { rounds = 100000, salt = "abcdefghijklmnop" })
  check(out ~= nil, "hash produced")
  if not out then return end
  check(crypto.verify_password(password, out.hash) == true, "correct password verifies")
  check(crypto.verify_password("wrong-password", out.hash) == false, "wrong password rejected")
  check(crypto.verify_password("", out.hash) == false, "empty password rejected")
  check(crypto.verify_password(password, "") == false, "empty stored hash rejected")
  check(crypto.verify_password(password, "not-a-hash") == false, "malformed hash rejected")
  local second = crypto.hash_password(password)
  check(second and second.hash ~= out.hash, "unique salt yields a different digest for the same password")
  check(crypto.verify_password_or_decoy("anything", nil) == false, "unknown account never verifies")
  local parsed = crypto.parse_hash(out.hash)
  check(parsed and parsed.salt == "abcdefghijklmnop", "parse_hash recovers the salt")
end)

test("crypto: token hashing stores no plaintext", function()
  local raw = crypto.random_hex(32)
  local digest = crypto.hash_token(raw)
  check(type(digest) == "string" and digest ~= raw, "digest differs from the raw token")
  check(digest:find(raw, 1, true) == nil, "digest does not embed the token")
  check(crypto.verify_token(raw, digest) == true, "token verifies against its digest")
  check(crypto.verify_token(raw .. "0", digest) == false, "modified token rejected")
  check(crypto.verify_token(raw, nil) == false, "missing digest rejected")
end)

----------------------------------------------------------------------------
-- 1. Calendar: leap year, day 31 anchoring, time zones
----------------------------------------------------------------------------

test("calendar: sha-anchored day 31 keeps the anchor across Feb/March", function()
  local tz = "Asia/Shanghai"
  -- January period for day 31: [Jan 31, Feb 28) in a non-leap year.
  local start_at, end_at = calendar.period_for(local_epoch(2027, 1, 31, 0, 0, 1), 31, tz)
  check_equal(calendar.iso_local(tz, start_at), "2027-01-31T00:00:00", "day31 Jan start")
  check_equal(calendar.iso_local(tz, end_at), "2027-02-28T00:00:00", "day31 Feb end clamps to 28")

  -- February period for day 31: [Feb 28, Mar 31) - anchor preserved, not drifted to 28.
  local s2, e2 = calendar.period_for(local_epoch(2027, 2, 28, 12, 0, 0), 31, tz)
  check_equal(calendar.iso_local(tz, s2), "2027-02-28T00:00:00", "day31 Feb start clamped")
  check_equal(calendar.iso_local(tz, e2), "2027-03-31T00:00:00", "day31 March restored to 31")

  -- March period: [Mar 31, Apr 30).
  local s3, e3 = calendar.period_for(local_epoch(2027, 3, 31, 0, 0, 0), 31, tz)
  check_equal(calendar.iso_local(tz, s3), "2027-03-31T00:00:00", "day31 March start")
  check_equal(calendar.iso_local(tz, e3), "2027-04-30T00:00:00", "day31 April clamps to 30")
end)

test("calendar: leap year February clamps to 29 and returns to 31", function()
  local tz = "Asia/Shanghai"
  -- 2028 is a leap year.
  check_equal(calendar.days_in_month(2028, 2), 29, "2028 has 29 February days")
  check_equal(calendar.days_in_month(2027, 2), 28, "2027 has 28 February days")
  local s, e = calendar.period_for(local_epoch(2028, 2, 1, 0, 0, 0), 31, tz)
  check_equal(calendar.iso_local(tz, s), "2028-01-31T00:00:00", "leap Jan 31 start")
  check_equal(calendar.iso_local(tz, e), "2028-02-29T00:00:00", "leap Feb 29 end")
  local s2, e2 = calendar.period_for(local_epoch(2028, 2, 29, 6, 0, 0), 31, tz)
  check_equal(calendar.iso_local(tz, s2), "2028-02-29T00:00:00", "leap Feb 29 start")
  check_equal(calendar.iso_local(tz, e2), "2028-03-31T00:00:00", "leap March back to 31")
  -- 2100 is NOT a leap year (century rule).
  check_equal(calendar.days_in_month(2100, 2), 28, "2100 is not a leap year")
end)

test("calendar: day 1 and day 15 periods align to local midnight", function()
  local tz = "Asia/Shanghai"
  local s, e = calendar.period_for(local_epoch(2026, 11, 20, 5, 0, 0), 15, tz)
  check_equal(calendar.iso_local(tz, s), "2026-11-15T00:00:00", "day15 start on the 15th")
  check_equal(calendar.iso_local(tz, e), "2026-12-15T00:00:00", "day15 end on the next 15th")
  local s1, e1 = calendar.period_for(local_epoch(2026, 11, 20, 5, 0, 0), 1, tz)
  check_equal(calendar.iso_local(tz, s1), "2026-11-01T00:00:00", "day1 start on the 1st")
  check_equal(calendar.iso_local(tz, e1), "2026-12-01T00:00:00", "day1 end on the next 1st")
  -- Boundary belongs to the new period (half-open interval).
  local bs, be = calendar.period_for(local_epoch(2026, 12, 1, 0, 0, 0), 1, tz)
  check_equal(bs, e1, "start boundary belongs to the new period")
  local _ = be
end)

test("calendar: UTC and Asia/Shanghai agree on civil anchors with an 8h offset", function()
  local utc_start = calendar.period_for(local_epoch(2026, 11, 1, 0, 0, 0, "UTC"), 1, "UTC")
  local sh_start = calendar.period_for(local_epoch(2026, 11, 1, 0, 0, 0, "Asia/Shanghai"), 1, "Asia/Shanghai")
  check_equal(sh_start - utc_start, -8 * 3600, "Shanghai anchor is 8h earlier in epoch terms")
  check(calendar.is_valid_zone("Asia/Shanghai"), "Asia/Shanghai is supported")
  check(calendar.is_valid_zone("UTC"), "UTC is supported")
  check(calendar.is_valid_zone("CST-8"), "POSIX CST-8 is supported")
  check(not calendar.is_valid_zone("Not/AZone"), "unknown zone rejected")
  check(not calendar.is_valid_zone("'; DROP TABLE users; --"), "injection-shaped zone rejected")
end)

test("calendar: reanchor is gap-free and overlap-free", function()
  -- Old period [Nov 15, Dec 15) with day 15; stage day 20: new period [Dec 15, Jan 20).
  local tz = "Asia/Shanghai"
  local old_start = local_epoch(2026, 11, 15)
  local old_end = local_epoch(2026, 12, 15)
  local new_end, err = calendar.reanchor(old_start, old_end, 20, tz)
  check(new_end ~= nil, "reanchor succeeds: " .. tostring(err))
  check_equal(new_end, local_epoch(2026, 12, 20), "new period ends on the next day-20 anchor after old end")
  local s_check = calendar.period_for(old_end, 20, tz)
  check(new_end > old_end, "transition period has positive length from old end")
end)

----------------------------------------------------------------------------
-- 2. Service bootstrap / schema / permissions
----------------------------------------------------------------------------

test("db: schema version, tables, foreign keys and file mode", function()
  local service = new_service()
  local version = dbmod.schema_version(service.db)
  check_equal(version, dbmod.SCHEMA_VERSION, "user_version is the current schema version")
  local names = dbmod.table_names(service.db)
  local required = { "users", "usage_periods", "portal_sessions", "network_sessions", "settings", "auth_attempts", "system_state" }
  local present = {}
  for _, n in ipairs(names or {}) do present[n] = true end
  for _, n in ipairs(required) do check(present[n] == true, "table exists: " .. n) end
  local fk = dbmod.scalar(service.db, "PRAGMA foreign_keys")
  check_equal(tonumber(fk), 1, "PRAGMA foreign_keys is ON")
  local journal_mode = dbmod.scalar(service.db, "PRAGMA journal_mode")
  check_equal(tostring(journal_mode):lower(), "wal", "journal mode is WAL")
  check_equal(tostring(dbmod.scalar(service.db, "PRAGMA synchronous")), "2", "synchronous is FULL (2)")
  local integrity = dbmod.integrity(service.db)
  check_equal(tostring(integrity), "ok", "integrity_check is ok")
  service:close()

  -- Re-open must reuse the existing database (never recreate it).
  local again = new_service()
  local version2 = dbmod.schema_version(again.db)
  check_equal(version2, dbmod.SCHEMA_VERSION, "reopening keeps the schema version")
  again:close()

  local perm = nil
  local ok_fs, fs = pcall(require, "nixio.fs")
  if ok_fs and fs and fs.stat then
    local st = fs.stat(TMP_DB)
    perm = st and st.modestr
  end
  if perm then
    check_equal(perm, "rw-------", "database file is mode 0600")
  end
end)

test("db: sqlite rejects a direct usage_periods total mismatch", function()
  local service = new_service()
  -- The CHECK constraint must refuse an inconsistent ledger row written outside the domain.
  local ok, err = dbmod.exec(service.db,
    "INSERT INTO usage_periods(user_id, period_start_at, period_end_at, reset_day_applied, upload_bytes, download_bytes, total_bytes, kernel_quota_used_bytes, state, created_at, updated_at) " ..
    "VALUES(?,?,?,?,?,?,?,?,'open',?,?)",
    { 999999, 1, 2, 1, 5, 5, 11, 0, 1, 1 })
  check(ok == nil, "mismatched total_bytes rejected by CHECK constraint")
  check(err ~= nil, "rejection carries an error envelope")
  local _ = err
  service:close()
end)

----------------------------------------------------------------------------
-- 3. Account lifecycle
----------------------------------------------------------------------------

local acct_a_id

test("create_account: valid account and public field shape", function()
  local service = new_service()
  local r = rq(service, "create_account", {
    username = "alice", password = "alice-password-1", quota_bytes = 10000000, reset_day = 15,
  })
  check(r and r.ok == true, "account created: " .. tostring(r and r.error and r.error.message))
  if r and r.ok then
    local d = r.data
    acct_a_id = d.id
    check(util.is_plain_integer(d.id) and d.id >= 1, "id is a positive integer")
    check_equal(d.username, "alice", "username echoed")
    check_equal(d.quota_bytes, 10000000, "quota echoed")
    check_equal(d.reset_day, 15, "reset_day echoed")
    check_equal(d.effective_reset_day, 15, "effective_reset_day is the explicit day")
    check_equal(d.pending_reset_day, nil, "no pending day initially")
    check_equal(d.pending_effective_at, nil, "no pending effective time initially")
    check_equal(d.upload_bytes, 0, "upload starts at zero")
    check_equal(d.download_bytes, 0, "download starts at zero")
    check_equal(d.total_bytes, 0, "total starts at zero")
    check_equal(d.remaining_bytes, 10000000, "remaining equals quota")
    check_equal(d.exhausted, false, "not exhausted")
    check_equal(d.online, false, "not online")
    check_equal(d.session_count, 0, "no sessions")
    check(d.period_start_at ~= nil and d.period_end_at ~= nil, "period bounds present")
    check_equal(d.next_reset_at, d.period_end_at, "next_reset_at equals period end")
    check(d.password_hash == nil and d.password == nil, "no password material in response")
    check(d.hash == nil and d.salt == nil, "no hash/salt in response")
    check(d.token == nil and d.session_token == nil, "no token in response")
    -- Serialised JSON must not contain the password or a crypt hash.
    local ok_json, jsonc = pcall(require, "luci.jsonc")
    if ok_json then
      local encoded = jsonc.stringify(r)
      check(encoded:find("alice-password-1", 1, true) == nil, "serialised response has no password")
      check(encoded:find("$6$", 1, true) == nil, "serialised response has no crypt hash")
    end
  end
  service:close()
end)

test("create_account: username is case-insensitively unique", function()
  local service = new_service()
  local r = rq(service, "create_account", {
    username = "ALICE", password = "another-password", quota_bytes = 5000,
  })
  check_error(r, util.CODES.CONFLICT, "duplicate username (different case) rejected")
  service:close()
end)

test("validation: strict usernames", function()
  local service = new_service()
  local bad = { "ab", "a" .. string.rep("b", 24), "al ice", "alice!", "ali'ce", "alice;drop", "älice", "" }
  for _, name in ipairs(bad) do
    local r = rq(service, "create_account", { username = name, password = "goodpassword", quota_bytes = 100 })
    check_error(r, util.CODES.INVALID_ARGUMENT, "username rejected: " .. string.format("%q", name))
  end
  for _, name in ipairs({ "abc", "a_b-c9", "a" .. string.rep("b", 23), "Z_9-x" }) do
    local r = rq(service, "create_account", { username = name, password = "goodpassword", quota_bytes = 100 })
    check(r and r.ok == true, "username accepted: " .. name)
  end
  service:close()
end)

test("validation: password length is 8..128 bytes", function()
  local service = new_service()
  local r1 = rq(service, "create_account", { username = "pwuser1", password = "1234567", quota_bytes = 100 })
  check_error(r1, util.CODES.INVALID_ARGUMENT, "7-byte password rejected")
  local r2 = rq(service, "create_account", { username = "pwuser2", password = string.rep("x", 129), quota_bytes = 100 })
  check_error(r2, util.CODES.INVALID_ARGUMENT, "129-byte password rejected")
  local r3 = rq(service, "create_account", { username = "pwuser3", password = "12345678", quota_bytes = 100 })
  check(r3 and r3.ok == true, "8-byte password accepted")
  local r4 = rq(service, "create_account", { username = "pwuser4", password = string.rep("y", 128), quota_bytes = 100 })
  check(r4 and r4.ok == true, "128-byte password accepted")
  service:close()
end)

test("validation: strict integers for ids and quota", function()
  local service = new_service()
  local bad_quotas = {
    "1000", -1, 0, 1.5, 9007199254740992, 2 ^ 60, true, {}, "10GB",
  }
  for _, q in ipairs(bad_quotas) do
    local r = rq(service, "create_account", { username = "quotatest", password = "goodpassword", quota_bytes = q })
    check_error(r, util.CODES.INVALID_ARGUMENT, "quota rejected: " .. tostring(q))
  end
  local maxr = rq(service, "create_account", {
    username = "maxquota", password = "goodpassword", quota_bytes = 9007199254740991,
  })
  check(maxr and maxr.ok == true, "quota at the 2^53-1 bound accepted")

  local bad_ids = { "1", 0, -5, 1.25, 9007199254740992, true }
  for _, id in ipairs(bad_ids) do
    local r = rq(service, "get_account", { id = id })
    check_error(r, util.CODES.INVALID_ARGUMENT, "id rejected: " .. tostring(id))
  end
  local missing = rq(service, "get_account", {})
  check_error(missing, util.CODES.INVALID_ARGUMENT, "missing id rejected")
  local notfound = rq(service, "get_account", { id = 999999 })
  check_error(notfound, util.CODES.NOT_FOUND, "unknown id yields NOT_FOUND")
  service:close()
end)

test("validation: invalid reset_day and unknown fields rejected", function()
  local service = new_service()
  for _, d in ipairs({ 0, 32, -1, 15.5, "15", true }) do
    local r = rq(service, "create_account", { username = "resettest", password = "goodpassword", quota_bytes = 100, reset_day = d })
    check_error(r, util.CODES.INVALID_ARGUMENT, "reset_day rejected: " .. tostring(d))
  end
  local unknown = rq(service, "create_account", {
    username = "unknownfield", password = "goodpassword", quota_bytes = 100, is_admin = true,
  })
  check_error(unknown, util.CODES.INVALID_ARGUMENT, "unknown field rejected on create_account")
  local unknown2 = rq(service, "update_account", { id = acct_a_id, quota_bytes = 100, role = "admin" })
  check_error(unknown2, util.CODES.INVALID_ARGUMENT, "unknown field rejected on update_account")
  service:close()
end)

test("injection: SQL-shaped strings are stored literally, never executed", function()
  local service = new_service()
  local payloads = {
    "'; DROP TABLE users; --",
    "1 OR 1=1",
    "\" OR \"1\"=\"1",
    "admin'--",
  }
  for i, payload in ipairs(payloads) do
    local r = rq(service, "create_account", {
      username = "inj" .. i, password = payload .. "padding", quota_bytes = 1000,
    })
    -- The password is accepted as an opaque secret; the username is strict alnum so we test
    -- that the payload is treated as data by searching for it and by keeping tables intact.
    check(r and r.ok == true, "account with injection-shaped password created")
    local files = dbmod.scalar(service.db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'")
    check_equal(tonumber(files), 1, "users table still exists after payload " .. i)
  end
  -- A payload used as a username is rejected by the character whitelist.
  local u = rq(service, "create_account", { username = "'; DROP TABLE users; --", password = "goodpassword", quota_bytes = 10 })
  check_error(u, util.CODES.INVALID_ARGUMENT, "injection-shaped username rejected")
  -- Searching with a payload must not error and must find nothing.
  local s = rq(service, "list_accounts", { search = "' OR 1=1 --" })
  check(s and s.ok == true, "injection-shaped search returns normally")
  check(s and s.ok and #s.data.items == 0, "injection-shaped search matches nothing")
  local tz = rq(service, "update_settings", { timezone = "UTC'; DROP TABLE settings; --" })
  check_error(tz, util.CODES.INVALID_ARGUMENT, "injection-shaped timezone rejected")
  local still = dbmod.scalar(service.db, "SELECT COUNT(*) FROM sqlite_master WHERE name='settings'")
  check_equal(tonumber(still), 1, "settings table intact")
  service:close()
end)

----------------------------------------------------------------------------
-- 4. Reset-day staging: pending day, global inheritance, pending null
----------------------------------------------------------------------------

test("update_account: reset_day 15->20 stages until the period end", function()
  local service = new_service()
  set_now(local_epoch(2026, 11, 3, 12, 0, 0))
  local r = rq(service, "update_account", { id = acct_a_id, reset_day = 20 })
  check(r and r.ok == true, "update accepted: " .. tostring(r and r.error and r.error.message))
  if r and r.ok then
    local d = r.data
    check_equal(d.reset_day, 15, "current reset_day is unchanged until the period ends")
    check_equal(d.effective_reset_day, 15, "effective day still 15")
    check_equal(d.pending_reset_day, 20, "pending_reset_day reports 20")
    check(d.pending_effective_at ~= nil, "pending_effective_at is set")
    check_equal(d.pending_effective_at, d.period_end_at, "pending applies at the current period end")
    check_equal(d.total_bytes, 0, "usage untouched")
  end
  service:close()
end)

test("update_account: repeated pending updates replace, cancel on equal", function()
  local service = new_service()
  local r1 = rq(service, "update_account", { id = acct_a_id, reset_day = 5 })
  check(r1 and r1.ok and r1.data.pending_reset_day == 5, "pending moves to 5")
  local r2 = rq(service, "update_account", { id = acct_a_id, reset_day = 9 })
  check(r2 and r2.ok and r2.data.pending_reset_day == 9, "pending replaced by 9")
  local r3 = rq(service, "update_account", { id = acct_a_id, clear_pending_reset_day = true })
  check(r3 and r3.ok, "clear_pending accepted")
  if r3 and r3.ok then
    check_equal(r3.data.pending_reset_day, nil, "pending cleared")
    check_equal(r3.data.pending_effective_at, nil, "pending effective time cleared")
    check_equal(r3.data.reset_day, 15, "current day preserved")
  end
  local r4 = rq(service, "update_account", { id = acct_a_id, reset_day = 15 })
  check(r4 and r4.ok, "setting reset_day back to the current value accepted")
  if r4 and r4.ok then
    check_equal(r4.data.pending_reset_day, nil, "no pending after no-op update")
  end
  service:close()
end)

test("staged reset_day applies at the period end without clearing usage", function()
  local service = new_service()
  -- Record some usage in the current period first.
  local snap = rq(service, "status", {})
  check(snap and snap.ok == true, "status available")
  local acc = rq(service, "get_account", { id = acct_a_id })
  check(acc and acc.ok == true, "account readable")
  if not (acc and acc.ok) then service:close(); return end
  local period_id = acc.data.period_id
  local period_end = acc.data.period_end_at

  local cp = service:checkpoint({ { user_id = acct_a_id, period_id = period_id, upload_bytes = 300, download_bytes = 700 } })
  check(cp and cp.ok == true, "checkpoint accepted: " .. tostring(cp and cp.error and cp.error.message))

  local before = rq(service, "get_account", { id = acct_a_id })
  check(before and before.data.total_bytes == 1000, "usage recorded before rollover")

  rq(service, "update_account", { id = acct_a_id, reset_day = 20 })

  -- Just before the end: nothing applied yet.
  set_now(period_end - 1)
  local mid = rq(service, "get_account", { id = acct_a_id })
  check(mid and mid.data.reset_day == 15, "reset_day unchanged one second before the boundary")
  check(mid and mid.data.total_bytes == 1000, "usage preserved before the boundary")

  -- At/after the boundary the staged change applies and a fresh period begins.
  set_now(period_end + 1)
  local tick = service:request("tick", {})
  check(tick and tick.ok == true, "tick after boundary succeeds")
  local after = rq(service, "get_account", { id = acct_a_id })
  check(after and after.ok == true, "account readable after rollover")
  if after and after.ok then
    check_equal(after.data.reset_day, 20, "staged reset_day applied at the old period end")
    check_equal(after.data.effective_reset_day, 20, "effective day now 20")
    check_equal(after.data.pending_reset_day, nil, "pending cleared after applying")
    check_equal(after.data.total_bytes, 0, "new period starts at zero usage")
    check_equal(after.data.period_start_at, period_end, "new period starts exactly at the old end")
    check(after.data.period_end_at > after.data.period_start_at, "new period has a positive length")
  end
  service:close()
end)

test("global default change stages inherited accounts only", function()
  local service = new_service()
  set_now(local_epoch(2026, 12, 1, 12, 0, 0))
  local inh = rq(service, "create_account", {
    username = "inheritor", password = "inheritor-pass", quota_bytes = 5000,
  })
  check(inh and inh.ok == true, "inherited account created")
  if not (inh and inh.ok) then service:close(); return end
  check_equal(inh.data.reset_day, nil, "reset_day null means inherit")
  local explicit = rq(service, "create_account", {
    username = "explicit", password = "explicit-pass", quota_bytes = 5000, reset_day = 9,
  })
  check(explicit and explicit.ok == true, "explicit account created")

  local settings = rq(service, "get_settings", {})
  check(settings and settings.ok == true, "settings readable")
  check_equal(settings.data.default_reset_day, 1, "default reset day starts at 1")

  local upd = rq(service, "update_settings", { default_reset_day = 7 })
  check(upd and upd.ok == true, "default reset day updated: " .. tostring(upd and upd.error and upd.error.message))
  if upd and upd.ok then
    check_equal(upd.data.default_reset_day, 7, "settings report the new default")
    check(upd.data.staged_accounts >= 1, "at least the inherited account was staged")
  end

  local inh_after = rq(service, "get_account", { id = inh.data.id })
  if inh_after and inh_after.ok then
    check_equal(inh_after.data.reset_day, nil, "inherited account still has no explicit day")
    check_equal(inh_after.data.effective_reset_day, 1, "inherited account keeps the old day this period")
    check(inh_after.data.pending_effective_at ~= nil, "inherited account has a scheduled change")
  end
  local exp_after = rq(service, "get_account", { id = explicit.data.id })
  if exp_after and exp_after.ok then
    check_equal(exp_after.data.effective_reset_day, 9, "explicit account unaffected by the default")
    check_equal(exp_after.data.pending_effective_at, nil, "explicit account has nothing scheduled")
  end
  service:close()
end)

test("pending inherit is distinguishable from no pending change", function()
  local service = new_service()
  local acc = rq(service, "create_account", {
    username = "inherit2", password = "inherit2-pass", quota_bytes = 5000, reset_day = 15,
  })
  check(acc and acc.ok == true, "explicit account created")
  if not (acc and acc.ok) then service:close(); return end
  local upd = rq(service, "update_account", { id = acc.data.id, reset_day = require("cjson").null })
  check(upd and upd.ok == true, "reset_day null (inherit) accepted: " .. tostring(upd and upd.error and upd.error.message))
  if upd and upd.ok then
    check_equal(upd.data.pending_reset_day, nil, "pending_reset_day is null for a pending inherit")
    check_equal(upd.data.pending_inherit, true, "pending_inherit flags the pending inherit explicitly")
    check(upd.data.pending_effective_at ~= nil, "pending inherit carries an effective time")
    check_equal(upd.data.reset_day, 15, "explicit day still in force this period")
  end
  service:close()
end)

----------------------------------------------------------------------------
-- 5. Quota changes, password changes, deletion versus usage
----------------------------------------------------------------------------

test("quota form saves do not stage unchanged inheritance or cancel real changes", function()
  local service = new_service()
  set_now(local_epoch(2026, 12, 1, 12, 0, 0))
  local settings = rq(service, "get_settings", {})
  local day = settings.data.default_reset_day
  local acc = rq(service, "create_account", {
    username = "quotareset", password = "quota-reset-pass", quota_bytes = 5000,
  })
  assert(acc.ok)
  local id = acc.data.id
  local before = rq(service, "get_account", { id = id }).data
  assert(service:checkpoint({ { user_id = id, period_id = before.period_id,
    upload_bytes = 400, download_bytes = 600 } }).ok)
  local saved = rq(service, "update_account", {
    id = id, quota_bytes = 10000, reset_day = require("cjson").null,
  })
  check(saved.ok, "inherited quota form saved")
  check_equal(saved.data.pending_effective_at, nil, "unchanged inheritance has no pending date")
  check_equal(saved.data.pending_inherit, nil, "unchanged inheritance has no pending flag")
  check_equal(saved.data.total_bytes, 1000, "quota form preserves usage")
  check_equal(saved.data.period_end_at, before.period_end_at, "quota form preserves current boundary")

  local next_day = day == 7 and 9 or 7
  assert(rq(service, "update_settings", { default_reset_day = next_day }).ok)
  saved = rq(service, "update_account", {
    id = id, quota_bytes = 12000, reset_day = require("cjson").null,
  })
  check(saved.ok, "quota form saves with a changed global default")
  check_equal(saved.data.pending_inherit, true, "real inherited change stays pending")
  check_equal(saved.data.pending_effective_at, before.period_end_at, "real change retains its boundary")
  check_equal(saved.data.effective_reset_day, day, "current day does not change early")
  check_equal(saved.data.total_bytes, 1000, "pending change preserves usage")

  -- Returning the default to this period's day makes the old pending record redundant.
  assert(rq(service, "update_settings", { default_reset_day = day }).ok)
  saved = rq(service, "update_account", {
    id = id, quota_bytes = 14000, reset_day = require("cjson").null,
  })
  check_equal(saved.data.pending_effective_at, nil, "redundant inherited pending record clears on save")
  check_equal(saved.data.total_bytes, 1000, "clearing redundant pending keeps usage")
  service:close()
end)

test("quota decrease below usage revokes sessions immediately", function()
  local service = new_service()
  local acc = rq(service, "create_account", {
    username = "quotacut", password = "quotacut-pass", quota_bytes = 100000,
  })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  local login = rq(service, "portal_login", {
    username = "quotacut", password = "quotacut-pass", ip = "192.168.8.44", mac = "aa:bb:cc:dd:ee:44",
  })
  check(login and login.ok == true, "login succeeds: " .. tostring(login and login.error and login.error.message))
  if not (login and login.ok) then service:close(); return end
  check_equal(login.data.network_authorized, true, "network authorized before the cut")

  local per = rq(service, "get_account", { id = id })
  local cp = service:checkpoint({ { user_id = id, period_id = per.data.period_id, upload_bytes = 400, download_bytes = 600 } })
  check(cp and cp.ok == true, "usage recorded")

  local cut = rq(service, "update_account", { id = id, quota_bytes = 500 })
  check(cut and cut.ok == true, "quota decreased: " .. tostring(cut and cut.error and cut.error.message))
  if cut and cut.ok then
    check_equal(cut.data.quota_bytes, 500, "new quota stored")
    check_equal(cut.data.total_bytes, 1000, "usage not cleared by the quota change")
    check_equal(cut.data.exhausted, true, "now exhausted")
    check_equal(cut.data.online, false, "sessions revoked")
    check(cut.data.session_count == 0, "session count zero after revocation")
  end
  service:close()
end)

test("quota increase above usage restores login without clearing usage", function()
  local service = new_service()
  local list = rq(service, "list_accounts", { search = "quotacut" })
  check(list and list.ok == true, "list available")
  local id = list.data.items[1].id
  local up = rq(service, "update_account", { id = id, quota_bytes = 10000 })
  check(up and up.ok == true, "quota raised")
  if up and up.ok then
    check_equal(up.data.exhausted, false, "no longer exhausted")
    check_equal(up.data.total_bytes, 1000, "usage retained across the quota increase")
  end
  local login = rq(service, "portal_login", {
    username = "quotacut", password = "quotacut-pass", ip = "192.168.8.45", mac = "aa:bb:cc:dd:ee:45",
  })
  check(login and login.ok and login.data.network_authorized == true, "login and network restored")
  service:close()
end)

test("password change via admin revokes sessions but keeps usage", function()
  local service = new_service()
  local acc = rq(service, "create_account", {
    username = "pwchange", password = "first-password", quota_bytes = 50000,
  })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  rq(service, "portal_login", {
    username = "pwchange", password = "first-password", ip = "192.168.8.50", mac = "aa:bb:cc:dd:ee:50",
  })
  local per = rq(service, "get_account", { id = id })
  service:checkpoint({ { user_id = id, period_id = per.data.period_id, upload_bytes = 111, download_bytes = 222 } })

  local upd = rq(service, "update_account", { id = id, password = "second-password" })
  check(upd and upd.ok == true, "password updated: " .. tostring(upd and upd.error and upd.error.message))
  if upd and upd.ok then
    check_equal(upd.data.total_bytes, 333, "usage preserved across a password change")
    check_equal(upd.data.online, false, "sessions revoked on password change")
  end
  local old_login = rq(service, "portal_login", {
    username = "pwchange", password = "first-password", ip = "192.168.8.51", mac = "aa:bb:cc:dd:ee:51",
  })
  check_error(old_login, util.CODES.AUTH_FAILED, "old password no longer logs in")
  local new_login = rq(service, "portal_login", {
    username = "pwchange", password = "second-password", ip = "192.168.8.52", mac = "aa:bb:cc:dd:ee:52",
  })
  check(new_login and new_login.ok == true, "new password logs in")
  service:close()
end)

test("account isolation: usage and quotas are per account", function()
  local service = new_service()
  local a = rq(service, "create_account", { username = "isola", password = "isolation-a-1", quota_bytes = 1000 })
  local b = rq(service, "create_account", { username = "isolb", password = "isolation-b-1", quota_bytes = 1000 })
  check(a and a.ok and b and b.ok, "two accounts created")
  if not (a and a.ok and b and b.ok) then service:close(); return end
  local pa = rq(service, "get_account", { id = a.data.id })
  service:checkpoint({ { user_id = a.data.id, period_id = pa.data.period_id, upload_bytes = 900, download_bytes = 100 } })
  local ra = rq(service, "get_account", { id = a.data.id })
  local rb = rq(service, "get_account", { id = b.data.id })
  check_equal(ra.data.total_bytes, 1000, "account A reaches its quota")
  check_equal(ra.data.exhausted, true, "account A exhausted")
  check_equal(rb.data.total_bytes, 0, "account B usage untouched")
  check_equal(rb.data.exhausted, false, "account B not exhausted")
  local login_b = rq(service, "portal_login", {
    username = "isolb", password = "isolation-b-1", ip = "192.168.8.60", mac = "aa:bb:cc:dd:ee:60",
  })
  check(login_b and login_b.ok and login_b.data.network_authorized == true,
    "account B still authorised while A is exhausted")
  service:close()
end)

test("delete_account revokes sessions and removes the account", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "deluser", password = "delete-password", quota_bytes = 5000 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  rq(service, "portal_login", { username = "deluser", password = "delete-password", ip = "192.168.8.70", mac = "aa:bb:cc:dd:ee:70" })
  local del = rq(service, "delete_account", { id = id })
  check(del and del.ok == true, "account deleted: " .. tostring(del and del.error and del.error.message))
  if del and del.ok then check(del.data.sessions_revoked >= 1, "sessions revoked on delete") end
  local get = rq(service, "get_account", { id = id })
  check_error(get, util.CODES.NOT_FOUND, "deleted account is no longer readable")
  local login = rq(service, "portal_login", {
    username = "deluser", password = "delete-password", ip = "192.168.8.71", mac = "aa:bb:cc:dd:ee:71",
  })
  check_error(login, util.CODES.AUTH_FAILED, "deleted account cannot log in")
  local del2 = rq(service, "delete_account", { id = id })
  check_error(del2, util.CODES.NOT_FOUND, "second delete is not found")
  local online = dbmod.scalar(service.db, "SELECT COUNT(*) FROM network_sessions WHERE user_id = ? AND state = 'online'", { id })
  check_equal(tonumber(online), 0, "no online sessions remain for the deleted account")
  service:close()
end)

----------------------------------------------------------------------------
-- 6. Checkpoint semantics: monotonic, stale-period refusal, overflow guard
----------------------------------------------------------------------------

test("checkpoint: counters are monotonic and never decrease", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "mono", password = "monotonic-pass", quota_bytes = 1000000 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  local per = rq(service, "get_account", { id = id })
  local pid = per.data.period_id

  local r1 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 100, download_bytes = 200 } })
  check(r1 and r1.ok == true, "first checkpoint applied")
  local r2 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 50, download_bytes = 20 } })
  check(r2 and r2.ok == true, "lower reading accepted but clamped")
  local r3 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 400, download_bytes = 100 } })
  check(r3 and r3.ok == true, "higher reading applied")
  local acct = rq(service, "get_account", { id = id })
  check_equal(acct.data.upload_bytes, 400, "upload is the maximum observed")
  check_equal(acct.data.download_bytes, 200, "download is the maximum observed")
  check_equal(acct.data.total_bytes, 600, "total equals upload + download")
  -- Replaying an older reading must never reduce usage.
  service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 1, download_bytes = 1 } })
  local acct2 = rq(service, "get_account", { id = id })
  check_equal(acct2.data.total_bytes, 600, "replay did not lower usage")
  service:close()
end)

test("checkpoint: stale period refused, cross-period observation rejected", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "stale", password = "stale-period-1", quota_bytes = 100000 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  local per = rq(service, "get_account", { id = id })
  local old_pid = per.data.period_id
  service:checkpoint({ { user_id = id, period_id = old_pid, upload_bytes = 10, download_bytes = 10 } })

  -- Force a rollover far into the future.
  set_now(per.data.period_end_at + 10)
  local tick = service:request("tick", {})
  check(tick and tick.ok == true, "tick rolls the period")
  local per2 = rq(service, "get_account", { id = id })
  check(per2.data.period_id ~= old_pid, "a new period id was created")
  check_equal(per2.data.total_bytes, 0, "new period starts empty")

  local stale = service:checkpoint({ { user_id = id, period_id = old_pid, upload_bytes = 5000, download_bytes = 5000 } })
  check_error(stale, util.CODES.SEQUENCE, "reading for the superseded period refused")
  local after = rq(service, "get_account", { id = id })
  check_equal(after.data.total_bytes, 0, "stale reading did not add usage to the new period")
  local old_row_upload = dbmod.scalar(service.db, "SELECT upload_bytes FROM usage_periods WHERE id = ?", { old_pid })
  check_equal(tonumber(old_row_upload), 10, "closed period ledger is unchanged")
  service:close()
end)

test("checkpoint: oversized or malformed readings rejected", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "overflow", password = "overflow-pass", quota_bytes = 9007199254740991 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  local per = rq(service, "get_account", { id = id })
  local pid = per.data.period_id
  local r1 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 9007199254740991, download_bytes = 9007199254740991 } })
  check_error(r1, util.CODES.INVALID_ARGUMENT, "sum exceeding the safe range rejected")
  local r2 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = -1, download_bytes = 0 } })
  check_error(r2, util.CODES.INVALID_ARGUMENT, "negative counter rejected")
  local r3 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 1.5 } })
  check_error(r3, util.CODES.INVALID_ARGUMENT, "fractional counter rejected")
  local r4 = service:checkpoint({ { user_id = "1", period_id = pid, upload_bytes = 1 } })
  check_error(r4, util.CODES.INVALID_ARGUMENT, "string user_id rejected")
  local r5 = service:checkpoint({ { user_id = id, period_id = pid, upload_bytes = 1, extra = 2 } })
  check_error(r5, util.CODES.INVALID_ARGUMENT, "unknown reading field rejected")
  local r6 = service:checkpoint("not-a-table")
  check_error(r6, util.CODES.INVALID_ARGUMENT, "non-array readings rejected")
  service:close()
end)

test("checkpoint: exhaustion at quota revokes and snapshot agrees", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "exhaust", password = "exhaustion-1", quota_bytes = 1000 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  rq(service, "portal_login", { username = "exhaust", password = "exhaustion-1", ip = "192.168.8.80", mac = "aa:bb:cc:dd:ee:80" })
  local per = rq(service, "get_account", { id = id })
  local cp = service:checkpoint({ { user_id = id, period_id = per.data.period_id, upload_bytes = 400, download_bytes = 600 } })
  check(cp and cp.ok == true, "checkpoint applied")
  local snap = service:snapshot()
  local found = nil
  for _, a in ipairs(snap.accounts) do if a.id == id then found = a end end
  check(found ~= nil, "account present in the kernel snapshot")
  if found then
    check_equal(found.exhausted, true, "snapshot marks exhaustion at quota_used >= quota")
    check_equal(found.quota_used_bytes, 1000, "snapshot quota_used equals upload+download")
    check_equal(#found.sessions, 0, "no online sessions remain after exhaustion")
  end
  local sum = rq(service, "get_summary", {})
  check(sum and sum.ok == true, "summary available")
  if sum and sum.ok then
    check(sum.data.exhausted_accounts >= 1, "summary counts the exhausted account")
  end
  service:close()
end)

test("snapshot: shape, account dedup in summary, settings", function()
  local service = new_service()
  local snap = service:snapshot()
  check(type(snap) == "table" and type(snap.accounts) == "table", "snapshot has accounts")
  check(type(snap.settings) == "table", "snapshot has settings")
  check(util.is_plain_integer(snap.updated_at), "snapshot has updated_at")
  for _, a in ipairs(snap.accounts or {}) do
    check(util.is_plain_integer(a.id), "snapshot account id integer")
    check(util.is_plain_integer(a.quota_bytes), "snapshot account quota integer")
    check(util.is_plain_integer(a.upload_bytes) and util.is_plain_integer(a.download_bytes), "snapshot counters integer")
    check(a.quota_used_bytes >= a.upload_bytes + a.download_bytes, "quota_used covers both directions")
    check(type(a.sessions) == "table", "sessions is a list")
    for _, s in ipairs(a.sessions) do
      check(s.id ~= nil and s.ipv4_address ~= nil and s.mac_address ~= nil, "session row shape")
      check(util.is_plain_integer(s.expires_at), "session has expiry")
    end
  end
  local list = rq(service, "list_accounts", {})
  local sum = rq(service, "get_summary", {})
  check(list and list.ok and sum and sum.ok, "list and summary available")
  if list and list.ok and sum and sum.ok then
    check_equal(sum.data.accounts, #list.data.items, "summary account count matches the list")
    check(sum.data.online_accounts <= sum.data.accounts, "online accounts are deduplicated")
  end
  service:close()
end)

----------------------------------------------------------------------------
-- 7. Clock rollback
----------------------------------------------------------------------------

test("clock rollback never reopens an older period or resets quota", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "clockuser", password = "clock-user-pass", quota_bytes = 100000, reset_day = 10 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local id = acc.data.id
  local per = rq(service, "get_account", { id = id })
  local per_end = per.data.period_end_at
  service:checkpoint({ { user_id = id, period_id = per.data.period_id, upload_bytes = 7000, download_bytes = 3000 } })

  -- Roll into the next period.
  set_now(per_end + 5)
  service:request("tick", {})
  local p2 = rq(service, "get_account", { id = id })
  check(p2.data.period_id ~= per.data.period_id, "period advanced")
  service:checkpoint({ { user_id = id, period_id = p2.data.period_id, upload_bytes = 2000, download_bytes = 1000 } })
  local p2_id = p2.data.period_id

  -- Clock jumps backwards well before the previous period start.
  set_now(per.data.period_start_at - 86400 * 40)
  local tick_back = service:request("tick", {})
  check(tick_back and tick_back.ok == true, "tick with a rolled-back clock succeeds")
  local p3 = rq(service, "get_account", { id = id })
  check_equal(p3.data.period_id, p2_id, "current period is unchanged by the rollback")
  check_equal(p3.data.total_bytes, 3000, "usage is not reset by the rollback")
  local count = dbmod.scalar(service.db, "SELECT COUNT(*) FROM usage_periods WHERE user_id = ?", { id })
  check_equal(tonumber(count), 2, "no older period was created by the rollback")

  -- Restoring the clock must not double-roll or lose the ledger.
  set_now(per_end + 60)
  service:request("tick", {})
  local p4 = rq(service, "get_account", { id = id })
  check_equal(p4.data.period_id, p2_id, "same period after the clock returns")
  check_equal(p4.data.total_bytes, 3000, "usage preserved after the clock returns")
  service:close()
end)

----------------------------------------------------------------------------
-- 8. Portal: login, brute force, CSRF, self-service identity
----------------------------------------------------------------------------

test("portal_login: valid credentials create hashed sessions only", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "portaler", password = "portal-login-1", quota_bytes = 8000 })
  check(acc and acc.ok == true, "account created")
  local login = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.90", mac = "aa:bb:cc:dd:ee:90",
  })
  check(login and login.ok == true, "login succeeds: " .. tostring(login and login.error and login.error.message))
  if not (login and login.ok) then service:close(); return end
  local d = login.data
  check(type(d.session_token) == "string" and #d.session_token == 64, "session token is 32 CSPRNG bytes as hex")
  check(type(d.csrf_token) == "string" and #d.csrf_token == 64, "csrf token is 32 CSPRNG bytes as hex")
  check(d.session_token ~= d.csrf_token, "session and csrf tokens differ")
  check_equal(d.network_authorized, true, "network authorised")
  check(util.is_plain_integer(d.expires_at), "expiry returned")
  check(d.account and d.account.username == "portaler", "account returned")
  check(d.account.password_hash == nil and d.account.token == nil, "no secrets in the account projection")

  -- The database must only hold digests.
  local row = dbmod.query_one(service.db, "SELECT token_hash, csrf_hash FROM portal_sessions ORDER BY id DESC LIMIT 1")
  check(row ~= nil, "portal session row exists")
  if row then
    check(row.token_hash ~= d.session_token, "raw session token not stored")
    check(row.csrf_hash ~= d.csrf_token, "raw csrf token not stored")
    check(row.token_hash:find(d.session_token, 1, true) == nil, "stored hash does not embed the token")
  end
  local dump = dbmod.scalar(service.db, "SELECT group_concat(password_hash) FROM users WHERE username = 'portaler'")
  check(tostring(dump):find("portal-login-1", 1, true) == nil, "password never stored in clear")
end)

test("portal_login: single generic error for bad password and unknown account", function()
  local service = new_service()
  local bad = rq(service, "portal_login", {
    username = "portaler", password = "wrong-password-x", ip = "192.168.8.91", mac = "aa:bb:cc:dd:ee:91",
  })
  check_error(bad, util.CODES.AUTH_FAILED, "wrong password rejected")
  local unknown = rq(service, "portal_login", {
    username = "nosuchuser", password = "wrong-password-x", ip = "192.168.8.92", mac = "aa:bb:cc:dd:ee:92",
  })
  check_error(unknown, util.CODES.AUTH_FAILED, "unknown account rejected")
  check_equal(bad.error.message, unknown.error.message, "identical message for both failures (no enumeration)")
  service:close()
end)

test("portal_login: invalid IP/MAC rejected, rate limit locks out", function()
  local service = new_service()
  local badip = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "999.1.1.1", mac = "aa:bb:cc:dd:ee:93",
  })
  check_error(badip, util.CODES.INVALID_ARGUMENT, "invalid IPv4 rejected")
  local badmac = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.93", mac = "zz:bb:cc:dd:ee:93",
  })
  check_error(badmac, util.CODES.INVALID_ARGUMENT, "invalid MAC rejected")

  -- Six failures from one source: lockout must engage and report a retry window.
  local last
  for i = 1, 6 do
    set_now(now() + 1)
    last = rq(service, "portal_login", {
      username = "portaler", password = "definitely-wrong", ip = "192.168.8.94", mac = "aa:bb:cc:dd:ee:94",
    })
  end
  check_error(last, util.CODES.RATE_LIMITED, "brute force is rate limited")
  check(last.error.retry_after ~= nil and last.error.retry_after > 0, "retry_after reported")

  -- Even the correct password is refused while locked out.
  local correct = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.94", mac = "aa:bb:cc:dd:ee:94",
  })
  check_error(correct, util.CODES.RATE_LIMITED, "lockout also applies to the correct password")

  -- A different source address for the same account is still limited by username.
  local other_ip = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.95", mac = "aa:bb:cc:dd:ee:95",
  })
  check_error(other_ip, util.CODES.RATE_LIMITED, "username-scoped lockout applies from another IP")

  local rows = dbmod.scalar(service.db, "SELECT COUNT(*) FROM auth_attempts")
  check((tonumber(rows) or 0) <= service.AUTH_ROW_CAP, "auth_attempts stays capped")
  service:close()
end)

test("portal_my_account: token is the authority, source binding enforced", function()
  local service = new_service()
  set_now(math.max(now(), local_epoch(2026, 11, 10, 9, 0, 0)) + core.LOGIN_LOCK + 1)
  local login = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.100", mac = "aa:bb:cc:dd:ee:a0",
  })
  check(login and login.ok == true, "login succeeds")
  if not (login and login.ok) then service:close(); return end
  local token = login.data.session_token

  local mine = rq(service, "portal_my_account", { session_token = token, ip = "192.168.8.100", mac = "aa:bb:cc:dd:ee:a0" })
  check(mine and mine.ok == true, "own account readable: " .. tostring(mine and mine.error and mine.error.message))
  if mine and mine.ok then
    check_equal(mine.data.account.username, "portaler", "identity comes from the session token")
    check_equal(mine.data.network_authorized, true, "network state reported")
    check(mine.data.account.password_hash == nil, "no hash returned to the portal")
    -- CSRF is not re-issued on reads: only the login response carries it.
    check(mine.data.csrf_token == nil, "get_my_account does not return a csrf token")
  end
  local spoof = rq(service, "portal_my_account", { session_token = token, ip = "192.168.8.200", mac = "aa:bb:cc:dd:ee:a0" })
  check_error(spoof, util.CODES.SESSION_INVALID, "session bound to another source address rejected")
  local no_token = rq(service, "portal_my_account", { session_token = "deadbeef", ip = "192.168.8.100" })
  check_error(no_token, util.CODES.SESSION_INVALID, "forged token rejected")
  -- A token must not be able to name a different account.
  local with_id = rq(service, "portal_my_account", { session_token = token, user_id = 1 })
  check_error(with_id, util.CODES.INVALID_ARGUMENT, "portal identity cannot be supplied as user_id")
  service:close()
  local _ = login
end)

test("portal_change_password: requires CSRF, old password and matching confirmation", function()
  local service = new_service()
  local login = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.101", mac = "aa:bb:cc:dd:ee:a1",
  })
  check(login and login.ok == true, "login succeeds")
  if not (login and login.ok) then service:close(); return end
  local token, csrf = login.data.session_token, login.data.csrf_token
  local base = { session_token = token, ip = "192.168.8.101", mac = "aa:bb:cc:dd:ee:a1",
    old_password = "portal-login-1", new_password = "brand-new-pass", confirm_password = "brand-new-pass" }

  local args_nocsrf = {}
  for k, v in pairs(base) do args_nocsrf[k] = v end
  check_error(rq(service, "portal_change_password", args_nocsrf), util.CODES.CSRF_INVALID, "missing csrf rejected")

  local args_badcsrf = {}
  for k, v in pairs(base) do args_badcsrf[k] = v end
  args_badcsrf.csrf_token = string.rep("0", 64)
  check_error(rq(service, "portal_change_password", args_badcsrf), util.CODES.CSRF_INVALID, "forged csrf rejected")

  local args_mismatch = {}
  for k, v in pairs(base) do args_mismatch[k] = v end
  args_mismatch.csrf_token = csrf
  args_mismatch.confirm_password = "different-pass"
  check_error(rq(service, "portal_change_password", args_mismatch), util.CODES.PASSWORD_MISMATCH, "confirmation mismatch rejected")

  local args_wrongold = {}
  for k, v in pairs(base) do args_wrongold[k] = v end
  args_wrongold.csrf_token = csrf
  args_wrongold.old_password = "not-the-old-one"
  check_error(rq(service, "portal_change_password", args_wrongold), util.CODES.AUTH_FAILED, "wrong current password rejected")

  local args_short = {}
  for k, v in pairs(base) do args_short[k] = v end
  args_short.csrf_token = csrf
  args_short.new_password = "short"
  args_short.confirm_password = "short"
  check_error(rq(service, "portal_change_password", args_short), util.CODES.INVALID_ARGUMENT, "short new password rejected")

  -- The account is untouched by all rejected attempts.
  local ok_old = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.102", mac = "aa:bb:cc:dd:ee:a2",
  })
  check(ok_old and ok_old.ok == true, "original password still valid after rejected changes")

  local args_ok = {}
  for k, v in pairs(base) do args_ok[k] = v end
  args_ok.csrf_token = csrf
  local changed = rq(service, "portal_change_password", args_ok)
  check(changed and changed.ok == true, "valid change succeeds: " .. tostring(changed and changed.error and changed.error.message))
  if changed and changed.ok then
    check_equal(changed.data.sessions_revoked, true, "all sessions revoked")
    check(changed.data.network_revoked >= 1, "network sessions revoked")
  end
  local after = rq(service, "portal_my_account", { session_token = token, ip = "192.168.8.101" })
  check_error(after, util.CODES.SESSION_INVALID, "current portal session invalidated by the change")
  local old_login = rq(service, "portal_login", {
    username = "portaler", password = "portal-login-1", ip = "192.168.8.103", mac = "aa:bb:cc:dd:ee:a3",
  })
  check_error(old_login, util.CODES.AUTH_FAILED, "old password no longer valid")
  local new_login = rq(service, "portal_login", {
    username = "portaler", password = "brand-new-pass", ip = "192.168.8.104", mac = "aa:bb:cc:dd:ee:a4",
  })
  check(new_login and new_login.ok == true, "new password works")
  service:close()
end)

test("portal: exhausted account keeps portal access without network", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "tired", password = "tired-user-pass", quota_bytes = 100 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local per = rq(service, "get_account", { id = acc.data.id })
  service:checkpoint({ { user_id = acc.data.id, period_id = per.data.period_id, upload_bytes = 100, download_bytes = 0 } })
  local login = rq(service, "portal_login", {
    username = "tired", password = "tired-user-pass", ip = "192.168.8.110", mac = "aa:bb:cc:dd:ee:b0",
  })
  check(login and login.ok == true, "exhausted account can still log in to the portal")
  if login and login.ok then
    check_equal(login.data.network_authorized, false, "no network authorisation when exhausted")
    check(login.data.session_token ~= nil, "portal session still issued for self service")
    local mine = rq(service, "portal_my_account", {
      session_token = login.data.session_token, ip = "192.168.8.110", mac = "aa:bb:cc:dd:ee:b0",
    })
    check(mine and mine.ok == true, "self-service page reachable while exhausted")
    if mine and mine.ok then check_equal(mine.data.account.exhausted, true, "exhaustion visible to the user") end
  end
  local online = dbmod.scalar(service.db, "SELECT COUNT(*) FROM network_sessions WHERE user_id = ? AND state = 'online'", { acc.data.id })
  check_equal(tonumber(online), 0, "no network session for an exhausted account")
  service:close()
end)

test("logout: revokes the current portal session and its network session", function()
  local service = new_service()
  local login = rq(service, "portal_login", {
    username = "isolb", password = "isolation-b-1",
    ip = "192.168.8.120", mac = "aa:bb:cc:dd:ee:c0",
  })
  check(login and login.ok == true, "login succeeds")
  if not (login and login.ok) then service:close(); return end
  local out = rq(service, "portal_logout", {
    session_token = login.data.session_token, csrf_token = login.data.csrf_token,
    ip = "192.168.8.120", mac = "aa:bb:cc:dd:ee:c0",
  })
  check(out and out.ok == true, "logout succeeds: " .. tostring(out and out.error and out.error.message))
  if out and out.ok then check(out.data.network_revoked >= 1, "matching network session revoked") end
  local again = rq(service, "portal_my_account", { session_token = login.data.session_token, ip = "192.168.8.120" })
  check_error(again, util.CODES.SESSION_INVALID, "logged-out token is invalid")
  service:close()
end)

----------------------------------------------------------------------------
-- 9. Dispatch / role separation / settings
----------------------------------------------------------------------------

test("request dispatch: unknown method and unknown fields rejected", function()
  local service = new_service()
  check_error(rq(service, "no_such_method", {}), util.CODES.NOT_FOUND, "unknown method rejected")
  check_error(rq(service, 123, {}), util.CODES.INVALID_ARGUMENT, "non-string method rejected")
  check_error(rq(service, "status", { evil = 1 }), util.CODES.INVALID_ARGUMENT, "unknown status field rejected")
  local st = rq(service, "status", {})
  check(st and st.ok == true, "status returns ok")
  if st and st.ok then
    check_equal(st.data.schema_version, dbmod.SCHEMA_VERSION, "status reports the schema version")
    check(st.data.database ~= nil, "status reports database state")
  end
  service:close()
end)

test("settings: timezone change refused while accounts exist", function()
  local service = new_service()
  local r = rq(service, "update_settings", { timezone = "UTC" })
  check_error(r, util.CODES.CONFLICT, "timezone change refused with accounts present")
  if r and r.error then check(r.error.accounts ~= nil, "conflict reports the account count") end
  local st = rq(service, "get_settings", {})
  check(st and st.ok == true, "settings readable")
  if st and st.ok then
    check_equal(st.data.timezone, "Asia/Shanghai", "timezone unchanged")
    check(util.is_plain_integer(st.data.default_reset_day), "default_reset_day is an integer")
  end
  local bad = rq(service, "update_settings", { timezone = "Mars/Olympus" })
  check_error(bad, util.CODES.INVALID_ARGUMENT, "unsupported timezone rejected")
  local noargs = rq(service, "update_settings", {})
  check_error(noargs, util.CODES.INVALID_ARGUMENT, "empty settings update rejected")
  service:close()
end)

test("get_portal_info and get_traffic shapes", function()
  local service = new_service()
  local info = rq(service, "get_portal_info", {})
  check(info and info.ok == true, "portal info available")
  if info and info.ok then
    check(type(info.data.portal) == "table", "portal block present")
    check(util.is_plain_integer(info.data.default_reset_day), "portal info exposes the default reset day")
  end
  local traffic = rq(service, "get_traffic", {})
  check(traffic and traffic.ok == true, "traffic available")
  if traffic and traffic.ok then
    check(type(traffic.data.items) == "table", "traffic items is a list")
    for _, row in ipairs(traffic.data.items) do
      check(row.total_bytes == row.upload_bytes + row.download_bytes, "traffic row total = up + down")
      check(row.password_hash == nil, "traffic row has no secrets")
    end
  end
  service:close()
end)

test("network adapter contract: freeze/snapshot/install/thaw ordering", function()
  local events = {}
  local readings = {
    { period_id = 1, upload_bytes = 0, download_bytes = 0, quota_used_bytes = 0 },
  }
  local net = {
    freeze = function() events[#events + 1] = "freeze" return true end,
    snapshot = function() events[#events + 1] = "snapshot" return readings end,
    install = function(snap) events[#events + 1] = "install"; return snap ~= nil end,
    thaw = function() events[#events + 1] = "thaw" return true end,
    probe = function() return { ok = true, errors = {}, warnings = { "no kernel counters in test" } } end,
  }
  local service = new_service({ network = net })
  local acc = rq(service, "create_account", { username = "netuser", password = "network-pass", quota_bytes = 5000 })
  check(acc and acc.ok == true, "account created with a network adapter")
  events = {}
  local tick = service:request("tick", {})
  check(tick and tick.ok == true, "tick succeeds with the network adapter")
  check_equal(table.concat(events, ","), "freeze,snapshot,install,thaw",
    "guarded sequence order is freeze, snapshot, install, thaw")
  service:close()

  -- A failing install must leave the guard closed (no thaw after the failure).
  local fail_events = {}
  local failing = {
    freeze = function() fail_events[#fail_events + 1] = "freeze" return true end,
    snapshot = function() fail_events[#fail_events + 1] = "snapshot" return {} end,
    install = function() fail_events[#fail_events + 1] = "install" return false, "boom" end,
    thaw = function() fail_events[#fail_events + 1] = "thaw" return true end,
  }
  local service2 = new_service({ network = failing })
  local tick2 = service2:request("tick", {})
  check(tick2 and tick2.ok == false, "tick reports failure when install fails")
  check(service2.guard_left == true, "guard is left closed after an install failure")
  local saw_thaw = false
  for _, e in ipairs(fail_events) do if e == "thaw" then saw_thaw = true end end
  check(saw_thaw == false, "no thaw after a failed install")
  service2:close()
end)

test("read-only requests never roll periods", function()
  local service = new_service()
  local acc = rq(service, "create_account", { username = "readonly", password = "read-only-pass", quota_bytes = 5000 })
  check(acc and acc.ok == true, "account created")
  if not (acc and acc.ok) then service:close(); return end
  local per = rq(service, "get_account", { id = acc.data.id })
  set_now(per.data.period_end_at + 3600)
  rq(service, "list_accounts", {})
  rq(service, "get_summary", {})
  rq(service, "get_traffic", {})
  rq(service, "status", {})
  local held = rq(service, "get_account", { id = acc.data.id })
  check_equal(held.data.period_id, per.data.period_id, "read-only requests did not roll the period")
  local tick = service:request("tick", {})
  check(tick and tick.ok == true, "tick performs the rollover")
  local rolled = rq(service, "get_account", { id = acc.data.id })
  check(rolled.data.period_id ~= per.data.period_id, "tick rolled the period")
  service:close()
end)

----------------------------------------------------------------------------
-- 10. util unit checks
----------------------------------------------------------------------------

test("util: strict scalar helpers", function()
  check(util.integer(5, 1, 10, "x") == 5, "integer in range accepted")
  check(util.integer(5.0, 1, 10, "x") == 5, "integral float rejected as integer is false: " .. tostring(util.integer(5.0, 1, 10, "x")))
  check(util.safe_integer(9007199254740991, 1, nil, "x") == 9007199254740991, "max safe integer accepted")
  local _, err = util.safe_integer(9007199254740992, 1, nil, "x")
  check(err and err.ok == false, "above max safe integer rejected")
  check_equal(util.usage_percent(50, 100), 50, "usage percent 50/100")
  check_equal(util.usage_percent(150, 100), 150, "usage percent above 100 reported")
  check_equal(util.usage_percent(0, 100), 0, "usage percent zero")
  check_equal(util.usage_percent(50, 0), 0, "usage percent with zero quota is 0")
  check_equal(util.ipv4("192.168.8.1"), "192.168.8.1", "valid ipv4")
  check(util.ipv4("192.168.08.1") == nil, "leading zero octet rejected")
  check(util.ipv4("256.1.1.1") == nil, "out-of-range octet rejected")
  check(util.ipv4("1.2.3") == nil, "short ipv4 rejected")
  check_equal(util.mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff", "mac normalised to lowercase colon form")
  check(util.mac("aa:bb") == nil, "truncated mac rejected")
  check_equal(util.json_int(9007199254740991), "9007199254740991", "json_int preserves large integers")
  check_equal(util.json_int(0), "0", "json_int zero")
  check_equal(util.add_safe(9007199254740990, 1), 9007199254740991, "add_safe near the limit")
  check(util.add_safe(9007199254740991, 1) == nil, "add_safe overflow detected")
  check(util.reject_unknown({ a = 1 }, { a = true }) == true, "known field accepted")
  local ok, uerr = util.reject_unknown({ a = 1, b = 2 }, { a = true })
  check(ok == nil and uerr.ok == false, "unknown field rejected")
end)

----------------------------------------------------------------------------
-- Summary
----------------------------------------------------------------------------

test("untrusted time cannot create accounts or reset periods", function()
  local service=new_service({clock_trusted=false})
  check_error(service:request('tick',{}),util.CODES.CLOCK,'rollover waits for trusted time')
  check_error(service:request('create_account',{username='unsynced',password='Clock-test-123',quota_bytes=1000}),
    util.CODES.CLOCK,'new account creation waits for trusted time')
  service:close()
end)

set_now(os.time())
remove_db_files(TMP_DB)

io.write(string.format("\n%d checks passed, %d failed\n", results.passed, results.failed))
if results.failed > 0 then
  io.write("\nfailures:\n")
  for _, e in ipairs(results.errors) do io.write("  - " .. e .. "\n") end
  os.exit(1)
end
io.write("RESULT: OK\n")
os.exit(0)

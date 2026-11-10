-- NetQuota domain service.
--
--   local service = require("netquota.core").open(opts)
--   service:request(method, args) -> { ok = true, data = ... } | { ok = false, error = {...} }
--
-- opt-in contract (all optional; the DB domain works standalone):
--   db_path        string   default /etc/netquota/netquota.db
--   clock          function default os.time
--   timezone       string   default Asia/Shanghai
--   crypto         table    hash_password/verify_password/verify_password_or_decoy/
--                           random_hex/hash_token/verify_token/equal (defaults to netquota.crypto)
--   network        table    freeze()/snapshot()/install(snapshot)/thaw()/probe()
--   lock_path      string   default /var/lock/netquota.lock
--   lock           table    acquire(path)/release(fd) built-ins overridable for tests
--   config         table    read-only LuCI metadata echoed by get_settings
--   session_ttl    number   default 3600 seconds
--   admin          boolean  default false (true allows the admin-only methods)
--
-- Locking / guard ordering for every write that can affect the kernel:
--   file lock -> network.freeze() -> network.snapshot() -> checkpoint read ->
--   DB transaction -> network.install(service:snapshot()) -> network.thaw()
-- Any failure after freeze leaves the network guarded (thaw is not attempted) and the DB
-- transaction is rolled back, so kernel and DB never diverge into an unguarded state.
--
-- Read-only requests NEVER roll periods: rollover only happens inside service:tick() or a
-- write request that runs the guarded sequence.

local util = require("netquota.util")
local crypto_mod = require("netquota.crypto")
local calendar = require("netquota.calendar")
local db = require("netquota.db")
local billing = require("netquota.billing")

local core = {}

core.SERVICE_NAME = "netquota"
core.VERSION = util.VERSION
core.ROLES = { admin = true, cli = true, portal = true }

-- Rate limiting parameters (per username and per source IP).
core.LOGIN_MAX_ATTEMPTS = 5
core.LOGIN_WINDOW = 900        -- seconds
core.LOGIN_LOCK = 900          -- seconds
core.AUTH_ROW_CAP = 512        -- hard cap on auth_attempts rows

-- Admin method whitelists; unknown fields are rejected before any SQL is prepared.
local ADMIN_METHODS = {
  status = true,
  get_summary = true,
  list_accounts = true,
  get_account = true,
  create_account = true,
  update_account = true,
  delete_account = true,
  get_traffic = true,
  get_settings = true,
  update_settings = true,
  get_portal_info = true,
}

local ADMIN_WRITES = {
  create_account = true,
  update_account = true,
  delete_account = true,
  update_settings = true,
}

local PORTAL_METHODS = {
  portal_login = true,
  portal_logout = true,
  portal_my_account = true,
  portal_change_password = true,
}

local INTERNAL_METHODS = {
  tick = true,
  checkpoint = true,
  snapshot = true,
}

local METHOD_ARGS = {
  status = {},
  get_summary = {},
  list_accounts = { "search", "status", "sort", "limit" },
  get_account = { "id" },
  create_account = { "username", "password", "quota_bytes", "reset_day" },
  update_account = { "id", "password", "quota_bytes", "reset_day", "clear_pending_reset_day", "username" },
  delete_account = { "id" },
  get_traffic = {},
  get_settings = {},
  update_settings = { "default_reset_day", "timezone", "traffic_multiplier_percent" },
  get_portal_info = {},
  portal_login = { "username", "password", "ip", "mac" },
  portal_logout = { "session_token", "csrf_token", "ip", "mac" },
  portal_my_account = { "session_token", "ip", "mac" },
  portal_change_password = { "session_token", "csrf_token", "old_password", "new_password", "confirm_password", "ip", "mac" },
  checkpoint = { "readings" },
}

local function allowed_set(list)
  local set = {}
  for _, k in ipairs(list or {}) do set[k] = true end
  return set
end

local METHOD_ALLOWED = {}
for method, keys in pairs(METHOD_ARGS) do METHOD_ALLOWED[method] = allowed_set(keys) end

----------------------------------------------------------------------------
-- Journal (structured logging without secrets)
----------------------------------------------------------------------------

local function make_logger(opts)
  local sink = opts.log
  if sink == nil then
    local ok, nixio = pcall(require, "nixio")
    if ok and type(nixio) == "table" and type(nixio.syslog) == "function" then
      sink = function(level, msg)
        pcall(nixio.syslog, level or "notice", msg)
      end
    else
      sink = function(level, msg) io.stderr:write("[netquota] " .. tostring(level) .. " " .. tostring(msg) .. "\n") end
    end
  elseif sink == false then
    sink = function() end
  end
  return function(level, msg) pcall(sink, level, msg) end
end

-- Structured journal entries recorded in memory for diagnostics/tests; never contains
-- secrets (password, hash, salt or token material).
local function journal(self, action, fields)
  local entry = { at = self:now(), action = action }
  if type(fields) == "table" then
    for k, v in pairs(fields) do
      if k ~= "password" and k ~= "hash" and k ~= "salt" and k ~= "token" and k ~= "csrf" then
        entry[k] = v
      end
    end
  end
  self._journal[#self._journal + 1] = entry
  if #self._journal > 256 then table.remove(self._journal, 1) end
  if self.log then
    local parts = {}
    for k, v in pairs(entry) do parts[#parts + 1] = tostring(k) .. "=" .. tostring(v) end
    table.sort(parts)
    self.log(entry.result == "error" and "err" or "info", action .. " " .. table.concat(parts, " "))
  end
  return entry
end

----------------------------------------------------------------------------
-- Time helpers
----------------------------------------------------------------------------

-- Converts a stored REAL/INTEGER to an integer epoch.
local function to_int_epoch(v)
  if type(v) ~= "number" then return nil end
  if v ~= v then return nil end
  return math.floor(v)
end

local function as_int(v)
  if v == nil then return nil end
  local n = tonumber(v)
  if not n then return nil end
  return math.floor(n)
end

----------------------------------------------------------------------------
-- Settings access
----------------------------------------------------------------------------

local DEFAULT_SETTINGS = {
  default_reset_day = util.DEFAULT_RESET_DAY,
  timezone = util.DEFAULT_TIMEZONE,
}

-- Returns settings from the DB merged over defaults; never throws.
function core.settings(self)
  local rows, err = db.query(self.db, "SELECT key, value FROM settings")
  if not rows then
    -- A settings read failure must not be treated as "defaults": callers that mutate
    -- quota rely on knowing the real values. Return nil + error.
    return nil, err
  end
  local raw = {}
  for _, r in ipairs(rows) do
    local n = tonumber(r.value)
    if n then raw[r.key] = math.floor(n) else raw[r.key] = r.value end
  end
  local s = {
    default_reset_day = DEFAULT_SETTINGS.default_reset_day,
    timezone = DEFAULT_SETTINGS.timezone,
    traffic_multiplier_percent = 100,
  }
  -- Stored integers come back as strings in SQLite text columns; normalise.
  local drd = raw.default_reset_day
  if util.is_plain_integer(drd) and drd >= 1 and drd <= 31 then s.default_reset_day = drd end
  if type(raw.timezone) == "string" and calendar.is_valid_zone(raw.timezone) then s.timezone = raw.timezone end
  if raw.traffic_multiplier_percent ~= nil then
    if not billing.valid_rate(raw.traffic_multiplier_percent) then
      return nil, util.error(util.CODES.INTERNAL, "invalid stored billing multiplier")
    end
    s.traffic_multiplier_percent = raw.traffic_multiplier_percent
  end
  s.raw = raw
  return s
end

local function put_setting(self, key, value, now)
  local ok, err = db.exec(self.db,
    "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) " ..
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    { key, tostring(value), now })
  if not ok then return nil, err end
  return true
end

----------------------------------------------------------------------------
-- Period helpers
----------------------------------------------------------------------------

-- Applies any pending reset-day change that became effective at or before `now` for one
-- account, opening the next period. Must be called inside a transaction.
local function apply_effective_pending(self, user, cur_period, settings, now)
  if user.pending_kind == nil then return cur_period end
  local eff = as_int(user.reset_day_effective_at)
  if not eff or now < eff then return cur_period end
  local tz = settings.timezone
  local new_day
  if user.pending_kind == 0 then
    new_day = settings.default_reset_day            -- inherit
  else
    new_day = as_int(user.pending_reset_day)
  end
  local ok = new_day and new_day >= 1 and new_day <= 31
  if not ok then new_day = cur_period.reset_day_applied end
  local new_end, err = calendar.reanchor(cur_period.period_start_at, cur_period.period_end_at, new_day, tz)
  if not new_end then return nil, util.error(util.CODES.INTERNAL, "cannot re-anchor period: " .. tostring(err)) end
  local closed, cerr = db.exec(self.db,
    "UPDATE usage_periods SET state = 'closed', closed_at = ?, updated_at = ? WHERE id = ? AND state = 'open'",
    { eff, now, cur_period.id })
  if not closed then return nil, cerr end
  local changed, new_id = db.exec(self.db,
    "INSERT INTO usage_periods(user_id, period_start_at, period_end_at, reset_day_applied, upload_bytes, download_bytes, total_bytes, kernel_quota_used_bytes, state, created_at, updated_at) " ..
    "VALUES(?,?,?,?,0,0,0,0,'open',?,?)",
    { user.id, cur_period.period_end_at, new_end, new_day, now, now })
  if not changed or changed < 1 then return nil, util.error(util.CODES.INTERNAL, "cannot open re-anchored period") end
  local stored_day = user.pending_kind == 0 and nil or new_day
  if user.pending_kind == 0 then stored_day = nil end
  local uok, uerr = db.exec(self.db,
    "UPDATE users SET reset_day = ?, pending_kind = NULL, pending_reset_day = NULL, reset_day_effective_at = NULL, updated_at = ? WHERE id = ?",
    { stored_day, now, user.id })
  if not uok then return nil, uerr end
  user.reset_day = stored_day
  user.pending_kind, user.pending_reset_day, user.reset_day_effective_at = nil, nil, nil
  journal(self, "pending_reset_applied", { user_id = user.id, reset_day = new_day, at = eff })
  return {
    id = new_id,
    user_id = user.id,
    period_start_at = cur_period.period_end_at,
    period_end_at = new_end,
    reset_day_applied = new_day,
    upload_bytes = 0,
    download_bytes = 0,
    total_bytes = 0,
    kernel_quota_used_bytes = 0,
    state = "open",
    closed_at = nil,
  }
end

-- Ensures exactly one open period exists for `user`, consistent with `now`. Must run inside
-- a transaction. Rolls over when `now` reaches the period end. Clock rollback never creates
-- an earlier period: we only ever move forward from the latest period on record.
local function ensure_period(self, user, settings, now)
  local tz = settings.timezone
  local day = user.reset_day or settings.default_reset_day
  local row, qerr = db.query_one(self.db,
    "SELECT * FROM usage_periods WHERE user_id = ? ORDER BY period_start_at DESC LIMIT 1", { user.id })
  if row == nil and qerr then return nil, qerr end
  local period
  if not row then
    -- First period for a new account. An account that already carries a pending change
    -- (only possible through update_settings) still starts from the current effective day;
    -- the pending value is applied at this period's end.
    local start_at, end_at, serr = calendar.period_for(now, day, tz)
    if not start_at then return nil, util.error(util.CODES.INTERNAL, "calendar error: " .. tostring(serr)) end
    local changed, id = db.exec(self.db,
      "INSERT INTO usage_periods(user_id, period_start_at, period_end_at, reset_day_applied, upload_bytes, download_bytes, total_bytes, kernel_quota_used_bytes, state, created_at, updated_at) " ..
      "VALUES(?,?,?,?,0,0,0,0,'open',?,?)",
      { user.id, start_at, end_at, day, now, now })
    if not changed or changed < 1 then return nil, util.error(util.CODES.INTERNAL, "cannot create period") end
    period = { id = id, user_id = user.id, period_start_at = start_at, period_end_at = end_at,
      reset_day_applied = day, upload_bytes = 0, download_bytes = 0, total_bytes = 0,
      kernel_quota_used_bytes = 0, state = "open" }
  else
    period = {
      id = row.id,
      user_id = row.user_id,
      period_start_at = as_int(row.period_start_at),
      period_end_at = as_int(row.period_end_at),
      reset_day_applied = as_int(row.reset_day_applied) or day,
      upload_bytes = as_int(row.upload_bytes) or 0,
      download_bytes = as_int(row.download_bytes) or 0,
      total_bytes = as_int(row.total_bytes) or 0,
      kernel_quota_used_bytes = as_int(row.kernel_quota_used_bytes) or 0,
      billed_bytes = as_int(row.billed_bytes), billing_carry = as_int(row.billing_carry) or 0,
      state = row.state,
      closed_at = as_int(row.closed_at),
    }
  end

  period = apply_effective_pending(self, user, period, settings, now) or period
  if period.error then return nil, period end

  -- Roll forward while the clock is at/after the current end.
  local guard = 0
  while now >= period.period_end_at and guard < 240 do
    guard = guard + 1
    local new_end, nerr = calendar.reanchor(period.period_start_at, period.period_end_at, period.reset_day_applied, tz)
    if not new_end then return nil, util.error(util.CODES.INTERNAL, "calendar error: " .. tostring(nerr)) end
    local ok, cerr = db.exec(self.db,
      "UPDATE usage_periods SET state = 'closed', closed_at = ?, updated_at = ? WHERE id = ? AND state = 'open'",
      { period.period_end_at, now, period.id })
    if not ok then return nil, cerr end
    local changed, id = db.exec(self.db,
      "INSERT INTO usage_periods(user_id, period_start_at, period_end_at, reset_day_applied, upload_bytes, download_bytes, total_bytes, kernel_quota_used_bytes, state, created_at, updated_at) " ..
      "VALUES(?,?,?,?,0,0,0,0,'open',?,?)",
      { user.id, period.period_end_at, new_end, period.reset_day_applied, now, now })
    if not changed or changed < 1 then return nil, util.error(util.CODES.INTERNAL, "cannot open next period") end
    journal(self, "period_rollover", { user_id = user.id, from_period = period.id, to_period = id, at = period.period_end_at })
    period = {
      id = id, user_id = user.id,
      period_start_at = period.period_end_at, period_end_at = new_end,
      reset_day_applied = period.reset_day_applied,
      upload_bytes = 0, download_bytes = 0, total_bytes = 0, kernel_quota_used_bytes = 0,
      state = "open", closed_at = nil,
    }
  end
  return period
end

----------------------------------------------------------------------------
-- Account loading / projection
----------------------------------------------------------------------------

local USER_COLUMNS = "id, username, password_hash, quota_bytes, reset_day, pending_kind, pending_reset_day, " ..
  "reset_day_effective_at, enabled, created_at, updated_at"

local function load_user_by_id(self, id)
  local row, err = db.query_one(self.db, "SELECT " .. USER_COLUMNS .. " FROM users WHERE id = ? AND deleted_at IS NULL", { id })
  if row == nil and err then return nil, err end
  return row
end

local function load_user_by_key(self, key)
  local row, err = db.query_one(self.db, "SELECT " .. USER_COLUMNS .. " FROM users WHERE username_key = ? AND deleted_at IS NULL", { key })
  if row == nil and err then return nil, err end
  return row
end

local function normalize_user(row)
  if not row then return nil end
  return {
    id = as_int(row.id),
    username = row.username,
    password_hash = row.password_hash,
    quota_bytes = as_int(row.quota_bytes),
    reset_day = as_int(row.reset_day),
    pending_kind = as_int(row.pending_kind),
    pending_reset_day = as_int(row.pending_reset_day),
    reset_day_effective_at = as_int(row.reset_day_effective_at),
    enabled = as_int(row.enabled),
    created_at = as_int(row.created_at),
    updated_at = as_int(row.updated_at),
  }
end

local function effective_reset_day(user, settings)
  if user.reset_day then return user.reset_day end
  return settings.default_reset_day
end

-- Public account projection. Never contains the hash, salt, tokens or secrets.
local function public_account(self, user, period, settings, now, stats)
  local used_upload = period and period.upload_bytes or 0
  local used_download = period and period.download_bytes or 0
  local total = util.add_safe(used_upload, used_download) or util.MAX_SAFE
  local quota = user.quota_bytes
  local billed = billing.used(period)
  local exhausted = billed >= quota
  local remaining = exhausted and 0 or (quota - billed)
  if remaining < 0 then remaining = 0 end
  local pending_day = nil
  if user.pending_kind ~= nil then
    if user.pending_kind == 1 then pending_day = user.pending_reset_day else pending_day = nil end
  end
  local pending_effective_at = user.pending_kind ~= nil and user.reset_day_effective_at or nil
  local online = stats and stats.online or 0
  local account = {
    id = user.id,
    username = user.username,
    quota_bytes = quota,
    reset_day = user.reset_day,
    effective_reset_day = period and period.reset_day_applied or effective_reset_day(user, settings),
    pending_reset_day = pending_day,
    pending_inherit = user.pending_kind == 0 or nil,
    pending_effective_at = pending_effective_at,
    period_id = period and period.id or nil,
    period_start_at = period and period.period_start_at or nil,
    period_end_at = period and period.period_end_at or nil,
    next_reset_at = period and period.period_end_at or nil,
    upload_bytes = used_upload,
    download_bytes = used_download,
    total_bytes = total,
    billed_bytes = billed,
    traffic_multiplier_percent = settings.traffic_multiplier_percent,
    remaining_bytes = remaining,
    usage_percent = util.usage_percent(billed, quota),
    online = online > 0,
    session_count = online,
    exhausted = exhausted,
    enabled = user.enabled == 1,
    created_at = user.created_at,
    updated_at = user.updated_at,
  }
  local _ = now
  return account
end

local function session_counts(self, user_ids)
  if #user_ids == 0 then return {}, {} end
  local placeholders = {}
  local params = {}
  for i, id in ipairs(user_ids) do
    placeholders[i] = "?"
    params[i] = id
  end
  local online, total = {}, {}
  local rows, err = db.query(self.db,
    "SELECT user_id, COUNT(*) AS n FROM network_sessions WHERE state = 'online' AND user_id IN (" ..
    table.concat(placeholders, ",") .. ") GROUP BY user_id", params)
  if rows then for _, r in ipairs(rows) do online[as_int(r.user_id)] = as_int(r.n) or 0 end end
  local rows2, err2 = db.query(self.db,
    "SELECT user_id, COUNT(*) AS n FROM network_sessions WHERE state != 'revoked' AND user_id IN (" ..
    table.concat(placeholders, ",") .. ") GROUP BY user_id", params)
  if rows2 then for _, r in ipairs(rows2) do total[as_int(r.user_id)] = as_int(r.n) or 0 end end
  local _ = err
  local _2 = err2
  return online, total
end

----------------------------------------------------------------------------
-- Network guard primitives
----------------------------------------------------------------------------

local function network_call(self, name, ...)
  local net = self.opts.network
  if type(net) ~= "table" then return true, nil end
  local fn = net[name]
  if type(fn) ~= "function" then return true, nil end
  if self.config.enabled == false then return true, nil end
  local ok, res, extra = pcall(fn, net, ...)
  if not ok then return nil, res end
  if res == false or (res == nil and extra ~= nil) then return nil, extra or "network." .. name .. " failed" end
  return true, res
end

-- Runs fn() inside the guarded sequence. Returns the transaction result on success, or
-- nil + error envelope on failure.
--   lock -> freeze -> snapshot -> [txn: apply kernel deltas, fn()] -> install -> thaw
-- Thaw guarantees:
--   * rollback   -> thaw (DB and kernel both unchanged; the next snapshot picks up bytes)
--   * install KO -> stay guarded (DB holds the intended state; tick() retries install)
local function guarded(self, fn)
  local locked, lockerr = self:lock()
  if not locked then return nil, lockerr end
  local function locked_return(a, b)
    self:unlock()
    return a, b
  end

  local frozen, ferr = network_call(self, "freeze")
  if not frozen then
    journal(self, "network_freeze_failed", { result = "error", error = tostring(ferr) })
    return locked_return(nil, util.error(util.CODES.NETWORK, "cannot freeze network: " .. tostring(ferr)))
  end
  local snap_ok, readings = network_call(self, "snapshot")
  if not snap_ok then
    journal(self, "network_snapshot_failed", { result = "error", error = tostring(readings) })
    return locked_return(nil, util.error(util.CODES.NETWORK, "cannot read network usage: " .. tostring(readings)))
  end
  local dbsnap, dberr = self:snapshot()
  if not dbsnap then
    return locked_return(nil, dberr)
  end

  local now = self:now() or 0
  local tx_ok, tx_result, tx_err = pcall(self._transaction, self, function()
    local applied, aerr = self:_apply_network_snapshot(readings or {}, dbsnap, now)
    if not applied then return nil, aerr end
    local res, err = fn()
    if res == nil or res == false then return nil, err end
    return res
  end)

  if not tx_ok or tx_result == nil then
    -- DB rolled back: kernel counters were not reset, so thawing is safe and the delta will
    -- be re-read on the next snapshot.
    self.guard_left = true
    self.guard_reason = "transaction failed; reconciliation required"
    journal(self, "guarded_transaction_failed", { result = "error" })
    if not tx_ok then return locked_return(nil, util.error(util.CODES.INTERNAL, "transaction failed")) end
    return locked_return(nil, tx_err or util.error(util.CODES.INTERNAL, "transaction failed"))
  end

  local fresh, ferr2 = self:snapshot()
  if not fresh then
    return locked_return(nil, ferr2)
  end
  local installed, ierr = network_call(self, "install", fresh)
  if not installed then
    journal(self, "network_install_failed", { result = "error", error = tostring(ierr) })
    self.guard_left = true
    self.guard_reason = "install failed: " .. tostring(ierr)
    return locked_return(nil, util.error(util.CODES.NETWORK, "network install failed; left guarded for reconciliation"))
  end
  local thawed, terr = network_call(self, "thaw")
  if not thawed then
    journal(self, "network_thaw_failed", { result = "error", error = tostring(terr) })
    self.guard_left = true
    self.guard_reason = "thaw failed after install"
    return locked_return(nil, util.error(util.CODES.NETWORK, "network thaw failed; controller must reconcile"))
  end
  self.guard_left = false
  self.guard_reason = nil
  return locked_return(tx_result, nil)
end

----------------------------------------------------------------------------
-- Opening the service
----------------------------------------------------------------------------

local function default_lock()
  -- nixio.flock(fd, "lock") gives an exclusive advisory lock held by the descriptor, so the
  -- lock is released automatically even if the process dies. Without nixio the lock is a
  -- no-op: DB transactions still provide atomicity, only cross-process serialisation of the
  -- guard sequence is weaker, which is recorded in the journal.
  local ok, nixio = pcall(require, "nixio")
  if not ok or type(nixio) ~= "table" then
    return { acquire = function() return nil, "nixio unavailable" end, release = function() end }
  end
  return {
    acquire = function(path)
      local fh, err = nixio.open(path, "w", "0600")
      if not fh then return nil, "cannot open lock file: " .. tostring(err) end
      local locked, lerr = fh:lock("lock")
      if not locked then
        pcall(function() fh:close() end)
        return nil, "flock failed: " .. tostring(lerr)
      end
      return fh
    end,
    release = function(fh)
      if not fh then return end
      pcall(function() fh:lock("ulock") end)
      pcall(function() fh:close() end)
    end,
  }
end

-- Serialises access to the lock. Re-entrant calls (nested inside guarded()) are no-ops.
function core.lock(self)
  if self._lock_depth > 0 then
    self._lock_depth = self._lock_depth + 1
    return true
  end
  local fh, err = self.lock_impl.acquire(self.lock_path)
  if not fh then
    self._journal[#self._journal + 1] = { at = self:now(), action = "lock_unavailable", error = tostring(err) }
    return nil, util.error(util.CODES.BUSY, "cannot acquire service lock")
  end
  self._lock_fh = fh
  self._lock_depth = 1
  return true
end

function core.unlock(self)
  if self._lock_depth > 1 then
    self._lock_depth = self._lock_depth - 1
    return true
  end
  self._lock_depth = 0
  if self._lock_fh then
    pcall(self.lock_impl.release, self._lock_fh)
    self._lock_fh = nil
  end
  return true
end

-- Raises an error while holding the lock; used only in tests to exercise cleanup.
function core.now(self)
  if self.clock_trusted == false then return nil end
  local ok, t = pcall(self.clock)
  if not ok or not util.is_plain_integer(t) or t < 1704067200 then
    return nil
  end
  return t
end

function core.open(opts)
  opts = opts or {}
  if type(opts) ~= "table" then error("netquota.core.open: opts must be a table", 2) end

  local self = setmetatable({}, { __index = core })
  self.opts = opts
  self.clock = type(opts.clock) == "function" and opts.clock or os.time
  self.clock_trusted = opts.clock_trusted ~= false
  self.crypto = type(opts.crypto) == "table" and opts.crypto or crypto_mod
  self.log = make_logger(opts)
  self._journal = {}
  self._lock_depth = 0
  self.guard_left = false
  self.lock_path = opts.lock_path or util.DEFAULT_LOCK_PATH
  self.lock_impl = type(opts.lock) == "table" and opts.lock or default_lock()
  local session_ttl = opts.session_ttl or (opts.config or {}).session_timeout_seconds
  self.session_ttl = util.is_plain_integer(session_ttl) and session_ttl > 0 and session_ttl or util.DEFAULT_SESSION_TTL
  self.admin_enabled = opts.admin == true
  self.config = opts.config or {}
  self.LOGIN_MAX_ATTEMPTS = opts.login_max_attempts or core.LOGIN_MAX_ATTEMPTS
  self.LOGIN_WINDOW = opts.login_window or core.LOGIN_WINDOW
  self.LOGIN_LOCK = opts.login_lock or core.LOGIN_LOCK
  self.AUTH_ROW_CAP = opts.auth_row_cap or core.AUTH_ROW_CAP

  local db_path = opts.db_path or util.DEFAULT_DB_PATH
  local handle, derr = db.open(db_path, { create = opts.create ~= false })
  if not handle then return nil, derr end
  self.db = handle

  -- Seed defaults once. Settings rows are separate from user data and never re-seeded.
  local settings, serr = core.settings(self)
  if not settings then
    db.close(handle)
    return nil, serr
  end
  local now = self:now() or 0
  if settings.raw and settings.raw.default_reset_day == nil then
    put_setting(self, "default_reset_day", util.DEFAULT_RESET_DAY, now)
  end
  if settings.raw and settings.raw.timezone == nil then
    local tz = opts.timezone or util.DEFAULT_TIMEZONE
    if not calendar.is_valid_zone(tz) then tz = util.DEFAULT_TIMEZONE end
    put_setting(self, "timezone", tz, now)
  end
  return self
end

function core.close(self)
  if not self then return true end
  self._lock_depth = 1
  self:unlock()
  if self.db then
    pcall(db.close, self.db)
    self.db = nil
  end
  return true
end

----------------------------------------------------------------------------
-- Snapshot / checkpoint
----------------------------------------------------------------------------

-- Returns the full kernel-facing snapshot:
-- {accounts=[{id, username, quota_bytes, period_id, upload_bytes, download_bytes,
--  quota_used_bytes, exhausted, sessions=[{id, ipv4_address, mac_address, expires_at}]}],
--  settings=..., updated_at=...}
function core.snapshot(self)
  local now = self:now()
  if not now then return nil, util.error(util.CODES.CLOCK, "clock unavailable") end
  local settings, serr = core.settings(self)
  if not settings then return nil, serr end
  local rows, err = db.query(self.db,
    "SELECT " .. USER_COLUMNS .. " FROM users WHERE deleted_at IS NULL AND enabled = 1")
  if not rows then return nil, err end
  local accounts = {}
  local counts = {}
  local srows, serr2 = db.query(self.db,
    "SELECT id, user_id, ipv4_address, mac_address, expires_at FROM network_sessions WHERE state = 'online' AND expires_at > ? " ..
    "AND period_id IN (SELECT id FROM usage_periods WHERE state = 'open') ORDER BY user_id, id", { now })
  if not srows then return nil, serr2 end
  for _, s in ipairs(srows) do
    local uid = as_int(s.user_id)
    counts[uid] = counts[uid] or {}
    counts[uid][#counts[uid] + 1] = {
      id = as_int(s.id),
      ipv4_address = s.ipv4_address,
      mac_address = s.mac_address,
      expires_at = to_int_epoch(s.expires_at),
    }
  end
  for _, row in ipairs(rows) do
    local user = normalize_user(row)
    local period = db.query_one(self.db,
      "SELECT * FROM usage_periods WHERE user_id = ? AND state = 'open' ORDER BY period_start_at DESC LIMIT 1", { user.id })
    local up = period and as_int(period.upload_bytes) or 0
    local down = period and as_int(period.download_bytes) or 0
    local used = util.add_safe(up, down) or util.MAX_SAFE
    local kernel_used = period and as_int(period.kernel_quota_used_bytes) or 0
    if kernel_used > used then used = kernel_used end
    local billed = billing.used(period)
    local real_limit = billing.real_limit(period or {}, user.quota_bytes, settings.traffic_multiplier_percent)
    accounts[#accounts + 1] = {
      id = user.id,
      username = user.username,
      quota_bytes = user.quota_bytes,
      real_quota_bytes = real_limit,
      billed_bytes = billed,
      period_id = period and as_int(period.id) or nil,
      upload_bytes = up,
      download_bytes = down,
      quota_used_bytes = used,
      exhausted = billed >= user.quota_bytes,
      sessions = counts[user.id] or {},
    }
  end
  return {
    accounts = accounts,
    settings = { default_reset_day = settings.default_reset_day, timezone = settings.timezone },
    updated_at = now,
  }
end

-- Transaction wrapper bound to this instance so guarded() can be unit-tested with a fake
-- implementation. Returns the callback result, or nil + error envelope.
function core._transaction(self, fn)
  return db.transaction(self.db, fn)
end

-- Applies kernel readings conservatively inside the caller's transaction.
-- readings: array of {user_id[,period_id], upload_bytes, download_bytes, quota_used_bytes}
-- The controller's network.snapshot() rows are keyed by period_id, so the owning account is
-- resolved from usage_periods when user_id is absent.
function core._apply_network_snapshot(self, readings, dbsnap, now)
  if type(readings) ~= "table" then return true end
  local period_by_user, user_by_period = {}, {}
  for _, acct in ipairs(dbsnap.accounts or {}) do
    if acct.period_id then
      period_by_user[acct.id] = acct.period_id
      user_by_period[acct.period_id] = acct.id
    end
  end
  for _, r in ipairs(readings) do
    if type(r) == "table" then
      local pid = r.period_id ~= nil and as_int(r.period_id) or nil
      local uid = as_int(r.user_id)
      if uid == nil and pid ~= nil then
        uid = user_by_period[pid]
        if uid == nil then
          local prow = db.query_one(self.db, "SELECT user_id FROM usage_periods WHERE id = ?", { pid })
          if prow then uid = as_int(prow.user_id) end
        end
      end
      if uid then
        local current = period_by_user[uid]
        local accept = (pid == nil) or (current ~= nil and pid == current)
        if accept then
          local one_ok, err = self:_checkpoint_one({
            user_id = uid,
            period_id = current,
            upload_bytes = r.upload_bytes,
            download_bytes = r.download_bytes,
            quota_used_bytes = r.quota_used_bytes,
          }, now, { internal = true })
          if not one_ok then return nil, err end
        else
          -- Reading for a superseded/expired period: ignore; install() rebuilds the kernel
          -- object from the DB snapshot, so the stale counter is replaced, not merged.
          journal(self, "checkpoint_stale_period", { user_id = uid, observed_period = pid, current_period = current })
        end
      end
    end
  end
  return true
end

-- Validates one reading without persisting it.
local function validate_reading(r)
  if type(r) ~= "table" then return nil, util.error(util.CODES.INVALID_ARGUMENT, "reading must be an object") end
  local ok, uerr = util.reject_unknown(r, util.allowed_keys({
    "user_id", "period_id", "upload_bytes", "download_bytes", "quota_used_bytes",
  }), "reading")
  if not ok then return nil, uerr end
  local user_id, e1 = util.safe_integer(r.user_id, 1, util.MAX_SAFE, "user_id")
  if not user_id then return nil, e1 end
  local period_id
  if r.period_id ~= nil then
    local e
    period_id, e = util.safe_integer(r.period_id, 1, util.MAX_SAFE, "period_id")
    if not period_id then return nil, e end
  end
  local out = { user_id = user_id, period_id = period_id }
  for _, f in ipairs({ "upload_bytes", "download_bytes", "quota_used_bytes" }) do
    if r[f] ~= nil then
      local v, e = util.safe_integer(r[f], 0, util.MAX_SAFE, f)
      if v == nil then return nil, e end
      out[f] = v
    end
  end
  if out.user_id == nil then return nil, util.error(util.CODES.INVALID_ARGUMENT, "user_id required") end
  return out
end

-- Persists a single reading. Must run inside a transaction.
-- Returns {applied=bool, period_id=..., upload_bytes=..., download_bytes=..., quota_used=...}
function core._checkpoint_one(self, reading, now, ctx)
  local uid = reading.user_id
  local user_row, uerr = db.query_one(self.db,
    "SELECT id, quota_bytes FROM users WHERE id = ? AND deleted_at IS NULL", { uid })
  if user_row == nil then
    if uerr then return nil, uerr end
    -- Deleted/unknown account: the reading is dropped; the kernel object will be removed by
    -- the controller during the next install.
    journal(self, "checkpoint_unknown_user", { user_id = uid })
    return { applied = false, reason = "unknown_account" }
  end
  local period_row, perr = db.query_one(self.db,
    "SELECT * FROM usage_periods WHERE user_id = ? AND state = 'open' ORDER BY period_start_at DESC LIMIT 1", { uid })
  if period_row == nil and perr then return nil, perr end
  if period_row == nil then
    return nil, util.error(util.CODES.SEQUENCE, "account has no open period")
  end
  local current_period_id = as_int(period_row.id)
  if reading.period_id ~= nil and reading.period_id ~= current_period_id then
    -- Cross-period observation (stale kernel quota object or late reading): refuse so that
    -- an older period can never be reopened or increased.
    journal(self, "checkpoint_stale_period", {
      user_id = uid, observed_period = reading.period_id, current_period = current_period_id,
    })
    return nil, util.error(util.CODES.SEQUENCE, "reading refers to a non-current period")
  end

  local function max_of(a, b)
    if a == nil then return b end
    if b == nil then return a end
    return a > b and a or b
  end
  local up = max_of(as_int(period_row.upload_bytes) or 0, reading.upload_bytes)
  local down = max_of(as_int(period_row.download_bytes) or 0, reading.download_bytes)
  local total = util.add_safe(up, down)
  if not total then
    return nil, util.error(util.CODES.INVALID_ARGUMENT, "counter sum exceeds safe integer range")
  end
  local kernel_used = max_of(as_int(period_row.kernel_quota_used_bytes) or 0, reading.quota_used_bytes)
  local quota = as_int(user_row.quota_bytes)
  if total >= quota and kernel_used < total then kernel_used = total end
  local settings, serr = core.settings(self)
  if not settings then return nil, serr end
  local raw = math.max(total, kernel_used)
  local delta = math.max(0, raw - billing.raw_used(period_row))
  local increment, carry = billing.accrue(delta, as_int(period_row.billing_carry) or 0,
    settings.traffic_multiplier_percent)
  local billed = util.add_safe(billing.used(period_row), increment) or util.MAX_SAFE
  if kernel_used > util.MAX_SAFE then kernel_used = util.MAX_SAFE end

  local ok, cerr = db.exec(self.db,
    "UPDATE usage_periods SET upload_bytes = ?, download_bytes = ?, total_bytes = ?, " ..
    "kernel_quota_used_bytes = ?, billed_bytes = ?, billing_carry = ?, updated_at = ? WHERE id = ?",
    { up, down, total, kernel_used, billed, carry, now, current_period_id })
  if not ok then return nil, cerr end

  local applied = { applied = true, period_id = current_period_id, upload_bytes = up, download_bytes = down,
    quota_used = kernel_used, user_id = uid }
  if billed >= quota then
    local revoked = self:_revoke_user_network(uid, "quota", now)
    applied.revoked = revoked
    journal(self, "quota_exhausted", { user_id = uid, total = total, quota = quota, revoked = revoked,
      result = "ok", internal = ctx and ctx.internal or false })
  end
  return applied
end

-- Public checkpoint: validated, atomic, guarded when a network is configured.
-- Accepts a single reading (table) or an array of readings.
function core.checkpoint(self, readings)
  if type(readings) ~= "table" then
    return util.error(util.CODES.INVALID_ARGUMENT, "readings must be an array")
  end
  local list
  if readings.user_id ~= nil then list = { readings } else list = readings end
  local now = self:now()
  if not now then return util.error(util.CODES.CLOCK, "clock unavailable") end
  local validated = {}
  for i, r in ipairs(list) do
    local v, err = validate_reading(r)
    if not v then
      err.error.field = "readings[" .. i .. "]"
      return err
    end
    validated[i] = v
  end

  if self.opts.network then
    local res, gerr = guarded(self, function()
      local results = {}
      for _, r in ipairs(validated) do
        local applied, aerr = self:_checkpoint_one(r, self:now() or now)
        if not applied then return nil, aerr end
        results[#results + 1] = applied
      end
      return { results = results }
    end)
    if not res then return gerr or util.error(util.CODES.INTERNAL, "checkpoint failed") end
    return util.ok(res)
  end

  local ok_tx, res, err = pcall(db.transaction, self.db, function()
    local results = {}
    for _, r in ipairs(validated) do
      local applied, aerr = self:_checkpoint_one(r, self:now() or now)
      if not applied then return nil, aerr end
      results[#results + 1] = applied
    end
    return { results = results }
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "checkpoint failed") end
  if res == nil then return err or util.error(util.CODES.INTERNAL, "checkpoint failed") end
  return util.ok(res)
end

----------------------------------------------------------------------------
-- Session revocation
----------------------------------------------------------------------------

-- Revokes all online network sessions of one account; returns rows changed.
function core._revoke_user_network(self, user_id, reason, now)
  local changed, err = db.exec(self.db,
    "UPDATE network_sessions SET state = 'revoked', revoked_at = ?, revoke_reason = ? " ..
    "WHERE user_id = ? AND state = 'online'", { now, reason, user_id })
  if changed == nil then return 0, err end
  return changed
end

local function revoke_network_for_user(self, user_id, reason, now)
  return core._revoke_user_network(self, user_id, reason, now)
end

local function revoke_portal_for_user(self, user_id, reason, now)
  local ch, err = db.exec(self.db,
    "UPDATE portal_sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL",
    { now, reason, user_id })
  if not ch then return nil, err end
  return ch
end

local function attempt_get(self, scope, subject)
  return db.query_one(self.db, "SELECT * FROM auth_attempts WHERE scope = ? AND subject = ?", { scope, subject })
end

-- True when the subject is currently locked out.
function core.is_locked_out(self, scope, subject)
  local now = self:now() or 0
  local row = attempt_get(self, scope, subject)
  if not row then return false, 0 end
  local locked_until = as_int(row.locked_until) or 0
  if locked_until > now then return true, locked_until - now end
  return false, 0
end

-- Records a failed attempt and enforces the window/lockout; caps total rows.
function core.register_failure(self, scope, subject)
  local now = self:now() or 0
  local row = attempt_get(self, scope, subject)
  if not row then
    -- Cap row growth: drop oldest rows before inserting.
      local count = db.scalar(self.db, "SELECT COUNT(*) FROM auth_attempts") or 0
    if count >= self.AUTH_ROW_CAP then
      db.exec(self.db,
        "DELETE FROM auth_attempts WHERE id IN (SELECT id FROM auth_attempts ORDER BY updated_at ASC LIMIT ?)",
        { math.max(1, math.floor(count / 4)) })
    end
    db.exec(self.db,
      "INSERT INTO auth_attempts(scope, subject, attempts, window_start, locked_until, created_at, updated_at) VALUES(?,?,1,?,0,?,?)",
      { scope, subject, now, now, now })
    return 1, 0
  end
  local attempts = as_int(row.attempts) or 0
  local window_start = as_int(row.window_start) or now
  if now - window_start > self.LOGIN_WINDOW then
    attempts = 0
    window_start = now
  end
  attempts = attempts + 1
  local locked_until = 0
  if attempts >= self.LOGIN_MAX_ATTEMPTS then
    locked_until = now + self.LOGIN_LOCK
  end
  db.exec(self.db,
    "UPDATE auth_attempts SET attempts = ?, window_start = ?, locked_until = ?, updated_at = ? WHERE scope = ? AND subject = ?",
    { attempts, window_start, locked_until, now, scope, subject })
  return attempts, locked_until
end

-- Clears counters after a successful authentication.
function core.register_success(self, scope, subject)
  db.exec(self.db, "DELETE FROM auth_attempts WHERE scope = ? AND subject = ?", { scope, subject })
  return true
end

----------------------------------------------------------------------------
-- Validation helpers used by admin writers
----------------------------------------------------------------------------

local function quota_arg(v)
  local q, err = util.safe_integer(v, 1, util.MAX_QUOTA, "quota_bytes")
  if not q then return nil, err end
  return q, nil
end

----------------------------------------------------------------------------
-- Admin methods
----------------------------------------------------------------------------

local function account_list(self, filter)
  local settings, serr = core.settings(self)
  if not settings then return nil, serr end
  local rows, err = db.query(self.db,
    "SELECT " .. USER_COLUMNS .. " FROM users WHERE deleted_at IS NULL ORDER BY username_key")
  if not rows then return nil, err end
  local now = self:now()
  local ids = {}
  local users = {}
  for _, row in ipairs(rows) do
    local u = normalize_user(row)
    users[#users + 1] = u
    ids[#ids + 1] = u.id
  end
  local online, total = session_counts(self, ids)
  local items = {}
  for _, u in ipairs(users) do
    local period = db.query_one(self.db,
      "SELECT * FROM usage_periods WHERE user_id = ? AND state = 'open' ORDER BY period_start_at DESC LIMIT 1", { u.id })
    local p = period and {
      id = as_int(period.id),
      period_start_at = as_int(period.period_start_at),
      period_end_at = as_int(period.period_end_at),
      reset_day_applied = as_int(period.reset_day_applied),
      upload_bytes = as_int(period.upload_bytes) or 0,
      download_bytes = as_int(period.download_bytes) or 0,
      total_bytes = as_int(period.total_bytes) or 0,
      kernel_quota_used_bytes = as_int(period.kernel_quota_used_bytes) or 0,
      billed_bytes = as_int(period.billed_bytes), billing_carry = as_int(period.billing_carry) or 0,
    } or nil
    local acct = public_account(self, u, p, settings, now, { online = online[u.id] or 0 })
    acct.session_count = online[u.id] or 0
    acct.sessions_total = total[u.id] or 0
    -- Pending inheritance carries an explicit boolean while pending_reset_day stays null.
    if u.pending_kind == 0 then acct.pending_reset_day = nil; acct.pending_inherit = true end
    items[#items + 1] = acct
  end

  -- Filtering: search (username substring, case-insensitive), status, sort.
  local search = filter and filter.search
  local status = filter and filter.status
  local sort = filter and filter.sort
  local out = {}
  for _, it in ipairs(items) do
    local keep = true
    if type(search) == "string" and search ~= "" then
      keep = it.username:lower():find(search:lower(), 1, true) ~= nil
    end
    if keep and status == "online" then keep = it.online end
    if keep and status == "offline" then keep = not it.online end
    if keep and status == "exhausted" then keep = it.exhausted end
    if keep then out[#out + 1] = it end
  end
  table.sort(out, function(a, b)
    if sort == "usage" then
      if a.billed_bytes ~= b.billed_bytes then return a.billed_bytes > b.billed_bytes end
      return a.username:lower() < b.username:lower()
    elseif sort == "username" then
      return a.username:lower() < b.username:lower()
    end
    return a.id < b.id
  end)
  local limit = filter and filter.limit
  if util.is_plain_integer(limit) and limit > 0 and #out > limit then
    local trimmed = {}
    for i = 1, limit do trimmed[i] = out[i] end
    out = trimmed
  end
  return out
end

local function method_status(self)
  local settings, serr = core.settings(self)
  if not settings then return serr end
  local now = self:now()
  local accounts = db.scalar(self.db, "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
  local integrity_ok, integrity = pcall(db.integrity, self.db)
  local net = { enabled = self.opts.network ~= nil and self.config.enabled ~= false, guarded = self.guard_left == true }
  if self.opts.network and type(self.opts.network.probe) == "function" then
    local ok, probe = pcall(self.opts.network.probe, self.opts.network)
    if ok and type(probe) == "table" then
      net.probe = { ok = probe.ok == true, errors = probe.errors or {}, warnings = probe.warnings or {} }
    else
      net.probe = { ok = false, errors = { tostring(probe) }, warnings = {} }
    end
  end
  local schema_version = db.schema_version(self.db)
  local runtime = {}
  local file = io.open('/var/run/netquota-status.json','r')
  if file then runtime=require('luci.jsonc').parse(file:read('*a')) or {}; file:close() end
  local running, board
  local connected, ubus = pcall(require,'ubus')
  if connected then
    local connection=ubus.connect()
    if connection then
      local success,services=pcall(connection.call,connection,'service','list',{name='netquota'})
      if success then
        running=false
        for _,instance in pairs(services and services.netquota and services.netquota.instances or {}) do
          if instance.running then running=true end
        end
      end
      local success,result=pcall(connection.call,connection,'system','board',{})
      if success then board=result end
      connection:close()
    end
  end
  local warnings,errors={},{}
  for _,message in ipairs(net.probe and net.probe.warnings or {}) do warnings[#warnings+1]=message end
  for _,message in ipairs(net.probe and net.probe.errors or {}) do
    local target=self.config.enabled and errors or warnings; target[#target+1]=message
  end
  if running then for _,message in ipairs(runtime.errors or {}) do errors[#errors+1]=message end end
  return util.ok({
    service = core.SERVICE_NAME,
    version = core.VERSION,
    enabled = self.config.enabled == true,
    running = running,
    backend = 'nftables shared account quota / native HTTPS portal',
    controlled_interface = self.config.guest,
    egress = self.config.egress,
    db_path = self.db.path,
    firmware = board and board.release and board.release.description,
    kernel = board and board.kernel,
    architecture = board and board.system,
    opennds_version = 'not used (native portal)',
    errors = errors,
    warnings = warnings,
    quota = {ready=running == true and self.config.enabled == true and net.probe and net.probe.ok == true and runtime.state == 'ready'},
    updated_at = now,
    schema_version = schema_version,
    time = now,
    timezone = settings.timezone,
    default_reset_day = settings.default_reset_day,
    database = {
      path = self.db.path,
      writable = true,
      integrity = integrity_ok and tostring(integrity) or "unknown",
    },
    accounts = accounts or 0,
    network = net,
    clock = { available = now ~= nil },
    journal_tail = self._journal and #self._journal or 0,
  })
end

local function method_get_summary(self)
  local settings, serr = core.settings(self)
  if not settings then return serr end
  local items, lerr = account_list(self, {})
  if not items then return lerr end
  local accounts = #items
  local online = 0
  local exhausted = 0
  local upload, download, billed = 0, 0, 0
  local quota = 0
  for _, it in ipairs(items) do
    if it.online then online = online + 1 end
    if it.exhausted then exhausted = exhausted + 1 end
    upload = util.add_safe(upload, it.upload_bytes) or util.MAX_SAFE
    download = util.add_safe(download, it.download_bytes) or util.MAX_SAFE
    quota = util.add_safe(quota, it.quota_bytes) or util.MAX_SAFE
    billed = util.add_safe(billed, it.billed_bytes) or util.MAX_SAFE
  end
  local total = util.add_safe(upload, download) or util.MAX_SAFE
  local remaining = quota - billed
  if remaining < 0 then remaining = 0 end
  local tz = settings.timezone
  local now = self:now()
  local start_at, end_at
  if now then start_at, end_at = calendar.period_for(now, settings.default_reset_day, tz) end
  return util.ok({
    accounts = accounts,
    total_accounts = accounts,
    online_accounts = online,
    exhausted_accounts = exhausted,
    upload_bytes = upload,
    download_bytes = download,
    total_bytes = total,
    quota_bytes = quota,
    remaining_bytes = remaining,
    billed_bytes = billed,
    traffic_multiplier_percent = settings.traffic_multiplier_percent,
    usage_percent = util.usage_percent(billed, quota > 0 and quota or 1),
    default_reset_day = settings.default_reset_day,
    timezone = tz,
    period_start_at = start_at,
    period_end_at = end_at,
    next_reset_at = end_at,
    updated_at = now,
  })
end

local function method_list_accounts(self, args)
  local items, err = account_list(self, { search = args.search, status = args.status, sort = args.sort, limit = args.limit })
  if not items then return err end
  local settings = core.settings(self)
  local now = self:now()
  local start_at, end_at
  if now and settings then start_at, end_at = calendar.period_for(now, settings.default_reset_day, settings.timezone) end
  return util.ok({
    items = items,
    period_start_at = start_at,
    period_end_at = end_at,
    updated_at = now,
  })
end

local function method_get_account(self, args)
  local id, err = util.safe_integer(args.id, 1, util.MAX_SAFE, "id")
  if not id then return err end
  local items, lerr = account_list(self, {})
  if not items then return lerr end
  for _, it in ipairs(items) do
    if it.id == id then return util.ok(it) end
  end
  return util.error(util.CODES.NOT_FOUND, "account not found")
end

-- Staging a reset-day change. `user.reset_day == nil` means the account inherits the global
-- default; such accounts are only restaged by update_settings. An explicit account always
-- stages its own new value (or "inherit" when target is nil).
-- pending_kind: 0 = inherit the global default, 1 = explicit pending_reset_day.
-- Pending state is what makes "no pending change" (pending_kind IS NULL) distinguishable
-- from "pending inherit" (pending_kind = 0, pending_reset_day IS NULL).
local function stage_reset_day(self, user, target, period, settings)
  -- Saving a quota also submits the selected reset day. Retaining inheritance
  -- is a no-op when the current period already uses the global default. Keep
  -- real pending changes caused by a different global default for next period.
  if target == nil and user.reset_day == nil and period and
      period.reset_day_applied == settings.default_reset_day then
    if user.pending_kind ~= nil then
      local changed, err = db.exec(self.db,
        "UPDATE users SET pending_kind = NULL, pending_reset_day = NULL, reset_day_effective_at = NULL, updated_at = ? WHERE id = ?",
        { self:now(), user.id })
      if not changed then return nil, err end
    end
    return true, { pending_inherit = false, cancelled = true }
  end
  local pending_kind
  if target == nil then
    pending_kind = 0
  else
    if target == user.reset_day then
      -- No-op: cancel any pending change and keep the current day.
      if user.pending_kind ~= nil then
        local ch, cerr = db.exec(self.db,
          "UPDATE users SET pending_kind = NULL, pending_reset_day = NULL, reset_day_effective_at = NULL, updated_at = ? WHERE id = ?",
          { self:now(), user.id })
        if not ch then return nil, cerr end
      end
      return true, { pending_reset_day = nil, pending_inherit = false, pending_effective_at = nil, cancelled = true }
    end
    pending_kind = 1
    if period and period.reset_day_applied == target then
      -- The next period already uses this day: drop any stale pending state.
      local ch, cerr = db.exec(self.db,
        "UPDATE users SET pending_kind = NULL, pending_reset_day = NULL, reset_day_effective_at = NULL, updated_at = ? WHERE id = ?",
        { self:now(), user.id })
      if not ch then return nil, cerr end
      return true, { pending_reset_day = nil, pending_inherit = false, pending_effective_at = nil, cancelled = true }
    end
  end
  local eff = period and period.period_end_at or nil
  local ok, uerr = db.exec(self.db,
    "UPDATE users SET pending_kind = ?, pending_reset_day = ?, reset_day_effective_at = ?, updated_at = ? WHERE id = ?",
    { pending_kind, pending_kind == 1 and target or nil, eff, self:now(), user.id })
  if not ok then return nil, uerr end
  journal(self, "reset_day_staged", { user_id = user.id, pending_kind = pending_kind,
    pending_day = target, at = eff })
  local _ = settings
  return true, { pending_reset_day = (pending_kind == 1) and target or nil,
    pending_inherit = pending_kind == 0, pending_effective_at = eff }
end

local function create_account(self, args)
  local username, uerr = util.username(args.username)
  if not username then return uerr end
  local password, perr = util.password(args.password, "password")
  if not password then return perr end
  local quota, qerr = quota_arg(args.quota_bytes)
  if not quota then return qerr end
  local reset_day
  if args.reset_day ~= nil then
    local e
    reset_day, e = util.reset_day(args.reset_day, "reset_day")
    if e then return e end
  end

  local settings, serr = core.settings(self)
  if not settings then return serr end
  local now = self:now()
  local key = util.username_key(username)

  local hashed, herr = self.crypto.hash_password(password)
  if not hashed then return util.error(util.CODES.INTERNAL, "password hashing unavailable: " .. tostring(herr)) end

  local created = {}
  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    local existing = db.query_one(self.db, "SELECT id FROM users WHERE username_key = ?", { key })
    if existing then return nil, util.error(util.CODES.CONFLICT, "username already exists") end
    local changed, id = db.exec(self.db,
      "INSERT INTO users(username, username_key, password_hash, quota_bytes, reset_day, created_at, updated_at) " ..
      "VALUES(?,?,?,?,?,?,?)",
      { username, key, hashed.hash, quota, reset_day, now, now })
    if not changed or changed < 1 then return nil, util.error(util.CODES.INTERNAL, "cannot create account") end
    local user = normalize_user({
      id = id, username = username, password_hash = hashed.hash, quota_bytes = quota,
      reset_day = reset_day, enabled = 1, created_at = now, updated_at = now,
    })
    local period, perr2 = ensure_period(self, user, settings, now)
    if not period then return nil, perr2 end
    created.user = user
    created.period = period
    return { id = id }
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "account creation failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "account creation failed") end

  journal(self, "account_created", { user_id = created.user.id, result = "ok" })
  local items = account_list(self, {})
  for _, it in ipairs(items or {}) do
    if it.id == created.user.id then return util.ok(it) end
  end
  return util.ok({ id = created.user.id, username = username, quota_bytes = quota, reset_day = reset_day })
end

local function update_account(self, args)
  local id, iderr = util.safe_integer(args.id, 1, util.MAX_SAFE, "id")
  if not id then return iderr end
  if args.username ~= nil then
    local uname, uerr = util.username(args.username)
    if not uname then return uerr end
    local current = normalize_user(load_user_by_id(self, id))
    if not current then return util.error(util.CODES.NOT_FOUND, "account not found") end
    if uname ~= current.username then
      return util.error(util.CODES.INVALID_ARGUMENT, "username is immutable")
    end
  end
  local has_change = false
  local new_quota, new_password, new_reset_day, clear_pending
  if args.quota_bytes ~= nil then
    local e
    new_quota, e = quota_arg(args.quota_bytes)
    if not new_quota then return e end
    has_change = true
  end
  if args.password ~= nil then
    if args.password ~= "" then
      local e
      new_password, e = util.password(args.password, "password")
      if not new_password then return e end
      has_change = true
    end
    -- Empty password string means "keep the current password" (LuCI edit form).
  end
  if args.reset_day ~= nil then
    local e
    new_reset_day, e = util.reset_day(args.reset_day, "reset_day")
    if e then return e end
    has_change = true
  end
  if args.clear_pending_reset_day == true then clear_pending = true; has_change = true end
  if not has_change then return util.error(util.CODES.INVALID_ARGUMENT, "no fields to update") end

  local settings, serr = core.settings(self)
  if not settings then return serr end
  local hashed = nil
  if new_password then
    local h, herr = self.crypto.hash_password(new_password)
    if not h then return util.error(util.CODES.INTERNAL, "password hashing unavailable: " .. tostring(herr)) end
    hashed = h
  end
  local now = self:now()
  local outcome = {}

  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    local user = normalize_user(load_user_by_id(self, id))
    if not user then return nil, util.error(util.CODES.NOT_FOUND, "account not found") end
    local period, perr = ensure_period(self, user, settings, now)
    if not period then return nil, perr end
    local used = billing.used(period)

    if hashed then
      local uok, uerr = db.exec(self.db, "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        { hashed.hash, now, id })
      if not uok then return nil, uerr end
      outcome.password_changed = true
    end

    if new_quota ~= nil then
      local uok, uerr = db.exec(self.db, "UPDATE users SET quota_bytes = ?, updated_at = ? WHERE id = ?",
        { new_quota, now, id })
      if not uok then return nil, uerr end
      user.quota_bytes = new_quota
      outcome.quota_changed = true
      if new_quota <= used then
        -- Immediate revocation: quota decrease below current usage at once.
        local n = revoke_network_for_user(self, id, "quota", now)
        outcome.sessions_revoked = n
        journal(self, "quota_decrease_revoked", { user_id = id, used = used, quota = new_quota, revoked = n })
      end
    end

    if args.reset_day ~= nil or clear_pending then
      local target
      if clear_pending and args.reset_day == nil then
        target = user.reset_day
      else
        target = new_reset_day -- nil means inherit
      end
      local sok, sinfo = stage_reset_day(self, user, target, period, settings)
      if not sok then return nil, sinfo end
      outcome.pending = sinfo
    end

    -- Password change revokes every portal and network session but keeps the ledger.
    if hashed then
      local n = revoke_network_for_user(self, id, "password_change", now)
      revoke_portal_for_user(self, id, "password_change", now)
      outcome.sessions_revoked = (outcome.sessions_revoked or 0) + n
    end

    outcome.user_id = id
    return outcome
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "account update failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "account update failed") end

  local items = account_list(self, {})
  for _, it in ipairs(items or {}) do
    if it.id == id then
      journal(self, "account_updated", { user_id = id, result = "ok" })
      return util.ok(it)
    end
  end
  return util.ok({ id = id })
end

local function delete_account(self, args)
  local id, iderr = util.safe_integer(args.id, 1, util.MAX_SAFE, "id")
  if not id then return iderr end
  local now = self:now()
  local outcome = {}
  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    local user = load_user_by_id(self, id)
    if not user then return nil, util.error(util.CODES.NOT_FOUND, "account not found") end
    -- Revoke before deleting so the controller can remove kernel quota/sessions in install.
    outcome.network_revoked = revoke_network_for_user(self, id, "account_deleted", now)
    revoke_portal_for_user(self, id, "account_deleted", now)
    local ch, err = db.exec(self.db,
      "UPDATE users SET deleted_at = ?, enabled = 0, password_hash = ?, updated_at = ? WHERE id = ?",
      { now, "!deleted", now, id })
    if not ch then return nil, err end
    journal(self, "account_deleted", { user_id = id, revoked = outcome.network_revoked })
    return { deleted = true }
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "account deletion failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "account deletion failed") end
  return util.ok({ id = id, deleted = true, sessions_revoked = outcome.network_revoked or 0 })
end

local function method_get_traffic(self)
  local items, err = account_list(self, { sort = "usage" })
  if not items then return err end
  local settings = core.settings(self)
  local now = self:now()
  local rows = {}
  for _, it in ipairs(items) do
    rows[#rows + 1] = {
      id = it.id,
      username = it.username,
      upload_bytes = it.upload_bytes,
      download_bytes = it.download_bytes,
      total_bytes = it.total_bytes,
      billed_bytes = it.billed_bytes,
      traffic_multiplier_percent = it.traffic_multiplier_percent,
      quota_bytes = it.quota_bytes,
      remaining_bytes = it.remaining_bytes,
      usage_percent = it.usage_percent,
      exhausted = it.exhausted,
      online = it.online,
      session_count = it.session_count,
      effective_reset_day = it.effective_reset_day,
      pending_reset_day = it.pending_reset_day,
      pending_inherit = it.pending_inherit,
      pending_effective_at = it.pending_effective_at,
      period_start_at = it.period_start_at,
      period_end_at = it.period_end_at,
      next_reset_at = it.next_reset_at,
    }
  end
  local start_at, end_at
  if now and settings then start_at, end_at = calendar.period_for(now, settings.default_reset_day, settings.timezone) end
  return util.ok({ items = rows, period_start_at = start_at, period_end_at = end_at, updated_at = now })
end

local function method_get_settings(self)
  local settings, serr = core.settings(self)
  if not settings then return serr end
  local cfg = {}
  if type(self.config) == "table" then
    for k, v in pairs(self.config) do
      if type(v) ~= "function" then cfg[k] = v end
    end
  end
  local network = { enabled = self.opts.network ~= nil and self.config.enabled ~= false, guarded = self.guard_left == true, reason = self.guard_reason }
  if self.opts.network and type(self.opts.network.probe) == "function" then
    local ok, probe = pcall(self.opts.network.probe, self.opts.network)
    if ok and type(probe) == "table" then
      network.probe = { ok = probe.ok == true, errors = probe.errors or {}, warnings = probe.warnings or {} }
    else
      network.probe = { ok = false, warnings = {}, errors = { tostring(probe) } }
    end
  end
  local accounts = db.scalar(self.db, "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL") or 0
  return util.ok({
    default_reset_day = settings.default_reset_day,
    timezone = settings.timezone,
    traffic_multiplier_percent = settings.traffic_multiplier_percent,
    billing_changes = db.query(self.db, "SELECT changed_at, old_percent, new_percent FROM billing_changes ORDER BY id DESC LIMIT 20") or {},
    supported_timezones = calendar.supported_zones(),
    accounts = accounts,
    config = cfg,
    network = network,
    updated_at = self:now(),
  })
end

local function method_update_settings(self, args)
  local new_day, new_tz, new_rate
  if args.traffic_multiplier_percent ~= nil then
    if not billing.valid_rate(args.traffic_multiplier_percent) then
      return util.error(util.CODES.INVALID_ARGUMENT, "traffic_multiplier_percent must be an integer from 100 to 500")
    end
    new_rate = args.traffic_multiplier_percent
  end
  if args.default_reset_day ~= nil then
    local e
    new_day, e = util.reset_day(args.default_reset_day, "default_reset_day")
    if new_day == nil then return e end
  end
  if args.timezone ~= nil then
    if type(args.timezone) ~= "string" then return util.error(util.CODES.INVALID_ARGUMENT, "timezone must be a string") end
    if not calendar.is_valid_zone(args.timezone) then
      return util.error(util.CODES.INVALID_ARGUMENT,
        "unsupported timezone; supported: " .. calendar.supported_zones())
    end
    new_tz = args.timezone
  end
  if new_day == nil and new_tz == nil and new_rate == nil then
    return util.error(util.CODES.INVALID_ARGUMENT, "no fields to update")
  end
  local settings, serr = core.settings(self)
  if not settings then return serr end
  local now = self:now()
  local accounts = db.scalar(self.db, "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL") or 0

  -- Timezone changes shift every period boundary. To never reset or reopen a quota by a
  -- timezone switch they are refused while accounts exist.
  if new_tz and new_tz ~= settings.timezone and accounts > 0 then
    return util.error_detail(util.CODES.CONFLICT,
      "timezone cannot be changed while accounts exist; delete accounts or wait for an explicit migration",
      { accounts = accounts, current_timezone = settings.timezone })
  end

  local staged = {}
  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    if new_day and new_day ~= settings.default_reset_day then
      local sok, serr2 = put_setting(self, "default_reset_day", new_day, now)
      if not sok then return nil, serr2 end
      -- Inherited accounts (reset_day IS NULL) are staged to the new default at their own
      -- period end. Explicit accounts are untouched.
      local rows = db.query(self.db,
        "SELECT id FROM users WHERE deleted_at IS NULL AND reset_day IS NULL") or {}
      local updated_settings = { default_reset_day = new_day, timezone = settings.timezone }
      for _, r in ipairs(rows) do
        local uid = as_int(r.id)
        local urow = normalize_user(load_user_by_id(self, uid))
        if urow then
          local period = ensure_period(self, urow, settings, now)
          if period then
            -- Stage only if the new default changes the effective day.
            if urow.pending_kind ~= 0 or urow.reset_day_effective_at ~= period.period_end_at then
              local uok, uerr = db.exec(self.db,
                "UPDATE users SET pending_kind = 0, pending_reset_day = NULL, reset_day_effective_at = ?, updated_at = ? WHERE id = ?",
                { period.period_end_at, now, uid })
              if not uok then return nil, uerr end
              staged[#staged + 1] = { id = uid, pending_effective_at = period.period_end_at }
            end
          end
          local _ = updated_settings
        end
      end
      journal(self, "default_reset_day_changed", { value = new_day, staged = #staged })
    end
    if new_tz and new_tz ~= settings.timezone then
      local tok, terr = put_setting(self, "timezone", new_tz, now)
      if not tok then return nil, terr end
      journal(self, "timezone_changed", { value = new_tz })
    end
    if new_rate and new_rate ~= settings.traffic_multiplier_percent then
      local rok, rerr = put_setting(self, "traffic_multiplier_percent", new_rate, now)
      if not rok then return nil, rerr end
      local hok, herr = db.exec(self.db,
        "INSERT INTO billing_changes(changed_at, old_percent, new_percent) VALUES(?,?,?)",
        { now, settings.traffic_multiplier_percent, new_rate })
      if not hok then return nil, herr end
      journal(self, "traffic_multiplier_changed", { old_percent = settings.traffic_multiplier_percent, new_percent = new_rate })
    end
    return { staged = staged }
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "settings update failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "settings update failed") end
  local after, aerr = core.settings(self)
  if not after then return aerr end
  return util.ok({
    default_reset_day = after.default_reset_day,
    timezone = after.timezone,
    traffic_multiplier_percent = after.traffic_multiplier_percent,
    staged_accounts = #staged,
    updated_at = now,
  })
end

local function method_get_portal_info(self)
  local settings, serr = core.settings(self)
  if not settings then return serr end
  local now = self:now()
  local start_at, end_at
  if now then start_at, end_at = calendar.period_for(now, settings.default_reset_day, settings.timezone) end
  local cfg = {}
  if type(self.config) == "table" then
    for k, v in pairs(self.config) do
      if type(v) ~= "function" then cfg[k] = v end
    end
  end
  return util.ok({
    portal = {
      enabled = cfg.enabled == true,
      title = cfg.portal_title or "NetQuota",
      welcome = cfg.portal_welcome or "请使用您的账号登录网络",
      https_required = cfg.portal_mode == 'https',
      protocol = cfg.portal_mode or 'http',
      self_service = true,
      url = cfg.guest_address and (require('netquota.config').portal_origin(cfg)..'/') or nil,
    },
    portal_url = cfg.guest_address and (require('netquota.config').portal_origin(cfg)..'/') or nil,
    tls = {enabled=cfg.enabled == true and cfg.portal_mode == 'https'},
    default_reset_day = settings.default_reset_day,
    timezone = settings.timezone,
    period_start_at = start_at,
    period_end_at = end_at,
    next_reset_at = end_at,
    time = now,
  })
end

----------------------------------------------------------------------------
-- Portal methods
----------------------------------------------------------------------------

local GENERIC_LOGIN_ERROR = "invalid username or password"

local function portal_session_lookup(self, token, now)
  if type(token) ~= "string" or token == "" or #token > 256 then return nil, util.error(util.CODES.SESSION_INVALID, "invalid session") end
  -- Iterate sessions bound to the digest: token digests use a fixed salt, so enumerate by
  -- computing the digest first (constant work) then match exactly.
  local digest, derr = self.crypto.hash_token(token)
  if not digest then return nil, util.error(util.CODES.INTERNAL, "token hashing unavailable: " .. tostring(derr)) end
  local row, err = db.query_one(self.db, "SELECT * FROM portal_sessions WHERE token_hash = ?", { digest })
  if row == nil and err then return nil, err end
  if not row then return nil, util.error(util.CODES.SESSION_INVALID, "invalid session") end
  if row.revoked_at ~= nil then return nil, util.error(util.CODES.SESSION_INVALID, "session revoked") end
  if (as_int(row.expires_at) or 0) <= now then
    return nil, util.error(util.CODES.SESSION_INVALID, "session expired")
  end
  return {
    id = as_int(row.id),
    user_id = as_int(row.user_id),
    csrf_hash = row.csrf_hash,
    ip_address = row.ip_address,
    mac_address = row.mac_address,
    expires_at = as_int(row.expires_at),
    created_at = as_int(row.created_at),
  }
end

local function portal_login(self, args)
  local username_in, uerr = util.username(args.username)
  if not username_in then return util.error(util.CODES.AUTH_FAILED, GENERIC_LOGIN_ERROR) end
  local password = args.password
  if type(password) ~= "string" or #password < 1 or #password > util.PASSWORD_MAX or password:find("%z") then
    return util.error(util.CODES.AUTH_FAILED, GENERIC_LOGIN_ERROR)
  end
  if not uerr then
    local _ = uerr
  end
  local ip, iperr = util.ipv4(args.ip)
  if not ip then return iperr end
  local mac, macerr = util.mac(args.mac)
  if not mac then return macerr end
  local now = self:now()
  local key = util.username_key(username_in)

  local locked_ip, ip_wait = self:is_locked_out("ip", ip)
  local locked_user, user_wait = self:is_locked_out("username", key)
  if locked_ip or locked_user then
    local wait = math.max(ip_wait or 0, user_wait or 0)
    journal(self, "login_rate_limited", { ip = ip, result = "error" })
    return util.error_detail(util.CODES.RATE_LIMITED, "too many failed attempts; try again later", { retry_after = wait })
  end

  local row = load_user_by_key(self, key)
  local stored = row and row.password_hash or nil
  if row and as_int(row.enabled) ~= 1 then stored = nil end
  local ok, verr = self.crypto.verify_password_or_decoy(password, stored)
  local user = ok and normalize_user(row) or nil
  if not ok or not user then
    -- Comparable work for unknown accounts; same message and same retry counters.
    self:register_failure("ip", ip)
    self:register_failure("username", key)
    journal(self, "login_failed", { ip = ip, result = "error", reason = tostring(verr or "mismatch") })
    return util.error(util.CODES.AUTH_FAILED, GENERIC_LOGIN_ERROR)
  end
  self:register_success("ip", ip)
  self:register_success("username", key)

  local settings, serr = core.settings(self)
  if not settings then return serr end
  local token, terr = self.crypto.random_hex(32)
  if not token then return util.error(util.CODES.INTERNAL, "cannot generate session token") end
  local csrf, cerr = self.crypto.random_hex(32)
  if not csrf then return util.error(util.CODES.INTERNAL, "cannot generate csrf token") end
  local token_hash = self.crypto.hash_token(token)
  local csrf_hash = self.crypto.hash_token(csrf)
  if not token_hash or not csrf_hash then return util.error(util.CODES.INTERNAL, "token hashing unavailable") end
  local expires_at = now + self.session_ttl

  local result = {}
  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    local fresh = normalize_user(load_user_by_id(self, user.id))
    if not fresh then return nil, util.error(util.CODES.AUTH_FAILED, GENERIC_LOGIN_ERROR) end
    local period, perr = ensure_period(self, fresh, settings, now)
    if not period then return nil, perr end
    local used = billing.used(period)
    local exhausted = used >= fresh.quota_bytes
    local changed, sid = db.exec(self.db,
      "INSERT INTO portal_sessions(token_hash, csrf_hash, user_id, ip_address, mac_address, created_at, last_seen_at, expires_at) " ..
      "VALUES(?,?,?,?,?,?,?,?)",
      { token_hash, csrf_hash, fresh.id, ip, mac, now, now, expires_at })
    if not changed or changed < 1 then return nil, util.error(util.CODES.INTERNAL, "cannot create portal session") end
    local network_authorized = false
    local network_session_id = nil
    if not exhausted then
      local revoked, rerr = db.exec(self.db,
        "UPDATE network_sessions SET state = 'revoked', revoked_at = ?, revoke_reason = 'relogin' " ..
        "WHERE state = 'online' AND (ipv4_address = ? OR mac_address = ?)", { now, ip, mac })
      if revoked == nil then return nil, rerr end
      local nch, nid = db.exec(self.db,
        "INSERT INTO network_sessions(user_id, period_id, portal_session_id, ipv4_address, mac_address, created_at, last_seen_at, expires_at, state) " ..
        "VALUES(?,?,?,?,?,?,?,?,'online')",
        { fresh.id, period.id, sid, ip, mac, now, now, expires_at })
      if not nch or nch < 1 then return nil, util.error(util.CODES.INTERNAL, "cannot create network session") end
      network_authorized = true
      network_session_id = nid
    end
    local account = public_account(self, fresh, period, settings, now,
      { online = network_authorized and 1 or 0 })
    result.account = account
    result.portal_session_id = sid
    result.network_session_id = network_session_id
    result.network_authorized = network_authorized
    return true
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "login failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "login failed") end
  journal(self, "login_ok", { user_id = user.id, ip = ip, network = result.network_authorized })
  -- Tokens are returned exactly once, to the login caller, and never persisted in cleartext.
  return util.ok({
    session_token = token,
    csrf_token = csrf,
    expires_at = expires_at,
    network_authorized = result.network_authorized,
    account = result.account,
  })
end

-- Enforces that the request source matches the session's bound address (defence in depth;
-- core token lookup is authority and the HTTP handler verifies the neighbour entry).
local function bind_source(session, args)
  if session.ip_address and args.ip ~= nil then
    local ip = util.ipv4(args.ip)
    if not ip or ip ~= session.ip_address then
      return nil, util.error(util.CODES.SESSION_INVALID, "session is not valid for this address")
    end
  end
  if session.mac_address and args.mac ~= nil then
    local mac = util.mac(args.mac)
    if not mac or mac ~= session.mac_address then
      return nil, util.error(util.CODES.SESSION_INVALID, "session is not valid for this device")
    end
  end
  return true
end

local function require_csrf(self, session, csrf)
  if type(csrf) ~= "string" or csrf == "" then return nil, util.error(util.CODES.CSRF_INVALID, "csrf token required") end
  local computed = self.crypto.hash_token(csrf)
  if not computed then return nil, util.error(util.CODES.INTERNAL, "token hashing unavailable") end
  if not self.crypto.equal(computed, session.csrf_hash) then
    return nil, util.error(util.CODES.CSRF_INVALID, "csrf token invalid")
  end
  return true
end

local function portal_my_account(self, args)
  local now = self:now()
  local session, serr = portal_session_lookup(self, args.session_token, now)
  if not session then return serr end
  local bok, berr = bind_source(session, args)
  if not bok then return berr end
  local settings = core.settings(self)
  local user = normalize_user(load_user_by_id(self, session.user_id))
  if not user then return util.error(util.CODES.SESSION_INVALID, "account unavailable") end
  local period = db.query_one(self.db,
    "SELECT * FROM usage_periods WHERE user_id = ? AND state = 'open' ORDER BY period_start_at DESC LIMIT 1",
    { user.id })
  local p = period and {
    id = as_int(period.id),
    period_start_at = as_int(period.period_start_at),
    period_end_at = as_int(period.period_end_at),
    upload_bytes = as_int(period.upload_bytes) or 0,
    download_bytes = as_int(period.download_bytes) or 0,
    total_bytes = as_int(period.total_bytes) or 0,
    kernel_quota_used_bytes = as_int(period.kernel_quota_used_bytes) or 0,
    billed_bytes = as_int(period.billed_bytes), billing_carry = as_int(period.billing_carry) or 0,
  }
  local online = db.scalar(self.db,
    "SELECT COUNT(*) FROM network_sessions WHERE user_id = ? AND state = 'online'", { user.id }) or 0
  local account = public_account(self, user, p, settings, now, { online = online })
  -- Touch last_seen for diagnostics only.
  db.exec(self.db, "UPDATE portal_sessions SET last_seen_at = ? WHERE id = ?", { now, session.id })
  return util.ok({
    account = account,
    expires_at = session.expires_at,
    network_authorized = online > 0,
    csrf_required = true,
  })
end

local function portal_change_password(self, args)
  local now = self:now()
  local session, serr = portal_session_lookup(self, args.session_token, now)
  if not session then return serr end
  local bok, berr = bind_source(session, args)
  if not bok then return berr end
  local cok, cerr = require_csrf(self, session, args.csrf_token)
  if not cok then return cerr end

  local old = args.old_password
  local new = args.new_password
  local confirm = args.confirm_password
  if type(old) ~= "string" or old == "" then
    return util.error(util.CODES.INVALID_ARGUMENT, "current password required")
  end
  local nv, nerr = util.password(new, "new_password")
  if not nv then return nerr end
  if confirm ~= new then
    return util.error(util.CODES.PASSWORD_MISMATCH, "new password and confirmation do not match")
  end
  if old == new then
    return util.error(util.CODES.INVALID_ARGUMENT, "new password must differ from the current password")
  end

  local user = normalize_user(load_user_by_id(self, session.user_id))
  if not user then return util.error(util.CODES.SESSION_INVALID, "account unavailable") end
  local ok, verr = self.crypto.verify_password(old, user.password_hash)
  if not ok then
    local _ = verr
    journal(self, "self_password_rejected", { user_id = user.id, result = "error" })
    return util.error(util.CODES.AUTH_FAILED, "current password is incorrect")
  end
  local hashed, herr = self.crypto.hash_password(nv)
  if not hashed then return util.error(util.CODES.INTERNAL, "password hashing unavailable: " .. tostring(herr)) end

  local revoked_network, revoked_portal
  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    local ch, uerr = db.exec(self.db, "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
      { hashed.hash, now, user.id })
    if not ch then return nil, uerr end
    revoked_network = revoke_network_for_user(self, user.id, "password_change", now)
    local pch, perr = revoke_portal_for_user(self, user.id, "password_change", now)
    if not pch then return nil, perr end
    revoked_portal = pch
    return true
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "password change failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "password change failed") end
  journal(self, "self_password_changed", { user_id = user.id, network_revoked = revoked_network,
    portal_revoked = revoked_portal })
  return util.ok({
    changed = true,
    sessions_revoked = true,
    network_revoked = revoked_network,
    requires_relogin = true,
  })
end

local function portal_logout(self, args)
  local now = self:now()
  local session, serr = portal_session_lookup(self, args.session_token, now)
  if not session then return serr end
  local bok, berr = bind_source(session, args)
  if not bok then return berr end
  local cok, cerr = require_csrf(self, session, args.csrf_token)
  if not cok then return cerr end
  local ok_tx, res, txerr = pcall(db.transaction, self.db, function()
    db.exec(self.db,
      "UPDATE portal_sessions SET revoked_at = ?, revoke_reason = 'logout' WHERE id = ? AND revoked_at IS NULL",
      { now, session.id })
    local n = db.exec(self.db,
      "UPDATE network_sessions SET state = 'revoked', revoked_at = ?, revoke_reason = 'logout' " ..
      "WHERE portal_session_id = ? AND state = 'online'", { now, session.id })
    return { network_revoked = n or 0 }
  end)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "logout failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "logout failed") end
  journal(self, "logout", { user_id = session.user_id })
  return util.ok({ logged_out = true, network_revoked = res.network_revoked })
end

----------------------------------------------------------------------------
-- Tick: the only place read-only refusals are lifted into a guarded mutation cycle
----------------------------------------------------------------------------

function core.tick(self)
  local now = self:now()
  if not now then return util.error(util.CODES.CLOCK, "clock unavailable") end
  local settings, serr = core.settings(self)
  if not settings then return serr end

  local function work()
    -- Kernel readings were already applied by guarded(); this transaction settles pending
    -- reset-day changes and rolls periods for every account, then prunes sessions.
    local rows, err = db.query(self.db, "SELECT " .. USER_COLUMNS .. " FROM users WHERE deleted_at IS NULL")
    if not rows then return nil, err end
    local rolled, revoked = 0, 0
    for _, row in ipairs(rows) do
      local u = normalize_user(row)
      local period, perr = ensure_period(self, u, settings, now)
      if not period then return nil, perr end
      local used = billing.used(period)
      local old_sessions, old_err = db.exec(self.db,
        "UPDATE network_sessions SET state = 'revoked', revoked_at = ?, revoke_reason = 'period' " ..
        "WHERE user_id = ? AND state = 'online' AND period_id <> ?", { now, u.id, period.id })
      if old_sessions == nil then return nil, old_err end
      if used >= u.quota_bytes then
        local n = revoke_network_for_user(self, u.id, "quota", now)
        if n > 0 then
          revoked = revoked + n
        end
      end
      if period.period_start_at > (as_int(row.created_at) or 0) then rolled = rolled + 1 end
    end
    local nch, exerr = db.exec(self.db,
      "UPDATE network_sessions SET state = 'closed', revoke_reason = 'expired' WHERE state = 'online' AND expires_at <= ?",
      { now })
    if nch == nil then return nil, exerr end
    db.exec(self.db,
      "UPDATE portal_sessions SET revoked_at = ?, revoke_reason = 'expired' WHERE revoked_at IS NULL AND expires_at <= ?",
      { now, now })
    db.exec(self.db, "DELETE FROM auth_attempts WHERE updated_at < ?", { now - (self.LOGIN_WINDOW * 4) })
    return { rolled = rolled, revoked = revoked, expired_network = nch }
  end

  if self.opts.network then
    local result, gerr = guarded(self, work)
    if not result then return gerr or util.error(util.CODES.NETWORK, "tick failed") end
    return util.ok({ at = now, result = result, guarded = self.guard_left == true })
  end
  local ok_tx, res, txerr = pcall(self._transaction, self, work)
  if not ok_tx then return util.error(util.CODES.INTERNAL, "tick failed") end
  if res == nil then return txerr or util.error(util.CODES.INTERNAL, "tick failed") end
  return util.ok({ at = now, result = res, guarded = false })
end

----------------------------------------------------------------------------
-- Request dispatch
----------------------------------------------------------------------------

local function ensure_admin(self, method)
  if self.admin_enabled then return true end
  -- Non-admin roles (portal, CLI status) may only call safe read-only admin methods.
  if ADMIN_WRITES[method] then
    return nil, util.error(util.CODES.UNAVAILABLE, "method not permitted in this context")
  end
  return true
end

local DISPATCH = {
  status = method_status,
  get_summary = method_get_summary,
  list_accounts = method_list_accounts,
  get_account = method_get_account,
  create_account = create_account,
  update_account = update_account,
  delete_account = delete_account,
  get_traffic = method_get_traffic,
  get_settings = method_get_settings,
  update_settings = method_update_settings,
  get_portal_info = method_get_portal_info,
  portal_login = portal_login,
  portal_change_password = portal_change_password,
  portal_my_account = portal_my_account,
  portal_logout = portal_logout,
  tick = function(self) return core.tick(self) end,
  checkpoint = function(self, args) return core.checkpoint(self, args.readings) end,
}

-- Validates and dispatches one admin/portal request. Never throws: all errors are mapped
-- to envelopes so callers cannot leak stack traces through RPC.
function core.request(self, method, args)
  if type(method) ~= "string" then
    return util.error(util.CODES.INVALID_ARGUMENT, "method must be a string")
  end
  local handler = DISPATCH[method]
  if not handler then
    return util.error(util.CODES.NOT_FOUND, "unknown method")
  end
  if ADMIN_METHODS[method] then
    local ok, aerr = ensure_admin(self, method)
    if not ok then return aerr end
  end
  if args == nil then args = {} end
  if type(args) ~= "table" then
    return util.error(util.CODES.INVALID_ARGUMENT, "arguments must be an object")
  end
  local allowed = METHOD_ALLOWED[method]
  if allowed then
    local ok, uerr = util.reject_unknown(args, allowed, "arguments")
    if not ok then return uerr end
  end
  local ok, res = pcall(function()
    if ADMIN_WRITES[method] or method == "portal_login" or method == "portal_change_password" or method == "portal_logout" then
      local answer, err = guarded(self, function() return handler(self, args) end)
      return answer or err
    end
    return handler(self, args)
  end)
  if not ok then
    journal(self, "request_error", { method = method, result = "error", error = tostring(res) })
    return util.error(util.CODES.INTERNAL, "internal error")
  end
  if type(res) ~= "table" or res.ok == nil then
    return util.error(util.CODES.INTERNAL, "internal error")
  end
  return res
end

-- List of methods available for the current role (used by rpcd list and CLI help).
function core.list_methods(self)
  local out = {}
  for method in pairs(ADMIN_METHODS) do
    if self.admin_enabled or not ADMIN_WRITES[method] then out[#out + 1] = method end
  end
  for method in pairs(PORTAL_METHODS) do out[#out + 1] = method end
  for method in pairs(INTERNAL_METHODS) do out[#out + 1] = method end
  table.sort(out)
  return out
end

core.ADMIN_METHODS = ADMIN_METHODS
core.ADMIN_WRITES = ADMIN_WRITES
core.PORTAL_METHODS = PORTAL_METHODS
core.INTERNAL_METHODS = INTERNAL_METHODS
core._dispatch_table = DISPATCH
core.journal_entry = journal

function core.portal_login(self, username, password, ip, mac)
  return self:request("portal_login", { username = username, password = password, ip = ip, mac = mac })
end

function core.get_my_account(self, token, ip, mac)
  return self:request("portal_my_account", { session_token = token, ip = ip, mac = mac })
end

function core.change_my_password(self, token, csrf, old_password, new_password, confirm_password, ip, mac)
  return self:request("portal_change_password", { session_token = token, csrf_token = csrf,
    old_password = old_password, new_password = new_password, confirm_password = confirm_password, ip = ip, mac = mac })
end

function core.logout(self, token, csrf, ip, mac)
  return self:request("portal_logout", { session_token = token, csrf_token = csrf, ip = ip, mac = mac })
end

return core

-- NetQuota SQLite persistence layer.
--
-- Responsibilities:
--   * open (never overwrite) or create the database with safe permissions
--   * apply PRAGMAs: foreign_keys, busy_timeout, WAL + synchronous=FULL
--   * schema migrations tracked with PRAGMA user_version (current version 2)
--   * strict prepared-statement binding helpers; every value is bound, never interpolated
--   * a coarse atomic transaction helper (BEGIN IMMEDIATE ... COMMIT/ROLLBACK)
--
-- No domain policy lives here: core.lua owns validation and business rules.

local util = require("netquota.util")

local db = {}

db.SCHEMA_VERSION = 2
db.DIR_MODE = "0700"
db.FILE_MODE = "0600"
db.BUSY_TIMEOUT_MS = 5000

local lsqlite3
local function sqlite()
  if lsqlite3 then return lsqlite3 end
  local ok, mod = pcall(require, "lsqlite3")
  if not ok or type(mod) ~= "table" then
    return nil, "lsqlite3 unavailable: " .. tostring(mod)
  end
  lsqlite3 = mod
  return lsqlite3
end

-- Optional handles to native helpers; the module degrades gracefully without them.
local function native()
  local ok, nixio = pcall(require, "nixio")
  if not ok then return nil end
  local ok2, fs = pcall(require, "nixio.fs")
  return { nixio = nixio, fs = ok2 and fs or nil }
end

----------------------------------------------------------------------------
-- Schema
----------------------------------------------------------------------------

db.SCHEMA_V1 = [[
CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  username             TEXT    NOT NULL,
  username_key         TEXT    NOT NULL UNIQUE,
  password_hash        TEXT    NOT NULL,
  quota_bytes          INTEGER NOT NULL CHECK (quota_bytes > 0),
  reset_day            INTEGER NULL CHECK (reset_day IS NULL OR (reset_day BETWEEN 1 AND 31)),
  pending_kind         INTEGER NULL CHECK (pending_kind IS NULL OR pending_kind IN (0,1)),
  pending_reset_day    INTEGER NULL CHECK (pending_reset_day IS NULL OR (pending_reset_day BETWEEN 1 AND 31)),
  reset_day_effective_at INTEGER NULL,
  enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL,
  deleted_at           INTEGER NULL
);

CREATE TABLE IF NOT EXISTS usage_periods (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id                INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  period_start_at        INTEGER NOT NULL,
  period_end_at          INTEGER NOT NULL,
  reset_day_applied      INTEGER NOT NULL CHECK (reset_day_applied BETWEEN 1 AND 31),
  upload_bytes           INTEGER NOT NULL DEFAULT 0 CHECK (upload_bytes >= 0),
  download_bytes         INTEGER NOT NULL DEFAULT 0 CHECK (download_bytes >= 0),
  total_bytes            INTEGER NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
  kernel_quota_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (kernel_quota_used_bytes >= 0),
  state                  TEXT    NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed')),
  created_at             INTEGER NOT NULL,
  updated_at             INTEGER NOT NULL,
  closed_at              INTEGER NULL,
  CHECK (period_end_at > period_start_at),
  CHECK (total_bytes = upload_bytes + download_bytes)
);

CREATE UNIQUE INDEX IF NOT EXISTS usage_periods_user_start_uq ON usage_periods(user_id, period_start_at);
CREATE INDEX IF NOT EXISTS usage_periods_user_state_ix ON usage_periods(user_id, state);

CREATE TABLE IF NOT EXISTS portal_sessions (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash      TEXT    NOT NULL UNIQUE,
  csrf_hash       TEXT    NOT NULL,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip_address      TEXT    NOT NULL,
  mac_address     TEXT    NOT NULL,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  revoked_at      INTEGER NULL,
  revoke_reason   TEXT    NULL
);
CREATE INDEX IF NOT EXISTS portal_sessions_user_ix ON portal_sessions(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS network_sessions (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  period_id       INTEGER NOT NULL REFERENCES usage_periods(id) ON DELETE CASCADE,
  portal_session_id INTEGER NULL REFERENCES portal_sessions(id) ON DELETE SET NULL,
  ipv4_address    TEXT    NOT NULL,
  mac_address     TEXT    NOT NULL,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  state           TEXT    NOT NULL DEFAULT 'online' CHECK (state IN ('online','closed','revoked')),
  revoked_at      INTEGER NULL,
  revoke_reason   TEXT    NULL
);
CREATE INDEX IF NOT EXISTS network_sessions_user_state_ix ON network_sessions(user_id, state);
CREATE INDEX IF NOT EXISTS network_sessions_period_ix ON network_sessions(period_id);

CREATE TABLE IF NOT EXISTS settings (
  key             TEXT PRIMARY KEY,
  value           TEXT NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_attempts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  scope           TEXT    NOT NULL CHECK (scope IN ('username','ip')),
  subject         TEXT    NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  window_start    INTEGER NOT NULL,
  locked_until    INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_attempts_scope_subject_uq ON auth_attempts(scope, subject);

CREATE TABLE IF NOT EXISTS system_state (
  key             TEXT PRIMARY KEY,
  value           TEXT NOT NULL,
  updated_at      INTEGER NOT NULL
);
]]

----------------------------------------------------------------------------
-- Errors
----------------------------------------------------------------------------

local function db_error(message, extra)
  local e = util.error(util.CODES.INTERNAL, message or "database error")
  e.error.kind = "database"
  if extra then for k, v in pairs(extra) do e.error[k] = v end end
  return e
end
db.error = db_error

----------------------------------------------------------------------------
-- Filesystem preparation
----------------------------------------------------------------------------

local function ensure_parent_dir(path)
  local dir = path:match("^(.*)/[^/]+$")
  if not dir or dir == "" then return true end
  local nat = native()
  if nat and nat.fs then
    if nat.fs.stat(dir) then return true end
    local ok = nat.fs.mkdirr and nat.fs.mkdirr(dir)
    if not ok then return nil, "cannot create directory " .. dir end
    if nat.fs.chmod then nat.fs.chmod(dir, db.DIR_MODE) end
    return true
  end
  local ok, err = os.execute("mkdir -p '" .. dir:gsub("'", "'\\''") .. "'")
  local _ = err
  if ok ~= 0 and ok ~= true then return nil, "cannot create directory " .. dir end
  return true
end

local function chmod_file(path, mode)
  local nat = native()
  if nat and nat.fs and nat.fs.chmod then
    nat.fs.chmod(path, mode)
    return true
  end
  os.execute("chmod " .. mode .. " '" .. path:gsub("'", "'\\''") .. "'")
  return true
end

----------------------------------------------------------------------------
-- Migration
----------------------------------------------------------------------------

local function user_version(handle)
  handle = type(handle) == "table" and handle.handle or handle
  local stmt, err = handle:prepare("PRAGMA user_version")
  if not stmt then return nil, err end
  local value
  local ok, rerr = pcall(function()
    if stmt:step() ~= nil then value = stmt:get_value(0) end
  end)
  stmt:finalize()
  if not ok then return nil, rerr end
  return tonumber(value) or 0
end

local function set_user_version(handle, version)
  -- PRAGMA does not accept bound parameters; version is a module constant integer.
  if not util.is_plain_integer(version) then return nil, "invalid version" end
  local stmt = handle:prepare("PRAGMA user_version = " .. util.json_int(version))
  if not stmt then return nil, handle:errmsg() end
  stmt:step()
  stmt:finalize()
  return true
end

local function apply_schema(handle)
  -- handle:exec() executes DDL text that contains no user data; every runtime query in this
  -- project is a prepared statement with all values bound.
  local ok, err = handle:exec(db.SCHEMA_V1)
  if ok ~= sqlite().OK then return nil, "schema creation failed: " .. tostring(err or handle:errmsg()) end
  return true
end

local function migrate(handle)
  -- Serialize first-open migrations across daemon, rpcd and portal processes.
  if handle:exec('BEGIN IMMEDIATE') ~= sqlite().OK then
    return nil, db_error('cannot lock schema migration')
  end
  local function finish(ok, info)
    if not ok then handle:exec('ROLLBACK'); return nil, info end
    if handle:exec('COMMIT') ~= sqlite().OK then
      handle:exec('ROLLBACK'); return nil, db_error('cannot commit schema migration')
    end
    return true, info
  end
  local version, err = user_version(handle)
  if not version then return finish(nil, db_error("cannot read user_version: " .. tostring(err))) end
  local original = version
  if version == 0 then
    if not apply_schema(handle) then return finish(nil, db_error("schema creation failed")) end
    version = 1
  end
  if version == 1 then
    local sql = [[
ALTER TABLE usage_periods ADD COLUMN billed_bytes INTEGER NOT NULL DEFAULT 0 CHECK (billed_bytes >= 0);
ALTER TABLE usage_periods ADD COLUMN billing_carry INTEGER NOT NULL DEFAULT 0 CHECK (billing_carry BETWEEN 0 AND 99);
UPDATE usage_periods SET billed_bytes = MAX(total_bytes, kernel_quota_used_bytes);
CREATE TABLE billing_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  changed_at INTEGER NOT NULL,
  old_percent INTEGER NOT NULL CHECK (old_percent BETWEEN 100 AND 500),
  new_percent INTEGER NOT NULL CHECK (new_percent BETWEEN 100 AND 500)
);
]]
    if handle:exec(sql) ~= sqlite().OK then
      return finish(nil, db_error('billing schema migration failed: '..handle:errmsg()))
    end
    if not set_user_version(handle, 2) then return finish(nil, db_error('cannot set schema version')) end
    version = 2
  end
  if version == db.SCHEMA_VERSION then
    return finish(true, { from = original, to = version, created = original == 0 })
  end
  if version > db.SCHEMA_VERSION then
    return finish(nil, db_error(string.format("database schema version %d is newer than supported %d", version, db.SCHEMA_VERSION)))
  end
  -- Future migrations (v1 -> vN) are applied here as ordered steps. v1 is the first
  -- released schema, so any lower version is unknown and must not be modified.
  return finish(nil, db_error(string.format("no migration path from schema version %d", version)))
end

----------------------------------------------------------------------------
-- Open
----------------------------------------------------------------------------

-- Opens or creates the database. Returns handle or nil, err.
-- `opts.create` (default true) allows creating a new file; an existing database is never
-- overwritten or recreated.
function db.open(path, opts)
  opts = opts or {}
  path = path or util.DEFAULT_DB_PATH
  if type(path) ~= "string" or path == "" then return nil, db_error("db_path required") end
  local L, lerr = sqlite()
  if not L then return nil, db_error(lerr) end

  local nat = native()
  local existed = false
  if nat and nat.fs then
    existed = nat.fs.access(path) and true or false
  else
    local fh = io.open(path, "rb")
    if fh then existed = true; fh:close() end
  end

  if not existed then
    if opts.create == false then return nil, db_error("database does not exist") end
    local ok, derr = ensure_parent_dir(path)
    if not ok then return nil, db_error(derr) end
  end

  local flags = L.OPEN_READWRITE
  if not existed then
    if L.OPEN_CREATE then flags = flags + L.OPEN_CREATE end
  end
  local handle, oerr, omsg = L.open(path, flags)
  if not handle then return nil, db_error("cannot open database: " .. tostring(oerr or omsg)) end

  -- Permissions: the database is only for root/service identities.
  if not existed then chmod_file(path, db.FILE_MODE) end

  local function pragma(stmt_text)
    local ok, err = handle:exec(stmt_text)
    if ok ~= L.OK then return nil, tostring(err or handle:errmsg()) end
    return true
  end

  local ok, perr = pragma("PRAGMA foreign_keys = ON")
  if not ok then handle:close(); return nil, db_error("cannot enable foreign keys: " .. tostring(perr)) end
  if handle.busy_timeout then
    local bok = pcall(handle.busy_timeout, handle, db.BUSY_TIMEOUT_MS)
    if not bok then pcall(handle.exec, handle, "PRAGMA busy_timeout = " .. db.BUSY_TIMEOUT_MS) end
  else
    pragma("PRAGMA busy_timeout = " .. db.BUSY_TIMEOUT_MS)
  end
  -- WAL improves durability under concurrent readers; synchronous=FULL keeps the commit
  -- boundary durable even when the checkpoint lags.
  local wok = pragma("PRAGMA journal_mode = WAL")
  if not wok then
    handle:close()
    return nil, db_error("cannot enable WAL journal mode")
  end
  pragma("PRAGMA synchronous = FULL")

  local mok, minfo = migrate(handle)
  if not mok then handle:close(); return nil, minfo end

  if not existed then
    chmod_file(path, db.FILE_MODE)
  end
  -- WAL/SHM side files inherit the directory umask; keep them owner-only as well.
  for _, suffix in ipairs({ "-wal", "-shm" }) do
    local p = path .. suffix
    local fexists = nat and nat.fs and nat.fs.access(p) or false
    if fexists then chmod_file(p, db.FILE_MODE) end
  end

  local wrapper = {
    handle = handle,
    path = path,
    migration = minfo,
    created = not existed,
  }
  return wrapper
end

function db.close(wrapper)
  if not wrapper or not wrapper.handle then return true end
  local ok, err = pcall(wrapper.handle.close, wrapper.handle)
  wrapper.handle = nil
  if not ok then return nil, db_error("close failed: " .. tostring(err)) end
  return true
end

----------------------------------------------------------------------------
-- Prepared statement helpers (strict binding)
----------------------------------------------------------------------------

-- Prepares and executes a write statement with positional parameters.
-- Supports integers, strings, real numbers, booleans (stored 0/1) and nil (SQL NULL).
-- Returns rows_changed, last_id on success.

local function has_bind_parameter(stmt)
  local ok, v = pcall(function() return stmt.bind_parameter end)
  return ok and type(v) == "function"
end

db.has_bind_parameter = has_bind_parameter

local PARAM_NULL = nil
db.PARAM_NULL = PARAM_NULL

local function prepare(handle, sql)
  handle = type(handle) == "table" and handle.handle or handle
  local stmt, err = handle:prepare(sql)
  if not stmt then
    return nil, db_error("prepare failed: " .. tostring(err or handle:errmsg()))
  end
  return stmt
end
db.prepare = prepare

-- Binds positional values to a prepared statement. NULL is representable only when
-- stmt:bind_parameter exists; the bind_values fallback supports nil solely as a trailing
-- argument, which is why opt-in parameters are appended last in every query.
local function bind_all(stmt, values)
  local L = sqlite()
  local count = stmt:bind_parameter_count()
  for i = 1, count do
    local v = values[i]
    if type(v) == "boolean" then v = v and 1 or 0 end
    local ok, rc = pcall(stmt.bind, stmt, i, v)
    if not ok or rc ~= L.OK then return nil, "bind failed for parameter " .. i end
  end
  return true
end

-- Executes a statement that changes rows. `params` is an array of positional values.
function db.exec(handle, sql, params)
  handle = type(handle) == "table" and handle.handle or handle
  local stmt, perr = prepare(handle, sql)
  if not stmt then return nil, perr end
  local bok, berr = bind_all(stmt, params or {})
  if not bok then
    stmt:finalize()
    return nil, db_error(berr)
  end
  local step_ok, step_err = pcall(stmt.step, stmt)
  local fin_ok, fin_err = pcall(stmt.finalize, stmt)
  if not step_ok then return nil, db_error("statement failed: " .. tostring(step_err)) end
  if step_err ~= sqlite().DONE then return nil, db_error("statement failed: " .. tostring(handle:errmsg())) end
  if not fin_ok then return nil, db_error("statement failed: " .. tostring(fin_err)) end
  local changed = handle:changes()
  local last_id = handle:last_insert_rowid()
  return changed, last_id
end

----------------------------------------------------------------------------
-- Query helpers
----------------------------------------------------------------------------

-- Runs a SELECT and returns an array of row tables keyed by column name.
function db.query(handle, sql, params)
  handle = type(handle) == "table" and handle.handle or handle
  local L = sqlite()
  local stmt, perr = prepare(handle, sql)
  if not stmt then return nil, perr end
  local bok, berr = bind_all(stmt, params or {})
  if not bok then
    stmt:finalize()
    return nil, db_error(berr)
  end
  local rows = {}
  while true do
    local rc = stmt:step()
    if rc == L.ROW then
      local row = {}
      local n = stmt:columns()
      for i = 0, n - 1 do
        row[stmt:get_name(i)] = stmt:get_value(i)
      end
      rows[#rows + 1] = row
    elseif rc == L.DONE then
      break
    else
      local msg = handle:errmsg()
      stmt:finalize()
      return nil, db_error("query failed: " .. tostring(msg))
    end
  end
  stmt:finalize()
  return rows
end

-- Runs a SELECT returning the first row or nil.
function db.query_one(handle, sql, params)
  local rows, err = db.query(handle, sql, params)
  if not rows then return nil, err end
  return rows[1]
end

-- Executes a scalar aggregate SELECT.
function db.scalar(handle, sql, params)
  local rows, err = db.query(handle, sql, params)
  if not rows then return nil, err end
  if not rows[1] then return nil end
  for _, v in pairs(rows[1]) do return v end
  return nil
end

----------------------------------------------------------------------------
-- Transaction helper (atomic; BEGIN IMMEDIATE avoids upgrade deadlocks)
----------------------------------------------------------------------------

-- fn() must return true/value on success or nil, err on failure. Any error rolls back.
local transaction_depth = setmetatable({}, { __mode = "k" })
function db.transaction(handle, fn)
  handle = type(handle) == "table" and handle.handle or handle
  local depth = transaction_depth[handle] or 0
  local point = "netquota_sp_" .. tostring(depth)
  local function exec_raw(sql)
    local ok, err = handle:exec(sql)
    if ok ~= sqlite().OK then return nil, tostring(err or handle:errmsg()) end
    return true
  end
  local begun, berr = exec_raw(depth == 0 and "BEGIN IMMEDIATE" or ("SAVEPOINT " .. point))
  if not begun then return nil, db_error("cannot begin transaction: " .. tostring(berr)) end
  transaction_depth[handle] = depth + 1
  local function rollback()
    if depth == 0 then
      exec_raw("ROLLBACK")
    else
      exec_raw("ROLLBACK TO SAVEPOINT " .. point)
      exec_raw("RELEASE SAVEPOINT " .. point)
    end
    transaction_depth[handle] = depth
  end
  local ok, result, err = pcall(fn)
  if not ok then
    pcall(rollback)
    return nil, db_error("transaction aborted: " .. tostring(result))
  end
  if result == nil or result == false then
    pcall(rollback)
    return nil, err or db_error("transaction failed")
  end
  local committed, cerr = exec_raw(depth == 0 and "COMMIT" or ("RELEASE SAVEPOINT " .. point))
  if not committed then
    pcall(rollback)
    return nil, db_error("commit failed: " .. tostring(cerr))
  end
  transaction_depth[handle] = depth
  return result
end

-- Table existence check used by diagnostics.
function db.table_names(handle)
  local rows, err = db.query(handle, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
  if not rows then return nil, err end
  local names = {}
  for _, r in ipairs(rows) do names[#names + 1] = r.name end
  return names
end

function db.schema_version(handle)
  return user_version(handle)
end

function db.integrity(handle)
  local v, err = db.scalar(handle, "PRAGMA integrity_check")
  if not v then return nil, err end
  return v
end

return db

-- NetQuota calendar / billing period arithmetic.
--
-- Periods are anchored to a calendar day (1..31) in a configured time zone and are stored
-- as UTC epoch seconds with half-open intervals [period_start_at, period_end_at).
--
-- Short months clamp to their last day while preserving the original anchor, so a reset
-- day of 31 behaves 1/31 -> 2/28 (2/29 in leap years) -> 3/31 with no drift.
--
-- Time zone handling never mutates the process TZ. Local civil-time conversion is
-- implemented from first principles for the supported zones, with a documented UTC-offset
-- fallback for tzdata "Etc/GMT-8" style names. Callers can register additional zones with
-- explicit POSIX offset rules via calendar.register_posix_zone().

local util = require("netquota.util")

local calendar = {}

calendar.MIN_YEAR = 1970
calendar.MAX_YEAR = 3000
calendar.MIN_EPOCH = 0

----------------------------------------------------------------------------
-- Proleptic Gregorian civil <-> epoch (UTC) conversion (Howard Hinnant's algorithm)
----------------------------------------------------------------------------

local function days_from_civil(y, m, d)
  y = m <= 2 and y - 1 or y
  local era = math.floor((y >= 0 and y or y - 399) / 400)
  local yoe = y - era * 400
  local mp = (m + 9) % 12
  local doy = math.floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

local function civil_from_days(z)
  z = z + 719468
  local era = math.floor((z >= 0 and z or z - 146096) / 146097)
  local doe = z - era * 146097
  local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
  local y = yoe + era * 400
  local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
  local mp = math.floor((5 * doy + 2) / 153)
  local d = doy - math.floor((153 * mp + 2) / 5) + 1
  local m = mp < 10 and mp + 3 or mp - 9
  if m <= 2 then y = y + 1 end
  return y, m, d
end

calendar.days_from_civil = days_from_civil
calendar.civil_from_days = civil_from_days

-- Epoch seconds for a UTC civil time.
function calendar.to_epoch(y, m, d, hh, mm, ss)
  return days_from_civil(y, m, d) * 86400 + (hh or 0) * 3600 + (mm or 0) * 60 + (ss or 0)
end

-- UTC civil time for epoch seconds.
function calendar.from_epoch(epoch)
  local days = math.floor(epoch / 86400)
  local secs = epoch - days * 86400
  local y, m, d = civil_from_days(days)
  local hh = math.floor(secs / 3600)
  local mm = math.floor((secs % 3600) / 60)
  local ss = secs % 60
  return y, m, d, hh, mm, ss
end

function calendar.is_leap(y)
  return (y % 4 == 0 and y % 100 ~= 0) or (y % 400 == 0)
end

function calendar.days_in_month(y, m)
  local dim = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
  if m == 2 and calendar.is_leap(y) then return 29 end
  return dim[m]
end

----------------------------------------------------------------------------
-- Time zone support
----------------------------------------------------------------------------
-- A zone is described by:
--   name        canonical name
--   offset      fixed UTC offset in seconds (used for Asia/Shanghai, UTC)
--   fixed       true when no DST exists, so offset is time-invariant
--   posix       optional { std_offset, dst_offset, rules } for zones with DST (not used by
--               the shipped zones; register_posix_zone() can add one).
--
-- The shipped set is deliberately small and verifiable:
--   UTC, Etc/UTC, GMT            -> offset 0
--   Asia/Shanghai, Asia/Chongqing, Asia/Harbin, PRC, Asia/Taipei (fixed +08:00, no DST
--                                 since 1991 and therefore a valid fixed rule for our
--                                 supported year range), CST-8 POSIX string.
-- DST-having zones are rejected unless a caller supplies a complete rule set, so we never
-- silently miscompute a period boundary.

local ZONES = {}

local function add_zone(names, offset, extra)
  local def = {
    name = names[1],
    offset = offset,
    fixed = true,
  }
  if extra then for k, v in pairs(extra) do def[k] = v end end
  for _, n in ipairs(names) do ZONES[n] = def end
  return def
end

add_zone({ "UTC", "Etc/UTC", "Etc/GMT0", "GMT", "Etc/GMT" }, 0)
add_zone({ "Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Chungking", "PRC", "CST-8" }, 8 * 3600)
add_zone({ "Asia/Taipei", "ROC" }, 8 * 3600)
add_zone({ "Asia/Hong_Kong", "Hongkong" }, 8 * 3600)
add_zone({ "Asia/Macau", "Asia/Macao" }, 8 * 3600)
add_zone({ "Asia/Singapore", "Singapore" }, 8 * 3600)
add_zone({ "Asia/Tokyo", "Japan" }, 9 * 3600)
add_zone({ "Asia/Seoul", "ROK" }, 9 * 3600)
-- Etc/GMT+/-N POSIX inversions: Etc/GMT-8 == UTC+8 (sign is inverted per POSIX).
for n = 0, 12 do
  add_zone({ "Etc/GMT+" .. n }, -n * 3600)
  if n > 0 then add_zone({ "Etc/GMT-" .. n }, n * 3600) end
end

-- Registers a fixed-offset zone alias supplied by configuration. The offset must be a whole
-- number of minutes multiples within +/-14:00 so a typo cannot shift periods wildly.
function calendar.register_fixed_zone(name, offset_seconds)
  if type(name) ~= "string" or name == "" then return nil, "zone name required" end
  if not util.is_plain_integer(offset_seconds) then return nil, "offset must be an integer number of seconds" end
  if offset_seconds < -14 * 3600 or offset_seconds > 14 * 3600 then return nil, "offset out of range" end
  if offset_seconds % 60 ~= 0 then return nil, "offset must be a whole number of minutes" end
  return add_zone({ name }, offset_seconds, { registered = true })
end

function calendar.zone(name)
  if type(name) ~= "string" or name == "" then return nil, "timezone must be a non-empty string" end
  if #name > 64 then return nil, "timezone name too long" end
  if not name:match("^[A-Za-z0-9_%./%+%-]+$") then return nil, "timezone name contains invalid characters" end
  local def = ZONES[name]
  if not def then
    -- Reject aliases that look like tzdata but are not in the verified fixed-offset table;
    -- a wrong silent offset would corrupt billing periods.
    if name:find("/", 1, true) or name:match("^[A-Z]+[+-]?%d+$") then
      return nil, "timezone '" .. name .. "' is not supported by the domain layer; supported zones: " .. calendar.supported_zones()
    end
    return nil, "unsupported timezone '" .. name .. "'"
  end
  return def
end

function calendar.supported_zones()
  local names = {}
  for n, def in pairs(ZONES) do
    names[#names + 1] = n
    local _ = def
  end
  table.sort(names)
  return table.concat(names, ",")
end

function calendar.is_valid_zone(name)
  return calendar.zone(name) ~= nil
end

-- UTC offset (seconds) applying at the given epoch for the zone name.
function calendar.offset_at(name, epoch)
  local def, err = calendar.zone(name)
  if not def then return nil, err end
  return def.offset
end

-- Converts a local civil time (in the zone) to epoch seconds.
function calendar.local_to_epoch(name, y, m, d, hh, mm, ss)
  local def, err = calendar.zone(name)
  if not def then return nil, err end
  return days_from_civil(y, m, d) * 86400 + (hh or 0) * 3600 + (mm or 0) * 60 + (ss or 0) - def.offset
end

-- Converts epoch seconds to a local civil time table in the zone.
function calendar.epoch_to_local(name, epoch)
  local def, err = calendar.zone(name)
  if not def then return nil, err end
  local days = math.floor((epoch + def.offset) / 86400)
  local secs = (epoch + def.offset) - days * 86400
  local y, m, d = civil_from_days(days)
  return {
    year = y, month = m, day = d,
    hour = math.floor(secs / 3600),
    minute = math.floor((secs % 3600) / 60),
    second = secs % 60,
    weekday = (days + 4) % 7,   -- 0 = Sunday
    offset = def.offset,
  }
end

----------------------------------------------------------------------------
-- Anchored day series
----------------------------------------------------------------------------

-- Clamps the anchor to the last day of the given civil month.
function calendar.clamp_day(year, month, day)
  local dim = calendar.days_in_month(year, month)
  if day > dim then return dim end
  if day < 1 then return 1 end
  return day
end

-- The anchor occurrence in (year, month) as epoch seconds at local midnight.
function calendar.anchor_epoch(name, year, month, day)
  local d = calendar.clamp_day(year, month, day)
  return calendar.local_to_epoch(name, year, month, d, 0, 0, 0)
end

-- Returns the epoch of the first anchor strictly greater than `after_epoch`, given that the
-- supplied (year, month) is the month containing `after_epoch` in local time.
function calendar.next_anchor_strictly_after(name, after_epoch, day)
  local loc, err = calendar.epoch_to_local(name, after_epoch)
  if not loc then return nil, err end
  local y, m = loc.year, loc.month
  for _ = 1, 4 do
    local cand = calendar.anchor_epoch(name, y, m, day)
    if cand > after_epoch then return cand end
    m = m + 1
    if m > 12 then m = 1; y = y + 1 end
  end
  return nil, "unable to find next anchor"
end

-- Period containing `now` for reset day `day` in zone `tz`.
-- Returns start_at, end_at (end exclusive), start_year, start_month.
function calendar.period_for(now, day, tz)
  if not util.is_plain_integer(now) then return nil, nil, "now must be an integer epoch" end
  if not util.is_plain_integer(day) or day < 1 or day > 31 then return nil, nil, "reset day must be an integer 1..31" end
  tz = tz or util.DEFAULT_TIMEZONE
  local loc, err = calendar.epoch_to_local(tz, now)
  if not loc then return nil, nil, err end
  local y, m = loc.year, loc.month
  local this_start = calendar.anchor_epoch(tz, y, m, day)
  local start_at, sy, sm
  if now >= this_start then
    start_at, sy, sm = this_start, y, m
  else
    local py, pm = y, m - 1
    if pm < 1 then pm = 12; py = py - 1 end
    start_at = calendar.anchor_epoch(tz, py, pm, day)
    sy, sm = py, pm
  end
  -- End boundary is the next anchor strictly after the start (never equal, never skipped),
  -- which keeps [start,end) gap-free and overlap-free even mid-month staged changes.
  local end_at, nerr = calendar.next_anchor_strictly_after(tz, start_at, day)
  if not end_at then return nil, nil, nerr end
  return start_at, end_at, sy, sm
end

-- Period that follows `start_at` when the reset day changes to `new_day` at the old period
-- end. Returns new_start (== old_end), new_end, plus civil info. Because the new period
-- begins exactly at the old end, no gaps or overlaps are created; the new end is the first
-- anchor of new_day strictly after old_end.
function calendar.reanchor(start_at, old_end, new_day, tz)
  if not util.is_plain_integer(start_at) or not util.is_plain_integer(old_end) then
    return nil, "start/end must be integers"
  end
  if old_end <= start_at then return nil, "end must be after start" end
  if not util.is_plain_integer(new_day) or new_day < 1 or new_day > 31 then
    return nil, "reset day must be an integer 1..31"
  end
  tz = tz or util.DEFAULT_TIMEZONE
  local new_end, err = calendar.next_anchor_strictly_after(tz, old_end, new_day)
  if not new_end then return nil, err end
  local loc = calendar.epoch_to_local(tz, old_end)
  return new_end, nil, loc
end

-- Formats an epoch as an ISO-8601 local timestamp in the given zone (diagnostics/UI).
function calendar.iso_local(tz, epoch)
  local loc, err = calendar.epoch_to_local(tz, epoch)
  if not loc then return nil, err end
  return string.format("%04d-%02d-%02dT%02d:%02d:%02d", loc.year, loc.month, loc.day, loc.hour, loc.minute, loc.second)
end

-- Formats an epoch for HTTP date style (not used for auth decisions).
function calendar.iso_utc(epoch)
  return calendar.iso_local("UTC", epoch)
end

return calendar

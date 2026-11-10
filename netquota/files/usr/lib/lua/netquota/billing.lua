-- Integer hundredths: never multiply a large byte counter by the rate directly.
local M = {}
local MAX = 9007199254740991

function M.valid_rate(rate)
  return type(rate) == 'number' and rate == math.floor(rate) and rate >= 100 and rate <= 500
end

function M.raw_used(period)
  return math.max(tonumber(period.total_bytes) or
    ((tonumber(period.upload_bytes) or 0) + (tonumber(period.download_bytes) or 0)),
    tonumber(period.kernel_quota_used_bytes) or 0)
end

function M.used(period)
  if not period then return 0 end
  return tonumber(period.billed_bytes) or M.raw_used(period)
end

function M.accrue(bytes, carry, rate)
  assert(M.valid_rate(rate), 'invalid billing rate')
  local whole = (bytes - bytes % 100) / 100
  local tail = (bytes % 100) * rate + carry
  local extra = math.floor(tail / 100)
  local available = MAX - extra
  if whole > (available - available % rate) / rate then return MAX, 0 end
  return whole * rate + extra, tail % 100
end

-- Absolute real-byte quota, seeded with the persistent real high-water mark.
-- ceil((remaining * 100 - carry) / rate), decomposed to stay exactly representable.
function M.real_limit(period, quota, rate)
  local raw, remaining = M.raw_used(period), quota - M.used(period)
  if remaining <= 0 then return math.max(1, raw) end
  local carry = tonumber(period.billing_carry) or 0
  local tail = remaining % rate
  local whole = (remaining - tail) / rate
  local budget = whole * 100 + math.ceil((tail * 100 - carry) / rate)
  return raw + math.min(budget, MAX - raw)
end

return M

-- NetQuota configuration loader and strict validator.
--
-- Loads /etc/config/netquota via UCI (when available), applies safe defaults and
-- validates every value that can reach nftables text or a shell command line.
-- The result is a plain Lua table so callers (network engine, service, rpcd)
-- never have to re-read UCI and cannot observe half-validated values.
--
-- Defaults are deliberately inert: enabled = false and guest = "br-guest".
-- A disabled configuration must still be loadable so administrative (account)
-- operations work even when the guest interface does not exist.

local M = {}

M.CONFIG_NAME = "netquota"

-- Defaults applied when a section/value is absent. Never enabling capture.
M.DEFAULTS = {
	enabled = false,
	guest = "br-guest",
	guest_address = "192.168.9.1",
	guest_cidr = "192.168.9.0/24",
	egress = { "eth0" },
	http_port = 2050,
	https_port = 2051,
	cert_path = "/etc/netquota/tls/cert.pem",
	key_path = "/etc/netquota/tls/key.pem",
	db_path = "/etc/netquota/netquota.db",
	default_reset_day = 1,
	session_timeout_seconds = 3600,
	checkpoint_seconds = 5,
	timezone = "Asia/Shanghai",
	management_address = "192.168.8.1",
	portal_hostname = "",
	portal_mode = "http",
	-- Network sessions always bind the observed guest IPv4 address and MAC.
}

-- Hard limits protecting nft/shell text and the router.
M.LIMITS = {
	max_egress = 8,
	max_name_len = 15,      -- IFNAMSIZ - 1
	max_path_len = 200,
	max_port = 65535,
	min_port = 1,
}

-- ---------------------------------------------------------------------------
-- Error helper
-- ---------------------------------------------------------------------------

local function fail(fmt, ...)
	error(string.format("netquota config: " .. fmt, ...), 0)
end

-- ---------------------------------------------------------------------------
-- Primitive validators (pure, reused by network.lua)
-- ---------------------------------------------------------------------------

--- Interface name: [A-Za-z0-9_.-], 1..15 chars, must not start with '-'.
-- Deliberately narrower than the kernel: no '/', spaces, quotes, '$', ';'.
function M.is_interface_name(v)
	if type(v) ~= "string" then return false end
	if #v < 1 or #v > M.LIMITS.max_name_len then return false end
	if v:sub(1, 1) == "-" then return false end
	return v:match("^[%w][%w%._%-]*$") ~= nil
end

--- Strict dotted-quad IPv4. Returns true/false.
function M.is_ipv4(v)
	if type(v) ~= "string" then return false end
	local a, b, c, d = v:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
	if not a then return false end
	for _, octet in ipairs({ a, b, c, d }) do
		-- reject leading zeros ("010") so nft and callers agree on the value
		if #octet > 1 and octet:sub(1, 1) == "0" then return false end
		if tonumber(octet) > 255 then return false end
	end
	return true
end

function M.is_hostname(v)
	if type(v) ~= 'string' or #v > 253 or not v:find('.', 1, true) then return false end
	if M.is_ipv4(v) or v:match('[^a-zA-Z0-9.%-]') or v:sub(1,1)=='.' or v:sub(-1) == '.' then return false end
	for label in v:gmatch('[^.]+') do
		if #label > 63 or not label:match('^[a-zA-Z0-9]') or not label:match('[a-zA-Z0-9]$') then return false end
	end
	return not v:find('..', 1, true)
end

function M.portal_origin(cfg)
	local host = cfg.portal_hostname and cfg.portal_hostname ~= '' and cfg.portal_hostname or cfg.guest_address
	local secure = cfg.portal_mode == 'https'
	return (secure and 'https://' or 'http://')..host..':'..tostring(secure and (cfg.https_port or 2051) or (cfg.http_port or 2050))
end

--- IPv4 address -> 32-bit number. Assumes is_ipv4() succeeded.
function M.ipv4_to_int(v)
	local a, b, c, d = v:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

--- Strict CIDR "A.B.C.D/len" with len 0..32. Returns network int, mask, bits.
function M.parse_cidr(v)
	if type(v) ~= "string" then return nil end
	local addr, bits = v:match("^(%d+%.%d+%.%d+%.%d+)/(%d%d?)$")
	if not addr or not M.is_ipv4(addr) then return nil end
	local n = tonumber(bits)
	if n > 32 or (bits:sub(1, 1) == "0" and #bits > 1) then return nil end
	local size = 2 ^ (32 - n)           -- 1 (single address) .. 2^32 (/0)
	local ip = M.ipv4_to_int(addr) % 4294967296
	return ip - (ip % size), 4294967296 - size, n
end

--- True when ipv4 string lies inside cidr string. False on bad input.
function M.cidr_contains(cidr, ip)
	local net, _, bits = M.parse_cidr(cidr)
	if not net or not M.is_ipv4(ip) then return false end
	local size = 2 ^ (32 - bits)
	return math.floor(M.ipv4_to_int(ip) / size) == math.floor(net / size)
end

--- MAC "aa:bb:cc:dd:ee:ff" (either case). Rejects zero, broadcast and
-- multicast (group) addresses, which are never a client unicast identity.
function M.is_mac(v)
	if type(v) ~= "string" then return false end
	if v:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") == nil then return false end
	-- reject multicast/broadcast/zero MACs
	if v == "00:00:00:00:00:00" or v == "FF:FF:FF:FF:FF:FF" then return false end
	local first = tonumber(v:sub(1, 2), 16)
	if first and (first % 2) == 1 then return false end
	return true
end

function M.normalize_mac(v)
	if type(v) ~= "string" then return nil end
	local hex = v:gsub("[:%-]", "")
	if #hex ~= 12 or hex:match("^%x+$") == nil then return nil end
	hex = hex:upper()
	return table.concat({
		hex:sub(1, 2), hex:sub(3, 4), hex:sub(5, 6),
		hex:sub(7, 8), hex:sub(9, 10), hex:sub(11, 12),
	}, ":")
end

--- Positive integer (quota) within 2^53-1, accepted as number or digit string.
function M.is_quota(v)
	if type(v) == "string" then
		if v:match("^%d+$") == nil then return false end
		v = tonumber(v)
	end
	if type(v) ~= "number" or v ~= math.floor(v) then return false end
	return v > 0 and v <= 9007199254740991
end

--- Nonnegative cumulative counter (Lua number, integral, <= 2^53-1).
function M.is_counter(v)
	if type(v) == "string" then
		if v:match("^%d+$") == nil then return false end
		v = tonumber(v)
	end
	if type(v) ~= "number" or v ~= math.floor(v) then return false end
	return v >= 0 and v <= 9007199254740991
end

--- Account/period identifier usable in nft object names: [A-Za-z0-9_], <=24.
function M.is_identifier(v, maxlen)
	if type(v) == "number" then
		if v ~= math.floor(v) or v < 0 then return false end
		v = string.format("%.0f", v)
	end
	if type(v) ~= "string" then return false end
	maxlen = maxlen or 24
	if #v < 1 or #v > maxlen then return false end
	return v:match("^[%w_]+$") ~= nil
end

--- Absolute filesystem path, conservative charset, no traversal.
function M.is_safe_path(v)
	if type(v) ~= "string" then return false end
	if #v < 2 or #v > M.LIMITS.max_path_len then return false end
	if v:sub(1, 1) ~= "/" then return false end
	if v:match("^/[/%w%._%-]+$") == nil then return false end
	if v:find("%.%.") or v:find("//") then return false end
	return true
end

--- TCP/UDP port 1..65535 (number or digit string).
function M.is_port(v)
	if type(v) == "string" then
		if v:match("^%d+$") == nil then return false end
		v = tonumber(v)
	end
	if type(v) ~= "number" or v ~= math.floor(v) then return false end
	return v >= M.LIMITS.min_port and v <= M.LIMITS.max_port
end

-- ---------------------------------------------------------------------------
-- UCI access (optional; absent UCI falls back to defaults)
-- ---------------------------------------------------------------------------

local function load_uci_table()
	local ok, uci = pcall(require, "uci")
	if not ok or not uci then return nil end
	local cursor
	ok, cursor = pcall(uci.cursor)
	if not ok or not cursor then return nil end
	local ok_all, all = pcall(cursor.get_all, cursor, M.CONFIG_NAME, "main")
	if ok_all and type(all) == "table" then return all, cursor end
	return {}, cursor
end

local function uci_bool(v, default, field)
	if v == nil then return default end
	if v == true or v == "1" or v == "true" or v == "yes" or v == "on" then return true end
	if v == false or v == "0" or v == "false" or v == "no" or v == "off" then return false end
	fail("invalid boolean for %s: %s", field, tostring(v))
end

local function uci_list(v)
	if v == nil then return nil end
	if type(v) == "table" then return v end
	-- UCI list with a single element may be returned as a string
	return { v }
end

local function uci_int(v, default, field)
	if v == nil then return default end
	if type(v) == "table" then
		fail("expected single integer for %s", field)
	end
	if type(v) == "string" then
		if v:match("^%d+$") == nil then fail("invalid integer for %s: %s", field, v) end
		v = tonumber(v)
	end
	if type(v) ~= "number" or v ~= math.floor(v) then
		fail("invalid integer for %s", field)
	end
	return v
end

local function uci_str(v, default)
	if v == nil then return default end
	if type(v) == "table" then fail("expected single string value, got list") end
	return tostring(v)
end

-- ---------------------------------------------------------------------------
-- Validation of a raw table into a normalized configuration
-- ---------------------------------------------------------------------------

--- Validate a raw (UCI-like) key/value table. Throws on invalid input.
-- Every rejected value names the offending field so the caller can report it.
function M.validate(raw)
	raw = raw or {}
	local cfg = {}

	cfg.enabled = uci_bool(raw.enabled, M.DEFAULTS.enabled, "enabled")

	cfg.guest = uci_str(raw.guest, M.DEFAULTS.guest)
	if not M.is_interface_name(cfg.guest) then
		fail("invalid guest interface name: %q", cfg.guest)
	end
	if raw.guest_address ~= nil or raw.guest_cidr ~= nil then
		cfg.guest_address = uci_str(raw.guest_address, M.DEFAULTS.guest_address)
		cfg.guest_cidr = uci_str(raw.guest_cidr, M.DEFAULTS.guest_cidr)
	else
		cfg.guest_address = M.DEFAULTS.guest_address
		cfg.guest_cidr = M.DEFAULTS.guest_cidr
	end
	if not M.is_ipv4(cfg.guest_address) then
		fail("invalid guest_address: %q", tostring(cfg.guest_address))
	end
	if not M.parse_cidr(cfg.guest_cidr) then
		fail("invalid guest_cidr: %q", tostring(cfg.guest_cidr))
	end
	if not M.cidr_contains(cfg.guest_cidr, cfg.guest_address) then
		fail("guest_address %s is not inside guest_cidr %s",
			cfg.guest_address, cfg.guest_cidr)
	end

	-- guest network may not contain the router management address
	if raw.management_address ~= nil then
		cfg.management_address = uci_str(raw.management_address)
		if not M.is_ipv4(cfg.management_address) then
			fail("invalid management_address: %q", cfg.management_address)
		end
	else
		cfg.management_address = M.DEFAULTS.management_address
	end
	if cfg.management_address and
		M.cidr_contains(cfg.guest_cidr, cfg.management_address) then
		fail("guest_cidr %s contains management address %s",
			cfg.guest_cidr, cfg.management_address)
	end

	-- egress device list (explicitly selected, never "all")
	local egress = uci_list(raw.egress)
	if egress == nil or #egress == 0 then
		egress = M.DEFAULTS.egress
	end
	if type(egress) ~= "table" then fail("invalid egress list") end
	if #egress > M.LIMITS.max_egress then
		fail("too many egress devices (max %d)", M.LIMITS.max_egress)
	end
	cfg.egress = {}
	local seen = {}
	for i = 1, #egress do
		local dev = egress[i]
		if type(dev) ~= "string" then fail("egress[%d] is not a string", i) end
		if not M.is_interface_name(dev) then
			fail("invalid egress interface name: %q", dev)
		end
		if seen[dev] then fail("duplicate egress device %q", dev) end
		seen[dev] = true
		if dev == cfg.guest then
			fail("guest interface %q cannot also be an egress device", dev)
		end
		cfg.egress[#cfg.egress + 1] = dev
	end

	cfg.http_port = uci_int(raw.http_port, M.DEFAULTS.http_port, "http_port")
	cfg.https_port = uci_int(raw.https_port, M.DEFAULTS.https_port, "https_port")
	if not M.is_port(cfg.http_port) then
		fail("invalid http_port: %s", tostring(cfg.http_port))
	end
	if not M.is_port(cfg.https_port) then
		fail("invalid https_port: %s", tostring(cfg.https_port))
	end
	if cfg.http_port == cfg.https_port then
		fail("http_port and https_port must differ")
	end

	cfg.cert_path = uci_str(raw.cert_path, M.DEFAULTS.cert_path)
	cfg.portal_hostname = uci_str(raw.portal_hostname, ''):lower()
	cfg.portal_mode = uci_str(raw.portal_mode, 'http')
	if cfg.portal_mode ~= 'http' and cfg.portal_mode ~= 'https' then fail('invalid portal mode') end
	if cfg.portal_hostname ~= '' and not M.is_hostname(cfg.portal_hostname) then fail('invalid portal hostname') end
	cfg.wifi_section = uci_str(raw.wifi_section, '')
	if cfg.wifi_section ~= '' and not cfg.wifi_section:match('^[%w_]+$') then fail('invalid Wi-Fi section') end
	cfg.tls_source = uci_str(raw.tls_source, 'unknown')
	cfg.key_path = uci_str(raw.key_path, M.DEFAULTS.key_path)
	if not M.is_safe_path(cfg.cert_path) then
		fail("invalid cert_path: %q", tostring(cfg.cert_path))
	end
	if not M.is_safe_path(cfg.key_path) then
		fail("invalid key_path: %q", tostring(cfg.key_path))
	end

	cfg.db_path = uci_str(raw.db_path, M.DEFAULTS.db_path)
	if not M.is_safe_path(cfg.db_path) then
		fail("invalid db_path: %q", tostring(cfg.db_path))
	end

	cfg.default_reset_day = uci_int(raw.default_reset_day,
		M.DEFAULTS.default_reset_day, "default_reset_day")
	if cfg.default_reset_day < 1 or cfg.default_reset_day > 31 then
		fail("default_reset_day must be 1..31")
	end

	cfg.session_timeout_seconds = uci_int(raw.session_timeout_seconds,
		M.DEFAULTS.session_timeout_seconds, "session_timeout_seconds")
	if cfg.session_timeout_seconds < 60 or cfg.session_timeout_seconds > 86400 then
		fail("session_timeout_seconds must be 60..86400")
	end
	cfg.checkpoint_seconds = uci_int(raw.checkpoint_seconds, M.DEFAULTS.checkpoint_seconds, "checkpoint_seconds")
	if cfg.checkpoint_seconds < 1 or cfg.checkpoint_seconds > 300 then fail("checkpoint_seconds must be 1..300") end

	if raw.timezone ~= nil or M.DEFAULTS.timezone then
		cfg.timezone = uci_str(raw.timezone, M.DEFAULTS.timezone)
		if cfg.timezone:match("^[A-Za-z][%w%+%-%/_]*$") == nil or #cfg.timezone > 64 then
			fail("invalid timezone: %q", cfg.timezone)
		end
	end


	return cfg
end

-- ---------------------------------------------------------------------------
-- Public loader
-- ---------------------------------------------------------------------------

--- Return a copy of defaults merged with validated values from `overrides`.
-- Never reads UCI. Throws on invalid overrides.
function M.from_table(overrides)
	local raw = {}
	for k, v in pairs(M.DEFAULTS) do
		if type(v) ~= "table" then raw[k] = v end
	end
	if overrides then
		for k, v in pairs(overrides) do raw[k] = v end
	end
	return M.validate(raw)
end

--- Load configuration from UCI (or defaults when UCI/section is absent).
-- Returns cfg on success. Throws a descriptive error on invalid settings.
-- `opts.raw` may supply an explicit table instead of reading UCI (tests).
function M.load(opts)
	opts = opts or {}
	local raw, cursor
	if opts.raw then
		raw = opts.raw
	else
		raw, cursor = load_uci_table()
		if raw == nil then raw = {} end
	end

	local cfg = M.validate(raw)

	-- Collect management/egress protection context from the live network.
	-- UCI reads are best-effort; absence is not an error while disabled.
	return cfg
end

--- Load without throwing: returns cfg, nil on success or nil, message on error.
function M.try_load(opts)
	local ok, res = pcall(M.load, opts)
	if ok then return res, nil end
	return nil, tostring(res)
end

--- Configuration reported when the section is missing or disabled.
function M.defaults()
	return M.from_table({})
end

return M

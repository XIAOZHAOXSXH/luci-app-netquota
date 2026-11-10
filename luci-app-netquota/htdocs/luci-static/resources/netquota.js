'require rpc';
'require baseclass';
'require ui';

/*
 * NetQuota shared LuCI JS module.
 *
 * Responsibilities:
 *  - declare the narrow admin rpcd object (`netquota`) methods;
 *  - unwrap the {ok:true,data} / {ok:false,error} envelope without silent fallbacks;
 *  - pure formatting helpers (decimal bytes, period dates in the configured timezone);
 *  - shared E()-node view builders (stat cards, usage bars, account cells, notices);
 *  - modal helpers built on LuCI ui.showModal/ui.hideModal;
 *  - an accessible, focus-managed page host with 15-30 s polling and manual refresh.
 *
 * No outer navigation, no iframe, no localStorage, no demo data.
 */

var C = rpc.declare({
	object: 'netquota',
	method: 'status',
	expect: { }
});

var C_SUMMARY = rpc.declare({
	object: 'netquota',
	method: 'get_summary',
	expect: { }
});

var C_LIST = rpc.declare({
	object: 'netquota',
	method: 'list_accounts',
	expect: { }
});

var C_GET = rpc.declare({
	object: 'netquota',
	method: 'get_account',
	params: [ 'id' ],
	expect: { }
});

var C_CREATE = rpc.declare({
	object: 'netquota',
	method: 'create_account',
	params: [ 'username', 'password', 'quota_bytes', 'reset_day' ],
	expect: { }
});

var C_UPDATE = rpc.declare({
	object: 'netquota',
	method: 'update_account',
	params: [ 'id', 'password', 'quota_bytes', 'reset_day' ],
	expect: { }
});

var C_DELETE = rpc.declare({
	object: 'netquota',
	method: 'delete_account',
	params: [ 'id' ],
	expect: { }
});

var C_TRAFFIC = rpc.declare({
	object: 'netquota',
	method: 'get_traffic',
	expect: { }
});

var C_GET_SETTINGS = rpc.declare({
	object: 'netquota',
	method: 'get_settings',
	expect: { }
});

var C_UPDATE_SETTINGS = rpc.declare({
	object: 'netquota',
	method: 'update_settings',
	params: [ 'default_reset_day', 'timezone' ],
	expect: { }
});

// Separate client declaration: billing saves omit reset-day/timezone entirely.
var C_UPDATE_BILLING = rpc.declare({
	object: 'netquota', method: 'update_settings',
	params: [ 'traffic_multiplier_percent' ], expect: { }
});

var C_PORTAL = rpc.declare({
	object: 'netquota',
	method: 'get_portal_info',
	expect: { }
});

var C_DEPLOY = rpc.declare({object:'netquota',method:'get_deployment',expect:{}});
var C_DEPLOY_SAVE = rpc.declare({object:'netquota',method:'save_deployment',params:['wifi_section','egress','portal_hostname','portal_mode'],expect:{}});
var C_GUEST_ENABLE = rpc.declare({object:'netquota',method:'enable_guest',params:['wifi_section'],expect:{}});
var C_CAPTURE = rpc.declare({object:'netquota',method:'set_capture',params:['enabled'],expect:{}});
var C_CERT_GENERATE = rpc.declare({object:'netquota',method:'generate_certificate',expect:{}});
var C_CERT_IMPORT = rpc.declare({object:'netquota',method:'import_certificate',params:['certificate_pem','private_key_pem'],expect:{}});
var C_CERT_GET = rpc.declare({object:'netquota',method:'get_certificate',expect:{}});

var METHODS = {
	get_deployment:C_DEPLOY, save_deployment:C_DEPLOY_SAVE, enable_guest:C_GUEST_ENABLE,
	set_capture:C_CAPTURE, generate_certificate:C_CERT_GENERATE, import_certificate:C_CERT_IMPORT, get_certificate:C_CERT_GET,
	status: C,
	get_summary: C_SUMMARY,
	list_accounts: C_LIST,
	get_account: C_GET,
	create_account: C_CREATE,
	update_account: C_UPDATE,
	delete_account: C_DELETE,
	get_traffic: C_TRAFFIC,
	get_settings: C_GET_SETTINGS,
	update_settings: C_UPDATE_SETTINGS,
	update_billing: C_UPDATE_BILLING,
	get_portal_info: C_PORTAL
};

var GB_BYTES = 1000000000;
var MAX_SAFE_INTEGER = 9007199254740991;
var USERNAME_RE = /^[A-Za-z0-9_-]{3,24}$/;

/* ------------------------------------------------------------------ */
/* envelope + errors                                                   */
/* ------------------------------------------------------------------ */

function ws(value) {
	if (value == null)
		return '';

	if (Array.isArray(value))
		return value.map(function(v) { return ws(v); }).join(' ').trim();

	if (typeof(value) === 'object' && value.nodeType)
		return String(value.innerText || value.textContent || '');

	return String(value);
}

function isEnvelope(res) {
	return res != null && typeof(res) === 'object' && !Array.isArray(res) &&
		Object.prototype.hasOwnProperty.call(res, 'ok') &&
		(res.ok === true || res.ok === false);
}

function parseMaybeJson(value) {
	if (typeof(value) === 'string') {
		var s = value.replace(/^\s+|\s+$/g, '');

		if (s.charAt(0) === '{' || s.charAt(0) === '[') {
			try { return JSON.parse(s); }
			catch (e) { return value; }
		}
	}

	return value;
}

function errorCode(err) {
	return err && err.code != null ? String(err.code) : 'rpc_error';
}

function errorText(err) {
	if (err && err.message != null && ws(err.message) !== '')
		return ws(err.message);

	return ws(ws(err)) || 'RPC call failed';
}

function failure(err, detail) {
	err.code = errorCode(err);
	err.message = errorText(err);

	if (detail)
		err.detail = ws(detail);

	return err;
}

function invoke(method, params) {
	var fn = METHODS[method];

	if (typeof(fn) !== 'function')
		return Promise.reject(failure({ code: 'client_error', message: 'Unsupported NetQuota method: ' + method }));

	var args = [];
	var argNames = null;
	var map = {};

	if (params != null && typeof(params) === 'object' && !Array.isArray(params))
		map = params;

	if (method === 'get_account' || method === 'delete_account')
		args = [ idParam(map.id) ];
	else if (method === 'update_account')
		args = [ idParam(map.id), optString(map.password), intParam(map.quota_bytes), resetParam(map.reset_day) ];
	else if (method === 'create_account')
		args = [ String(map.username), String(map.password), intParam(map.quota_bytes), resetParam(map.reset_day) ];
	else if (method === 'update_settings')
		args = [ intParam(map.default_reset_day), String(map.timezone) ];
	else if (method === 'update_billing')
		args = [ intParam(map.traffic_multiplier_percent) ];
	else if (method === 'save_deployment')
		args = [String(map.wifi_section || ''),String(map.egress || ''),String(map.portal_hostname || ''),String(map.portal_mode || 'http')];
	else if (method === 'enable_guest')
		args = [String(map.wifi_section || '')];
	else if (method === 'set_capture')
		args = [map.enabled === true];
	else if (method === 'import_certificate')
		args = [String(map.certificate_pem || ''),String(map.private_key_pem || '')];

	return Promise.resolve(fn.apply(null, args)).then(function(res) {
		var body = parseMaybeJson(res);

		if (body == null)
			throw failure({ code: 'protocol_error', message: 'NetQuota returned an empty response' });

		if (typeof(body) !== 'object' || !('ok' in body))
			throw failure({ code: 'protocol_error', message: 'NetQuota returned a non-envelope response' }, body);

		if (body.ok !== true)
			throw failure(body.error || { code: 'error', message: 'NetQuota reported an unspecified failure' });

		return body.data;
	}, function(err) {
		throw failure({ code: 'rpc_transport', message: 'RPC unavailable' }, ws(err) || 'request failed');
	});
}

function idParam(v) {
	var n = Number(v);

	if (!isFinite(n) || n <= 0 || Math.floor(n) !== n || n > MAX_SAFE_INTEGER)
		throw failure({ code: 'client_error', message: 'Invalid account id' });

	return n;
}

function intParam(v) {
	return Number(v);
}

function optString(v) {
	return (v == null) ? '' : String(v);
}

function resetParam(v) {
	return (v == null || v === '') ? null : Number(v);
}

/* ------------------------------------------------------------------ */
/* formatting                                                          */
/* ------------------------------------------------------------------ */

function isNum(v) {
	return typeof(v) === 'number' && isFinite(v);
}

function dec(v) {
	return isNum(v) ? v : parseFloat(v);
}

function groupInt(str) {
	var out = '';
	var i;

	for (i = 0; i < str.length; i++) {
		if (i > 0 && (str.length - i) % 3 === 0)
			out += ',';
		out += str.charAt(i);
	}

	return out;
}

/** Format an integer byte count with decimal (SI) units: 1 GB = 1000^3 bytes. */
function bytes(v, digits) {
	var n = dec(v);

	if (!isFinite(n) || n < 0)
		return '—';

	var d = (digits == null) ? 2 : digits;
	var units = [ 'B', 'KB', 'MB', 'GB', 'TB', 'PB' ];
	var i = 0;

	while (n >= 1000 && i < units.length - 1) {
		n = n / 1000;
		i++;
	}

	if (i === 0)
		return groupInt(String(Math.round(n))) + ' B';

	var s = n.toFixed(d).replace(/0+$/, '').replace(/\.$/, '');

	return s + ' ' + units[i];
}

/** Split formatted bytes into an E() number/unit pair for stat cards. */
function bytesParts(v, digits) {
	var s = bytes(v, digits);
	var i = s.indexOf(' ');

	return { num: i > 0 ? s.substring(0, i) : s, unit: i > 0 ? s.substring(i + 1) : '' };
}

/** Parse a GB input field into a safe integer byte count. Returns null when invalid. */
function gbToBytes(gb) {
	var s = String(gb == null ? '' : gb).replace(/^\s+|\s+$/g, '');

	if (!/^\d+(\.\d+)?$/.test(s))
		return null;

	var parts = s.split('.');
	var whole = parts[0];
	var frac = (parts[1] || '') + '000000000';
	var b;

	if (whole.length > 9)
		return null;

	b = parseInt(whole, 10) * 1000000000 + parseInt(frac.substring(0, 9), 10);

	if (!(b > 0) || b > MAX_SAFE_INTEGER)
		return null;

	return b;
}

function bytesToGbInput(v) {
	var n = dec(v);

	if (!isFinite(n) || n <= 0)
		return '';

	var s = (n / GB_BYTES).toFixed(9).replace(/0+$/, '').replace(/\.$/, '');

	return s;
}

function pct(v) {
	var n = dec(v);

	if (!isFinite(n) || n < 0)
		return 0;

	return Math.min(100, Math.round(n * 10) / 10);
}

function pctLabel(v) {
	var n = pct(v);
	return (Math.round(n * 10) % 10 === 0) ? String(Math.round(n)) : n.toFixed(1);
}

function usageClass(p) {
	return (p >= 100) ? 'danger' : (p >= 80) ? 'warn' : 'ok';
}

function initials(name) {
	var s = String(name || '');
	if (s.length === 0)
		return '·';
	return s.substring(0, 2).toUpperCase();
}

function accountNumber(id) {
	var s = String(id == null ? '' : id);
	while (s.length < 4)
		s = '0' + s;
	return 'NQ' + s;
}

/** Parse a backend epoch (seconds or milliseconds) into epoch milliseconds. */
function epochMs(v) {
	var n = dec(v);

	if (!isFinite(n) || n <= 0)
		return null;

	if (n > 100000000000)
		return null;

	if (n > 10000000000)
		return Math.floor(n);

	return Math.floor(n * 1000);
}

/**
 * Create a date formatter bound to a configured IANA timezone. The timezone is
 * never invented: an empty value uses the browser zone, and an unparseable
 * IANA/POSIX name is reported as unresolved so pages can label the fallback.
 */
function dateFormatter(tz) {
	var zone = ws(tz);
	var resolved = true;

	if (zone !== '') {
		try {
			new Intl.DateTimeFormat('en-US', { timeZone: zone });
		}
		catch (e) {
			zone = '';
			resolved = false;
		}
	}

	function fmt(epoch, style) {
		var ms = epochMs(epoch);

		if (ms == null)
			return '—';

		var d = new Date(ms);
		var opts;

		if (style === 'date')
			opts = { year: 'numeric', month: '2-digit', day: '2-digit' };
		else if (style === 'short')
			opts = { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false };
		else
			opts = {
				year: 'numeric', month: '2-digit', day: '2-digit',
				hour: '2-digit', minute: '2-digit', hour12: false
			};

		if (zone)
			opts.timeZone = zone;

		try {
			return new Intl.DateTimeFormat('en-CA', opts).format(d).replace(',', '');
		}
		catch (e) {
			return '—';
		}
	}

	return {
		timezone: zone,
		resolved: resolved,
		datetime: function(v) { return fmt(v, 'datetime'); },
		date: function(v) { return fmt(v, 'date'); },
		short: function(v) { return fmt(v, 'short'); }
	};
}

function statusOf(a) {
	if (!a || typeof(a) !== 'object')
		return { cls: 'offline', label: _('未知') };

	if (a.exhausted === true || dec(a.usage_percent) >= 100)
		return { cls: 'exhausted', label: _('流量用尽') };

	if (a.online === true)
		return { cls: 'online', label: _('在线') };

	return { cls: 'offline', label: _('离线') };
}

function warningLevel(a) {
	var p = dec(a && a.usage_percent);

	if (!isFinite(p))
		return 'ok';

	if (p >= 100 || (a && a.exhausted === true))
		return 'danger';

	return (p >= 80) ? 'warn' : 'ok';
}

function sortAccounts(list) {
	return (list || []).slice().sort(function(x, y) {
		return String(x.username || '').localeCompare(String(y.username || ''));
	});
}

function sum(list, key) {
	var t = 0;

	(list || []).forEach(function(a) {
		var n = dec(a[key]);
		if (isFinite(n))
			t += n;
	});

	return t;
}

function listData(data) {
	if (data == null)
		return { items: [], updated_at: null };

	if (Array.isArray(data))
		return { items: data, updated_at: null };

	var items = Array.isArray(data.items) ? data.items : [];

	return { items: items, updated_at: data.updated_at };
}

/* ------------------------------------------------------------------ */
/* E() builders                                                        */
/* ------------------------------------------------------------------ */

/* Single-path 24px stroke glyphs; tone is carried by the surrounding card. */
var ICONS = {
	accounts: 'M15 20.5v-1.8a3.7 3.7 0 0 0-3.7-3.7H6.2a3.7 3.7 0 0 0-3.7 3.7v1.8M8.75 11.8a3.9 3.9 0 1 0 0-7.8 3.9 3.9 0 0 0 0 7.8M21.5 20.5v-1.8a3.7 3.7 0 0 0-2.8-3.6M15.6 4.1a3.7 3.7 0 0 1 0 7.4',
	online: 'M2 8.5a15 15 0 0 1 20 0M5 12.5a11 11 0 0 1 14 0M8.5 16a6 6 0 0 1 7 0M12 19.6h.01',
	usage: 'M4 7h10.5a3 3 0 0 1 0 6H6.5a3 3 0 0 0 0 6H20M16.5 4l3.5 2.8-3.5 2.8',
	exhausted: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M9 9l6 6M15 9l-6 6',
	upload: 'M12 19V5M5 12l7-7 7 7',
	download: 'M12 5v14M19 12l-7 7-7-7',
	total: 'M3 3v18h18M7 14.5l4-4 3 3 5.5-6.5',
	quota: 'M4 5.5h16v13H4zM4 10.5h16M8.5 15.5h3',
	refresh: 'M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5',
	plus: 'M12 5v14M5 12h14',
	alert: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 8v5M12 16h.01',
	clock: 'M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18M12 7v5l3.2 2',
	lock: 'M6.5 11h11v9.5h-11zM9 11V7.5a3 3 0 0 1 6 0V11'
};

function icon(pathName) {
	var attrs = {
		class: 'nq-icon',
		viewBox: '0 0 24 24',
		width: '16',
		height: '16',
		fill: 'none',
		stroke: 'currentColor',
		'stroke-width': '1.8',
		'stroke-linecap': 'round',
		'stroke-linejoin': 'round',
		'aria-hidden': 'true',
		focusable: 'false'
	};
	var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
	Object.keys(attrs).forEach(function(key) { svg.setAttribute(key, attrs[key]); });
	var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
	path.setAttribute('d', ICONS[pathName] || ICONS.alert);
	svg.appendChild(path);
	return svg;
}

function count(n) {
	var v = dec(n);
	return isFinite(v) ? groupInt(String(Math.max(0, Math.round(v)))) : '—';
}

/** A tone-coded numeric card with a synthetic period-gauge footer. */
function statCard(opts) {
	var parts = (opts.parts != null) ? opts.parts : { num: count(opts.value), unit: '' };
	var ratio = isFinite(dec(opts.ratio)) ? Math.max(0, Math.min(1, dec(opts.ratio))) : 0;
	var gauge = E('div', { class: 'nq-gauge', 'aria-hidden': 'true' }, [
		E('i', { class: 'nq-gauge-fill nq-tone-' + (opts.gauge || opts.tone || 'blue'), style: 'width:' + (ratio * 100).toFixed(1) + '%' })
	]);

	return E('section', { class: 'nq-card nq-stat nq-tone-' + (opts.tone || 'blue') }, [
		E('div', { class: 'nq-stat-top' }, [
			E('span', { class: 'nq-stat-label' }, [ opts.label ]),
			E('span', { class: 'nq-stat-icon', 'aria-hidden': 'true' }, [ icon(opts.icon || 'total') ])
		]),
		E('div', { class: 'nq-stat-value' }, [
			ws(parts.num),
			parts.unit ? E('small', {}, [ parts.unit ]) : ''
		]),
		opts.foot ? E('div', { class: 'nq-stat-foot' }, [ opts.foot ]) : '',
		gauge
	]);
}

function usageTrack(percent, label) {
	var p = pct(percent);

	return E('div', {
		class: 'nq-usage',
		role: 'progressbar',
		'aria-valuemin': '0',
		'aria-valuemax': '100',
		'aria-valuenow': String(Math.round(p)),
		'aria-label': label || _('额度使用率')
	}, [
		E('div', { class: 'nq-usage-track', 'aria-hidden': 'true' }, [
			E('i', { class: 'nq-usage-fill nq-fill-' + usageClass(p), style: 'width:' + p.toFixed(1) + '%' })
		])
	]);
}

function billedBytes(a) {
	return a && a.billed_bytes != null ? Number(a.billed_bytes) : Number(a && a.total_bytes) || 0;
}

function usageCell(a, label) {
	var p = pct(a && a.usage_percent);

	return E('div', { class: 'nq-usage-cell' }, [
		E('div', { class: 'nq-usage-text' }, [
			E('strong', {}, [ bytes(billedBytes(a)) ]),
			E('span', {}, [ pctLabel(p) + '%' ])
		]),
		usageTrack(p, (label || _('额度使用率')) + ': ' + ws(a && a.username) + ' ' + pctLabel(p) + '%')
	]);
}

function userNameCell(a) {
	var st = statusOf(a);

	return E('div', { class: 'nq-user' }, [
		E('span', { class: 'nq-avatar nq-avatar-' + st.cls, 'aria-hidden': 'true' }, [ initials(a && a.username) ]),
		E('span', { class: 'nq-user-copy' }, [
			E('span', { class: 'nq-user-name' }, [ ws(a && a.username) ]),
			E('span', { class: 'nq-user-sub' }, [ accountNumber(a && a.id) ])
		])
	]);
}

function statusBadge(a) {
	var st = statusOf(a);

	return E('span', { class: 'nq-status nq-status-' + st.cls }, [ st.label ]);
}

function emptyRow(colspan, text) {
	return E('tr', { class: 'nq-empty' }, [
		E('td', { colspan: String(colspan) }, [ E('div', { class: 'nq-empty-box' }, [ icon('alert'), E('span', {}, [ text ]) ]) ])
	]);
}

function notice(text, tone) {
	return E('div', { class: 'nq-notice' + (tone ? ' nq-notice-' + tone : ''), role: 'note' }, [
		icon(tone === 'warn' ? 'alert' : 'alert'),
			E('div', {}, Array.isArray(text) ? text : [ text ])
	]);
}

function errorBox(err, onRetry) {
	return E('div', { class: 'nq-error', role: 'alert' }, [
		E('div', { class: 'nq-error-head' }, [
			icon('alert'),
			E('strong', {}, [ _('NetQuota 请求失败') ])
		]),
		E('p', { class: 'nq-error-msg' }, [ (err && err.message) || _('未知错误') ]),
		E('p', { class: 'nq-error-code' }, [
			E('span', {}, [ _('错误码') + ': ' ]),
			E('code', {}, [ (err && err.code) || 'error' ]),
			(err && err.detail) ? E('span', { class: 'nq-error-detail' }, [ ' · ' + err.detail ]) : ''
		]),
		onRetry ? E('div', { class: 'nq-error-actions' }, [
			E('button', { type: 'button', class: 'nq-btn', click: function(ev) { ev.preventDefault(); onRetry(); } }, [
				icon('refresh'),
				E('span', {}, [ _('重试') ])
			])
		]) : ''
	]);
}

function skeleton(label) {
	return E('div', { class: 'nq-skeleton', 'aria-busy': 'true', 'aria-live': 'polite' }, [
		E('span', { class: 'nq-spinner', 'aria-hidden': 'true' }),
		E('span', {}, [ label || _('加载中…') ])
	]);
}

function pageHeader(opts) {
	var actions = (opts.actions || []).filter(function(x) { return x != null; });

	return E('div', { class: 'nq-head' }, [
		E('div', { class: 'nq-head-copy' }, [
			E('p', { class: 'nq-eyebrow' }, [ opts.eyebrow ]),
			E('h2', { class: 'nq-title', id: opts.titleId || null }, [ opts.title ]),
			opts.desc ? E('p', { class: 'nq-desc' }, [ opts.desc ]) : ''
		]),
		actions.length ? E('div', { class: 'nq-head-actions' }, actions) : ''
	]);
}

function actionButton(label, opts) {
	opts = opts || {};

	var node = E('button', {
		type: 'button',
		class: 'nq-btn' + (opts.primary ? ' nq-btn-primary' : '') + (opts.danger ? ' nq-btn-danger' : '') +
			(opts.small ? ' nq-btn-sm' : '') + (opts.quiet ? ' nq-btn-quiet' : ''),
		disabled: opts.disabled ? '' : null,
		click: opts.click || null
	}, [
		opts.icon ? icon(opts.icon) : '',
		E('span', {}, [ label ])
	]);

	return node;
}

function panel(title, subtitle, body, extra) {
	return E('section', { class: 'nq-card nq-panel' }, [
		E('div', { class: 'nq-panel-head' }, [
			E('div', {}, [
				E('h3', { class: 'nq-panel-title' }, [ title ]),
				subtitle ? E('p', { class: 'nq-panel-sub' }, [ subtitle ]) : ''
			]),
			extra || ''
		]),
		E('div', { class: 'nq-panel-body' }, Array.isArray(body) ? body : [ body ])
	]);
}

function tablePanel(title, subtitle, toolbar, headers, bodyRows, extraHead) {
	return E('section', { class: 'nq-card nq-panel nq-table-panel' }, [
		E('div', { class: 'nq-panel-head' }, [
			E('div', {}, [
				E('h3', { class: 'nq-panel-title' }, [ title ]),
				subtitle ? E('p', { class: 'nq-panel-sub' }, [ subtitle ]) : ''
			]),
			extraHead || ''
		]),
		toolbar ? E('div', { class: 'nq-toolbar' }, [ toolbar ]) : '',
		E('div', { class: 'nq-table-scroll', tabindex: '0', role: 'region', 'aria-label': title }, [
			E('table', { class: 'nq-table' }, [
				E('thead', {}, [ E('tr', {}, headers.map(function(h) {
					return E('th', { scope: 'col', class: h.cls || null }, [ h.label ]);
				})) ]),
				E('tbody', {}, bodyRows)
			])
		])
	]);
}

function updatedStamp(updatedAt, fmt, refreshSeconds) {
	var when = fmt ? fmt.datetime(updatedAt) : '—';

	return E('p', { class: 'nq-stamp', 'aria-live': 'polite' }, [
		icon('clock'),
		E('span', {}, [ _('数据更新时间') + ' ' + when ]),
		refreshSeconds ? E('span', { class: 'nq-stamp-sep' }, [ '· ' + _('每 %d 秒自动刷新').format(refreshSeconds) ]) : ''
	]);
}

/* ------------------------------------------------------------------ */
/* modals                                                              */
/* ------------------------------------------------------------------ */

var openModals = [];

function modalCloseAll() {
	while (openModals.length)
		openModals.pop().close();
}

/**
 * Open a LuCI modal built from E() nodes. `opts.build(close)` returns the body
 * node(s); footer buttons are appended in a consistent order. Escape and the
 * close button dismiss it, and focus returns to the invoker.
 */
function openModal(opts) {
	if (typeof(ui.showModal) !== 'function' || typeof(ui.hideModal) !== 'function')
		throw failure({ code: 'client_error', message: 'LuCI modal API unavailable' });

	var invoker = (window.document && window.document.activeElement) || null;
	var closing = false;
	var keyHandler = null;
	var dialog = null;

	function close() {
		if (closing)
			return;
		closing = true;

		var idx = openModals.map(function(m) { return m.close; }).indexOf(close);
		if (idx >= 0)
			openModals.splice(idx, 1);

		if (keyHandler)
			window.document.removeEventListener('keydown', keyHandler, true);

		try { ui.hideModal(); }
		catch (e) { /* modal already gone */ }
		if (dialog) dialog.classList.remove('nq-owned-modal');

		if (invoker && typeof(invoker.focus) === 'function') {
			try { invoker.focus(); }
			catch (e) { /* element detached */ }
		}
	}

	var buttons = (opts.buttons || []).filter(function(b) { return b != null; });

	var md = {
		close: close,
		setBusy: function(busy) {
			Array.prototype.forEach.call(footer.querySelectorAll('button'), function(btn) {
				btn.disabled = !!busy;
			});
		}
	};

	var footer = E('div', { class: 'nq-modal-foot' }, buttons.map(function(b) {
		return E('button', {
			type: 'button',
			class: 'nq-btn' + (b.primary ? ' nq-btn-primary' : '') + (b.danger ? ' nq-btn-danger' : ''),
			id: b.id || null,
			click: function(ev) {
				ev.preventDefault();
				if (b.click)
					b.click(close, md);
				else
					close();
			}
		}, [ b.label ]);
	}));

	md.footer = footer;

	var body = opts.build(close, md);

	var content = [
		E('div', { class: 'nq-modal-head' }, [
			E('div', {}, [
				opts.subtitle ? E('p', { class: 'nq-modal-sub' }, [ opts.subtitle ]) : ''
			]),
			E('button', {
				type: 'button',
				class: 'nq-modal-close',
				'aria-label': _('关闭'),
				click: function(ev) { ev.preventDefault(); close(); }
			}, [ '\u00d7' ])
		]),
		E('div', { class: 'nq-modal-body' }, Array.isArray(body) ? body : [ body ]),
		footer
	];

	openModals.push({ close: close });
	ui.showModal(opts.title, [E('div', { class: 'netquota nq-modal-host' }, content)]);
	dialog = document.querySelector('.nq-modal-host').closest('.modal');
	if (dialog) dialog.classList.add('nq-owned-modal');

	keyHandler = function(ev) {
		if (ev.key === 'Escape') {
			ev.stopPropagation();
			close();
		}
	};
	window.document.addEventListener('keydown', keyHandler, true);

	return close;
}

function field(id, label, control, help, required) {
	return E('div', { class: 'nq-field' }, [
		E('label', { class: 'nq-label', for: id }, [
			label,
			required ? E('span', { class: 'nq-req', 'aria-hidden': 'true' }, [ '*' ]) : ''
		]),
		control,
		help ? E('p', { class: 'nq-help', id: id + '-help' }, [ help ]) : ''
	]);
}

function input(id, attrs) {
	var a = {
		type: 'text',
		id: id,
		class: 'nq-input',
		autocomplete: 'off',
		'aria-describedby': id + '-help'
	};

	for (var k in attrs)
		a[k] = attrs[k];

	return E('input', a);
}

function select(id, options, value) {
	var max = 0;

	return E('select', {
		id: id,
		class: 'nq-select',
		'aria-describedby': id + '-help'
	}, options.map(function(o) {
		return E('option', { value: o.value, selected: (String(o.value) === String(value)) ? '' : null }, [ o.label ]);
	}));
}

function formError(id) {
	return E('div', { class: 'nq-form-error', id: id, role: 'alert', hidden: '' }, [ ]);
}

function setFormError(container, text) {
	if (!container)
		return;

	container.textContent = text || '';

	if (text) {
		container.removeAttribute('hidden');
		container.scrollIntoView({ block: 'nearest' });
	}
	else {
		container.setAttribute('hidden', '');
	}
}

/** Guard a one-shot submit: ignores re-entry and re-enables on failure. */
function submitGuard(fn, setBusy) {
	var running = false;

	return function() {
		if (running)
			return;

		running = true;
		if (setBusy) setBusy(true);

		var p;

		try {
			p = Promise.resolve(fn());
		}
		catch (e) {
			p = Promise.reject(e);
		}

		return p.then(function(v) {
			running = false;
			return v;
		}, function(e) {
			running = false;
			if (setBusy) setBusy(false);
			throw e;
		});
	};
}

function resetDayOptions(inheritLabel) {
	var opts = [ { value: '', label: inheritLabel } ];
	var i;

	for (i = 1; i <= 31; i++)
		opts.push({ value: String(i), label: _('每月 %d 日').format(i) });

	return opts;
}

/* ------------------------------------------------------------------ */
/* page host                                                           */
/* ------------------------------------------------------------------ */

var REFRESH_DEFAULT = 20;

/**
 * Normalise a LuCI handle from a view `render()` into a page mount/teardown
 * pair. LuCI 21.02 hands us E() node arrays; a plain object with
 * children, or a single node, is accepted for testability.
 */
function mountTarget(handle) {
	if (!handle)
		return null;
	if (handle.nodeType === 1)
		return { replace: function(nodes) { handle.replaceChildren.apply(handle, nodes); } };

	if (Array.isArray(handle))
		return { replace: function(nodes) { handle.splice.apply(handle, [ 0, handle.length ].concat(nodes)); } };

	if (handle.children && Array.isArray(handle.children))
		return { replace: function(nodes) { handle.children.splice.apply(handle.children, [ 0, handle.children.length ].concat(nodes)); } };

	return null;
}

// Follow the rendered LuCI canvas, including themes which force a mode instead
// of following the OS. Do not change the theme's own classes or preferences.
function watchTheme(handle) {
	var root = document.documentElement;
	var media = window.matchMedia('(prefers-color-scheme: dark)');
	var frame = null;
	function sync() {
		frame = null;
		var dark = media.matches;
		var node = handle && handle.parentElement || document.body;
		for (; node; node = node.parentElement) {
			var rgb = window.getComputedStyle(node).backgroundColor.match(/^rgba?\(([^)]+)\)$/);
			if (!rgb) continue;
			var channels = rgb[1].split(',').map(Number);
			if (channels.length > 3 && channels[3] < 0.95) continue;
			// An opaque ancestor is the actual canvas behind the application.
			dark = (channels[0]*0.2126 + channels[1]*0.7152 + channels[2]*0.0722) < 128;
			break;
		}
		root.setAttribute('data-netquota-theme', dark ? 'dark' : 'light');
	}
	function schedule() {
		if (frame === null) frame = window.requestAnimationFrame(sync);
	}
	var observer = new MutationObserver(schedule);
	for (var node = handle && handle.parentElement || document.body; node; node = node.parentElement)
		observer.observe(node, { attributes: true, attributeFilter: ['class', 'style', 'data-theme', 'data-bs-theme'] });
	observer.observe(document.head, { childList: true, subtree: true, characterData: true,
		attributes: true, attributeFilter: ['href', 'media', 'disabled'] });
	// Covers asynchronously loaded theme CSS as well as inline theme changes.
	document.head.addEventListener('load', schedule, true);
	// Some LuCI themes animate the canvas after a media/class change.
	document.addEventListener('transitionend', schedule, true);
	if (media.addEventListener) media.addEventListener('change', schedule);
	else media.addListener(schedule);
	sync();
	return function() {
		observer.disconnect();
		document.head.removeEventListener('load', schedule, true);
		document.removeEventListener('transitionend', schedule, true);
		if (media.removeEventListener) media.removeEventListener('change', schedule);
		else media.removeListener(schedule);
		if (frame !== null) window.cancelAnimationFrame(frame);
	};
}

/**
 * Create the shared page host: status strip, view content area, polling and
 * manual refresh. `load()` resolves to the data the renderer consumes;
 * loader failures are shown verbosely and never replaced with fake numbers.
 */
function createPage(opts) {
	if (!document.getElementById('netquota-stylesheet'))
		document.head.appendChild(E('link', { id: 'netquota-stylesheet', rel: 'stylesheet', href: L.resource('netquota.css') }));
	var target = mountTarget(opts.target);
	var refreshSeconds = (opts.refreshSeconds > 0) ? opts.refreshSeconds : REFRESH_DEFAULT;
	var state = {
		destroyed: false,
		timer: null,
		inFlight: false,
		head: null,
		content: null,
		strip: null,
		stamp: null,
		lastOk: null,
		lastError: null,
		fmt: dateFormatter(opts.timezone)
	};

	if (!target)
		return { render: function() {}, refresh: function() { return Promise.resolve(); }, destroy: function() {} };
	var stopTheme = watchTheme(opts.target);

	function paintStrip() {
		var model = state.lastOk || {};
		var data = model.status || model;
		var err = state.lastError;
		var chips = [];

		if (err) {
			chips.push(E('span', { class: 'nq-chip nq-chip-danger' }, [ E('i', { class: 'nq-dot' }), _('数据不可用') ]));
		}
		else if (state.lastOk) {
			chips.push(E('span', { class: 'nq-chip nq-chip-' + (data.running === true ? 'ok' : 'warn') }, [
				E('i', { class: 'nq-dot' }),
				data.running === true ? _('服务运行中') : (data.running === false ? _('服务已停止') : _('服务状态未知'))
			]));

			if (data.enabled === false)
				chips.push(E('span', { class: 'nq-chip nq-chip-warn' }, [ E('i', { class: 'nq-dot' }), _('访客网络未接管') ]));
			else if (data.enabled === true)
				chips.push(E('span', { class: 'nq-chip nq-chip-' + (data.network && data.network.guarded ? 'warn' : 'ok') }, [
					E('i', { class: 'nq-dot' }), data.network && data.network.guarded ? _('接管守卫中') : _('认证与配额已启用') ]));

			if (ws(data.version) !== '')
				chips.push(E('span', { class: 'nq-chip nq-chip-quiet' }, [ 'v' + ws(data.version) ]));
		}

		if (!state.strip)
			return;

		state.strip.replaceChildren(E('div', { class: 'nq-strip' }, [
			E('span', { class: 'nq-strip-branch' }, [ icon('quota'), _('NetQuota') ]),
			E('span', { class: 'nq-strip-sep', 'aria-hidden': 'true' }, [ '/' ]),
			E('span', { class: 'nq-strip-view' }, [ opts.title ]),
			E('span', { class: 'nq-strip-chips' }, chips)
		]));
	}

	function paintHeader() {
		var actions = [];

		actions.push(actionButton(_('刷新'), {
			icon: 'refresh',
			small: true,
			disabled: state.inFlight,
			click: function(ev) {
				ev.preventDefault();
				refresh(true);
			}
		}));

		if (opts.headerActions)
			Array.prototype.push.apply(actions, opts.headerActions(refresh) || []);

		var node = pageHeader({
			eyebrow: opts.eyebrow || 'NETQUOTA',
			title: opts.title,
			titleId: 'nq-page-title',
			desc: opts.desc,
			actions: actions
		});

		if (state.head)
			state.head.replaceChildren(node);
	}

	function paintContent() {
		var node;

		if (state.lastError) {
			node = E('div', { class: 'nq-content' }, [
				errorBox(state.lastError, function() { refresh(); }),
				state.lastOk ? E('div', { class: 'nq-content-stale' }, opts.render(state.lastOk, ctx())) : ''
			]);
		}
		else if (state.lastOk) {
			node = E('div', { class: 'nq-content' }, opts.render(state.lastOk, ctx()));
		}
		else {
			node = E('div', { class: 'nq-content' }, [ skeleton() ]);
		}

		if (state.content)
			state.content.replaceChildren(node);

		paintStrip();
	}

	function ctx() {
		return {
			fmt: state.fmt,
			refresh: refresh,
			openModal: openModal,
			reloadSettings: reloadSettings
		};
	}

	function reloadSettings() {
		return invoke('get_settings').then(function(s) {
			if (s && ws(s.timezone) !== '')
				state.fmt = dateFormatter(s.timezone);
			return s;
		});
	}

	function refresh() {
		if (state.destroyed || state.inFlight)
			return Promise.resolve();

		state.inFlight = true;
		paintHeader();

		var preload = opts.needsSettings ? reloadSettings() : Promise.resolve();

		return Promise.resolve(preload).then(function() {
			return opts.load(ctx());
		}).then(function(data) {
			if (data && !data.status)
				return invoke('status').then(function(status) { data.status=status; return data; }, function() { return data; });
			return data;
		}).then(function(data) {
			state.lastOk = data;
			state.lastError = null;
		}, function(err) {
			state.lastError = (err && err.message) ? err : { code: 'error', message: ws(err) || 'Load failed' };
		}).then(function() {
			state.inFlight = false;

			if (state.destroyed)
				return;

			paintHeader();
			paintContent();
		});
	}

	function destroy() {
		state.destroyed = true;
		stopTheme();

		if (state.timer)
			window.clearInterval(state.timer);
		state.timer = null;

		window.document.removeEventListener('visibilitychange', onVisibility);
		modalCloseAll();
	}

	function onVisibility() {
		if (state.destroyed)
			return;

		if (window.document.hidden === true)
			return;

		refresh(false);
	}

	state.head = E('div', { class: 'nq-head-slot' });
	state.strip = E('div', { class: 'nq-strip-slot' });
	state.content = E('section', { class: 'nq-page', 'aria-labelledby': 'nq-page-title' });

	target.replace([ E('div', { class: 'netquota' }, [ state.strip, state.head, state.content ]) ]);

	paintHeader();
	paintContent();
	refresh(false);

	state.timer = window.setInterval(function() {
		if (!window.document.hidden && (!opts.shouldRefresh || opts.shouldRefresh()))
			refresh(false);
	}, refreshSeconds * 1000);

	window.document.addEventListener('visibilitychange', onVisibility);
	window.addEventListener('pagehide', destroy, { once: true });

	return {
		refresh: function() { return refresh(true); },
		destroy: destroy
	};
}

/* ------------------------------------------------------------------ */
/* domain view: response normalisation                                 */
/* ------------------------------------------------------------------ */

function asAccount(v) {
	if (!v || typeof(v) !== 'object')
		return null;

	return v;
}

function accountsOf(data) {
	var list = listData(data);
	var seen = {};
	var out = [];

	list.items.forEach(function(a) {
		if (!a || typeof(a) !== 'object' || a.id == null)
			return;
		if (seen[String(a.id)])
			return;
		seen[String(a.id)] = true;
		out.push(a);
	});

	return { items: out, updated_at: list.updated_at };
}

function endOf(list, updatedAt) {
	if (updatedAt != null)
		return updatedAt;

	var best = null;

	list.forEach(function(a) {
		var v = dec(a.period_end_at);
		if (isFinite(v) && v > 0 && (best == null || v > best))
			best = v;
	});

	return best;
}

var NetQuota = baseclass.extend({
	invoke: invoke,
	methods: METHODS,
	rpc: rpc,

	status: function() { return invoke('status'); },
	getSummary: function() { return invoke('get_summary'); },
	listAccounts: function() { return invoke('list_accounts'); },
	getAccount: function(id) { return invoke('get_account', { id: id }); },
	createAccount: function(p) { return invoke('create_account', p); },
	updateAccount: function(p) { return invoke('update_account', p); },
	deleteAccount: function(id) { return invoke('delete_account', { id: id }); },
	getTraffic: function() { return invoke('get_traffic'); },
	getSettings: function() { return invoke('get_settings'); },
	updateBilling: function(percent) { return invoke('update_billing', { traffic_multiplier_percent: percent }); },
	updateSettings: function(day, tz) { return invoke('update_settings', { default_reset_day: day, timezone: tz }); },
	getPortalInfo: function() { return invoke('get_portal_info'); },
	getDeployment: function() { return invoke('get_deployment'); },
	saveDeployment: function(p) { return invoke('save_deployment',p); },
	enableGuest: function(id) { return invoke('enable_guest',{wifi_section:id}); },
	setCapture: function(enabled) { return invoke('set_capture',{enabled:enabled}); },
	generateCertificate: function() { return invoke('generate_certificate'); },
	importCertificate: function(p) { return invoke('import_certificate',p); },
	getCertificate: function() { return invoke('get_certificate'); },

	/* formatting */
	bytes: bytes,
	billedBytes: billedBytes,
	bytesParts: bytesParts,
	gbToBytes: gbToBytes,
	bytesToGbInput: bytesToGbInput,
	pct: pct,
	pctLabel: pctLabel,
	usageClass: usageClass,
	initials: initials,
	accountNumber: accountNumber,
	count: count,
	dateFormatter: dateFormatter,

	/* data helpers */
	accountsOf: accountsOf,
	asAccount: asAccount,
	statusOf: statusOf,
	warningLevel: warningLevel,
	sortAccounts: sortAccounts,
	sum: sum,
	endOf: endOf,
	usernamePattern: USERNAME_RE,
	maxSafeInteger: MAX_SAFE_INTEGER,
	gbBytes: GB_BYTES,

	/* E() builders */
	icons: ICONS,
	icon: icon,
	statCard: statCard,
	usageTrack: usageTrack,
	usageCell: usageCell,
	userNameCell: userNameCell,
	statusBadge: statusBadge,
	emptyRow: emptyRow,
	notice: notice,
	errorBox: errorBox,
	skeleton: skeleton,
	pageHeader: pageHeader,
	actionButton: actionButton,
	panel: panel,
	tablePanel: tablePanel,
	updatedStamp: updatedStamp,
	field: field,
	input: input,
	select: select,
	formError: formError,
	setFormError: setFormError,
	resetDayOptions: resetDayOptions,

	/* interaction */
	openModal: openModal,
	closeModals: modalCloseAll,
	submitGuard: submitGuard,
	createPage: createPage,
	isEnvelope: isEnvelope,
	ws: ws
});

return NetQuota;

'require view';
'require netquota as NQ';

/*
 * About / diagnostics: honest service and compatibility information built only
 * from `status`. Every value is shown as reported; anything the backend omits
 * is displayed as “not reported” instead of being guessed.
 */

var FIELDS = [
	[ 'version', _('NetQuota 版本') ],
	[ 'backend', _('配额执行后端') ],
	[ 'controlled_interface', _('受控接口') ],
	[ 'egress', _('允许的出口设备') ],
	[ 'db_path', _('数据库路径') ],
	[ 'timezone', _('时区') ],
	[ 'firmware', _('固件版本') ],
	[ 'kernel', _('内核版本') ],
	[ 'architecture', _('处理器架构') ],
	[ 'opennds_version', _('openNDS 版本') ]
];

function value(v) {
	if (v == null)
		return E('span', { class: 'nq-muted' }, [ _('未上报') ]);

	if (Array.isArray(v))
		return v.length ? v.map(function(x) { return NQ.ws(x); }).join(', ') : E('span', { class: 'nq-muted' }, [ _('无') ]);

	if (typeof(v) === 'boolean')
		return v ? _('是') : _('否');

	var s = NQ.ws(v);

	return s === '' ? E('span', { class: 'nq-muted' }, [ _('未上报') ]) : s;
}

function boolChip(label, v) {
	if (v == null)
		return E('span', { class: 'nq-chip nq-chip-quiet' }, [ E('i', { class: 'nq-dot' }), label + ': ' + _('未上报') ]);

	if (v === true)
		return E('span', { class: 'nq-chip nq-chip-ok' }, [ E('i', { class: 'nq-dot' }), label ]);

	return E('span', { class: 'nq-chip nq-chip-warn' }, [ E('i', { class: 'nq-dot' }), label ]);
}

function systemPanel(model, ctx) {
	var s = model.status;
	var rows = FIELDS.map(function(f) {
		return E('div', { class: 'nq-fact' }, [
			E('dt', {}, [ f[1] ]),
			E('dd', {}, [ (f[0] === 'timezone' && model.fmt && model.fmt.timezone) ? model.fmt.timezone : value(s[f[0]]) ])
		]);
	});

	rows.push(E('div', { class: 'nq-fact' }, [
		E('dt', {}, [ _('最近一次数据落盘') ]),
		E('dd', {}, [ s.last_checkpoint != null ? (ctx.fmt ? ctx.fmt.datetime(s.last_checkpoint) : '—') : value(null) ])
	]));

	return NQ.panel(_('服务与平台信息'), _('由 NetQuota rpcd 对象返回的数值'), E('dl', { class: 'nq-facts' }, rows));
}

function statePanel(model) {
	var s = model.status;
	var quota = s.quota != null ? s.quota : s.quota_state;

	return NQ.panel(_('运行状态'), _('服务、采集与执行状态'), E('div', {}, [
		E('div', { class: 'nq-chip-row' }, [
			boolChip(_('服务运行中'), s.running),
			boolChip(_('流量采集已启用'), s.enabled),
			boolChip(_('配额引擎就绪'), (quota && typeof(quota) === 'object') ? quota.ready : quota)
		]),
		E('p', { class: 'nq-help' }, [
			_('“未上报”表示后端未返回该字段，本页不会自行推断。')
		])
	]));
}

function messagesPanel(model) {
	var errs = model.errors;
	var warns = model.warnings;

	if (errs.length === 0 && warns.length === 0)
		return NQ.panel(_('错误与告警'), _('由服务上报'), NQ.notice(_('服务未上报任何错误或告警。')));

	return NQ.panel(_('错误与告警'), _('由服务上报'), E('div', { class: 'nq-stack' }, [
		errs.length ? E('ul', { class: 'nq-msg-list nq-msg-error' }, errs.map(function(m) {
			return E('li', {}, [ NQ.ws(m) ]);
		})) : '',
		warns.length ? E('ul', { class: 'nq-msg-list nq-msg-warn' }, warns.map(function(m) {
			return E('li', {}, [ NQ.ws(m) ]);
		})) : ''
	]));
}

function compatibilityPanel() {
	return NQ.panel(_('兼容性说明'), _('已验证与待验证的内容'), E('div', { class: 'nq-stack' }, [
		E('ul', { class: 'nq-checklist' }, [
			check(true, _('GL-MT3000 · GL.iNet GL4.11 · OpenWrt 21.02 · fw3 环境下经 rpcd 提供数据的 LuCI JS 视图是本前端的参考目标。')),
			check(true, _('配额记账与执行由 netquota 后端和内核计数完成，本页仅用于展示。')),
			check(false, _('GL-MT6000 仍需硬件实测验证：固件 build、内核 ABI、硬件加速（HNAT/WED）与认证页 TLS 表现都必须在设备上实测。')),
			check(false, _('开启硬件加速可能导致客户端流量统计不准确，计量精度需以逐台设备的测试报告为准。'))
		])
	]));
}

function check(ok, text) {
	return E('li', { class: 'nq-check ' + (ok ? 'is-ok' : 'is-pending') }, [
		E('span', { class: 'nq-check-mark', 'aria-hidden': 'true' }, [ ok ? '\u2713' : '?' ]),
		E('span', {}, [ text ])
	]);
}

function scopePanel() {
	return NQ.panel(_('功能范围'), _('本版本不包含'), E('div', { class: 'nq-stack' }, [
		E('p', { class: 'nq-help' }, [
			_('包含：账号管理、按账号月度额度、上下行流量展示、用尽自动断网、下次结算日自动恢复。')
		]),
		E('p', { class: 'nq-help' }, [
			_('不包含：独立限速、手动断网或恢复、历史月份切换、数据导出与终端数量限制。')
		])
	]));
}

function render(model, ctx) {
	var out = [
		E('div', { class: 'nq-split' }, [ systemPanel(model, ctx), statePanel(model) ]),
		messagesPanel(model),
		E('div', { class: 'nq-split' }, [ compatibilityPanel(), scopePanel() ]),
		NQ.updatedStamp(model.updated_at, ctx.fmt, 30)
	];

	if (!model.status)
		out.unshift(NQ.notice(_('状态接口调用失败，无法获取平台信息；以下内容仅限本页说明。'), 'warn'));

	return out;
}

function toArray(v) {
	if (Array.isArray(v))
		return v;
	if (v == null)
		return [];
	if (typeof(v) === 'string')
		return NQ.ws(v) !== '' ? [ v ] : [];
	if (typeof(v) === 'object') {
		/* Some adapters report errors as a map keyed by subsystem. */
		return Object.keys(v).map(function(k) {
			return k + ': ' + NQ.ws(v[k]);
		});
	}
	return [ NQ.ws(v) ];
}

return view.extend({
	load: function() {
		return NQ.status().then(function(s) {
			return {
				status: s && typeof(s) === 'object' ? s : {},
				errors: toArray(s && s.errors),
				warnings: toArray(s && s.warnings),
				updated_at: (s && s.last_checkpoint != null) ? s.last_checkpoint : null
			};
		});
	},

	render: function() {
		var handle = E('div');

		NQ.createPage({
			target: handle,
			title: _('系统信息'),
			eyebrow: 'ABOUT',
			desc: _('NetQuota 插件及当前路由器环境信息。'),
			refreshSeconds: 30,
			needsSettings: true,
			load: this.load,
			render: render
		});

		return handle;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});

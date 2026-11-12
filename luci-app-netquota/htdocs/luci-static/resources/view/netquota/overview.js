'require view';
'require netquota as NQ';

/* Overview: account counts, actual/billed totals, top-five usage and attention. */

var ATTENTION_PERCENT = 80;
var RECENT_LIMIT = 8;
var TOP_LIMIT = 5;

function derive(status, accounts, updatedAt) {
	var items = accounts.items;
	var totals = { account_count: items.length, online_count: 0, exhausted_count: 0, at_risk_count: 0, total_bytes: 0, quota_bytes: 0, attention_count: 0 };

	items.forEach(function(a) {
		if (a.online === true)
			totals.online_count++;
		if (a.exhausted === true || NQ.pct(a.usage_percent) >= 100)
			totals.exhausted_count++;
		else if (NQ.pct(a.usage_percent) >= ATTENTION_PERCENT)
			totals.at_risk_count++;

		totals.total_bytes += NQ.billedBytes(a);
		if (typeof(a.quota_bytes) === 'number' && isFinite(a.quota_bytes))
			totals.quota_bytes += a.quota_bytes;
	});

	totals.attention_count = totals.at_risk_count + totals.exhausted_count;

	return {
		status: status,
		items: items,
		updated_at: updatedAt,
		totals: totals
	};
}

function sortRecent(items) {
	return items.slice().sort(function(x, y) {
		var cx = Number(x.created_at) || 0, cy = Number(y.created_at) || 0;
		if (cx !== cy)
			return cy - cx;
		return Number(y.id) - Number(x.id);
	});
}

function countCards(model) {
	var t = model.totals;
	var n = Math.max(1, t.account_count);

	return E('div', { class: 'nq-cards nq-account-counts' }, [
		NQ.statCard({
			label: _('账号总数'),
			icon: 'accounts',
			tone: 'blue',
			value: t.account_count,
			ratio: 0,
			foot: _('当前已创建的上网账号')
		}),
		NQ.statCard({
			label: _('在线账号'),
			icon: 'online',
			tone: 'green',
			value: t.online_count,
			ratio: t.online_count / n,
			gauge: 'green',
			foot: _('按账号去重的在线终端')
		}),
		NQ.statCard({
			label: _('流量用尽'),
			icon: 'exhausted',
			tone: 'red',
			value: t.exhausted_count,
			ratio: t.exhausted_count / n,
			gauge: 'red',
			foot: _('已自动限制联网，下次结算日恢复')
		})
	]);
}

function topUsage(model, fmt) {
	if (model.items.length === 0)
		return NQ.panel(_('账号流量使用排行'), _('当前周期计费用量前 %d 名').format(TOP_LIMIT),
			E('div', { class: 'nq-empty-inline' }, [ _('暂无账号，创建账号后开始统计流量。') ]));

	var ranked = model.items.slice().sort(function(x, y) {
		return (NQ.billedBytes(y) || 0) - (NQ.billedBytes(x) || 0) || String(x.username).localeCompare(String(y.username));
	}).slice(0, TOP_LIMIT);

	var max = 0;
	ranked.forEach(function(a) { max = Math.max(max, NQ.billedBytes(a) || 0); });

	var bars = ranked.map(function(a) {
		var p = NQ.pct(a.usage_percent);
		var width = max > 0 ? (Math.max(0, NQ.billedBytes(a) || 0) / max) * 100 : 0;
		var level = NQ.usageClass(p);

		return E('li', { class: 'nq-bar-row' }, [
			E('span', { class: 'nq-bar-name', title: String(a.username) }, [ String(a.username) ]),
			E('span', {
				class: 'nq-bar-track',
				role: 'progressbar',
				'aria-label': _('%s：已用 %s，共 %s').format(a.username, NQ.bytes(NQ.billedBytes(a)), NQ.bytes(a.quota_bytes)),
				'aria-valuemin': '0',
				'aria-valuemax': '100',
				'aria-valuenow': String(Math.round(p))
			}, [
				E('i', { class: 'nq-bar-fill nq-fill-' + level, style: 'width:' + width.toFixed(1) + '%' })
			]),
			E('span', { class: 'nq-bar-value' }, [ NQ.bytes(NQ.billedBytes(a)) ])
		]);
	});

	return NQ.panel(_('账号流量使用排行'), _('当前周期计费用量前 %d 名').format(TOP_LIMIT),
		E('div', {}, [
			E('div', { class: 'nq-total-line' }, [
				E('strong', {}, [ NQ.bytes(model.totals.total_bytes) ]),
				E('span', {}, [ _('合计') ]),
				E('span', { class: 'nq-total-sep', 'aria-hidden': 'true' }, [ '·' ]),
				E('span', {}, [ _('额度共 %s').format(NQ.bytes(model.totals.quota_bytes)) ])
			]),
			E('ul', { class: 'nq-bars' }, bars),
			E('div', { class: 'nq-legend', 'aria-hidden': 'true' }, [
				E('span', {}, [ E('i', { class: 'nq-key nq-fill-ok' }), _('正常使用') ]),
				E('span', {}, [ E('i', { class: 'nq-key nq-fill-warn' }), _('接近额度') ]),
				E('span', {}, [ E('i', { class: 'nq-key nq-fill-danger' }), _('用尽') ])
			])
		]),
		E('span', { class: 'nq-chip nq-chip-quiet' }, [ fmt ? fmt.datetime(model.updated_at) : '—' ]));
}

function attentionPanel(model) {
	var list = model.items.filter(function(a) {
		return NQ.pct(a.usage_percent) >= ATTENTION_PERCENT || a.exhausted === true;
	}).sort(function(x, y) {
		return NQ.pct(y.usage_percent) - NQ.pct(x.usage_percent);
	});

	var body;

	if (list.length === 0) {
		body = E('div', { class: 'nq-empty-inline' }, [ _('暂无账号用量达到额度的 %d%%。').format(ATTENTION_PERCENT) ]);
	}
	else {
		body = E('ul', { class: 'nq-mini-list' }, list.slice(0, 6).map(function(a) {
			var st = NQ.statusOf(a);
			return E('li', { class: 'nq-mini-item' }, [
				E('span', { class: 'nq-avatar nq-avatar-sm nq-avatar-' + st.cls, 'aria-hidden': 'true' }, [ NQ.initials(a.username) ]),
				E('span', { class: 'nq-mini-copy' }, [
					E('span', { class: 'nq-mini-name' }, [ String(a.username) ]),
					E('span', { class: 'nq-mini-sub' }, [ st.label ])
				]),
				E('span', { class: 'nq-mini-value nq-text-' + NQ.warningLevel(a) }, [
					NQ.pctLabel(a.usage_percent) + '%'
				])
			]);
		}));
	}

	return NQ.panel(_('需要关注'), _('用量达到 %d%% 或已用尽额度的账号').format(ATTENTION_PERCENT), body,
		E('span', { class: 'nq-chip nq-chip-' + (list.length ? 'warn' : 'quiet') }, [
			_('%d 个账号').format(list.length)
		]));
}

function recentTable(model, fmt, ctx) {
	var rows = sortRecent(model.items).slice(0, RECENT_LIMIT);

	var body = rows.length ? rows.map(function(a) {
		return E('tr', {}, [
			E('td', {}, [ NQ.userNameCell(a) ]),
			E('td', {}, [ NQ.usageCell(a) ]),
			E('td', { class: 'nq-num' }, [ NQ.bytes(a.quota_bytes) ]),
			E('td', {}, [ NQ.statusBadge(a) ]),
			E('td', { class: 'nq-num' }, [ fmt ? fmt.short(a.next_reset_at) : '—' ]),
			E('td', {}, [
				E('a', {
					href: L.url('admin/services/netquota/accounts') + '?detail=' + encodeURIComponent(String(a.id)),
					class: 'nq-link'
				}, [ _('详情') ])
			])
		]);
	}) : [ NQ.emptyRow(6, _('暂无账号。')) ];

	var headers = [
		{ label: _('账号') },
		{ label: _('本周期计费用量') },
		{ label: _('周期额度'), cls: 'nq-num' },
		{ label: _('状态') },
		{ label: _('结算日恢复'), cls: 'nq-num' },
		{ label: _('操作') }
	];

	return NQ.tablePanel(_('账号使用概况'), _('最近创建的账号'), null, headers, body,
		NQ.actionButton(_('查看全部账号'), {
			small: true,
			click: function(ev) {
				ev.preventDefault();
				window.location.href = L.url('admin/services/netquota/accounts');
			}
		}));
}

function render(model, ctx) {
	var warnings = [];

	if (model.status == null)
		warnings.push(NQ.notice(_('无法读取服务状态，以下数据仅来自账号列表。'), 'warn'));

	if (model.items.length === 0)
		warnings.push(NQ.notice(_('暂无账号，请进入“账号管理”创建第一个账号。')));

	return [
		countCards(model),
		NQ.trafficTotalCards(model.items),
		E('div', { class: 'nq-split' }, [ topUsage(model, ctx.fmt), attentionPanel(model) ]),
		recentTable(model, ctx.fmt, ctx),
		NQ.updatedStamp(model.updated_at, ctx.fmt, 20)
	].concat(warnings);
}

return view.extend({
	load: function() {
		return Promise.all([
			NQ.status().catch(function() { return null; }),
			NQ.listAccounts()
		]).then(function(r) {
			var accounts = NQ.accountsOf(r[1]);
			return derive(r[0], accounts, accounts.updated_at);
		});
	},

	render: function() {
		var handle = E('div');

		handle.host = NQ.createPage({
			target: handle,
			title: _('网络流量总览'),
			eyebrow: 'OVERVIEW',
			desc: _('账号状态与当前周期用量。数据由 rpcd 后台定时读取，不是实时速率看板。'),
			refreshSeconds: 20,
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

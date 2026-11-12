'require view';
'require netquota as NQ';

/*
 * Traffic: upload / download / total / shared quota progress and the current
 * period window with the next reset for every account. Values are shown only
 * when the backend supplies them; nothing is interpolated from missing fields.
 */

function totalsOf(items) {
	var t = { upload: 0, download: 0, total: 0, raw: 0, quota: 0, measured: 0, unknown: 0 };

	items.forEach(function(a) {
		var up = Number(a.upload_bytes);
		var down = Number(a.download_bytes);
		var total = NQ.billedBytes(a);
		t.raw += Number(a.total_bytes) || 0;

		if (isFinite(up) && isFinite(down)) {
			t.upload += up;
			t.download += down;
		}
		else {
			t.unknown++;
		}

		if (isFinite(total))
			t.total += total;
		else if (isFinite(up) && isFinite(down))
			t.total += up + down;

		if (isFinite(Number(a.quota_bytes)))
			t.quota += Number(a.quota_bytes);

		t.measured++;
	});

	return t;
}

function share(part, whole) {
	if (!isFinite(part) || !isFinite(whole) || whole <= 0)
		return 0;
	return (part / whole) * 100;
}

function summaryCards(model) {
	var t = model.totals;
	var upShare = share(t.upload, t.raw);
	var downShare = share(t.download, t.raw);

	return E('div', { class: 'nq-cards nq-traffic-totals' }, [
		NQ.statCard({
			label: _('实际上传'),
			icon: 'upload',
			tone: 'green',
			parts: NQ.bytesParts(t.upload),
			ratio: upShare / 100,
			gauge: 'green',
			foot: _('占实际流量 %s%%').format(NQ.pctLabel(upShare))
		}),
		NQ.statCard({
			label: _('实际下载'),
			icon: 'download',
			tone: 'amber',
			parts: NQ.bytesParts(t.download),
			ratio: downShare / 100,
			gauge: 'amber',
			foot: _('占实际流量 %s%%').format(NQ.pctLabel(downShare))
		})
	]);
}

function sharedBar(model) {
	var t = model.totals;
	var p = NQ.pct(share(t.total, t.quota));

	return NQ.panel(_('共享额度消耗'), _('各账号使用各自月度额度，此处为合计'), E('div', {}, [
		E('div', { class: 'nq-total-line' }, [
			E('strong', {}, [ NQ.bytes(t.total) ]),
			E('span', {}, [ _('计费用量，共') ]),
			E('strong', {}, [ NQ.bytes(t.quota) ])
		]),
		NQ.usageTrack(p, _('合计额度使用率 %s').format(NQ.pctLabel(p) + '%')),
		E('div', { class: 'nq-legend' }, [
			E('span', {}, [ E('i', { class: 'nq-key nq-fill-green' }), _('实际上传') + ' ' + NQ.bytes(t.upload) ]),
			E('span', {}, [ E('i', { class: 'nq-key nq-fill-blue' }), _('实际下载') + ' ' + NQ.bytes(t.download) ])
		]),
		t.unknown > 0 ? NQ.notice(_('%d 个账号未返回上下行计数，合计仅包含已上报的数据。')
			.format(t.unknown), 'warn') : ''
	]));
}

function rulesPanel(model) {
	return NQ.panel(_('流量统计说明'), _('统计口径与配额规则'), E('ul', { class: 'nq-rules' }, [
		rule(_('统计口径'), _('实际流量为上传 + 下载；计费用量按全局倍率扣减，修改仅影响后续流量')),
		rule(_('额度周期'), _('按账号重置日 00:00（配置时区）开始新周期')),
		rule(_('达到配额'), _('自动限制联网，认证页仍可访问')),
		rule(_('结算日恢复'), _('进入下个周期自动恢复额度，历史记录保留'))
	]));
}

function rule(label, text) {
	return E('li', { class: 'nq-rule' }, [
		E('span', { class: 'nq-rule-label' }, [ label ]),
		E('span', { class: 'nq-rule-text' }, [ text ])
	]);
}

function barsPanel(model) {
	var rows = model.items.slice().sort(function(x, y) {
		return (NQ.billedBytes(y) || 0) - (NQ.billedBytes(x) || 0);
	});

	if (rows.length === 0)
		return NQ.panel(_('账号流量消耗明细'), _('当前周期'), NQ.notice(_('暂无账号。')));

	var max = 0;
	rows.forEach(function(a) { max = Math.max(max, NQ.billedBytes(a) || 0); });

	return NQ.panel(_('账号流量消耗明细'), _('进度条以用量最高的账号为基准'), E('ul', { class: 'nq-bars' },
		rows.map(function(a) {
			var width = max > 0 ? ((NQ.billedBytes(a) || 0) / max) * 100 : 0;
			var p = NQ.pct(a.usage_percent);

			return E('li', { class: 'nq-bar-row' }, [
				E('span', { class: 'nq-bar-name', title: String(a.username) }, [ String(a.username) ]),
				E('span', {
					class: 'nq-bar-track',
					role: 'progressbar',
					'aria-label': _('%s 已用 %s，共 %s').format(a.username, NQ.bytes(NQ.billedBytes(a)), NQ.bytes(a.quota_bytes)),
					'aria-valuemin': '0',
					'aria-valuemax': '100',
					'aria-valuenow': String(Math.round(p))
				}, [ E('i', { class: 'nq-bar-fill nq-fill-' + NQ.usageClass(p), style: 'width:' + width.toFixed(1) + '%' }) ]),
				E('span', { class: 'nq-bar-value' }, [ NQ.bytes(NQ.billedBytes(a)) ])
			]);
		})));
}

function trafficTable(model, fmt) {
	var rows = model.items.slice().sort(function(x, y) {
		return (NQ.billedBytes(y) || 0) - (NQ.billedBytes(x) || 0);
	});

	var body = rows.length ? rows.map(function(a) {
		return E('tr', {}, [
			E('td', {}, [ NQ.userNameCell(a) ]),
			E('td', { class: 'nq-num' }, [ NQ.bytes(a.upload_bytes) ]),
			E('td', { class: 'nq-num' }, [ NQ.bytes(a.download_bytes) ]),
			E('td', { class: 'nq-num' }, [ NQ.bytes(a.total_bytes) ]),
			E('td', { class: 'nq-num nq-strong' }, [ NQ.bytes(NQ.billedBytes(a)) ]),
			E('td', { class: 'nq-num' }, [ NQ.bytes(a.quota_bytes) ]),
			E('td', {}, [ NQ.usageCell(a) ]),
			E('td', { class: 'nq-period-cell' }, [
				E('span', { class: 'nq-period-range' }, [
					(fmt ? fmt.short(a.period_start_at) : '—') + ' → ' + (fmt ? fmt.short(a.period_end_at) : '—')
				]),
				E('span', { class: 'nq-period-next' }, [
					_('下次重置：%s').format(fmt ? fmt.datetime(a.next_reset_at) : '—')
				])
			])
		]);
	}) : [ NQ.emptyRow(8, _('暂无流量记录，账号首次使用后显示数据。')) ];

	var headers = [
		{ label: _('账号') },
		{ label: _('实际上传'), cls: 'nq-num' },
		{ label: _('实际下载'), cls: 'nq-num' },
		{ label: _('实际合计'), cls: 'nq-num' },
		{ label: _('计费用量'), cls: 'nq-num' },
		{ label: _('周期额度'), cls: 'nq-num' },
		{ label: _('使用比例') },
		{ label: _('当前周期 / 下次重置') }
	];

	return NQ.tablePanel(_('账号当前周期流量明细'), _('仅显示当前周期；历史周期保留在路由器上但不在本页展示'),
		null, headers, body);
}

function render(model, ctx) {
	var out = [
		NQ.trafficTotalCards(model.items),
		summaryCards(model),
		E('div', { class: 'nq-split' }, [ sharedBar(model), rulesPanel(model) ]),
		barsPanel(model),
		trafficTable(model, ctx.fmt),
		NQ.updatedStamp(model.updated_at, ctx.fmt, 25)
	];

	if (model.items.length === 0)
		out.push(NQ.notice(_('暂无账号，没有可展示的流量数据。')));

	return out;
}

return view.extend({
	load: function() {
		return Promise.all([ NQ.getTraffic(), NQ.status().catch(function() { return null; }) ]).then(function(r) {
			var traffic = NQ.accountsOf(r[0]);
			var statusOk = (r[1] != null);

			return {
				items: traffic.items,
				updated_at: traffic.updated_at,
				totals: totalsOf(traffic.items),
				status: r[1],
				statusOk: statusOk
			};
		});
	},

	render: function() {
		var handle = E('div');

		NQ.createPage({
			target: handle,
			title: _('流量统计'),
			eyebrow: 'TRAFFIC',
			desc: _('各账号当前结算周期的流量用量，按十进制单位计算。'),
			refreshSeconds: 25,
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

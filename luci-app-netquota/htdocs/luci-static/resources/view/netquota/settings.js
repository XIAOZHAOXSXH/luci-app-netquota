'require view';
'require netquota as NQ';

/*
 * Settings: the global default reset day and the router timezone. Changes are
 * confirmed explicitly, apply from the next period, and never clear usage.
 */

var ZONES = [
	'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Taipei', 'Asia/Macau', 'Asia/Singapore',
	'Asia/Tokyo', 'Asia/Seoul', 'UTC'
];

function zoneKnown(tz) {
	return ZONES.indexOf(tz) >= 0;
}

function isValidZone(tz) {
	if (typeof(Intl) === 'undefined' || !Intl.DateTimeFormat)
		return /^[A-Za-z][A-Za-z0-9_+\-\/]*$/.test(tz);

	try {
		new Intl.DateTimeFormat('en-US', { timeZone: tz });
		return true;
	}
	catch (e) {
		return false;
	}
}

function currentPeriodNote(settings, accounts) {
	var tz = String(settings.timezone || '');
	var day = Number(settings.default_reset_day);
	var lines = [];

	lines.push(E('span', {}, [
		_('重置日为每个日历月的第 N 日 00:00（路由器时区）。短月取当月最后一天（31 日在 2 月为 28/29 日，3 月恢复为 31 日），日号不会漂移。')
	]));

	lines.push(E('span', { class: 'nq-block' }, [
		_('对继承系统默认的账号，变更在本次周期结束后生效；单独设置重置日的账号不受影响，已用流量不会被清空。')
	]));

	if (accounts > 0) {
		lines.push(E('span', { class: 'nq-block nq-text-warn' }, [
			_('当前已有 %d 个账号，为保持账本边界稳定，禁止更改时区；重置日仍可安排在下期变更。').format(accounts)
		]));
	}

	if (tz !== '' && !isValidZone(tz)) {
		lines.push(E('span', { class: 'nq-block nq-text-warn' }, [
			_('路由器时区“%s”不是本浏览器可识别的 IANA 名称，页面日期将按浏览器时区显示。').format(tz)
		]));
	}

	return lines;
}

function formPanel(model, ctx) {
	var settings = model.settings;
	var errNode = NQ.formError('nq-settings-error');
	var daySelect = NQ.select('nq-default-day', Array.from({ length: 31 }, function(value, i) {
		return { value: String(i + 1), label: _('每月 %d 日').format(i + 1) };
	}), String(settings.default_reset_day));

	var tz = String(settings.timezone || '');
	var zoneOptions = ZONES.map(function(z) {
		return { value: z, label: z };
	});

	if (tz !== '' && !zoneKnown(tz))
		zoneOptions.unshift({ value: tz, label: _('%s（路由器当前值）').format(tz) });

	var tzSelect = E('select', {
		id: 'nq-timezone',
		class: 'nq-select',
		disabled: model.accounts > 0 ? '' : null,
		'aria-describedby': 'nq-timezone-help'
	}, zoneOptions.map(function(o) {
		return E('option', { value: o.value, selected: (o.value === tz) ? '' : null }, [ o.label ]);
	}));

	var form = E('form', { class: 'nq-form', novalidate: '', submit: function(ev) {
		ev.preventDefault();
		confirmSave(Number(daySelect.value), String(tzSelect.value));
	} }, [
		NQ.field('nq-default-day', _('默认每月重置日'), daySelect,
			_('可选 1–31 日，适用于所有继承系统默认的账号。'), true),
		NQ.field('nq-timezone', _('时区'), tzSelect,
			_('IANA 时区名称。周期边界按该时区的 00:00 计算。'), true),
		NQ.notice(_('继承默认值的账号将从下个周期开始使用新设置；保存本页不会清空当前用量。')),
		errNode,
		E('div', { class: 'nq-form-actions' }, [
			NQ.actionButton(_('保存设置'), { primary: true, click: function(ev) {
				ev.preventDefault();
				confirmSave(Number(daySelect.value), String(tzSelect.value));
			} })
		])
	]);

	return NQ.panel(_('结算策略'), _('作用于未单独设置重置日的账号'), form,
		E('span', { class: 'nq-chip nq-chip-quiet' }, [
			_('当前：每月 %d 日 · %s').format(Number(settings.default_reset_day), tz || _('浏览器时区'))
		]));
}

function confirmSave(day, tz) {
	var problems = [];

	if (!(Math.floor(day) === day && day >= 1 && day <= 31))
		problems.push(_('重置日必须是 1–31 之间的整数。'));

	if (tz === '' || !isValidZone(tz))
		problems.push(_('请选择有效的 IANA 时区。'));

	if (problems.length) {
		var node = window.document.getElementById('nq-settings-error');

		if (node) {
			node.textContent = problems.join(' ');
			node.removeAttribute('hidden');
		}
		return;
	}

	NQ.openModal({
		id: 'nq-settings-confirm',
		title: _('确认变更结算策略'),
		subtitle: _('保存前请确认影响范围'),
		build: function(close, md) {
			var errNode = NQ.formError('nq-settings-confirm-error');

			function save() {
				NQ.setFormError(errNode, '');
				md.setBusy(true);

				return NQ.updateSettings(day, tz).then(function(data) {
					md.setBusy(false);
					close();
					var host = window.document.getElementById('nq-settings-flash');

					if (host) {
						host.textContent = _('结算策略已保存，将在下个周期生效。');
						host.classList.add('is-visible');
						window.setTimeout(function() { host.classList.remove('is-visible'); }, 5000);
					}

					var refresh = window.document.getElementById('nq-settings-refresh');

					if (refresh)
						refresh.click();

					return data;
				}, function(err) {
					md.setBusy(false);
					NQ.setFormError(errNode, err.message + ' (' + err.code + ')');
				});
			}

			md.submit = NQ.submitGuard(save, function(busy) { md.setBusy(busy); });

			return [
				E('dl', { class: 'nq-facts' }, [
					E('div', { class: 'nq-fact' }, [ E('dt', {}, [ _('默认重置日') ]), E('dd', {}, [ _('每月 %d 日').format(day) ]) ]),
					E('div', { class: 'nq-fact' }, [ E('dt', {}, [ _('时区') ]), E('dd', {}, [ tz ]) ])
				]),
				NQ.notice(_('此操作不会重置用量。继承默认值的账号将在当前周期结束后切换；单独设置的重置日保持不变。'), 'warn'),
				errNode
			];
		},
		buttons: [
			{ label: _('取消') },
			{ label: _('保存并确认'), primary: true, click: function(close, md) {
				md.submit();
			} }
		]
	});
}

function render(model, ctx) {
	return [
		E('div', { class: 'nq-split nq-split-wide' }, [
			formPanel(model, ctx),
			NQ.panel(_('周期规则说明'), _('该策略的实际影响'), E('div', { class: 'nq-stack' }, currentPeriodNote(model.settings, model.accountCount)),
				NQ.actionButton(_('刷新'), { small: true, icon: 'refresh', click: function(ev) {
					ev.preventDefault();
					var refresh = window.document.getElementById('nq-settings-refresh');
					if (refresh) refresh.click();
				} }))
		])
	];
}

return view.extend({
	load: function() {
		return Promise.all([
			NQ.getSettings(),
			NQ.listAccounts().then(function(d) { return NQ.accountsOf(d).items.length; }, function() { return null; })
		]).then(function(r) {
			if (!r[0] || typeof(r[0]) !== 'object')
				throw { code: 'protocol_error', message: _('get_settings 未返回任何设置') };

			return { settings: r[0], accountCount: r[1] };
		});
	},

	render: function() {
		var handle = E('div');

		NQ.createPage({
			target: handle,
			title: _('结算设置'),
			eyebrow: 'SETTINGS',
			desc: _('设置账号结算周期的默认重置日与时区。'),
			refreshSeconds: 30,
			needsSettings: false,
			load: this.load,
			render: function(model, ctx) {
				var out = render(model, ctx);

				out.push(E('button', {
					type: 'button',
					id: 'nq-settings-refresh',
					class: 'nq-visually-hidden',
					'aria-hidden': 'true',
					tabindex: '-1',
					click: function() { ctx.refresh(); }
				}));
				out.push(E('div', { class: 'nq-toast', id: 'nq-settings-flash', role: 'status', 'aria-live': 'polite' }));

				return out;
			}
		});

		return handle;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});

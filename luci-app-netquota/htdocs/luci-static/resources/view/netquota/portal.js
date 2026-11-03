'require view';
'require netquota as NQ';

/*
 * Portal preview: a static, labelled illustration of what a guest sees after
 * joining the controlled network. It never submits credentials and never calls
 * any portal endpoint from the administrator context; only read-only
 * get_portal_info / status data is shown next to it.
 */

function previewCard(info) {
	var secure=info && info.portal && info.portal.https_required===true;
	var userField = E('input', {
		type: 'text',
		class: 'nq-portal-input',
		id: 'nq-preview-user',
		placeholder: _('账号'),
		autocomplete: 'off',
		readonly: '',
		'aria-describedby': 'nq-preview-note'
	});

	var passField = E('input', {
		type: 'password',
		class: 'nq-portal-input',
		id: 'nq-preview-pass',
		placeholder: _('登录密码'),
		autocomplete: 'off',
		readonly: '',
		'aria-describedby': 'nq-preview-note'
	});

	return E('div', { class: 'nq-portal-stage', role: 'group', 'aria-label': _('认证页静态预览') }, [
		E('div', { class: 'nq-portal-card' }, [
			E('div', { class: 'nq-portal-brand' }, [
				E('span', { class: 'nq-portal-mark', 'aria-hidden': 'true' }, [ NQ.icon('online') ]),
				E('span', {}, [
					E('strong', {}, [ 'NetQuota' ]),
					E('small', {}, [ _('访客网络接入') ])
				])
			]),
			E('h3', { class: 'nq-portal-title' }, [ _('欢迎使用网络') ]),
			E('p', { class: 'nq-portal-desc' }, [ _('请输入网络管理员分配的上网账号，认证成功后即可连接互联网。') ]),
			E('label', { class: 'nq-label', for: 'nq-preview-user' }, [ _('账号') ]),
			userField,
			E('label', { class: 'nq-label', for: 'nq-preview-pass' }, [ _('登录密码') ]),
			passField,
			E('button', {
				type: 'button',
				class: 'nq-btn nq-btn-primary nq-portal-submit',
				disabled: '',
				'aria-describedby': 'nq-preview-note'
			}, [ _('登录并连接网络') ]),
			E('p', { class: 'nq-portal-links' }, [
				E('span', {}, [ _('修改我的登录密码') ])
			]),
			E('p', { class: 'nq-portal-foot' }, [
				NQ.icon(secure ? 'lock' : 'online'),
				secure ? _('HTTPS 加密认证 · 按账号独立计量') : _('HTTP 认证未加密 · 按账号独立计量')
			])
		])
	]);
}

function tlsState(info, status) {
	if(info && info.portal && info.portal.protocol==='http')
		return {known:true,ok:false,plain:true,label:_('HTTP 模式免证书，传输未加密')};
	var tls = (info && info.tls) || (status && status.tls) || null;

	if (tls == null)
		return { known: false, label: _('后端未返回该状态') };

	if (tls.enabled !== true)
		return { known: true, ok: false, label: _('认证页未启用 HTTPS') };

	if (tls.trusted === false || tls.self_signed === true)
		return { known: true, ok: false, label: _('HTTPS 证书不受客户端信任') };

	return { known: true, ok: false, label: _('HTTPS 已配置，客户端信任仍需验证') };
}

function infoPanel(model, ctx) {
	var info = model.info;
	var rows = [];
	var tls = tlsState(info, model.status);
	var url = info ? NQ.ws(info.portal_url || info.url) : '';

	if (url !== '') {
		var safe = /^https?:\/\/[^\s"'<>]+$/i.test(url);
		rows.push(E('div', { class: 'nq-fact' }, [
			E('dt', {}, [ _('认证页公开地址') ]),
			E('dd', {}, [
				safe
					? E('a', { href: url, rel: 'noopener noreferrer', target: '_blank', class: 'nq-link' }, [ url ])
					: E('code', { class: 'nq-code' }, [ url ])
			])
		]));
	}

	rows.push(E('div', { class: 'nq-fact' }, [
		E('dt', {}, [ _('传输安全') ]),
		E('dd', {}, [ E('span', { class: 'nq-chip nq-chip-' + (tls.plain ? 'warn' : tls.known ? (tls.ok ? 'ok' : 'danger') : 'quiet') }, [
			E('i', { class: 'nq-dot' }),
			tls.label
		]) ])
	]));

	if (info && NQ.ws(info.walled_garden) !== '')
		rows.push(E('div', { class: 'nq-fact' }, [ E('dt', {}, [ _('受限放行名单（Walled Garden）') ]), E('dd', {}, [ NQ.ws(info.walled_garden) ]) ]));

	if (info && info.self_service != null)
		rows.push(E('div', { class: 'nq-fact' }, [
			E('dt', {}, [ _('用户自助改密') ]),
			E('dd', {}, [ info.self_service === true ? _('认证页已提供') : _('未提供') ])
		]));

	if (info == null)
		rows.push(E('div', { class: 'nq-fact' }, [ E('dt', {}, [ _('认证页信息') ]), E('dd', {}, [ _('不可用') ]) ]));

	return NQ.panel(_('认证页部署信息'), _('来自 get_portal_info 的只读信息'),
		E('dl', { class: 'nq-facts nq-facts-single' }, rows),
		E('span', { class: 'nq-chip nq-chip-warn' }, [ _('仅预览') ]));
}

function checklist(info, status) {
	var tls = tlsState(info, status);
	var items = [
		{ ok: tls.plain || (tls.known && tls.ok), text: tls.plain ? _('当前使用 HTTP，免证书；账号传输未加密') : _('HTTPS 模式需使用客户端信任的证书') },
		{ ok: (info && NQ.ws(info.portal_url || info.url) !== '') === true, text: _('受控网络内可访问的固定认证页地址') },
		{ ok: true, text: _('账号配额由后端独立执行，不依赖认证页') },
		{ ok: true, text: _('额度用尽的账号仍可访问认证页进行自助操作') }
	];

	return NQ.panel(_('上线前检查'), _('正式认证页的前置条件'), E('ul', { class: 'nq-checklist' },
		items.map(function(it) {
			return E('li', { class: 'nq-check ' + (it.ok ? 'is-ok' : 'is-pending') }, [
				E('span', { class: 'nq-check-mark', 'aria-hidden': 'true' }, [ it.ok ? '\u2713' : '\u2022' ]),
				E('span', {}, [ it.text ])
			]);
		})));
}

function flowPanel() {
	return NQ.panel(_('用户认证流程'), _('受控网络内的认证过程'), E('ol', { class: 'nq-steps' }, [
		E('li', {}, [ _('终端连接受控 Wi-Fi，系统弹出网络认证提示。') ]),
		E('li', {}, [ _('若未自动弹出，用户打开任意 HTTP 网页即可触发认证页。') ]),
		E('li', {}, [ _('账号与密码按接管设置中的 HTTP 或 HTTPS 模式提交到本地认证服务。') ]),
		E('li', {}, [ _('认证成功后，该账号下所有终端共用同一份额度。') ])
	]));
}

/* Current epoch seconds as known by the browser clock; used only to label the
 * fetch time of the read-only portal facts, never as business data. */
function modelNow() {
	return Math.floor(new Date().getTime() / 1000);
}

function render(model, ctx) {
	return [
		NQ.notice(_('这是管理页面内的静态预览，不会提交凭证；真实认证页位于独立的本地门户服务，协议由“接管设置”选择。')),
		E('div', { class: 'nq-split nq-split-wide nq-portal-split' }, [
			previewCard(model.info),
			E('div', { class: 'nq-stack-wide' }, [ infoPanel(model, ctx), checklist(model.info, model.status), flowPanel() ])
		]),
		NQ.updatedStamp(model.updated_at, ctx.fmt, 30)
	];
}

return view.extend({
	load: function() {
		return Promise.all([
			NQ.getPortalInfo().catch(function(err) { return { __error: err }; }),
			NQ.status().catch(function() { return null; })
		]).then(function(r) {
			var info = r[0];

			if (info && info.__error)
				info = null;

			return { info: info, status: r[1], updated_at: modelNow() };
		});
	},

	render: function() {
		var handle = E('div');

		NQ.createPage({
			target: handle,
			title: _('认证页预览'),
			eyebrow: 'CAPTIVE PORTAL',
			desc: _('用户认证页的样式预览与部署信息。'),
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

'use strict';
'require view';
'require netquota as NQ';

var draft = null;
var busy = false;
var flash = '';
var error = '';
var certFile = null;
var keyFile = null;

function selected(model) {
	if (!draft) {
		var wifi = model.candidates.find(function(item) { return item.id === model.selected.wifi_section; }) ||
			model.candidates.find(function(item) { return /5[Gg]/.test(item.ssid); }) || model.candidates[0];
		var route = model.uplinks.find(function(item) { return (model.selected.egress || []).indexOf(item.device) >= 0; }) || model.uplinks[0];
		draft = {wifi_section:wifi ? wifi.id : '', egress:route ? route.device : '', portal_hostname:model.selected.portal_hostname || '',portal_mode:model.selected.portal_mode || 'http'};
	}
	return draft;
}

function waitApplied(attempt) {
	return NQ.getDeployment().then(function(model) {
		if (model.job.state === 'done') return model;
		if (model.job.state === 'failed') throw new Error(model.job.message);
		if (attempt >= 60) throw new Error(_('应用仍在进行，请刷新页面查看状态。'));
		return new Promise(function(resolve) { window.setTimeout(resolve, 1000); }).then(function() { return waitApplied(attempt + 1); });
	});
}

function action(fn, ctx) {
	if (busy) return Promise.resolve();
	busy = true; error = ''; flash = _('正在处理，请稍候…');
	ctx.refresh();
	return Promise.resolve().then(fn).then(function(result) {
		return (result.applying ? waitApplied(0) : Promise.resolve()).then(function() { flash = result.message || _('操作完成'); });
	}).catch(function(err) {
		error = err.message || String(err); flash = '';
	}).then(function() { busy = false; return ctx.refresh(); });
}

function button(label, fn, ctx, disabled, primary) {
	return NQ.actionButton(label, {primary:primary,disabled:busy || disabled,click:function() { action(fn,ctx); }});
}

function networkPanel(model, ctx) {
	var d = selected(model);
	var chosen = model.candidates.find(function(item) { return item.id === d.wifi_section; });
	var locked = model.enabled || busy;
	var wifi = NQ.select('nq-guest-wifi', model.candidates.map(function(item) {
		return {value:item.id,label:item.ssid + (item.enabled ? _('（已开启）') : _('（未开启）'))};
	}), d.wifi_section);
	wifi.disabled = locked;
	wifi.addEventListener('change', function() { d.wifi_section = wifi.value; ctx.refresh(); });
	var route = NQ.select('nq-uplink', model.uplinks.map(function(item) {
		var names={wan:_('有线上网'),wwan:_('无线中继'),tethering:_('USB 共享上网')};
		return {value:item.device,label:(names[item.network] || item.network) + (item === model.uplinks[0] ? _('（当前出口，推荐）') : '')};
	}), d.egress);
	route.disabled = locked;
	route.addEventListener('change', function() { d.egress = route.value; });
	var mode = NQ.select('nq-portal-mode',[
		{value:'http',label:_('HTTP · 免证书（默认）')},
		{value:'https',label:_('HTTPS · 加密认证（需配置证书）')}
	],d.portal_mode);
	mode.disabled=locked;
	mode.addEventListener('change',function() {d.portal_mode=mode.value;ctx.refresh();});
	var host = NQ.input('nq-portal-host',{value:d.portal_hostname,placeholder:_('留空使用访客网关 IP，例如 192.168.9.1')});
	host.disabled = locked;
	host.addEventListener('input', function() { d.portal_hostname = host.value.trim(); });
	return NQ.panel(_('1. 选择要接管的访客 Wi-Fi'), _('自动识别 GL 原厂访客网络和当前上网出口'), E('div',{class:'nq-form'},[
		NQ.field('nq-guest-wifi',_('访客 Wi-Fi'),wifi,_('仅列出原厂标记的访客 Wi-Fi，普通管理 Wi-Fi 不会被接管。'),true),
		NQ.notice(_('GL 的 2.4GHz 与 5GHz 访客 Wi-Fi 通常共用一个网络。接管作用于整个访客网络；其他访客频段若开启，也会要求认证。'),'warn'),
		NQ.field('nq-uplink',_('当前上网出口'),route,_('自动识别有线 WAN、无线中继等当前默认路由。更换上网方式后请重新检查。'),true),
		NQ.field('nq-portal-mode',_('认证协议'),mode,_('HTTP 无需证书；HTTPS 需要有效证书。切换后终端需要重新登录，已用流量保留。'),true),
		d.portal_mode==='http' ? NQ.notice(_('HTTP 不加密传输上网账号、密码和会话。请使用专用上网账号，不要复用管理密码或个人常用密码。'),'warn') : '',
		NQ.field('nq-portal-host',_('认证域名（可选）'),host,_('有可信域名证书时填写对应域名；插件自动添加本地 DNS 解析。仅试用可留空。')),
		E('div',{class:'nq-head-actions'},[
			button(_('保存网络设置'),function() { return NQ.saveDeployment(d); },ctx,model.enabled || !d.wifi_section || !d.egress,true),
			button(chosen && chosen.enabled ? _('所选访客 Wi-Fi 已开启') : _('开启所选访客 Wi-Fi'),function() { return NQ.enableGuest(d.wifi_section); },ctx,model.enabled || !d.wifi_section || (chosen && chosen.enabled))
		]),
		NQ.notice(model.enabled ? _('修改网络或证书前，请先停止接管。现有账号和流量不会被删除。') : _('开启已关闭的访客 Wi-Fi 时，同频无线可能短暂重连；不会修改普通 Wi-Fi 的名称或密码。'))
	]));
}

function chooseFile(id, label, type, current, set, ctx) {
	var input = E('input',{id:id,class:'nq-input',type:'file',accept:type,disabled:busy ? '' : null});
	input.addEventListener('change',function() {
		var file = input.files[0];
		if (!file) return;
		if (file.size > 32768) { error = _('文件不能超过 32KB'); ctx.refresh(); return; }
		var reader = new FileReader();
		reader.onload = function() { set({name:file.name,pem:String(reader.result)}); error=''; ctx.refresh(); };
		reader.onerror = function() { error=_('无法读取文件'); ctx.refresh(); };
		reader.readAsText(file);
	});
	return NQ.field(id,label,input,current ? _('已选择：%s').format(current.name) : _('选择 PEM 格式文件'));
}

function certificatePanel(model, ctx) {
	var cert = model.certificate;
	var disabled = model.enabled || !model.selected.wifi_section;
	var secure = window.location.protocol === 'https:';
	var upload = [];
	if (secure) {
		upload = [
			chooseFile('nq-cert-file',_('证书或完整证书链'),'.pem,.crt,.cer',certFile,function(value) { certFile=value; },ctx),
			chooseFile('nq-key-file',_('不带密码的私钥'),'.pem,.key',keyFile,function(value) { keyFile=value; },ctx),
			button(_('上传并校验证书'),function() {
				return NQ.importCertificate({certificate_pem:certFile.pem,private_key_pem:keyFile.pem}).then(function(result) {
					certFile=null; keyFile=null; draft=null; return result;
				});
			},ctx,disabled || !certFile || !keyFile,true)
		];
	} else {
		upload = [NQ.notice(_('上传私钥需要使用 HTTPS 管理页面，避免通过明文连接传输私钥。测试证书在路由器本地生成，无需上传。')),
			model.admin_https_port ? E('a',{class:'nq-link',href:'https://' + window.location.hostname + ':' + model.admin_https_port + window.location.pathname},[_('打开 HTTPS 管理页面上传证书')]) : ''];
	}
	var content=E('div',{class:'nq-form'},[
		NQ.notice(cert.message,cert.ready ? undefined : 'warn'),
		E('div',{class:'nq-head-actions'},[
			NQ.actionButton(cert.ready ? _('重新生成测试证书') : _('一键生成测试证书'),{primary:true,disabled:busy || disabled,click:function() {
				function generate() { return NQ.generateCertificate().then(function(result) {draft=null;return result;}); }
				if (!cert.ready) { action(generate,ctx); return; }
				NQ.openModal({title:_('替换当前门户证书'),build:function() {
					return NQ.notice(_('重新生成将替换当前证书。已信任旧证书的终端需要重新信任；正式域名证书也会被测试证书替换。'),'warn');
				},buttons:[{label:_('取消')},{label:_('确认重新生成'),primary:true,click:function(close) {
					close(); action(generate,ctx);
				}}]});
			}}),
			button(_('下载公共证书'),function() {
				return NQ.getCertificate().then(function(value) {
					var url=URL.createObjectURL(new Blob([value.certificate_pem],{type:'application/x-pem-file'}));
					var link=E('a',{href:url,download:value.filename}); link.click();
					window.setTimeout(function() { URL.revokeObjectURL(url); },1000);
					return {message:_('已下载公共证书，不包含私钥')};
				});
			},ctx,!cert.ready)
		]),
		NQ.notice(_('测试证书不能自动被手机信任。试用时需在终端信任证书或确认浏览器提示；正式客户应使用终端信任的域名证书。插件不能绕过浏览器的证书验证。'),'warn'),
		E('details',{open:secure && (certFile || keyFile) ? '' : null},[E('summary',{},[_('正式部署：上传已有证书')]),E('div',{class:'nq-form'},upload)]),
		cert.details ? E('details',{},[E('summary',{},[_('查看证书有效期和指纹')]),E('pre',{class:'nq-certificate-details'},[cert.details])]) : ''
	]);
	if(model.selected.portal_mode==='http') return NQ.panel(_('2. HTTPS 加密认证（可选）'),_('HTTP 模式可跳过此步骤，直接检查并启用接管'),[
		NQ.notice(_('当前为 HTTP，无需证书。成功生成或上传证书后会自动选择 HTTPS；也可在认证协议中切回 HTTP。')),
		E('details',{},[E('summary',{},[_('配置证书并切换到 HTTPS')]),content])
	]);
	return NQ.panel(_('2. 配置 HTTPS 门户证书'),_('生成或上传成功后选择 HTTPS，不需要 SSH'),content);
}

function capturePanel(model, ctx) {
	var label=model.active ? _('认证与配额已接管') : model.enabled ? _('接管已开启，正在等待就绪') : _('当前未接管，访客可按原厂规则上网');
	function confirm(enabled) {
		NQ.openModal({title:enabled ? _('启用访客认证和流量配额') : _('停止接管'),build:function() {
			return NQ.notice(enabled ? _('启用后，整个访客网络必须先登录 NetQuota 账号才能上网；已连接终端也会受控。管理 Wi-Fi 不受接管规则影响。') : _('停止后，访客恢复原厂普通上网，不再要求 NetQuota 认证。账号、已用流量和证书均保留。'),'warn');
		},buttons:[{label:_('取消')},{label:enabled ? _('确认启用接管') : _('确认停止接管'),primary:true,click:function(close) {
			close(); action(function() { return NQ.setCapture(enabled); },ctx);
		}}]});
	}
	return NQ.panel(_('3. 检查并启用接管'),label,E('div',{class:'nq-stack'},[
		E('ul',{class:'nq-checklist'},model.checks.map(function(item) {
			return E('li',{class:'nq-check ' + (item.ok ? 'is-ok' : 'is-pending')},[
				E('span',{class:'nq-check-mark'},[item.ok ? '✓' : '!']),
				E('div',{},[E('strong',{},[item.label]),!item.ok ? E('p',{class:'nq-help'},[item.message]) : ''])
			]);
		})),
		model.job.state === 'failed' ? NQ.notice(model.job.message,'warn') : '',
		E('div',{class:'nq-head-actions'},[
			NQ.actionButton(busy ? _('正在处理…') : model.enabled ? _('停止接管') : _('启用接管'),{
				primary:!model.enabled,disabled:busy || model.job.state==='applying' || (!model.enabled && !model.can_enable),
				click:function() { confirm(!model.enabled); }
			}),
			NQ.actionButton(_('重新检查'),{disabled:busy,click:function() { ctx.refresh(); }})
		]),
		E('div',{class:'nq-portal-access'},[
			E('strong',{},[_('访客认证地址')]),E('p',{},[E('code',{},[model.selected.url])]),
			E('p',{class:'nq-help'},[_('终端连接访客 Wi-Fi 后访问此地址，或打开 HTTP 网页触发跳转。管理页内的“认证页预览”不会实际登录。')])
		]),
		NQ.notice(_('先在“账号管理”创建上网账号并分配额度，再让终端连接访客 Wi-Fi 登录。同一账号的多个终端共享上传＋下载总额度。'))
	]));
}

return view.extend({
	load:function() { return NQ.getDeployment(); },
	render:function() {
		var handle=E('div');
		NQ.createPage({target:handle,title:_('访客网络接管设置'),eyebrow:'GUEST SETUP',
			desc:_('选择访客 Wi-Fi、配置门户证书，并在此启用或停止认证与流量配额。'),
			refreshSeconds:10,shouldRefresh:function() {
				return !busy && !document.querySelector('.netquota input:focus, .netquota select:focus, .netquota details[open]');
			},load:this.load,render:function(model,ctx) {
				return [error ? NQ.notice(error,'warn') : '',flash ? NQ.notice(flash) : '',
					!model.supported ? NQ.notice(_('当前设备未识别为支持的 GL 原厂配置，无法自动接管。'),'warn') : '',
					E('div',{class:'nq-stack'},[networkPanel(model,ctx),certificatePanel(model,ctx),capturePanel(model,ctx)])];
			}});
		return handle;
	},
	handleSaveApply:null,handleSave:null,handleReset:null
});

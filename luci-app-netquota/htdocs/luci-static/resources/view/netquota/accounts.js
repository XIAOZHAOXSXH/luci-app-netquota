'require view';
'require netquota as NQ';

/*
 * Accounts: searchable / filterable / sortable list, create and edit modal,
 * read-only detail modal and a guarded delete confirmation.
 *
 * Every value shown here comes from rpcd; nothing is cached in the browser and
 * no placeholder account data exists in this module.
 */

var QUOTA_PRESETS = [ 10, 20, 50, 100 ];
var USERNAME_RE = /^[A-Za-z0-9_-]{3,24}$/;
var PASSWORD_MIN = 8;
var PASSWORD_MAX = 128;
var ATTENTION_PERCENT = 80;

/* UTF-8 byte length, rejecting lone surrogates that would not encode. */
function utf8Length(s) {
	var bytes = 0;
	var i, c, next;

	for (i = 0; i < s.length; i++) {
		c = s.charCodeAt(i);

		if (c >= 0xD800 && c <= 0xDBFF) {
			next = (i + 1 < s.length) ? s.charCodeAt(i + 1) : 0;
			if (next < 0xDC00 || next > 0xDFFF)
				return -1;
			bytes += 4;
			i++;
		}
		else if (c >= 0xDC00 && c <= 0xDFFF) {
			return -1;
		}
		else if (c < 0x80) {
			bytes += 1;
		}
		else if (c < 0x800) {
			bytes += 2;
		}
		else {
			bytes += 3;
		}
	}

	return bytes;
}

function validatePassword(pw, required) {
	var len;

	if (pw === '' && !required)
		return null;

	if (pw === '')
		return _('请输入密码');

	len = utf8Length(pw);

	if (len < 0 || len < PASSWORD_MIN)
		return _('密码至少需要 %d 字节').format(PASSWORD_MIN);

	if (len > PASSWORD_MAX)
		return _('密码不能超过 %d 字节').format(PASSWORD_MAX);

	return null;
}

function validateUsername(name) {
	if (!USERNAME_RE.test(name))
		return _('用户名需为 3–24 位字母、数字、下划线或短横线');
	return null;
}

function accountStats(items) {
	var s = { total: items.length, online: 0, normal: 0, exhausted: 0 };

	items.forEach(function(a) {
		if (a.online === true)
			s.online++;
		if (a.exhausted === true || NQ.pct(a.usage_percent) >= 100)
			s.exhausted++;
		else
			s.normal++;
	});

	return s;
}

function filterList(items, query, status) {
	var q = String(query || '').trim().toLowerCase();

	return items.filter(function(a) {
		var p, exhausted;

		if (q !== '' && String(a.username).toLowerCase().indexOf(q) < 0)
			return false;

		p = NQ.pct(a.usage_percent);
		exhausted = (a.exhausted === true || p >= 100);

		if (status === 'online')
			return a.online === true && !exhausted;
		if (status === 'offline')
			return a.online !== true && !exhausted;
		if (status === 'exhausted')
			return exhausted;
		if (status === 'attention')
			return !exhausted && p >= ATTENTION_PERCENT;

		return true;
	});
}

function sortList(items, mode) {
	var list = items.slice();

	if (mode === 'used')
		list.sort(function(a, b) { return NQ.billedBytes(b) - NQ.billedBytes(a); });
	else if (mode === 'usage')
		list.sort(byNum('usage_percent'));
	else if (mode === 'created')
		list.sort(byNum('created_at'));
	else
		list = NQ.sortAccounts(list);

	return list;
}

function byNum(key) {
	return function(x, y) {
		var d = (Number(y[key]) || 0) - (Number(x[key]) || 0);
		if (d !== 0)
			return d;
		return String(x.username).localeCompare(String(y.username));
	};
}

function effectiveDay(a) {
	if (a.effective_reset_day != null && a.effective_reset_day !== '')
		return Number(a.effective_reset_day);
	if (a.reset_day != null && a.reset_day !== '')
		return Number(a.reset_day);
	return null;
}

function resetSummary(a) {
	var eff = effectiveDay(a);

	if (eff == null)
		return _('未知');

	if (a.reset_day == null || a.reset_day === '')
		return _('继承默认（每月 %d 日）').format(eff);

	return _('每月 %d 日').format(eff);
}

function hasPending(a) {
	return a.pending_effective_at != null || (a.pending_reset_day != null && a.pending_reset_day !== '');
}

function pendingSummary(a) {
	if (a.pending_inherit)
		return _('继承系统默认日');
	var day = Number(a.pending_reset_day);
	return day >= 1 && day <= 31 && Math.floor(day) === day
		? _('每月 %d 日').format(day) : _('重置日待确认');
}

/* ------------------------------------------------------------------ */
/* shared cards                                                        */
/* ------------------------------------------------------------------ */

function statsCards(model) {
	var s = model.stats;
	var n = Math.max(1, s.total);

	return E('div', { class: 'nq-cards' }, [
		NQ.statCard({ label: _('查看全部账号'), icon: 'accounts', tone: 'blue', value: s.total, foot: _('已创建的账号数量') }),
		NQ.statCard({ label: _('正常使用'), icon: 'online', tone: 'green', value: s.normal, ratio: s.normal / n, gauge: 'green', foot: _('额度内可正常联网') }),
		NQ.statCard({ label: _('在线'), icon: 'total', tone: 'blue', value: s.online, ratio: s.online / n, gauge: 'blue', foot: _('当前在线账号（去重）') }),
		NQ.statCard({ label: _('流量用尽'), icon: 'exhausted', tone: 'red', value: s.exhausted, ratio: s.exhausted / n, gauge: 'red', foot: _('到下次结算日恢复') })
	]);
}

/* ------------------------------------------------------------------ */
/* detail modal                                                        */
/* ------------------------------------------------------------------ */

function fact(label, value) {
	return E('div', { class: 'nq-fact' }, [
		E('dt', {}, [ label ]),
		E('dd', {}, [ value ])
	]);
}

function directionCard(label, bytes, share, tone) {
	var s = Math.max(0, Math.min(100, share));

	return E('div', { class: 'nq-direction-card nq-tone-' + tone }, [
		E('span', { class: 'nq-direction-label' }, [ label ]),
		E('strong', { class: 'nq-direction-value' }, [ NQ.bytes(bytes) ]),
		NQ.usageTrack(s, label + ': ' + NQ.pctLabel(s) + '%'),
		E('span', { class: 'nq-direction-share' }, [ _('占总用量 %s%%').format(NQ.pctLabel(s)) ])
	]);
}

function detailBody(acc, fmt) {
	var p = NQ.pct(acc.usage_percent);
	var st = NQ.statusOf(acc);
	var up = Number(acc.upload_bytes) || 0;
	var down = Number(acc.download_bytes) || 0;
	var total = up + down;
	var upShare = total > 0 ? (up / total) * 100 : 0;

	return [
		E('div', { class: 'nq-detail-hero' }, [
			E('span', { class: 'nq-avatar nq-avatar-lg nq-avatar-' + st.cls, 'aria-hidden': 'true' }, [ NQ.initials(acc.username) ]),
			E('div', { class: 'nq-detail-copy' }, [
				E('h4', { class: 'nq-detail-name' }, [ String(acc.username) ]),
				E('p', { class: 'nq-detail-meta' }, [
					_('账号 ID：%s').format(NQ.accountNumber(acc.id)),
					' · ',
					_('创建于 %s').format(fmt ? fmt.date(acc.created_at) : '—')
				]),
				E('p', { class: 'nq-detail-meta' }, [
					resetSummary(acc),
					' · ',
					_('在线会话 %d 个').format(Number(acc.session_count) || 0)
				]),
				E('div', { class: 'nq-detail-badges' }, [ NQ.statusBadge(acc) ])
			])
		]),
		E('div', { class: 'nq-detail-progress' }, [
			E('div', { class: 'nq-detail-progress-head' }, [
				E('span', {}, [ _('本周期计费用量') ]),
				E('strong', {}, [ NQ.pctLabel(p) + '%' ])
			]),
			NQ.usageTrack(p, _('额度使用率：%s').format(NQ.pctLabel(p) + '%'))
		]),
		E('dl', { class: 'nq-facts' }, [
			fact(_('已用计费流量'), NQ.bytes(NQ.billedBytes(acc))),
			fact(_('实际流量'), NQ.bytes(acc.total_bytes)),
			fact(_('当前计费倍率'), ((Number(acc.traffic_multiplier_percent) || 100) / 100).toFixed(2) + ' 倍'),
			fact(_('剩余流量'), NQ.bytes(acc.remaining_bytes)),
			fact(_('周期额度'), NQ.bytes(acc.quota_bytes)),
			fact(_('重置日'), resetSummary(acc)),
			fact(_('周期开始'), fmt ? fmt.datetime(acc.period_start_at) : '—'),
			fact(_('周期结束'), fmt ? fmt.datetime(acc.period_end_at) : '—'),
			fact(_('结算日恢复'), fmt ? fmt.datetime(acc.next_reset_at) : '—'),
			fact(_('在线会话'), String(Number(acc.session_count) || 0))
		]),
		E('div', { class: 'nq-direction' }, [
			directionCard(_('上传流量'), up, upShare, 'green'),
			directionCard(_('下载流量'), down, 100 - upShare, 'blue')
		]),
		hasPending(acc) ? NQ.notice(_('已安排重置日变更：自 %s 起改为 %s，当前用量保留。')
			.format(fmt ? fmt.datetime(acc.pending_effective_at) : '—',
				pendingSummary(acc)), 'warn') : '',
		NQ.notice(_('统计周期为 [%s, %s)，按 %s 时区显示；实际流量为本周期上传与下载之和；额度按计费用量扣减，倍率修改仅影响后续流量。')
			.format(fmt ? fmt.datetime(acc.period_start_at) : '—', fmt ? fmt.datetime(acc.period_end_at) : '—',
				(fmt && fmt.timezone) ? fmt.timezone : _('浏览器本地时区')))
	];
}

function openDetail(accountId, opts) {
	var id = Number(accountId);

	NQ.openModal({
		id: 'nq-detail',
		title: _('账号使用详情'),
		subtitle: _('查看该账号当前周期的额度与流量'),
		build: function(close, md) {
			var host = E('div', { class: 'nq-detail' }, [ NQ.skeleton(_('正在读取账号…')) ]);
			var errNode = NQ.formError('nq-detail-error');

			md.setBusy(true);

			NQ.getAccount(id).then(function(data) {
				host.replaceChildren.apply(host, detailBody(data, opts.fmt));
			}, function(err) {
				host.replaceChildren();
				NQ.setFormError(errNode, err.message + ' (' + err.code + ')');
				opts.onError(err);
			}).then(function() {
				md.setBusy(false);
			});

			return [ host, errNode ];
		},
		buttons: [
			{ label: _('关闭') },
			{ label: _('编辑账号'), primary: true, click: function(close) {
				close();
				opts.onEdit(id);
			} }
		]
	});
}

/* ------------------------------------------------------------------ */
/* account form modal                                                  */
/* ------------------------------------------------------------------ */

function openAccountForm(seed, opts) {
	var editing = !!seed;

	NQ.openModal({
		id: 'nq-account',
		title: editing ? _('编辑账号') : _('创建账号'),
		subtitle: editing
			? _('用户名不可修改；密码留空表示不修改。')
			: _('为用户创建独立账号与月度流量额度'),
		build: function(close, md) {
			var presetGb = seed ? Number(seed.quota_bytes) / 1000000000 : 50;
			var state = {
				preset: (!seed) ? '50' : (QUOTA_PRESETS.indexOf(presetGb) >= 0 ? String(presetGb) : 'custom')
			};

			var errNode = NQ.formError('nq-account-error');

			var usernameInput = NQ.input('nq-username', {
				maxlength: '24',
				placeholder: _('例如：guest-01'),
				value: seed ? String(seed.username) : '',
				readonly: editing ? '' : null,
				disabled: editing ? '' : null,
				'aria-required': editing ? null : 'true',
				tabindex: editing ? '-1' : null
			});

			var passwordInput = NQ.input('nq-password', {
				type: 'password',
				autocomplete: 'new-password',
				maxlength: '128',
				placeholder: editing
					? _('留空表示不修改密码')
					: _('至少 %d 个字符').format(PASSWORD_MIN),
				'aria-required': editing ? null : 'true'
			});

			var quotaInput = NQ.input('nq-quota', {
				type: 'text',
				inputmode: 'decimal',
				placeholder: '50',
				value: seed ? NQ.bytesToGbInput(seed.quota_bytes) : '50'
			});

			var resetSelect = NQ.select('nq-reset-day', NQ.resetDayOptions(_('继承系统默认日期')), '');
			var pendingNote = E('p', { class: 'nq-inline-note', hidden: '' });
			var chips = E('div', { class: 'nq-chip-group', role: 'group', 'aria-label': _('常用额度') });

			function paintChips() {
				chips.replaceChildren.apply(chips, QUOTA_PRESETS.map(function(gb) {
					var k = String(gb);
					return E('button', {
						type: 'button',
						class: 'nq-chip-btn' + (state.preset === k ? ' is-selected' : ''),
						'aria-pressed': state.preset === k ? 'true' : 'false',
						click: function(ev) {
							ev.preventDefault();
							state.preset = k;
							quotaInput.value = String(gb);
							paintChips();
						}
					}, [ gb + ' GB' ]);
				}).concat([
					E('button', {
						type: 'button',
						class: 'nq-chip-btn' + (state.preset === 'custom' ? ' is-selected' : ''),
						'aria-pressed': state.preset === 'custom' ? 'true' : 'false',
						click: function(ev) {
							ev.preventDefault();
							state.preset = 'custom';
							paintChips();
							try { quotaInput.focus(); } catch (e) { /* detached */ }
						}
					}, [ _('自定义') ])
				]));
			}

			paintChips();

			if (seed) {
				var plannedDay = hasPending(seed) ? seed.pending_reset_day : seed.reset_day;
				resetSelect.value = (plannedDay == null || plannedDay === '') ? '' : String(plannedDay);

				if (hasPending(seed)) {
					pendingNote.textContent = _('已安排自 %s 起改为 %s。')
						.format(opts.fmt ? opts.fmt.datetime(seed.pending_effective_at) : '—',
							pendingSummary(seed));
					pendingNote.removeAttribute('hidden');
				}
			}

			function save() {
				var username = String(usernameInput.value || '').trim();
				var password = String(passwordInput.value || '');
				var quota = NQ.gbToBytes(quotaInput.value);
				var dayRaw = resetSelect.value;
				var resetDay = (dayRaw === '') ? null : Number(dayRaw);
				var problem = null;
				var request;

				NQ.setFormError(errNode, '');

				if (!editing)
					problem = validateUsername(username);

				if (!problem)
					problem = validatePassword(password, !editing);

				if (!problem && (quota == null || quota <= 0 || quota > NQ.maxSafeInteger))
					problem = _('请输入有效的流量额度（GB，正数，最大 9,007,199.25 GB）。');

				if (!problem && resetDay != null && (Math.floor(resetDay) !== resetDay || resetDay < 1 || resetDay > 31))
					problem = _('重置日只能选择 1–31。');

				if (problem) {
					NQ.setFormError(errNode, problem);
					return Promise.resolve();
				}

				md.setBusy(true);

				request = editing
					? NQ.updateAccount({ id: Number(seed.id), password: password, quota_bytes: quota, reset_day: resetDay })
					: NQ.createAccount({ username: username, password: password, quota_bytes: quota, reset_day: resetDay });

				return request.then(function(data) {
					md.setBusy(false);
					close();
					opts.onSaved(editing
						? _('账号“%s”已更新。').format(String(seed.username))
						: _('账号“%s”创建成功。').format(username));
					return data;
				}, function(err) {
					md.setBusy(false);
					passwordInput.value = '';
					NQ.setFormError(errNode, err.message + ' (' + err.code + ')');
				});
			}

			/* Single-flight: repeated clicks or Enter presses are ignored until
			 * the request settles, so a slow backend cannot create duplicates. */
			md.submit = NQ.submitGuard(save, function(busy) { md.setBusy(busy); });

			var form = E('form', { class: 'nq-form', novalidate: '', submit: function(ev) {
				ev.preventDefault();
				md.submit();
			} }, [
				NQ.field('nq-username', _('用户名'), usernameInput,
					editing ? _('账号创建后用户名不可修改。')
						: _('3–24 位字母、数字、下划线或短横线，不区分大小写且不可重复。'),
					!editing),
				NQ.field('nq-password', editing ? _('新密码') : _('登录密码'), passwordInput,
					editing ? _('留空则不修改；修改后该账号所有在线会话将被断开。')
						: _('%d–%d 字节；路由器只保存加盐哈希。').format(PASSWORD_MIN, PASSWORD_MAX),
					!editing),
				NQ.field('nq-quota', _('每月流量额度（GB）'), quotaInput,
					_('十进制 GB（1 GB = 1,000,000,000 字节），提交前换算为精确整数。'),
					true),
				chips,
				NQ.field('nq-reset-day', _('每月流量重置日期'), resetSelect,
					editing
						? _('新日期将在下个周期开始时生效，当前用量不变。')
						: _('可选 1–31 日或继承系统默认；短月自动取当月最后一天。'),
					false),
				pendingNote,
				errNode
			]);

			window.setTimeout(function() {
				try {
					(editing ? passwordInput : usernameInput).focus();
				}
				catch (e) { /* detached */ }
			}, 40);

			return [
				form,
				NQ.notice(editing
					? _('额度修改立即生效。若新额度低于已用量，账号会立即被限制联网并断开在线会话。')
					: _('新账号从当前周期开始记账，初始用量为零。'))
			];
		},
		buttons: [
			{ label: _('取消') },
			{ label: _('保存账号'), primary: true, click: function(close, md) {
				md.submit();
			} }
		]
	});
}

/* ------------------------------------------------------------------ */
/* delete confirmation                                                 */
/* ------------------------------------------------------------------ */

function openDeleteConfirm(acc, opts) {
	NQ.openModal({
		id: 'nq-delete',
		title: _('删除账号'),
		subtitle: _('此操作无法撤销'),
		build: function(close, md) {
			var errNode = NQ.formError('nq-delete-error');

			function run() {
				NQ.setFormError(errNode, '');
				md.setBusy(true);

				return NQ.deleteAccount(acc.id).then(function(data) {
					md.setBusy(false);
					close();
					opts.onDeleted(_('账号“%s”已删除。').format(String(acc.username)));
					return data;
				}, function(err) {
					md.setBusy(false);
					NQ.setFormError(errNode, err.message + ' (' + err.code + ')');
				});
			}

			md.submit = NQ.submitGuard(run, function(busy) { md.setBusy(busy); });

			return [
				E('p', { class: 'nq-confirm-text' }, [
					_('确定删除账号“%s”？账号将从列表移除，所有在线会话会立即断开；旧账本保留供审计。')
						.format(String(acc.username))
				]),
				E('p', { class: 'nq-help' }, [ _('该操作无法恢复。') ]),
				errNode
			];
		},
		buttons: [
			{ label: _('取消') },
			{ label: _('删除账号'), danger: true, click: function(close, md) {
				md.submit();
			} }
		]
	});
}

/* ------------------------------------------------------------------ */
/* list rendering                                                      */
/* ------------------------------------------------------------------ */

function resetCell(a, fmt) {
	var pending = hasPending(a);

	return E('div', { class: 'nq-reset-cell' }, [
		E('span', { class: 'nq-reset-main' }, [ resetSummary(a) ]),
		pending ? E('span', { class: 'nq-reset-pending' }, [
			NQ.icon('clock'),
			_('下期起：%s').format(pendingSummary(a))
		]) : '',
		fmt ? E('span', { class: 'nq-reset-sub' }, [ _('%s 重置').format(fmt.short(a.next_reset_at)) ]) : ''
	]);
}

function accountRow(a, fmt, h) {
	return E('tr', {}, [
		E('td', {}, [ NQ.userNameCell(a) ]),
		E('td', {}, [ NQ.usageCell(a) ]),
		E('td', { class: 'nq-num' }, [ NQ.bytes(a.quota_bytes) ]),
		E('td', {}, [ resetCell(a, fmt) ]),
		E('td', { class: 'nq-num' }, [ fmt ? fmt.datetime(a.next_reset_at) : '—' ]),
		E('td', {}, [ NQ.statusBadge(a) ]),
		E('td', { class: 'nq-num' }, [ fmt ? fmt.date(a.created_at) : '—' ]),
		E('td', { class: 'nq-actions-cell' }, [
			E('button', { type: 'button', class: 'nq-link-btn', 'aria-label': _('查看 %s 的详情').format(String(a.username)),
				click: function(ev) { ev.preventDefault(); h.detail(a.id); } }, [ _('详情') ]),
			E('button', { type: 'button', class: 'nq-link-btn', 'aria-label': _('编辑 %s').format(String(a.username)),
				click: function(ev) { ev.preventDefault(); h.edit(a); } }, [ _('编辑') ]),
			E('button', { type: 'button', class: 'nq-link-btn nq-link-danger', 'aria-label': _('删除 %s').format(String(a.username)),
				click: function(ev) { ev.preventDefault(); h.remove(a); } }, [ _('删除') ])
		])
	]);
}

function filterSelect(id, label, options, value, onChange) {
	return E('span', { class: 'nq-filter' }, [
		E('label', { class: 'nq-sr-only', for: id }, [ label ]),
		E('select', {
			id: id,
			class: 'nq-select nq-select-sm',
			change: function(ev) { onChange(String(ev.target.value)); }
		}, options.map(function(o) {
			return E('option', { value: o.value, selected: (String(o.value) === String(value)) ? '' : null }, [ o.label ]);
		}))
	]);
}

/*
 * Controller for the list: keeps search / filter / sort state across refresh
 * repaints and owns the modal entry points.
 */
function createAccountsView() {
	var state = {
		items: [],
		query: '',
		status: 'all',
		sort: 'name',
		ctx: null,
		slots: null,
		toast: null,
		toastTimer: null
	};

	function flash(message) {
		if (!state.slots)
			return;

		if (state.toastTimer)
			window.clearTimeout(state.toastTimer);

		state.toast.textContent = message;
		state.toast.classList.add('is-visible');

		state.toastTimer = window.setTimeout(function() {
			state.toast.classList.remove('is-visible');
		}, 4000);
	}

	function afterWrite(message) {
		flash(message);
		if (state.ctx && state.ctx.refresh)
			state.ctx.refresh();
	}

	function find(id) {
		return state.items.filter(function(x) { return Number(x.id) === Number(id); })[0] || null;
	}

	function edit(acc) {
		if (!acc || acc.id == null) {
			flash(_('该账号已不在列表中，请刷新后重试。'));
			return;
		}

		openAccountForm(acc, { fmt: state.ctx.fmt, onSaved: afterWrite });
	}

	function detail(id) {
		openDetail(id, {
			fmt: state.ctx.fmt,
			onError: function(err) { flash(err.message); },
			onEdit: function(accId) {
				var known = find(accId);

				if (known) {
					edit(known);
					return;
				}

				NQ.getAccount(accId).then(function(data) {
					edit(data);
				}, function(err) {
					flash(err.message + ' (' + err.code + ')');
				});
			}
		});
	}

	function paintTable() {
		var h = {
			detail: detail,
			edit: edit,
			remove: function(acc) { openDeleteConfirm(acc, { onDeleted: afterWrite }); }
		};
		var filtered = sortList(filterList(state.items, state.query, state.status), state.sort);
		var rows = filtered.length
			? filtered.map(function(a) { return accountRow(a, state.ctx.fmt, h); })
			: [ NQ.emptyRow(8, state.items.length
				? _('没有找到匹配的账号。')
				: _('暂无账号，请先创建账号。')) ];

		var toolbar = E('div', { class: 'nq-toolbar-row' }, [
			E('div', { class: 'nq-search' }, [
				NQ.icon('accounts'),
				E('input', {
					type: 'search',
					class: 'nq-search-input',
					id: 'nq-account-search',
					placeholder: _('搜索用户名…'),
					'aria-label': _('按用户名搜索账号'),
					value: state.query,
					input: function(ev) {
						state.query = String(ev.target.value || '');
						paintTable();
					}
				})
			]),
			E('div', { class: 'nq-filters' }, [
				filterSelect('nq-status-filter', _('按状态筛选'), [
					{ value: 'all', label: _('全部状态') },
					{ value: 'online', label: _('在线') },
					{ value: 'offline', label: _('离线') },
					{ value: 'attention', label: _('接近额度') },
					{ value: 'exhausted', label: _('流量用尽') }
				], state.status, function(v) { state.status = v; paintTable(); }),
				filterSelect('nq-sort-filter', _('排序方式'), [
					{ value: 'name', label: _('按用户名排序') },
					{ value: 'usage', label: _('按使用比例从高到低') },
					{ value: 'used', label: _('按已用流量从高到低') },
					{ value: 'created', label: _('按创建时间从新到旧') }
				], state.sort, function(v) { state.sort = v; paintTable(); })
			])
		]);

		var headers = [
			{ label: _('账号') },
			{ label: _('本周期计费用量') },
			{ label: _('周期额度'), cls: 'nq-num' },
			{ label: _('重置日') },
			{ label: _('结算日恢复'), cls: 'nq-num' },
			{ label: _('状态') },
			{ label: _('创建时间'), cls: 'nq-num' },
			{ label: _('操作') }
		];

		var panel = NQ.tablePanel(_('查看全部账号'), _('管理账号信息、密码与月度流量额度'),
			toolbar, headers, rows, NQ.actionButton(_('刷新'), {
				small: true,
				icon: 'refresh',
				click: function(ev) {
					ev.preventDefault();
					if (state.ctx && state.ctx.refresh)
						state.ctx.refresh();
				}
			}));

		var foot = E('p', { class: 'nq-table-foot', 'aria-live': 'polite' }, [
			_('共 %d 个账号，当前显示 %d 个').format(state.items.length, filtered.length)
		]);

		state.slots.table.replaceChildren(panel, foot);
	}

	function render(model, ctx) {
		state.items = model.items;
		state.ctx = ctx;

		if (!state.slots) {
			state.slots = {
				cards: E('div', { class: 'nq-slot' }),
				table: E('div', { class: 'nq-slot' }),
				toast: E('div', { class: 'nq-slot nq-toast-slot', 'aria-live': 'polite' })
			};
			state.toast = E('div', { class: 'nq-toast' });
			state.slots.toast.replaceChildren(state.toast);
		}

		state.slots.cards.replaceChildren(statsCards({ stats: accountStats(state.items) }));
		state.slots.table.replaceChildren();

		paintTable();

		return E('div', { class: 'nq-accounts' }, [
			state.slots.cards,
			state.slots.table,
			NQ.updatedStamp(model.updated_at, ctx.fmt, 25),
			NQ.notice(_('同一账号可在多个终端登录，流量统一累计到该账号。本版本不包含独立限速、手动断网与历史导出。')),
			state.slots.toast
		]);
	}

	return {
		render: render,
		openCreate: function() {
			if (state.ctx)
				openAccountForm(null, { fmt: state.ctx.fmt, onSaved: afterWrite });
		}
	};
}

var controller = createAccountsView();


return view.extend({
	load: function() {
		return NQ.listAccounts().then(function(data) {
			return NQ.accountsOf(data);
		});
	},

	render: function() {
		var handle = E('div');

		NQ.createPage({
			target: handle,
			title: _('账号管理'),
			eyebrow: 'ACCOUNTS',
			desc: _('创建并管理上网账号，为每个账号分配独立的月度流量额度。'),
			refreshSeconds: 25,
			needsSettings: true,
			load: this.load,
			render: function(model, ctx) {
				return controller.render(model, ctx);
			},
			headerActions: function() {
				return [
					NQ.actionButton(_('创建账号'), {
						primary: true,
						icon: 'plus',
						click: function(ev) {
							ev.preventDefault();
							controller.openCreate();
						}
					})
				];
			}
		});

		return handle;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});

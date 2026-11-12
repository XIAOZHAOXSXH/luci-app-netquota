/* NetQuota guest portal client.
 * - Session token never reaches JavaScript: it lives only in the HttpOnly
 *   nq_session cookie.
 * - csrf_token is kept in sessionStorage (per tab, survives refresh) and sent
 *   back in the X-CSRF-Token header together with the Origin the browser adds.
 * - No localStorage, no inline handlers, no data persisted as truth.
 */
(function () {
  'use strict';

  var API = '/cgi-bin/api';
  var CSRF_KEY = 'nq.csrf';
  var USER_KEY = 'nq.user';
  var NET_KEY = 'nq.net';
  var REFRESH_MS = 15000;

  var state = {
    csrf: null,
    account: null,
    networkAuthorized: null,
    refTimer: null,
    config: null,
    busy: false
  };

  var $ = function (id) { return document.getElementById(id); };

  function on(id, ev, fn) {
    var el = $(id);
    if (el) { el.addEventListener(ev, fn); }
    return el;
  }

  /* ---------- formatting (decimal units: 1 KB = 1000 bytes) ---------- */
  function fmtBytes(n) {
    n = Number(n);
    if (!isFinite(n) || n < 0) { return '—'; }
    var units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    var i = 0;
    var v = n;
    while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
    var digits = (i === 0) ? 0 : (v < 10 ? 2 : (v < 100 ? 1 : 0));
    return v.toFixed(digits) + ' ' + units[i];
  }

  function fmtTime(epoch) {
    var n = Number(epoch);
    if (!isFinite(n) || n <= 0) { return '—'; }
    try {
      return new Date(n * 1000).toLocaleString('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit'
      });
    } catch (e) { return '—'; }
  }

  function pct(used, quota) {
    if (!quota || quota <= 0) { return 0; }
    var p = Math.floor((used / quota) * 100);
    return Math.max(0, Math.min(100, p));
  }

  /* ---------- basics ---------- */
  function show(id) {
    ['view-login', 'view-account', 'view-password', 'view-done'].forEach(function (v) {
      var el = $(v);
      if (el) { el.hidden = (v !== id); }
    });
    var main = $('main');
    if (main && typeof main.scrollIntoView === 'function') {
      try { main.scrollIntoView({ block: 'start' }); } catch (e) { /* ignore */ }
    }
  }

  function setText(id, text) {
    var el = $(id);
    if (el) { el.textContent = (text === null || text === undefined) ? '—' : String(text); }
  }

  function setAlert(id, message) {
    var el = $(id);
    if (!el) { return; }
    if (message) { el.textContent = message; el.hidden = false; } else { el.textContent = ''; el.hidden = true; }
  }

  function setBusy(buttonId, busy, label) {
    var b = $(buttonId);
    if (!b) { return; }
    if (busy) {
      if (!b.dataset.label) { b.dataset.label = b.textContent; }
      b.disabled = true;
      b.setAttribute('aria-busy', 'true');
      b.textContent = label || b.dataset.label;
    } else {
      b.disabled = false;
      b.removeAttribute('aria-busy');
      if (b.dataset.label) { b.textContent = b.dataset.label; }
    }
  }

  function badge(text, kind) {
    var el = $('service-badge');
    if (!el) { return; }
    el.textContent = text;
    el.className = 'badge ' + (kind || 'badge-muted');
  }

  var ERRORS = {
    https_required: '必须通过 HTTPS 访问本页面的功能。',
    origin_rejected: '请求来源校验失败，请重新载入页面后再试。',
    rate_limited: '尝试过于频繁，请稍后再试。',
    peer_rejected: '无法确认当前设备身份，请重新连接访客网络后再试。',
    unauthenticated: '登录会话已失效，请重新登录。',
    service_unavailable: '认证服务暂不可用，请稍后再试。',
    auth_failed: '账号或密码错误。',
    csrf_failed: '安全校验失败，请重新载入页面后再试。',
    invalid_request: '提交的内容无效，请检查后重试。',
    mismatch: '两次输入的新密码不一致。',
    weak_password: '新密码长度需为 8–128 个字符。',
    too_large: '提交内容过大。',
    internal_error: '服务暂时不可用，请稍后再试。',
    network_error: '安全连接未完成。请保持访客 Wi-Fi 连接；若使用测试证书，请在完整浏览器中确认信任后重试。'
  };

  function errorText(res, fallback) {
    if (res && res.error) {
      var code = String(res.error.code || '');
      if(code==='network_error' && window.location.protocol==='http:') return '认证连接中断，请保持访客 Wi-Fi 连接并刷新页面后重试。';
      if (ERRORS[code]) { return ERRORS[code]; }
      // Only use short server messages; ignore anything long or unexpected.
      var msg = String(res.error.message || '');
      if (msg && msg.length <= 80) { return msg; }
    }
    return fallback || '操作失败，请稍后再试。';
  }

  /* ---------- HTTP ---------- */
  function request(method, path, payload, withCsrf) {
    var opts = {
      method: method,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: { 'Accept': 'application/json' }
    };
    if (method === 'POST') {
      // Origin is set by the browser itself and checked server-side.
      opts.headers['Content-Type'] = 'application/json';
      if (withCsrf && state.csrf) {
        // Stock uhttpd does not export arbitrary request headers to CGI.
        // Keep the token in the HTTPS JSON body as well as the header.
        opts.headers['X-CSRF-Token'] = state.csrf;
        payload = Object.assign({}, payload || {}, { csrf_token: state.csrf });
      }
      opts.body = JSON.stringify(payload || {});
    }
    return fetch(path, opts).then(function (resp) {
      return resp.text().then(function (text) {
        var data = null;
        try { data = JSON.parse(text); } catch (e) { data = null; }
        if (!data) {
          return { ok: false, status: resp.status,
                   error: { code: resp.status === 401 ? 'unauthenticated' : 'internal_error' } };
        }
        data.status = resp.status;
        return data;
      });
    }).catch(function () {
      return { ok: false, status: 0, error: { code: 'network_error' } };
    });
  }

  function clearCsrf() {
    state.csrf = null;
    try {
      sessionStorage.removeItem(CSRF_KEY);
      sessionStorage.removeItem(USER_KEY);
      sessionStorage.removeItem(NET_KEY);
    } catch (e) { /* storage may be blocked */ }
  }

  function storeCsrf(token) {
    state.csrf = token;
    try { sessionStorage.setItem(CSRF_KEY, token); } catch (e) { /* ignore */ }
  }

  function readCsrf() {
    if (state.csrf) { return state.csrf; }
    try { state.csrf = sessionStorage.getItem(CSRF_KEY) || null; } catch (e) { state.csrf = null; }
    return state.csrf;
  }

  /* ---------- account rendering ---------- */
  function renderAccount(acct) {
    if (!acct) { return; }
    state.account = acct;
    setText('acct-username', acct.username || '—');
    var used = Number(acct.used_bytes || 0);
    var quota = Number(acct.quota_bytes || 0);
    var remaining = Math.max(0, quota - used);
    var p = pct(used, quota);

    setText('acct-used', fmtBytes(used));
    setText('acct-quota', fmtBytes(quota));
    setText('acct-remaining', fmtBytes(remaining));
    setText('acct-percent', p + '%');
    setText('acct-period-start', fmtTime(acct.period_start_at));
    setText('acct-period-end', fmtTime(acct.next_reset_at || acct.period_end_at));
    setText('acct-sessions', (acct.session_count === undefined || acct.session_count === null)
      ? '—' : String(acct.session_count));
    setText('acct-updated', fmtTime(Math.floor(Date.now() / 1000)));

    var bar = $('acct-progress-bar');
    var wrap = $('acct-progress');
    if (bar) {
      bar.style.width = p + '%';
      bar.className = 'progress-bar' + (acct.exhausted ? ' is-danger' :
        (p >= 80 ? ' is-warn' : ''));
    }
    if (wrap) { wrap.setAttribute('aria-valuenow', String(p)); }

    var exhausted = $('acct-exhausted');
    if (exhausted) { exhausted.hidden = !acct.exhausted; }
    var online = $('acct-online');
    if (online) {
      var authorized = state.networkAuthorized === true;
      online.hidden = !authorized || !!acct.exhausted;
    }
    setText('acct-session-note', '');
  }

  function stopRefresh() {
    if (state.refTimer) { clearInterval(state.refTimer); state.refTimer = null; }
  }

  function startRefresh() {
    stopRefresh();
    state.refTimer = setInterval(function () {
      var acctView = $('view-account');
      if (!acctView || acctView.hidden || document.hidden) { return; }
      if (state.busy) { return; }
      refreshAccount(true);
    }, REFRESH_MS);
  }

  function privateView() {
    var showed = false;
    var acct = $('view-account');
    var pw = $('view-password');
    if (acct && !acct.hidden) { showed = true; }
    if (pw && !pw.hidden) { showed = true; }
    return showed;
  }

  function toLogin() {
    clearCsrf();
    state.account = null;
    state.networkAuthorized = null;
    stopRefresh();
    show('view-login');
    setAlert('login-error', '');
    var pw = $('login-password');
    if (pw) { pw.value = ''; }
  }

  function openAccount() {
    if (!readCsrf()) {
      // Refresh lost the CSRF token (sessionStorage unavailable): force login.
      toLogin();
      setAlert('login-error', '请重新登录以继续。');
      return;
    }
    show('view-account');
    setAlert('acct-error', '');
    refreshAccount(false);
    startRefresh();
  }

  function refreshAccount(quiet) {
    if (state.busy) { return Promise.resolve(); }
    state.busy = true;
    if (!quiet) { setBusy('acct-refresh', true, '刷新中…'); }
    return request('GET', API + '/account').then(function (res) {
      state.busy = false;
      if (!quiet) { setBusy('acct-refresh', false); }
      if (res.ok && res.data && res.data.account) {
        setAlert('acct-error', '');
        renderAccount(res.data.account);
      } else if (res.status === 401) {
        toLogin();
        setAlert('login-error', ERRORS.unauthenticated);
      } else if (!quiet) {
        setAlert('acct-error', errorText(res, '暂时无法获取用量。'));
      }
    });
  }

  /* ---------- bootstrap ---------- */
  function applyConfig(cfg) {
    state.config = cfg || {};
    var tls = $('tls-status');
    var plain=cfg && cfg.protocol==='http';
    if (tls) { tls.textContent = plain ? '未加密（HTTP）' : (cfg && cfg.tls_trust === 'unverified' ? 'HTTPS（证书信任由浏览器验证）' : '未知'); }
    setText('login-transmission-note',plain ? '当前使用 HTTP，账号、密码和会话不受传输加密保护。请仅使用专用上网账号，不要复用管理密码或个人常用密码。' : '凭据通过 HTTPS 提交。试用证书首次访问需要在完整浏览器中确认信任；无法确认的证书请联系管理员，勿提交密码。');
    setText('tls-note', (cfg && cfg.tls_note) || '');
    setText('version-label', 'v' + ((cfg && cfg.version) || ''));

    var problems = [];
    if (!cfg) { problems.push('无法获取门户配置。'); }
    if (cfg && cfg.service === 'misconfigured') { problems.push('门户配置不可用，管理员尚未完成部署。'); }
    if (cfg && cfg.service === 'unavailable') { problems.push('认证服务暂不可用，请稍后再试。'); }
    setAlert('global-alert', problems.length ? problems.join(' ') : '');

    if (!cfg || cfg.service !== 'ready') {
      badge(cfg && cfg.service === 'misconfigured' ? '配置不完整' : '服务不可用',
        cfg && cfg.service === 'misconfigured' ? 'badge-warn' : 'badge-danger');
      var submit = $('login-submit');
      if (submit) { submit.disabled = true; }
    } else {
      badge('服务正常', 'badge-ok');
      var s2 = $('login-submit');
      if (s2) { s2.disabled = false; }
    }
  }

  function boot() {
    request('GET', API + '/status').then(function (res) {
      if (!res.ok) {
        applyConfig(null);
        show('view-login');
        if (res.status === 0) {
          badge(window.location.protocol==='https:' ? '安全连接未建立' : '认证连接未建立', 'badge-warn');
          setAlert('global-alert', errorText(res));
        } else {
          badge('服务暂不可用', 'badge-danger');
          setAlert('global-alert', errorText(res));
        }
        return;
      }
      var data = res.data || {};
      applyConfig(data.config);
      if (data.session && data.session.account) {
        renderAccount(data.session.account);
        if (readCsrf()) {
          openAccount();
          return;
        }
        // We can see the account but have no CSRF token in this tab: offer
        // viewing; mutations will ask for a fresh login.
        openAccount();
        setAlert('acct-error', '当前标签页缺少安全令牌，如需修改密码请重新登录。');
        return;
      }
      show('view-login');
    });
  }

  /* ---------- login ---------- */
  function bindLogin() {
    on('login-form', 'submit', function (ev) {
      ev.preventDefault();
      setAlert('login-error', '');
      var u = ($('login-username') || {}).value || '';
      var p = ($('login-password') || {}).value || '';
      u = u.trim();
      if (u.length < 3 || u.length > 24 || !/^[A-Za-z0-9_-]+$/.test(u)) {
        setAlert('login-error', '请输入 3–24 位字母、数字、下划线或短横线组成的账号。');
        return;
      }
      if (p.length < 8 || p.length > 128) {
        setAlert('login-error', '请输入正确的密码。');
        return;
      }
      var payload = { username: u, password: p };
      setBusy('login-submit', true, '登录中…');
      request('POST', API + '/login', payload, false).then(function (res) {
        setBusy('login-submit', false);
        var pw = $('login-password');
        if (pw) { pw.value = ''; }
        if (!res.ok || !res.data) {
          setAlert('login-error', errorText(res, '登录失败，请稍后再试。'));
          return;
        }
        storeCsrf(res.data.csrf_token || null);
        state.networkAuthorized = res.data.network_authorized === true;
        try { sessionStorage.setItem(NET_KEY, state.networkAuthorized ? '1' : '0'); } catch (e) { /* ignore */ }
        renderAccount(res.data.account);
        var exhausted = !!(res.data.account && res.data.account.exhausted) ||
          !state.networkAuthorized;
        var de = $('done-exhausted');
        if (de) { de.hidden = !exhausted; }
        setText('done-message', state.networkAuthorized
          ? '已获得上网权限，可以正常访问互联网。'
          : '账号验证成功，但当前不会获得上网权限。');
        show('view-done');
      });
    });
  }

  function bindPasswordToggle() {
    var btn = on('login-toggle-pw', 'click', function () {
      var pw = $('login-password');
      if (!pw) { return; }
      var showing = pw.type === 'text';
      pw.type = showing ? 'password' : 'text';
      btn.setAttribute('aria-pressed', showing ? 'false' : 'true');
      btn.textContent = showing ? '显示' : '隐藏';
    });
    return btn;
  }

  /* ---------- password change ---------- */
  function bindAccount() {
    on('done-account', 'click', openAccount);
    on('acct-refresh', 'click', function () { refreshAccount(false); });
    on('acct-to-password', 'click', function (ev) {
      ev.preventDefault();
      setAlert('password-error', '');
      setAlert('password-ok', '');
      ['pw-old', 'pw-new', 'pw-confirm'].forEach(function (id) {
        var el = $(id);
        if (el) { el.value = ''; }
      });
      show('view-password');
      var first = $('pw-old');
      if (first) { first.focus(); }
    });
    on('password-cancel', 'click', function () {
      setAlert('password-error', '');
      setAlert('password-ok', '');
      openAccount();
    });

    on('logout-btn', 'click', function () {
      if (!readCsrf()) { toLogin(); return; }
      setBusy('logout-btn', true, '退出中…');
      request('POST', API + '/logout', {}, true).then(function (res) {
        setBusy('logout-btn', false);
        stopRefresh();
        toLogin();
        if (!res.ok && res.status !== 401) {
          setAlert('login-error', '已退出本页登录状态。');
        }
      });
    });

    on('password-form', 'submit', function (ev) {
      ev.preventDefault();
      setAlert('password-error', '');
      setAlert('password-ok', '');
      var oldPw = ($('pw-old') || {}).value || '';
      var newPw = ($('pw-new') || {}).value || '';
      var confirmPw = ($('pw-confirm') || {}).value || '';
      if (newPw !== confirmPw) {
        setAlert('password-error', ERRORS.mismatch);
        return;
      }
      if (newPw.length < 8 || newPw.length > 128) {
        setAlert('password-error', ERRORS.weak_password);
        return;
      }
      if (!readCsrf()) {
        toLogin();
        setAlert('login-error', '安全令牌缺失，请重新登录后再修改密码。');
        return;
      }
      setBusy('password-submit', true, '保存中…');
      request('POST', API + '/password', {
        old_password: oldPw,
        new_password: newPw,
        confirm_password: confirmPw
      }, true).then(function (res) {
        setBusy('password-submit', false);
        if (res.ok && res.data) {
          stopRefresh();
          clearCsrf();
          state.networkAuthorized = null;
          setAlert('password-ok', res.data.message || '密码已修改。');
          setTimeout(function () {
            toLogin();
            setAlert('login-error', '密码已修改，全部会话已退出。请使用新密码重新登录。');
          }, 2500);
          return;
        }
        if (res.status === 401) {
          toLogin();
          setAlert('login-error', ERRORS.unauthenticated);
          return;
        }
        setAlert('password-error', errorText(res, '密码修改失败。'));
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    bindLogin();
    bindPasswordToggle();
    bindAccount();
    boot();
  });
}());

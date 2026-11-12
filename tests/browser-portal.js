// Requires authenticated admin page, router-guest-client.sh and guest_browser_proxy.py.
// Creates/deletes only an isolated fixture account, then tests the real guest HTML/JS,
// HTTP/HTTPS transport and CGI through the actual guest namespace. No successful response
// is mocked; one status request is deliberately aborted to test connection errors.
async (page) => {
  const setup=await page.evaluate(async()=>{const nq=await L.require('netquota');return nq.getDeployment()});
  const url=setup.selected.url;
  const secure=url.startsWith('https:');
  const account={username:'web_'+Date.now().toString(36),password:'Fixture-only-Portal-123',quota_bytes:2000000};
  const created=await page.evaluate(async value => {
    const nq=await L.require('netquota'); return nq.createAccount(value);
  },account);
  const context=await page.context().browser().newContext({ignoreHTTPSErrors:secure,
    proxy:{server:'http://127.0.0.1:51255'},viewport:{width:390,height:844},
    userAgent:'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36'});
  const guest=await context.newPage();
  const errors=[];
  guest.on('pageerror',error=>errors.push(error.message));
  try {
    await guest.goto(url);
    await guest.getByText('服务正常',{exact:true}).waitFor();
    await guest.locator('#login-username').fill(account.username);
    await guest.locator('#login-password').fill(account.password);
    await guest.locator('#login-submit').click();
    await guest.locator('#view-done').waitFor({state:'visible'});
    const cookies=await context.cookies(url);
    const cookie=cookies.find(c=>c.name===(secure ? 'nq_session' : 'nq_session_http'));
    if(!cookie || cookie.secure!==secure || !cookie.httpOnly)throw new Error('Wrong protocol cookie');
    if(!secure && !(await guest.locator('#tls-status').innerText()).includes('HTTP'))throw new Error('Missing HTTP transport label');
    await guest.locator('#done-account').click();
    await guest.locator('#view-account').waitFor({state:'visible'});
    await guest.waitForFunction(value=>document.querySelector('#acct-username').textContent===value,account.username);
    const publicAccount=await guest.evaluate(async()=> (await (await fetch('/cgi-bin/api/account')).json()).data.account);
    for(const key of ['upload_bytes','download_bytes','total_bytes','billed_bytes','traffic_multiplier_percent'])
      if(key in publicAccount) throw new Error('Guest API exposes admin billing detail: '+key);
    const accountText=await guest.locator('#view-account').innerText();
    if(/虚标|倍率|计费|实际上传|实际下载|实际流量/.test(accountText))
      throw new Error('Guest account view exposes admin billing policy');
    await guest.getByText('已用流量',{exact:true}).waitFor();
    await guest.locator('#logout-btn').click();
    await guest.locator('#view-login').waitFor({state:'visible'});
    // Real page, but a deliberately failed API exchange. It must not claim
    // the router backend has stopped when transport cannot be established.
    await guest.route('**/cgi-bin/api/status',route=>route.abort('failed'));
    await guest.reload();
    await guest.getByText(secure ? '安全连接未建立' : '认证连接未建立',{exact:true}).waitFor();
    const message=await guest.locator('#global-alert').innerText();
    if(!message.includes(secure ? '完整浏览器' : '访客 Wi-Fi') || !await guest.locator('#login-submit').isDisabled())
      throw new Error('Connection/trust guidance missing');
    if(errors.length) throw new Error(errors.join('; '));
    return {protocol:secure ? 'https':'http',realGuestBrowserLogin:true,cookieIsolation:true,accountView:true,adminBillingDetailsHidden:true,logout:true,transportFailureGuidance:true,pageErrors:errors};
  }
  finally {
    await context.close();
    await page.evaluate(async id=>{const nq=await L.require('netquota');return nq.deleteAccount(id)},created.id);
  }
}

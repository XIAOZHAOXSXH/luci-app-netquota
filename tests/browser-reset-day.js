// Run in an authenticated LuCI session against installed code and real RPC.
// Creates and deletes only its own account; never changes global reset settings.
async page => {
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  const noCache = route => route.continue();
  await page.route('**/*', noCache);
  const username = 'reset_' + Date.now().toString(36);
  const origin = new URL(page.url()).origin;
  const created = await page.evaluate(async username => {
    const nq = await L.require('netquota');
    return nq.createAccount({username, password:'Fixture-reset-123', quota_bytes:5000000000, reset_day:null});
  }, username);
  const account = () => page.evaluate(async id => (await L.require('netquota')).getAccount(id), created.id);
  const row = () => page.locator('tr').filter({has:page.getByText(username, {exact:true})});
  async function openEditor() {
    await row().getByRole('button', {name:'编辑 ' + username, exact:true}).click();
    await page.locator('#nq-quota').waitFor();
  }
  async function save() {
    await page.getByRole('button', {name:'保存账号', exact:true}).click();
    await page.locator('.nq-owned-modal').waitFor({state:'detached'});
    await page.locator('.nq-table-panel').getByRole('button', {name:'刷新', exact:true}).click();
    await row().waitFor();
  }
  try {
    await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/accounts');
    await row().waitFor();
    const before = await account();
    await openEditor();
    await page.locator('#nq-quota').fill('10');
    await save();
    const quotaOnly = await account();
    if (quotaOnly.quota_bytes !== 10000000000 || quotaOnly.pending_effective_at != null ||
        quotaOnly.period_end_at !== before.period_end_at || quotaOnly.total_bytes !== before.total_bytes)
      throw new Error('Quota-only save changed the reset schedule or usage');
    if (await row().locator('.nq-reset-pending').count()) throw new Error('Spurious pending reset label');

    const nextDay = before.effective_reset_day === 15 ? 20 : 15;
    await openEditor();
    await page.locator('#nq-reset-day').selectOption(String(nextDay));
    await save();
    const explicit = await account();
    if (explicit.pending_reset_day !== nextDay || explicit.pending_effective_at !== before.period_end_at)
      throw new Error('Explicit reset day was not staged for next period');
    await page.waitForFunction(day => [...document.querySelectorAll('.nq-reset-pending')]
      .some(n => n.textContent.includes('每月 ' + day + ' 日')), nextDay);
    await openEditor();
    await page.locator('#nq-quota').fill('12');
    await save();
    if ((await account()).pending_reset_day !== nextDay) throw new Error('Quota save lost pending explicit day');

    // Switch an explicit account to inheritance: all three UI locations must
    // show the inheritance label, even though pending_reset_day is absent.
    await page.evaluate(async value => {
      const nq = await L.require('netquota');
      await nq.deleteAccount(value.id);
    }, created);
    const replacement = await page.evaluate(async value => {
      const nq = await L.require('netquota');
      return nq.createAccount({username:value.username, password:'Fixture-reset-123', quota_bytes:5000000000,
        reset_day:value.day});
    }, {username:username + 'i', day:nextDay});
    created.id = replacement.id;
    await page.evaluate(async id => {
      const nq = await L.require('netquota');
      return nq.updateAccount({id, quota_bytes:10000000000, password:'', reset_day:null});
    }, created.id);
    await page.reload();
    const inheritRow = page.locator('tr').filter({has:page.getByText(username + 'i', {exact:true})});
    await inheritRow.waitFor();
    await inheritRow.getByText('下期起：继承系统默认日', {exact:true}).waitFor();
    await inheritRow.getByRole('button', {name:'查看 ' + username + 'i 的详情', exact:true}).click();
    await page.getByText(/已安排重置日变更：.*继承系统默认日/).waitFor();
    await page.locator('.nq-modal-foot').getByRole('button', {name:'关闭', exact:true}).click();
    await inheritRow.getByRole('button', {name:'编辑 ' + username + 'i', exact:true}).click();
    await page.getByText(/已安排自 .*继承系统默认日。/).waitFor();
    await page.getByRole('button', {name:'取消', exact:true}).click();
    if ((await page.locator('.netquota').allTextContents()).join(' ').includes('NaN')) throw new Error('NaN remains in account UI');
    if (errors.length) throw new Error(errors.join('; '));
    return {quotaOnlyKeepsSchedule:true,explicitPendingPreserved:true,inheritanceLabels:true,pageErrors:errors};
  }
  finally {
    await page.evaluate(async id => (await L.require('netquota')).deleteAccount(id), created.id);
    page.off('pageerror', onError);
    await page.unroute('**/*', noCache);
  }
}

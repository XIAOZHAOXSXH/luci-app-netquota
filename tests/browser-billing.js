// Real LuCI/RPC settings flow; restores the original global rate in finally.
async page => {
  const origin = new URL(page.url()).origin;
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  const noCache = route => route.continue();
  await page.route('**/*', noCache);
  const settings = () => page.evaluate(async () => (await L.require('netquota')).getSettings());
  const accounts = () => page.evaluate(async () => {
    const nq = await L.require('netquota'); return nq.accountsOf(await nq.listAccounts()).items;
  });
  let original;
  try {
    await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/settings');
    const input = page.locator('#nq-billing-multiplier');
    await input.waitFor();
    original = await settings();
    const before = await accounts();
    const target = original.traffic_multiplier_percent === 120 ? 130 : 120;
    const save = page.getByRole('button', {name:'保存计费倍率', exact:true});
    if (await save.isEnabled()) throw new Error('Unchanged multiplier should disable save');
    for (const invalid of ['0.99', '5.01', '1.234', '']) {
      await input.fill(invalid);
      if (await save.isEnabled()) throw new Error('Invalid multiplier accepted: ' + invalid);
    }
    await input.fill((target / 100).toFixed(2));
    await save.click();
    await page.getByRole('button', {name:'取消', exact:true}).click();
    if ((await settings()).traffic_multiplier_percent !== original.traffic_multiplier_percent)
      throw new Error('Cancel persisted multiplier');
    await save.click();
    await page.getByRole('button', {name:'确认并生效', exact:true}).click();
    await page.locator('.nq-owned-modal').waitFor({state:'detached'});
    await page.getByText('当前 ' + (target / 100).toFixed(2) + ' 倍', {exact:true}).waitFor();
    const after = await settings();
    if (after.traffic_multiplier_percent !== target) throw new Error('Multiplier not persisted');
    if (after.default_reset_day !== original.default_reset_day || after.timezone !== original.timezone)
      throw new Error('Billing save changed reset settings');
    for (const old of before) {
      const now = (await accounts()).find(a => a.id === old.id);
      for (const key of ['quota_bytes', 'reset_day', 'pending_reset_day', 'pending_effective_at', 'period_id'])
        if (now[key] !== old[key]) throw new Error('Billing save changed account ' + key);
      if (now.billed_bytes < old.billed_bytes) throw new Error('Billing save refunded past usage');
    }
    if (after.billing_changes[0].new_percent !== target) throw new Error('No persistent change record');
    for (const scheme of ['dark', 'light']) {
      await page.setViewportSize({width:1440, height:1250});
      await page.emulateMedia({colorScheme:scheme});
      await page.waitForFunction(value => document.documentElement.getAttribute('data-netquota-theme') === value, scheme);
      await page.screenshot({path:'output/playwright/billing-settings-' + scheme + '.png', fullPage:true, animations:'disabled'});
    }
    await page.setViewportSize({width:390, height:844});
    if (await page.locator('.netquota:not(.nq-modal-host)').evaluate(n => n.scrollWidth > n.clientWidth + 1))
      throw new Error('Mobile billing page overflows');
    await page.screenshot({path:'output/playwright/billing-settings-mobile.png', fullPage:true, animations:'disabled'});
    await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/traffic');
    await page.getByRole('columnheader', {name:'实际合计', exact:true}).waitFor();
    await page.getByRole('columnheader', {name:'计费用量', exact:true}).waitFor();
    if (errors.length) throw new Error(errors.join('; '));
    return {savedRate:target, invalidInputs:4, cancellation:true, accountStatePreserved:true,
      history:true, themes:['dark','light'], mobileWidth:390, trafficColumns:true, pageErrors:errors};
  } finally {
    if (original) await page.evaluate(async rate => (await L.require('netquota')).updateBilling(rate), original.traffic_multiplier_percent);
    page.off('pageerror', onError);
    await page.unroute('**/*', noCache);
    await page.setViewportSize({width:1440,height:1100});
    await page.emulateMedia({colorScheme:'dark'});
    await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/settings');
  }
}

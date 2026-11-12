// Read-only verification against installed LuCI and real admin RPC.
// Compare separately accumulated ledgers; filtering never narrows global totals.
async page => {
  const origin = new URL(page.url()).origin;
  const errors = [];
  const onError = error => errors.push(error.message);
  const noCache = route => route.continue();
  page.on('pageerror', onError);
  await page.route('**/*', noCache);
  const results = [];
  try {
    for (const view of ['overview','accounts','traffic']) {
      await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/' + view);
      const totals = page.locator('.nq-traffic-totals').first();
      await totals.waitFor();
      const expected = await page.evaluate(async view => {
        const nq = await L.require('netquota');
        const data = view === 'traffic' ? await nq.getTraffic() : await nq.listAccounts();
        const items = nq.accountsOf(data).items;
        return {raw:nq.bytes(nq.sum(items,'total_bytes'),2),
          billed:nq.bytes(items.reduce((n,a)=>n+nq.billedBytes(a),0),2)};
      }, view);
      const read = async () => (await totals.locator('.nq-stat-value').allTextContents()).map(s=>s.replace(/\s/g,''));
      const values = await read();
      if (JSON.stringify(values)!==JSON.stringify([expected.raw,expected.billed].map(s=>s.replace(/\s/g,''))))
        throw new Error(view + ': totals differ from the two account ledgers');
      if (view === 'accounts') {
        await page.getByLabel('按用户名搜索账号',{exact:true}).fill('no_matching_fixture_user');
        await page.getByLabel('按状态筛选',{exact:true}).selectOption('online');
        if (JSON.stringify(await read())!==JSON.stringify(values)) throw new Error('Filtering changed global totals');
        await page.getByLabel('按用户名搜索账号',{exact:true}).fill('');
        await page.getByLabel('按状态筛选',{exact:true}).selectOption('all');
      }
      for (const scheme of ['dark','light']) {
        await page.setViewportSize({width:1440,height:1100});
        await page.emulateMedia({colorScheme:scheme});
        await page.waitForFunction(value=>document.documentElement.getAttribute('data-netquota-theme')===value,scheme);
        await totals.screenshot({path:'output/playwright/usage-totals-'+view+'-'+scheme+'.png',animations:'disabled'});
      }
      await page.setViewportSize({width:390,height:844});
      if (await page.locator('.netquota:not(.nq-modal-host)').evaluate(n=>n.scrollWidth>n.clientWidth+1))
        throw new Error(view + ': mobile content overflows');
      await totals.screenshot({path:'output/playwright/usage-totals-'+view+'-mobile.png',animations:'disabled'});
      results.push({view,...expected,filterIndependent:view==='accounts'});
    }
    if (errors.length) throw new Error(errors.join('; '));
    return {views:results,themes:['dark','light'],mobileWidth:390,pageErrors:errors};
  } finally {
    page.off('pageerror',onError);
    await page.unroute('**/*',noCache);
    await page.setViewportSize({width:1440,height:1100});
    await page.emulateMedia({colorScheme:'dark'});
  }
}

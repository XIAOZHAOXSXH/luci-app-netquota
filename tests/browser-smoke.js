// playwright-cli run-code --filename tests/browser-smoke.js
// Requires an authenticated LuCI browser session; uses the real RPC backend.
async (page) => {
  const origin = new URL(page.url()).origin;
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  // Routing continues all requests unchanged and disables the browser cache.
  const noCache = route => route.continue();
  await page.route('**/*', noCache);
  try {
    await page.setViewportSize({ width: 1440, height: 1100 });
    const results = [];
    for (const view of ['overview', 'deployment', 'accounts', 'traffic', 'settings', 'portal', 'about']) {
      await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/' + view);
      await page.locator('.netquota .nq-content').waitFor();
      await page.locator('.netquota .nq-skeleton').waitFor({ state: 'detached' });
      if (await page.locator('.netquota .nq-error').count())
        throw new Error(view + ': backend error');
      const text = await page.locator('.netquota').innerText();
      if (text.includes('[object ') || text.includes('undefined') || /%\d+\$/.test(text))
        throw new Error(view + ': invalid rendering');
      results.push(view);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/overview');
    await page.locator('.netquota .nq-content').waitFor();
    await page.locator('.netquota .nq-skeleton').waitFor({ state: 'detached' });
    const overflow = await page.locator('.netquota').evaluate(node => node.scrollWidth > node.clientWidth + 1);
    if (overflow) throw new Error('Mobile application content overflows');
    if (errors.length) throw new Error(errors.join('; '));
    return { views: results, mobileWidth: 390, pageErrors: errors };
  }
  finally {
    page.off('pageerror', onError);
    await page.unroute('**/*', noCache);
    await page.setViewportSize({ width: 1440, height: 1100 });
  }
}

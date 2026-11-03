// Run with playwright-cli run-code --filename tests/browser-theme.js after LuCI login.
// Uses the installed pages and real RPC. Never saves theme settings or accounts.
async (page) => {
  const origin = new URL(page.url()).origin;
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  const noCache = route => route.continue();
  await page.route('**/*', noCache);
  const results = [];
  async function mode(expected) {
    await page.locator('.main-right').evaluate(async node => {
      await Promise.all(node.getAnimations().map(animation => animation.finished.catch(() => {})));
    });
    await page.waitForFunction(value => document.documentElement.getAttribute('data-netquota-theme') === value, expected);
  }
  async function readable(selector, dark, backgroundSelector) {
    return page.locator(selector).first().evaluate((node, opts) => {
      const rgb = value => value.match(/[\d.]+/g).slice(0, 3).map(Number);
      const luminance = color => rgb(color).map(v => {
        v /= 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      }).reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
      const fg = getComputedStyle(node).color;
      let canvas = opts.backgroundSelector ? document.querySelector(opts.backgroundSelector) : node;
      let bg;
      do {
        bg = getComputedStyle(canvas).backgroundColor;
        const parts = bg.match(/[\d.]+/g).map(Number);
        if (parts.length < 4 || parts[3] > 0.95) break;
        canvas = canvas.parentElement;
      } while (canvas);
      const a = luminance(fg), b = luminance(bg);
      const contrast = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      if (contrast < 4.5) throw new Error(opts.selector + ': insufficient contrast ' + contrast.toFixed(2));
      if ((b < 0.3) !== opts.dark) throw new Error(opts.selector + ': wrong surface ' + bg);
      return { fg, bg, contrast: +contrast.toFixed(2) };
    }, { selector, dark, backgroundSelector });
  }
  try {
    await page.setViewportSize({ width: 1440, height: 1100 });
    for (const scheme of ['dark', 'light']) {
      await page.emulateMedia({ colorScheme: scheme });
      for (const view of ['overview', 'deployment', 'accounts', 'traffic', 'settings', 'portal', 'about']) {
        await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/' + view);
        await page.locator('.netquota .nq-content').waitFor();
        await page.locator('.netquota .nq-skeleton').waitFor({ state: 'detached' });
        await mode(scheme);
        const selectors = ['.nq-stat', '.nq-panel', '.nq-portal-card'];
        for (const selector of selectors)
          if (await page.locator(selector).count()) await readable(selector, scheme === 'dark');
        if (view === 'overview') {
          await readable('.nq-title', scheme === 'dark', '.main-right');
          await page.screenshot({ path: 'output/playwright/netquota-' + scheme + '.png', fullPage: true });
        }
        if (view === 'accounts') {
          await page.getByRole('button', { name: '创建账号', exact: true }).click();
          await page.waitForFunction(() => {
            let node = document.querySelector('.nq-owned-modal');
            if (!node) return false;
            for (; node; node = node.parentElement) {
              const style = getComputedStyle(node);
              if (+style.opacity < 0.99 || style.display === 'none' || style.visibility === 'hidden') return false;
            }
            return true;
          });
          await readable('.nq-owned-modal', scheme === 'dark');
          await readable('.nq-modal-host .nq-input', scheme === 'dark');
          await page.screenshot({ path: 'output/playwright/netquota-modal-' + scheme + '.png', fullPage: true });
          await page.getByRole('button', { name: '关闭', exact: true }).click();
        }
        results.push(scheme + '/' + view);
      }
    }
    await page.goto(origin + '/cgi-bin/luci/admin/services/netquota/overview');
    await page.locator('.nq-stat').first().waitFor();
    // A forced LuCI canvas must win over the opposite OS preference.
    for (const [scheme, color] of [['dark', '#1e1e1e'], ['light', '#f4f7fb']]) {
      await page.emulateMedia({ colorScheme: scheme === 'dark' ? 'light' : 'dark' });
      const style = await page.addStyleTag({ content: '.main-right, body {background-color:' + color + ' !important}' });
      await mode(scheme);
      await readable('.nq-stat', scheme === 'dark');
      await style.evaluate(node => node.remove());
    }
    // Switch without navigation, then verify mobile layout as well.
    await page.emulateMedia({ colorScheme: 'dark' });
    await mode('dark');
    await page.setViewportSize({ width: 390, height: 844 });
    if (await page.locator('.netquota').evaluate(node => node.scrollWidth > node.clientWidth + 1))
      throw new Error('Mobile content overflows');
    await page.screenshot({ path: 'output/playwright/netquota-dark-mobile.png', fullPage: true });
    if (errors.length) throw new Error(errors.join('; '));
    return { views: results, forcedModes: true, liveSwitch: true, mobileWidth: 390, pageErrors: errors };
  }
  finally {
    page.off('pageerror', onError);
    await page.unroute('**/*', noCache);
    await page.emulateMedia({ colorScheme: null });
    await page.setViewportSize({ width: 1440, height: 1100 });
  }
}

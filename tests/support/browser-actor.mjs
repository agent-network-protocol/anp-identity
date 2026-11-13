import { createRequire } from 'node:module';
const { chromium } = createRequire(new URL('../../packages/dsh-anp-identity/package.json', import.meta.url))('playwright');
import { AcceptanceError } from './config.mjs';

/** Operate only the actual authenticated product UI; never call management RPCs. */
export async function withUserBrowser(runtime, run) {
  let browser;
  let stage = 'launch';
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 1000 } });
    const web = await runtime.rpc('browser');
    stage = 'login';
    // The URL is a local login credential. Keep it out of navigation failures and logs.
    try {
      const response = await context.request.get(web.authenticatedUrl);
      if (!response.ok()) throw new Error('Login failed');
    } catch { throw new AcceptanceError('acceptance_browser_login_failed'); }
    const page = await context.newPage();
    stage = 'navigation';
    await page.goto(web.origin, { waitUntil: 'load', timeout: 30000 });
    const actor = {
      page,
      async openIdentities() {
        stage = 'preview_notice';
        const notice = page.getByRole('dialog').filter({ has: page.getByRole('heading', { name: '预览版说明', exact: true }) });
        try { await notice.waitFor({ state: 'visible', timeout: 5000 }); }
        catch (error) { if (error.name !== 'TimeoutError') throw error; }
        if (await notice.isVisible()) await notice.getByRole('button', { name: '继续', exact: true }).click();
        stage = 'account_menu';
        await page.getByRole('button', { name: '账号菜单', exact: true, includeHidden: true }).click();
        await page.getByRole('menuitem', { name: '设置', exact: true }).click();
        stage = 'identity_settings';
        const dialog = page.getByRole('dialog', { name: '设置', exact: true });
        await dialog.getByRole('button', { name: '身份管理', exact: true }).click();
        await page.getByRole('heading', { name: '身份管理', exact: true }).waitFor();
        stage = 'scenario';
      },
      async enterPhone(phone) {
        if (!/^\+[1-9][0-9]{6,14}$/u.test(phone)) throw new AcceptanceError('acceptance_browser_invalid_phone');
        try {
          await page.getByLabel('国家/地区码', { exact: true }).selectOption('international');
          await page.getByLabel('注册手机号', { exact: true }).fill(phone);
        }
        catch { throw new AcceptanceError('acceptance_browser_factor_entry_failed'); }
      },
      async enterOtp(code) {
        try { await page.getByLabel('短信验证码', { exact: true }).fill(code); }
        catch { throw new AcceptanceError('acceptance_browser_factor_entry_failed'); }
        await page.getByRole('button', { name: '验证并注册', exact: true }).click();
      },
    };
    stage = 'scenario';
    return await run(actor);
  } catch (error) {
    if (error instanceof AcceptanceError || error.name === 'AssertionError') throw error;
    throw new AcceptanceError('acceptance_browser_' + stage + '_failed');
  } finally { await browser?.close(); }
}

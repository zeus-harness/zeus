import { expect, test, type Locator, type Page, type TestInfo } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { loadEnvironment, freshTotp, setEnvironmentValue } from '../work-item.mjs';

async function fillSecret(locator: Locator, value: string) {
  try { await locator.fill(value); }
  catch { throw new Error('The credential field could not be filled.'); }
}

async function checkResponsive(page: Page, testInfo: TestInfo, prefix: string) {
  for (const [width, height] of [[1440, 900], [1024, 768], [390, 844]]) {
    await page.setViewportSize({ width, height });
    await expect(page.locator('main')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`${prefix}-${width}.png`) });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}

export async function login(page: Page) {
  const environment = await loadEnvironment();
  await page.goto('/login');
  await expect(page).toHaveTitle('Zeus · 登录');
  await page.getByLabel('Email', { exact: true }).fill(environment.ZEUS_E2E_EMAIL);
  await fillSecret(page.getByLabel('Password', { exact: true }), environment.ZEUS_E2E_PASSWORD);
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect(page.getByRole('heading', { name: '多因素验证' })).toBeVisible();
  const current = await freshTotp(environment);
  await setEnvironmentValue('ZEUS_E2E_TOTP_LAST_COUNTER', String(current.counter));
  await fillSecret(page.getByLabel('验证码或恢复码'), current.code);
  await page.getByRole('button', { name: '完成验证' }).click();
  await page.waitForURL((url) => /^\/[0-9a-f-]{36}$/u.test(url.pathname) ||
    (url.pathname === '/workspaces' && url.searchParams.get('auto') !== '1') || url.pathname === '/platform');
}

test('login, MFA, Workspace POST selection, WorkItem approval and live result', async ({ page }, testInfo) => {
  const state = JSON.parse(await readFile('.zeus/e2e-state.json', 'utf8'));
  let consoleIssues = 0;
  let contextPosts = 0;
  page.on('console', (message) => { if (['warning', 'error'].includes(message.type())) consoleIssues += 1; });
  page.on('pageerror', () => { consoleIssues += 1; });
  page.on('request', (request) => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/workspaces') contextPosts += 1;
  });

  await login(page);
  await page.goto('/workspaces');
  await expect(page.getByRole('heading', { name: '选择 Workspace' })).toBeVisible();
  await page.locator('form').filter({ has: page.locator(`input[value="${state.workspaceId}"]`) })
    .getByRole('button', { name: '进入 Workspace' }).click();
  await expect(page).toHaveURL(new RegExp(`/${state.workspaceId}$`));
  expect(contextPosts).toBeGreaterThan(0);

  await page.goto(`/${state.workspaceId}/work-items`);
  await page.getByRole('button', { name: '新建工作项', exact: true }).first().click();
  const title = `Browser acceptance ${Date.now()}`;
  await page.getByLabel('标题', { exact: true }).fill(title);
  await page.getByLabel('描述', { exact: true }).fill('Verify the browser Agent approval flow.');
  await page.locator('form[action="?/create"]').getByRole('button', { name: /创建/ }).click();
  await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
  await page.getByLabel('Workflow', { exact: true }).selectOption(state.workflowId);
  await page.getByLabel('给 Agent 的消息').fill('Run the approval fixture and report the result.');
  await page.getByRole('button', { name: '启动运行', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${state.workspaceId}/runs/`));
  await page.getByRole('button', { name: '批准', exact: true }).click();
  // No reload: the result must arrive through the page's SSE refresh path.
  await expect(page.getByText('succeeded', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('approved', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/测试运行已完成/).first()).toBeVisible();

  await checkResponsive(page, testInfo, 'run');
  expect(await page.locator('vite-error-overlay').count()).toBe(0);
  expect(consoleIssues).toBe(0);
});

test('configure a model, publish an Agent and Workflow, and read the linked WorkItem', async ({ page }, testInfo) => {
  const state = JSON.parse(await readFile('.zeus/e2e-state.json', 'utf8'));
  const environment = await loadEnvironment();
  const base = `/${state.workspaceId}`;
  const suffix = Date.now();
  const agentName = `Review Agent ${suffix}`;
  const workflowName = `Review Workflow ${suffix}`;
  const modelName = `Review Model ${suffix}`;
  let issues = 0;
  page.on('console', (message) => { if (['warning', 'error'].includes(message.type())) issues += 1; });
  page.on('pageerror', () => { issues += 1; });
  await login(page);

  await page.goto(`${base}/settings/connections`);
  await page.getByLabel('连接名称', { exact: true }).fill(`Review connection ${suffix}`);
  await fillSecret(page.getByLabel('API Key', { exact: true }), environment.ZEUS_E2E_MODEL_API_KEY);
  await page.getByRole('button', { name: '保存连接', exact: true }).click();
  await expect(page).toHaveURL(/settings\/model-profiles\?connection=/);
  await page.getByLabel('配置名称', { exact: true }).fill(modelName);
  await page.getByLabel('API Base URL', { exact: true }).fill(environment.ZEUS_E2E_MODEL_BASE_URL);
  await page.getByLabel('模型 ID', { exact: true }).fill('zeus-e2e');
  await page.getByRole('button', { name: '保存模型配置', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('模型配置已保存');

  await page.goto(`${base}/settings/capabilities`);
  await page.getByRole('button', { name: '启用工作项读取', exact: true }).click();
  await expect(page).toHaveURL(/capabilities\?saved=1/);

  await page.goto(`${base}/agents`);
  await page.getByLabel('Agent 名称', { exact: true }).fill(agentName);
  await page.getByRole('button', { name: '创建 Agent', exact: true }).click();
  await expect(page).toHaveURL(/agents\?selected=/);
  await page.getByLabel('Agent 指令', { exact: true }).fill('Read the current WorkItem using the available tool, then provide a concise recommendation.');
  await page.getByRole('button', { name: '保存新版本', exact: true }).click();
  await page.getByRole('button', { name: '发布版本 1', exact: true }).click();
  await expect(page.getByText('已发布', { exact: true }).first()).toBeVisible();
  await checkResponsive(page, testInfo, 'agent-published');

  await page.goto(`${base}/workflows`);
  await page.getByLabel('Workflow 名称', { exact: true }).fill(workflowName);
  await page.getByRole('button', { name: '创建 Workflow', exact: true }).click();
  await expect(page).toHaveURL(/workflows\?selected=/);
  await page.getByLabel('已发布的 Agent', { exact: true }).selectOption({ label: agentName });
  await page.getByLabel('模型配置', { exact: true }).selectOption({ label: `${modelName} · zeus-e2e` });
  await page.getByRole('checkbox', { name: /读取当前工作项/ }).check();
  await page.getByRole('button', { name: '保存新版本', exact: true }).click();
  await page.getByRole('button', { name: '发布版本 1', exact: true }).click();
  await expect(page.getByText('已发布', { exact: true }).first()).toBeVisible();

  await checkResponsive(page, testInfo, 'workflow-published');

  const task = `Invoice review ${suffix}`;
  await page.goto(`${base}/work-items?create=1`);
  await page.getByLabel('标题', { exact: true }).fill(task);
  await page.getByLabel('描述', { exact: true }).fill('Review the invoice and propose the next action.');
  await page.locator('form[action="?/create"]').getByRole('button', { name: /创建/ }).click();
  await expect(page.getByRole('heading', { name: task, exact: true })).toBeVisible();
  await page.getByLabel('Workflow', { exact: true }).selectOption({ label: workflowName });
  await page.getByLabel('给 Agent 的消息').fill('Read the current WorkItem and propose the next action.');
  await page.getByRole('button', { name: '启动运行', exact: true }).click();
  await page.getByRole('button', { name: '批准', exact: true }).click();
  await expect(page.getByText('succeeded', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(`已读取工作项：${task}`, { exact: false }).first()).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('agent-work-item-result.png') });
  expect(issues).toBe(0);
});

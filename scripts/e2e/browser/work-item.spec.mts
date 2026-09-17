import { expect, test, type Locator, type Page, type TestInfo } from '@playwright/test';
import { readFile, readdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
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
  await expect(page.getByRole('heading', { name: '选择工作空间' })).toBeVisible();
  await page.locator('form').filter({ has: page.locator(`input[value="${state.workspaceId}"]`) })
    .getByRole('button', { name: '进入工作空间' }).click();
  await expect(page).toHaveURL(new RegExp(`/${state.workspaceId}$`));
  expect(contextPosts).toBeGreaterThan(0);

  await page.goto(`/${state.workspaceId}/work-items`);
  await page.getByRole('button', { name: '新建工作项', exact: true }).first().click();
  const title = `Browser acceptance ${Date.now()}`;
  await page.getByLabel('标题', { exact: true }).fill(title);
  await page.getByLabel('描述', { exact: true }).fill('Verify the browser Agent approval flow.');
  await page.locator('form[action="?/create"]').getByRole('button', { name: /创建/ }).click();
  await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
  await page.getByLabel('流程', { exact: true }).selectOption(state.workflowId);
  await page.getByLabel('给 Agent 的消息').fill('Run the approval fixture and report the result.');
  await page.getByRole('button', { name: '启动运行', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${state.workspaceId}/runs/`));
  await page.getByRole('button', { name: '批准', exact: true }).click();
  // No reload: the result must arrive through the page's SSE refresh path.
  await expect(page.getByText('succeeded', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('approved', { exact: true }).first()).toBeVisible();
  await expect(page.getByTestId('run-output-content')).toContainText('测试运行已完成');
  const rawOutput = page.locator('details').filter({ has: page.getByText('查看原始 JSON', { exact: true }) });
  await expect(rawOutput.locator('pre')).toBeHidden();
  await rawOutput.locator('summary').click();
  await expect(rawOutput.locator('pre')).toContainText('"content"');
  await rawOutput.locator('summary').click();

  const originalRunUrl = page.url();
  const originalRunId = new URL(originalRunUrl).pathname.split('/').at(-1)!;
  await page.getByRole('link', { name: '返回关联 WorkItem', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/${state.workspaceId}/work-items/[0-9a-f-]+$`));
  const workItemUrl = page.url();
  await page.getByLabel('验收的运行', { exact: true }).selectOption(originalRunId);
  await page.getByLabel('验收决定', { exact: true }).selectOption('needs_changes');
  const changeReason = '请补充验收标准并保留原有事实。';
  await page.getByLabel('验收原因', { exact: true }).fill(changeReason);
  await page.getByRole('button', { name: '保存验收记录', exact: true }).click();
  await expect(page.getByText('验收已保存。工作项状态保持不变，需要时请单独更新。')).toBeVisible();
  const reprocess = page.getByRole('button', { name: '按此意见重新处理', exact: true });
  await expect(reprocess).toHaveCount(1);
  await reprocess.click();
  await expect(page).toHaveURL(new RegExp(`/${state.workspaceId}/runs/`));
  expect(page.url()).not.toBe(originalRunUrl);
  const newRunId = new URL(page.url()).pathname.split('/').at(-1)!;
  const basis = page.getByRole('region', { name: '重新处理依据' });
  await expect(basis).toContainText(changeReason);
  await expect(basis.getByRole('link', { name: '查看原运行与结果' })).toHaveAttribute('href', `/${state.workspaceId}/runs/${originalRunId}`);
  await page.getByRole('button', { name: '批准', exact: true }).click();
  await expect(page.getByText('succeeded', { exact: true }).first()).toBeVisible();
  await expect(page.getByTestId('run-output-content')).toContainText('测试运行已完成');
  await page.screenshot({ path: testInfo.outputPath('reprocessed-run.png') });
  await page.goto(workItemUrl);
  await page.getByLabel('验收的运行', { exact: true }).selectOption(newRunId);
  await page.getByLabel('验收决定', { exact: true }).selectOption('accepted');
  await page.getByLabel('验收原因', { exact: true }).fill('已核对新运行与修改意见的关联，确定性流程验收通过。');
  await page.getByRole('button', { name: '保存验收记录', exact: true }).click();
  await expect(page.getByText('验收已保存。工作项状态保持不变，需要时请单独更新。')).toBeVisible();
  await expect(page.getByRole('link', { name: '查看本次验收的运行' })).toHaveCount(2);
  await expect(page.getByRole('button', { name: '按此意见重新处理', exact: true })).toHaveCount(1);
  await page.screenshot({ path: testInfo.outputPath('reprocessed-acceptance.png') });
  await page.goto(`/${state.workspaceId}/runs/${newRunId}`);

  await checkResponsive(page, testInfo, 'run');
  expect(await page.locator('vite-error-overlay').count()).toBe(0);
  expect(consoleIssues).toBe(0);
});

test('configure a model, publish an Agent and Workflow, and read the linked WorkItem', async ({ page }, testInfo) => {
  const state = JSON.parse(await readFile('.zeus/e2e-state.json', 'utf8'));
  const environment = await loadEnvironment();
  const base = `/${state.workspaceId}`;
  const organizationBase = `/organizations/${state.organizationId}`;
  const suffix = Date.now();
  const agentName = `Review Agent ${suffix}`;
  const workflowName = `Review Workflow ${suffix}`;
  const modelName = `Review Model ${suffix}`;
  const connectionName = `Review connection ${suffix}`;
  let issues = 0;
  page.on('console', (message) => { if (['warning', 'error'].includes(message.type())) issues += 1; });
  page.on('pageerror', () => { issues += 1; });
  await login(page);

  await page.goto(`${organizationBase}/settings`);
  await page.getByRole('navigation', { name: 'Organization 设置导航' }).getByRole('link', { name: '模型供应商', exact: true }).click();
  await page.getByLabel('供应商名称', { exact: true }).fill(connectionName);
  await fillSecret(page.getByLabel('API Key', { exact: true }), environment.ZEUS_E2E_MODEL_API_KEY);
  await page.getByRole('button', { name: '保存供应商', exact: true }).click();
  await expect(page).toHaveURL(/settings\/model-profiles\?connection=/);
  const modelCreationUrl = page.url();
  await page.goto(`${organizationBase}/settings/connections`);
  const connectionCard = page.locator('div.rounded-lg').filter({ has: page.getByText(connectionName, { exact: true }) });
  await connectionCard.getByText('轮换 API Key', { exact: true }).click();
  await fillSecret(connectionCard.getByLabel('新的 API Key', { exact: true }), randomUUID());
  await connectionCard.getByRole('button', { name: '保存新密钥', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('连接密钥已更新');
  await expect(connectionCard.locator('input[name="api_key"]')).toHaveValue('');
  await checkResponsive(page, testInfo, 'connection-rotated');
  await page.goto(modelCreationUrl);
  const createModel = page.locator('form').filter({ has: page.locator('input[name="intent"][value="create"]') });
  await createModel.getByLabel('配置名称', { exact: true }).fill(modelName);
  await createModel.getByLabel('API Base URL', { exact: true }).fill(environment.ZEUS_E2E_MODEL_BASE_URL);
  await createModel.getByLabel('模型 ID', { exact: true }).fill('zeus-e2e');
  await page.getByRole('button', { name: '保存模型配置', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('模型配置已保存');
  const modelCard = page.locator('div.rounded-lg').filter({ has: page.getByText(modelName, { exact: true }) });
  await modelCard.getByText('编辑模型配置', { exact: true }).click();
  await modelCard.getByLabel('单次请求超时（秒）', { exact: true }).fill('45');
  await modelCard.getByRole('button', { name: '保存修改', exact: true }).click();
  await page.reload();
  await modelCard.getByText('编辑模型配置', { exact: true }).click();
  await expect(modelCard.getByLabel('单次请求超时（秒）', { exact: true })).toHaveValue('45');
  await checkResponsive(page, testInfo, 'model-edited');

  await page.goto(modelCreationUrl);
  await createModel.getByLabel('配置名称', { exact: true }).fill(`${modelName} alternative`);
  await createModel.getByLabel('API Base URL', { exact: true }).fill(environment.ZEUS_E2E_MODEL_BASE_URL);
  await createModel.getByLabel('模型 ID', { exact: true }).fill('zeus-e2e-alternative');
  await page.getByRole('button', { name: '保存模型配置', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('模型配置已保存');
  await page.goto(`${organizationBase}/settings/connections`);
  await expect(connectionCard).toContainText(`${modelName} · zeus-e2e`);
  await expect(connectionCard).toContainText(`${modelName} alternative · zeus-e2e-alternative`);

  await page.goto(`${base}/settings/capabilities`);
  await page.getByRole('button', { name: '启用工作项读取', exact: true }).click();
  await expect(page).toHaveURL(/capabilities\?saved=1/);

  await page.goto(`${base}/agents`);
  await page.getByLabel('智能体 名称', { exact: true }).fill(agentName);
  await page.getByRole('button', { name: '创建 智能体', exact: true }).click();
  await expect(page).toHaveURL(/agents\?selected=/);
  await page.getByLabel('模型', { exact: true }).selectOption({ label: `${modelName} · zeus-e2e` });
  await expect(page.getByText('模型连接', { exact: true })).toHaveCount(0);
  await page.getByLabel('Agent 指令', { exact: true }).fill('Read the current WorkItem using the available tool, then provide a concise recommendation.');
  await page.getByRole('button', { name: '保存新版本', exact: true }).click();
  await page.getByRole('button', { name: '发布版本 1', exact: true }).click();
  await expect(page.getByText('已发布', { exact: true }).first()).toBeVisible();
  await checkResponsive(page, testInfo, 'agent-published');

  await page.goto(`${base}/workflows`);
  await page.getByLabel('流程 名称', { exact: true }).fill(workflowName);
  await page.getByRole('button', { name: '创建 流程', exact: true }).click();
  await expect(page).toHaveURL(/workflows\?selected=/);
  await page.getByLabel('已发布的 Agent', { exact: true }).selectOption({ label: agentName });
  await expect(page.getByLabel('模型配置', { exact: true })).toHaveCount(0);
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

test('failed and canceled pilot runs show recovery guidance', async ({ page }, testInfo) => {
  const reports = (await readdir('.zeus')).filter((name) => /^pilot-report-\d+\.json$/u.test(name)).sort();
  expect(reports.length).toBeGreaterThan(0);
  const report = JSON.parse(await readFile(`.zeus/${reports.at(-1)}`, 'utf8'));
  const state = JSON.parse(await readFile('.zeus/e2e-state.json', 'utf8'));
  let issues = 0;
  page.on('console', (message) => { if (['warning', 'error'].includes(message.type())) issues += 1; });
  page.on('pageerror', () => { issues += 1; });
  await login(page);
  for (const id of ['timeout', 'canceled']) {
    const entry = report.cases.find((item: { case_id: string }) => item.case_id === id);
    expect(entry.passed).toBe(true);
    await page.goto(`/${state.workspaceId}/runs/${entry.run_id}`);
    await expect(page).toHaveTitle('Zeus · Run Trace');
    await expect(page.getByRole('region', { name: '恢复指引' })).toContainText(id === 'timeout' ? '部分用量' : '原运行记录保留');
    await expect(page.getByRole('button', { name: '创建重试 Run' })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`recovery-${id}.png`) });
  }
  expect(await page.locator('vite-error-overlay').count()).toBe(0);
  expect(issues).toBe(0);
});

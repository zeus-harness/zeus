// Local demo only: reuse the existing isolated E2E identity, no account/credential creation.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile, chmod, mkdir } from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';
import { loadEnvironment, ZeusClient, login, selectWorkspace, listItems, waitForRunStatus } from './work-item.mjs';

const mode = process.argv[2] ?? 'verify';
const statePath = new URL('../../.zeus/demo-state.json', import.meta.url);
const evidencePath = '/tmp/zeus-demo-browser';
const title = 'Zeus 首版体验：审批与验收';

async function browserFor(client, visible) {
  const browser = await chromium.launch({ headless: !visible });
  const context = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 960 } });
  // Browser-session cookies stay in the temporary context; never export login storage or credentials.
  await context.addCookies(client.cookies.header().split('; ').filter(Boolean).map(pair => {
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator);
    return { name, value: pair.slice(separator + 1), url: client.origin, httpOnly: name !== 'zeus_csrf', sameSite: 'Lax' };
  }));
  return { browser, context, page: await context.newPage() };
}

async function existingFixture(client, environment) {
  const setup = await client.json('/api/v1/setup/status');
  if (setup.setup_required) throw new Error('Existing demo identity is unavailable; no identity was created.');
  await login(client, environment);
  const tenant = await selectWorkspace(client);
  const saved = JSON.parse(await readFile(new URL('../../.zeus/e2e-state.json', import.meta.url), 'utf8'));
  assert.equal(saved.organizationId, tenant.organizationId);
  assert.equal(saved.workspaceId, tenant.workspaceId);
  const org = `/api/v1/organizations/${tenant.organizationId}`;
  const providers = await listItems(client, `${org}/model-providers`);
  const provider = providers.find(value => value.id === saved.connectionId && value.name === 'E2E Deterministic Model');
  if (!provider) throw new Error('Existing deterministic model provider is unavailable; no provider was created.');
  const metadata = await listItems(client, `${org}/model-providers/${provider.id}/secrets`);
  if (!metadata.some(value => value.secret_name === 'api_key')) throw new Error('Existing fixture credential is unavailable; no credential was created.');
  const profiles = await listItems(client, `${org}/model-profiles`);
  const profile = profiles.find(value => value.id === saved.modelProfileId && value.name === 'E2E Deterministic Model');
  if (!profile || profile.connection_id !== provider.id) throw new Error('Existing deterministic model configuration is unavailable.');
  const endpoint = new URL(environment.ZEUS_E2E_MODEL_BASE_URL);
  if (endpoint.protocol !== 'http:' || !/^192\.168\.64\.\d+$/.test(endpoint.hostname) || endpoint.pathname !== '/v1') {
    throw new Error('Expected the private isolated E2E model adapter; no external model was contacted.');
  }
  if (profile.base_url !== endpoint.href) {
    await client.json(`${org}/model-profiles/${profile.id}`, {
      method: 'PATCH', headers: { 'if-match': `"revision-${profile.revision}"` }, body: { base_url: endpoint.href }
    });
  }
  return { ...saved, ...tenant };
}

async function newGoal(client, fixture, label) {
  const base = `/api/v1/workspaces/${fixture.workspaceId}`;
  const item = await client.json(`${base}/work-items`, {
    method: 'POST', headers: { 'idempotency-key': randomUUID() },
    body: { title: label, description: '只使用本地确定性模型和 builtin.echo 合成回显，体验工具审批、暂停恢复、人工接受与验证归档。没有代码提交、部署或 SQL 修改。', priority: 'normal', input: {} }
  }, [201]);
  const result = await client.json(`${base}/work-items/${item.id}/runs`, {
    method: 'POST', headers: { 'idempotency-key': randomUUID() },
    body: { workflow_id: fixture.workflowId, input: {}, message: '执行合成回显验证，等待本人批准后再继续；最终结果只说明模拟流程完成。' }
  }, [201]);
  await waitForRunStatus(client, fixture.workspaceId, result.run.id, new Set(['waiting_approval']), 60_000);
  return { workItemId: item.id, runId: result.run.id };
}

async function durableDemoWorkflow(client, fixture) {
  const base = `/api/v1/workspaces/${fixture.workspaceId}`;
  const source = (await listItems(client, `${base}/workflows/${fixture.workflowId}/versions`))
    .find(value => value.id === fixture.workflowVersionId);
  if (!source || source.capability_policy.allowed.length !== 1 || source.capability_policy.allowed[0] !== 'e2e.echo') {
    throw new Error('Expected the existing echo-only approval fixture.');
  }
  let workflow = (await listItems(client, `${base}/workflows`)).find(value => value.name === '[本地演示] 持久审批流程');
  if (!workflow) workflow = await client.json(`${base}/workflows`, {
    method: 'POST', body: { name: '[本地演示] 持久审批流程', description: '纯合成回显，保留原审批策略；等待不占执行预算，不执行外部动作。' }
  }, [201]);
  let version = (await listItems(client, `${base}/workflows/${workflow.id}/versions`))[0];
  if (!version) version = await client.json(`${base}/workflows/${workflow.id}/versions`, {
    method: 'POST', body: {
      agent_version_id: source.agent_version_id, model_profile_id: source.model_profile_id,
      input_schema: source.input_schema, output_schema: source.output_schema,
      capability_policy: source.capability_policy, approval_policy: source.approval_policy,
      experience_policy: source.experience_policy, max_steps: source.max_steps,
      max_runtime_seconds: source.max_runtime_seconds, token_budget: source.token_budget,
      retry_policy: source.retry_policy,
      time_policy: { runtime_clock: 'active', wait_timeout_seconds: 86400, business_timeout_seconds: 86400 }
    }
  }, [201]);
  if (workflow.active_version_id !== version.id) await client.json(`${base}/workflows/${workflow.id}/active-version`, {
    method: 'POST', headers: { 'if-match': `"revision-${workflow.revision}"` }, body: { version_id: version.id }
  });
  return { ...fixture, workflowId: workflow.id, workflowVersionId: version.id };
}

async function groupFixture(client, fixture) {
  const org = `/api/v1/organizations/${fixture.organizationId}/im`;
  const conversations = await listItems(client, `${org}/conversations`);
  let conversation = conversations.find(value => value.kind === 'group' && value.title === title);
  if (!conversation) {
    const people = await client.json(`${org}/people`);
    const me = await client.json('/api/v1/auth/me');
    const peer = people.items.find(value => value.id !== me.user_id);
    // Do not create or invite identities merely to populate the demo.
    if (!peer) return null;
    conversation = await client.json(`${org}/conversations`, {
      method: 'POST', body: { kind: 'group', title, participants: [peer.id], request_id: randomUUID() }
    }, [201]);
  }
  const detail = await client.json(`${org}/conversations/${conversation.id}`);
  if (!detail.agents.some(value => value.workflow_version_id === fixture.workflowVersionId)) {
    await client.json(`/api/v1/workspaces/${fixture.workspaceId}/im/conversations/${conversation.id}/agents`, {
      method: 'POST', body: { workflow_version_id: fixture.workflowVersionId }
    });
  }
  await client.json(`${org}/conversations/${conversation.id}/messages`, {
    method: 'POST', body: { content: '本地首版体验：请验证合成回显的审批链路。只使用模拟工具，不执行真实代码、SQL 或发布。点击本消息下的“交给 Agent”，创建持久工作项后处理审批、验收并归档。', request_id: randomUUID(), mentions: [] }
  });
  return { conversationId: conversation.id };
}

async function verify(client, fixture) {
  await mkdir(evidencePath, { recursive: true });
  const goal = await newGoal(client, fixture, '[自动验收] 本地审批与归档');
  const { browser, page } = await browserFor(client, false);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const itemUrl = `${client.origin}/${fixture.workspaceId}/work-items/${goal.workItemId}`;
  try {
    await page.goto(`${client.origin}/${fixture.workspaceId}/runs/${goal.runId}`);
    await page.reload();
    await expect(page.getByRole('button', { name: '批准', exact: true })).toBeVisible();
    await page.screenshot({ path: `${evidencePath}/actual-waiting-approval.png` });
    await page.getByRole('button', { name: '批准', exact: true }).click();
    await expect(page.getByTestId('run-output-content')).toContainText('测试运行已完成');
    await waitForRunStatus(client, fixture.workspaceId, goal.runId, new Set(['succeeded']), 60_000);
    await page.goto(itemUrl);
    await page.getByLabel('验收决定', { exact: true }).selectOption('accepted');
    await page.getByLabel('验收原因', { exact: true }).fill('已核对本地合成回显、审批记录和运行事件。仅验收演示链路，不代表真实业务修复。');
    await page.getByLabel('我已核对上方所选运行的结果').check();
    await page.getByRole('button', { name: '保存验收记录', exact: true }).click();
    await expect(page.getByRole('button', { name: '验证完成并归档' })).toBeEnabled();
    await page.getByLabel('问题解决验证报告', { exact: true }).fill('实际 Rust API、PostgreSQL、Supervisor、确定性模型与浏览器均完成审批到归档链路。仅使用合成输入及内置回显；无外部业务操作。');
    await page.getByLabel('我已验证目标达成', { exact: false }).check();
    await page.getByRole('button', { name: '验证完成并归档' }).click();
    await expect(page.getByText('工作项已归档', { exact: false })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('button', { name: '启动运行', exact: true })).toHaveCount(0);
    await page.locator('#closure').scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${evidencePath}/actual-archived.png` });
    const archive = await client.json(`/api/v1/workspaces/${fixture.workspaceId}/work-items/${goal.workItemId}/archive`);
    assert.equal(archive.run_id, goal.runId);
    assert.deepEqual(errors, []);
    return goal;
  } finally { await browser.close(); }
}

async function verifySimplifiedUi(client, fixture) {
  const evidence = '/tmp/zeus-ui-simplification';
  await mkdir(evidence, { recursive: true });
  const base = `/api/v1/workspaces/${fixture.workspaceId}`;
  const verified = [];
  const goalRuns = async workItemId => (await client.json(`${base}/runs?work_item_id=${workItemId}&limit=100`)).items;
  for (const width of [1440, 390]) {
    const { browser, page } = await browserFor(client, false);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    try {
      await page.setViewportSize({ width, height: 960 });
      await page.goto(`${client.origin}/${fixture.workspaceId}/new`);
      await page.locator('summary').filter({ hasText: '执行方式' }).click();
      await page.getByLabel('执行方式', { exact: true }).selectOption(fixture.workflowId);
      await page.getByLabel('任务目标', { exact: true }).fill(`[界面验收 ${width}px] 只使用合成回显验证拒绝、再次尝试、批准、人工验收与归档。所有结论仅限本地模拟工具链路。`);
      await page.screenshot({ path: `${evidence}/after-entry-${width}.png` });
      await page.getByRole('button', { name: '发起任务', exact: true }).click();
      await expect(page).toHaveURL(/\/work-items\/[0-9a-f-]+$/);
      const workItemId = new URL(page.url()).pathname.split('/').at(-1);
      const itemUrl = page.url();
      let runs = await goalRuns(workItemId);
      const first = runs[0];
      await waitForRunStatus(client, fixture.workspaceId, first.id, new Set(['waiting_approval']), 60_000);
      await page.reload();
      await expect(page.getByRole('button', { name: '批准', exact: true })).toBeVisible();
      await page.screenshot({ path: `${evidence}/after-approval-${width}.png`, fullPage: true });
      await page.getByLabel('审批说明', { exact: true }).fill('本地界面验收：先拒绝合成回显，检查决定与目标保存。');
      await page.getByRole('button', { name: '拒绝', exact: true }).click();
      const rejectedAttempt = await waitForRunStatus(client, fixture.workspaceId, first.id, new Set(['succeeded','failed']), 60_000);
      const firstTrace = await client.json(`${base}/runs/${first.id}/trace`);
      assert.equal(firstTrace.approvals.some(value => value.status === 'rejected'), true);
      assert.equal((await client.json(`${base}/work-items/${workItemId}`)).archived_at, null);
      await page.reload();
      if (rejectedAttempt.status === 'failed') {
        await page.getByLabel('已核对执行记录与已有操作', { exact: false }).check();
        await page.getByRole('button', { name: '重试任务', exact: true }).click();
      } else {
        // Model completion after a denied tool is still subject to human acceptance.
        await page.getByLabel('验收决定', { exact: true }).selectOption('needs_changes');
        await page.getByLabel('验收原因', { exact: true }).fill('回显操作已拒绝，目标尚未验证。请求再次尝试；仅测试模拟链路。');
        await page.getByLabel('我已核对上方所选运行的结果').check();
        await page.getByRole('button', { name: '保存验收记录', exact: true }).click();
        await expect(page.getByRole('button', { name: '按意见继续处理', exact: true })).toBeVisible();
        await page.getByRole('button', { name: '按意见继续处理', exact: true }).click();
      }
      await expect(page).toHaveURL(itemUrl);
      await expect.poll(async () => (await goalRuns(workItemId)).length).toBe(2);
      runs = await goalRuns(workItemId);
      const second = runs.find(value => value.id !== first.id);
      await waitForRunStatus(client, fixture.workspaceId, second.id, new Set(['waiting_approval']), 60_000);
      await page.reload();
      await expect(page.getByRole('button', { name: '批准', exact: true })).toBeVisible();
      await page.getByLabel('审批说明', { exact: true }).fill('批准当前固定内容的合成回显，不执行真实代码、SQL 或发布。');
      await page.route(url => url.origin === client.origin && url.search === '?/decide', async route => { await route.fetch(); await route.abort(); }, { times: 1 });
      const approvalForm = page.locator('form[action="?/decide"]');
      await approvalForm.evaluate(form => { const approve = form.querySelector('button[value="approve"]'); form.requestSubmit(approve); form.requestSubmit(approve); });
      await expect(page.getByText('连接中断，操作尚未确认', { exact: false })).toBeVisible();
      await waitForRunStatus(client, fixture.workspaceId, second.id, new Set(['succeeded']), 60_000);
      await page.reload();
      await expect(page.getByRole('heading', { name: 'Agent 提交的结果', exact: true })).toBeVisible();
      await page.getByLabel('验收决定', { exact: true }).selectOption('accepted');
      await page.getByLabel('验收原因', { exact: true }).fill('已核对实际 API、持久审批和第二次合成回显结果，仅验收界面流程。');
      await page.getByLabel('我已核对上方所选运行的结果').check();
      await page.getByRole('button', { name: '保存验收记录', exact: true }).click();
      await expect(page.getByRole('button', { name: '验证完成并归档' })).toBeEnabled();
      const report = '使用真实 PostgreSQL、Rust Supervisor 和确定性模型完成拒绝、再次尝试、批准恢复、人工验收；只验证合成回显和界面流程，不代表真实问题修复。';
      await page.getByLabel('问题解决验证报告', { exact: true }).fill(report);
      await page.getByLabel('我已验证目标达成', { exact: false }).check();
      await page.route(url => url.origin === client.origin && url.search === '?/archive', route => route.abort(), { times: 1 });
      await page.getByRole('button', { name: '验证完成并归档' }).click();
      await expect(page.getByText('连接中断，归档尚未确认', { exact: false })).toBeVisible();
      await expect(page.getByLabel('问题解决验证报告', { exact: true })).toHaveValue(report);
      await page.locator('form[action="?/archive"]').evaluate(form => { form.requestSubmit(); form.requestSubmit(); });
      await expect(page.getByText('工作项已归档', { exact: false })).toBeVisible();
      await page.reload();
      await expect(page.getByText(report, { exact: true })).toBeVisible();
      assert.equal((await goalRuns(workItemId)).length, 2);
      assert.equal((await client.json(`${base}/work-items/${workItemId}/archive`)).run_id, second.id);
      await page.locator('#closure').scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${evidence}/after-archived-${width}.png`, fullPage: true });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      assert.deepEqual(errors, []);
      verified.push({ width, workItemId, firstRunId: first.id, successfulRunId: second.id });
      await page.goto(`${client.origin}/${fixture.workspaceId}`);
      await page.screenshot({ path: `${evidence}/after-home-${width}.png`, fullPage: true });
    } catch (error) {
      await page.screenshot({ path: `${evidence}/ui-failure-${width}.png`, fullPage: true }).catch(() => {});
      console.error(`Synthetic UI verification: ${error.message}`);
      throw error;
    } finally { await browser.close(); }
  }
  await writeFile(`${evidence}/actual-ui-results.json`, `${JSON.stringify({ status: 'verified', environment: 'local isolated E2E, synthetic echo only', verified }, null, 2)}\n`);
  console.log(JSON.stringify({ status: 'simplified_ui_verified', widths: verified.map(value => value.width), evidencePath: evidence }));
}

async function main() {
  if (!['verify', 'refresh', 'open', 'ui'].includes(mode)) throw new Error('Usage: node scripts/e2e/demo.mjs <verify|refresh|open|ui>');
  const environment = await loadEnvironment();
  const origin = environment.ZEUS_E2E_PUBLIC_URL ?? 'http://127.0.0.1:3100';
  const client = new ZeusClient(origin);
  const originalFixture = await existingFixture(client, environment);
  const fixture = mode === 'open' ? originalFixture : await durableDemoWorkflow(client, originalFixture);
  if (mode === 'ui') { await verifySimplifiedUi(client, fixture); } else if (mode === 'verify') {
    const evidence = await verify(client, fixture);
    const pending = await newGoal(client, fixture, '[请体验] 批准模拟工具，验收后验证归档');
    const group = await groupFixture(client, fixture);
    const state = { origin, organizationId: fixture.organizationId, workspaceId: fixture.workspaceId, workflowId: fixture.workflowId, workflowVersionId: fixture.workflowVersionId, ...pending, ...group, verificationWorkItemId: evidence.workItemId, verificationRunId: evidence.runId };
    await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await chmod(statePath, 0o600);
    console.log(JSON.stringify({ status: 'browser_verified', pendingGoalUrl: `${origin}/${fixture.workspaceId}/work-items/${pending.workItemId}`, pendingRunUrl: `${origin}/${fixture.workspaceId}/runs/${pending.runId}`, groupUrl: group ? `${origin}/organizations/${fixture.organizationId}/im?conversation=${group.conversationId}` : null, evidencePath }));
  } else if (mode === 'refresh') {
    const state = JSON.parse(await readFile(statePath, 'utf8'));
    assert.equal(state.origin, origin);
    assert.equal(state.workspaceId, fixture.workspaceId);
    const base = `/api/v1/workspaces/${fixture.workspaceId}`;
    const previous = await client.json(`${base}/runs/${state.runId}`);
    if (previous.status === 'waiting_approval') {
      const response = await client.request(`${base}/runs/${previous.id}/cancel`, {
        method: 'POST', body: { reason: '演示准备：保留旧尝试，改用独立的持久审批版本。仅合成回显，尚未执行工具。' }
      });
      assert.equal(response.status, 202);
    }
    const item = await client.json(`${base}/work-items/${state.workItemId}`);
    let pending;
    if (item.archived_at || !['waiting_approval', 'canceled'].includes(previous.status)) pending = await newGoal(client, fixture, '[请体验] 批准模拟工具，验收后验证归档');
    else {
      const started = await client.json(`${base}/work-items/${item.id}/runs`, {
        method: 'POST', headers: { 'idempotency-key': randomUUID() },
        body: { workflow_id: fixture.workflowId, input: {}, message: '使用合成回显等待本人审批，保留旧尝试，不执行真实业务动作。' }
      }, [201]);
      await waitForRunStatus(client, fixture.workspaceId, started.run.id, new Set(['waiting_approval']), 60_000);
      pending = { workItemId: item.id, runId: started.run.id };
    }
    const current = await client.json(`${base}/runs/${pending.runId}`);
    assert.equal(current.status, 'waiting_approval');
    assert.equal(current.wait_expires_at > new Date(Date.now() + 23 * 3600_000).toISOString(), true);
    const next = { ...state, ...pending, workflowId: fixture.workflowId, workflowVersionId: fixture.workflowVersionId, deadline: current.wait_expires_at };
    await writeFile(statePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
    const { browser, page } = await browserFor(client, false);
    try {
      await page.goto(`${origin}/${fixture.workspaceId}/runs/${pending.runId}`);
      await expect(page.getByRole('button', { name: '批准', exact: true })).toBeVisible();
      await page.screenshot({ path: `${evidencePath}/actual-user-ready.png` });
    } finally { await browser.close(); }
    console.log(JSON.stringify({ status: 'durable_demo_ready', pendingGoalUrl: `${origin}/${fixture.workspaceId}/work-items/${pending.workItemId}`, pendingRunUrl: `${origin}/${fixture.workspaceId}/runs/${pending.runId}`, deadline: current.wait_expires_at }));
  } else {
    const state = JSON.parse(await readFile(statePath, 'utf8'));
    assert.equal(state.origin, origin);
    assert.equal(state.workspaceId, fixture.workspaceId);
    const { browser, page } = await browserFor(client, true);
    const target = state.conversationId ? `${origin}/organizations/${fixture.organizationId}/im?conversation=${state.conversationId}` : `${origin}/${fixture.workspaceId}/work-items/${state.workItemId}`;
    await page.goto(target);
    await expect(page.getByRole('heading', { name: state.conversationId ? '团队消息' : '[请体验] 批准模拟工具，验收后验证归档', exact: true })).toBeVisible();
    console.log(`Zeus demo browser ready: ${target}`);
    await new Promise(resolve => browser.on('disconnected', resolve));
  }
}

main().catch(error => {
  // Do not print request bodies, credentials, cookies, environment values or browser traces.
  console.error(`Local demo did not complete (${error.name}). Check isolated service status and the existing fixture.`);
  process.exitCode = 1;
});

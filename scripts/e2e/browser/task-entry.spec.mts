// Real Svelte SSR; synthetic HTTP adapter verifies committed-but-lost response recovery.
import { test, expect } from '@playwright/test';
import { createServer, type Server } from 'node:http';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
async function listen(server: Server) {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No fixture address');
  return `http://127.0.0.1:${address.port}`;
}
for (const width of [1440, 390]) test(`single task entry preserves a committed request after connection loss at ${width}px`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  const org = randomUUID(), workspace = randomUUID(), user = randomUUID(), workflow = randomUUID(), version = randomUUID(), itemId = randomUUID(), runId = randomUUID();
  const time = '2026-10-01T00:00:00Z';
  const item = { id: itemId, title: 'Synthetic task', description: '', organization_id: org, workspace_id: workspace, priority: 'normal', status: 'open', revision: 1, input: {}, output: null, created_at: time, updated_at: time, archived_at: null, assignee_user_id: null };
  const run = { id: runId, work_item_id: itemId, workflow_version_id: version, parent_run_id: null, status: 'waiting_approval', input: {}, output: null, created_at: time, updated_at: time, attempt_count: 1 };
  let created = false, started = false, creationCommits = 0, executionCommits = 0;
  const keys = new Map<string, unknown>();
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  const api = createServer(async (request, response) => {
    const url = new URL(request.url!, 'http://fixture');
    const path = url.pathname;
    const json = (data: unknown, status = 200) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(data)); };
    const principal = { principal_kind: 'user', principal_id: user, user_id: user, display_name: 'Synthetic Owner', email: 'owner@example.invalid', organization_id: org, workspace_id: workspace, organization_role: 'owner', workspace_role: 'owner', platform_roles: [], auth_methods: ['password','totp'], email_verified_at: time, mfa_required: false, scopes: [] };
    if (path.endsWith('/auth/me')) return json(principal);
    if (path.endsWith('/users/me/organizations')) return json([{ organization_id: org, organization_slug: 'synthetic', organization_name: 'Synthetic organization', organization_status: 'active', organization_role: 'owner', identity_settings_mode: 'organization_managed', support_access: false, workspaces: [{ id: workspace, slug: 'synthetic', name: 'Synthetic workspace', status: 'active', role: 'owner', support_access: false }] }]);
    if (path.endsWith('/setup/status')) return json({ setup_required: false });
    if (path.endsWith('/workflows')) return json({ items: [{ id: workflow, name: 'Synthetic approval flow', active_version_id: version }], next_cursor: null });
    if (request.method === 'POST') {
      const chunks = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const payload = JSON.parse(Buffer.concat(chunks).toString());
      const key = String(request.headers['idempotency-key']);
      if (keys.has(key)) expect(keys.get(key)).toEqual(payload); else keys.set(key, payload);
      if (path.endsWith('/work-items')) {
        if (!created) { created = true; creationCommits++; item.description = payload.description; item.title = payload.title; }
        return json(item, 201);
      }
      if (path.endsWith(`/work-items/${itemId}/runs`)) {
        if (!started) { started = true; executionCommits++; }
        return json({ run }, 201);
      }
    }
    if (path.endsWith('/work-items')) return json({ items: created ? [item] : [], next_cursor: null });
    if (path.endsWith(`/work-items/${itemId}`)) return json(item);
    if (path.endsWith('/runs')) return json({ items: started ? [run] : [], next_cursor: null });
    if (path.endsWith('/trace')) return json({ run, approvals: [], tool_calls: [], run_events: [], session_events: [], linked_runs: [], experience_injections: [], usage: {} });
    if (path.endsWith('/reviews')) return json({ items: [], next_cursor: null });
    if (path.endsWith('/archive')) return json(null);
    if (path.endsWith('/members') || path.endsWith('/approvals') || path.endsWith('/attachments') || path.endsWith('/external-references')) return json([]);
    return json({ items: [], next_cursor: null });
  });
  const apiUrl = await listen(api), reserved = createServer();
  const webUrl = await listen(reserved); await new Promise<void>(resolve => reserved.close(() => resolve()));
  const web = spawn(process.execPath, ['apps/web/build/index.js'], { env: { ...process.env, HOST: '127.0.0.1', PORT: new URL(webUrl).port, ORIGIN: webUrl, ZEUS_API_URL: apiUrl }, stdio: 'ignore' });
  try {
    await expect.poll(async () => { try { return (await fetch(webUrl)).status; } catch { return 0; } }).toBe(200);
    await page.goto(`${webUrl}/${workspace}`);
    await expect(page.getByRole('heading', { name: '工作台', exact: true })).toBeVisible();
    await page.getByRole('link', { name: '发起任务 描述目标，让 Zeus 帮你推进' }).click();
    const goal = '分析合成测试日志。提出修改方案，执行前等待审批。';
    await page.getByLabel('任务目标', { exact: true }).fill(goal);
    await page.screenshot({ path: info.outputPath(`task-entry-${width}.png`) });
    await page.route(url => url.origin === webUrl && url.search === '?/create', async route => { await route.fetch(); await route.abort(); }, { times: 1 });
    await page.getByRole('button', { name: '发起任务', exact: true }).click();
    await expect(page.getByText('连接中断，发起尚未确认', { exact: false })).toBeVisible();
    await expect(page.getByLabel('任务目标', { exact: true })).toHaveValue(goal);
    expect(creationCommits).toBe(1); expect(executionCommits).toBe(1);
    const form = page.locator('form[action="?/create"]');
    await form.evaluate((element: HTMLFormElement) => { element.requestSubmit(); element.requestSubmit(); });
    await expect(page).toHaveURL(`${webUrl}/${workspace}/work-items/${itemId}`);
    expect(creationCommits).toBe(1); expect(executionCommits).toBe(1);
    expect(keys.size).toBe(2);
    await page.reload();
    await expect(page.getByRole('heading', { name: '等待审批', exact: true })).toBeVisible();
    await page.getByRole('link', { name: '工作台', exact: true }).first().click();
    await expect(page.getByText(item.title, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  } finally { web.kill('SIGTERM'); api.closeAllConnections(); await new Promise<void>(resolve => api.close(() => resolve())); }
});

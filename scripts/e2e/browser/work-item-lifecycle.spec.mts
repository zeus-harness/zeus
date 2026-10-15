// Hermetic UI acceptance: real Svelte SSR/browser, synthetic API and adapters.
// This proves interaction behavior, not a real external merge, SQL change or deployment.
import { expect, test } from '@playwright/test';
import { createServer, type Server } from 'node:http';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

async function listen(server: Server) {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fixture did not bind.');
  return `http://127.0.0.1:${address.port}`;
}

for (const width of [1440, 390]) test(`chat task, rejection, retry, approval, interrupted archival at ${width}px`, async ({ page }, testInfo) => {
  await page.setViewportSize({ width, height: 900 });
  const org = randomUUID(), workspace = randomUUID(), user = randomUUID(), itemId = randomUUID();
  const conv = randomUUID(), member = randomUUID(), source = randomUUID(), version = randomUUID();
  const workflow = randomUUID(), firstRun = randomUUID(), secondRun = randomUUID();
  const time = '2026-10-01T00:00:00Z';
  const item = { id: itemId, organization_id: org, workspace_id: workspace, title: 'Synthetic log repair', description: 'Verify a synthetic failure and fix', source_kind: 'im_agent', external_reference: `im:${conv}:${source}`, priority: 'normal', status: 'in_progress', input: {}, output: null as unknown, revision: 1, assignee_user_id: null, created_by: user, created_at: time, updated_at: time, completed_at: null as string | null, archived_at: null as string | null };
  const run = (id: string, status: string) => ({ id, organization_id: org, workspace_id: workspace, workflow_version_id: version, session_id: randomUUID(), work_item_id: itemId, parent_run_id: null, retry_of_run_id: id === secondRun ? firstRun : null, status, input: {}, output: null as unknown, error_code: null, error_detail: null, attempt_count: 1, cancel_requested_at: null, started_at: time, finished_at: null, created_at: id === firstRun ? time : '2026-10-01T00:01:00Z', updated_at: time, deadline_at: null, wait_expires_at: null });
  const runs = [run(firstRun, 'waiting_approval')];
  const reviews: Record<string, unknown>[] = [];
  let archive: Record<string, unknown> | null = null;
  let invoked = false, retried = false, archivePosts = 0, archiveCommits = 0, rejectOnce = true;
  const approval = (id: string) => ({ id, run_id: id, tool_call_id: id, workspace_id: workspace, status: runs.find(run => run.id === id)?.status === 'waiting_approval' ? 'pending' : runs.find(run => run.id === id)?.status === 'failed' ? 'rejected' : 'approved', kind: 'execution', requested_by: user, requested_at: time, expires_at: null, decided_at: null, decided_by: null, authorized_until: null, revoked_at: null, reason: null, can_decide: true });
  const api = createServer(async (request, response) => {
    const path = new URL(request.url!, 'http://fixture').pathname;
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const payload = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    const json = (data: unknown, status = 200) => { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(data)); };
    const principal = { principal_kind: 'user', principal_id: user, user_id: user, display_name: 'Synthetic Owner', email: 'owner@example.invalid', organization_id: org, workspace_id: workspace, organization_role: 'owner', workspace_role: 'owner', platform_roles: [], auth_methods: ['password', 'totp'], email_verified_at: time, has_native_password: true, totp_enabled: true, mfa_required: false, tenant_access_grant_id: null, scopes: [] };
    if (path === '/api/v1/auth/me') return json(principal);
    if (path === '/api/v1/users/me/organizations') return json([{ organization_id: org, organization_slug: 'fixture', organization_name: 'Synthetic organization', organization_status: 'active', organization_role: 'owner', identity_settings_mode: 'organization_managed', can_manage_organization: true, can_manage_identity_settings: true, support_access: false, workspaces: [{ id: workspace, slug: 'fixture', name: 'Synthetic workspace', status: 'active', role: 'owner', support_access: false }] }]);
    if (path.endsWith('/im/people')) return json({ items: [], next_cursor: null });
    const conversation = { id: conv, kind: 'group', title: 'Synthetic issue group', organization_id: org, created_by: user, created_at: time, updated_at: time, unread: 0, last_sequence: 1 };
    const agents = [{ id: member, display_name: 'Repair Agent', workspace_id: workspace, workflow_version_id: version, joined_sequence: 1 }];
    if (path.endsWith('/im/conversations')) return json({ items: [conversation], next_cursor: null });
    if (path.endsWith(`/im/conversations/${conv}`)) {
      if (request.method === 'PATCH') return json({});
      return json({ conversation, members: [{ id: user, display_name: 'Synthetic Owner', role: 'owner' }], agents, calls: invoked ? [{ run_id: firstRun, agent_member_id: member, source_message_id: source, workspace_id: workspace, status: runs.find(run => run.id === firstRun)!.status, work_item_id: itemId }] : [] });
    }
    if (path.endsWith(`/im/conversations/${conv}/messages`)) return json({ items: [{ id: source, conversation_id: conv, sequence: 1, sender_id: user, sender_agent_id: null, agent_run_id: null, sender_name: 'Synthetic Owner', organization_name: 'Synthetic organization', sender_organization_id: org, content: 'Synthetic log repair', reply_to: null, mentions: [], created_at: time }], next_cursor: null });
    if (path.endsWith('/agent-calls')) {
      expect(payload.create_work_item).toBe(true);
      expect(request.headers['idempotency-key']).toBe(`im:${member}:${source}`);
      invoked = true; return json({ id: firstRun, work_item_id: itemId });
    }
    if (path.endsWith('/workflows')) return json({ items: [{ id: workflow, name: 'Repair workflow', active_version_id: version, archived_at: null }], next_cursor: null });
    if (path.endsWith('/members')) return json([{ user_id: user, display_name: 'Synthetic Owner', email: 'owner@example.invalid', status: 'active' }]);
    if (path.endsWith('/capabilities')) return json({ items: [], next_cursor: null });
    if (path.endsWith(`/work-items/${itemId}`)) return json(item);
    if (path.endsWith(`/work-items/${itemId}/reviews`)) {
      if (request.method === 'POST') {
        expect(request.headers['if-match']).toBe(`"revision-${item.revision}"`);
        reviews.unshift({ id: randomUUID(), work_item_id: itemId, run_id: payload.run_id, workflow_version_id: version, work_item_revision: item.revision, decision: payload.decision, reason: payload.reason, reviewed_by: user, created_at: time });
        item.revision += 1; return json(reviews[0], 201);
      }
      return json({ items: reviews, next_cursor: null });
    }
    if (path.endsWith(`/work-items/${itemId}/archive`)) {
      if (request.method === 'POST') {
        archivePosts += 1;
        expect(request.headers['idempotency-key']).toBe(`archive-${reviews[0].id}-${item.revision}`);
        if (rejectOnce) { rejectOnce = false; return json({ detail: 'Synthetic revision conflict' }, 412); }
        await new Promise(resolve => setTimeout(resolve, 300));
        if (!archive) {
          archiveCommits += 1;
          archive = { id: randomUUID(), work_item_id: itemId, run_id: secondRun, review_id: reviews[0].id, workflow_version_id: version, work_item_revision: item.revision, resolution_summary: payload.resolution_summary, archived_by: user, created_at: time };
          item.status = 'completed'; item.archived_at = time; item.completed_at = time; item.revision += 1; item.output = runs[0].output;
        }
        return json(archive, 201);
      }
      return json(archive ?? { detail: 'Not archived' }, archive ? 200 : 404);
    }
    if (path.endsWith('/external-references') || path.endsWith('/attachments') || path.endsWith('/children')) return json([]);
    if (path.endsWith('/approvals') && request.method === 'GET') return json(runs.map(run => approval(run.id)));
    if (/\/approvals\/[^/]+\/(approve|reject)$/.test(path)) {
      const id = path.split('/').at(-2)!;
      const current = runs.find(run => run.id === id)!;
      current.status = path.endsWith('/reject') ? 'failed' : 'succeeded';
      current.output = current.status === 'succeeded' ? { content: 'Synthetic log fixture verified' } : null;
      response.writeHead(204); return response.end();
    }
    if (path.endsWith(`/runs/${firstRun}/retry`)) {
      expect(request.headers['idempotency-key']).toBe(`retry-${firstRun}`);
      if (!retried) { runs.unshift(run(secondRun, 'waiting_approval')); retried = true; }
      return json(runs[0], 201);
    }
    if (path.endsWith('/runs')) return json({ items: runs, next_cursor: null });
    if (path.endsWith('/trace')) {
      const current = runs.find(run => run.id === path.split('/').at(-2))!;
      return json({ conversation_id: conv, code_checkpoints: [], run: current, run_events: [], session_events: [], tool_calls: [{ id: current.id, capability_id: member, input: { action: 'synthetic echo only', message: item.description }, status: 'waiting_approval', created_at: time }], approvals: [approval(current.id)], usage: { prompt_tokens: 0, completion_tokens: 0, cache_tokens: 0, entries: [] }, linked_runs: [], experience_injections: [] });
    }
    return json({ detail: 'Unknown fixture route' }, 404);
  });
  const apiUrl = await listen(api);
  const portReservation = createServer();
  const webUrl = await listen(portReservation);
  await new Promise<void>(resolve => portReservation.close(() => resolve()));
  const web = spawn(process.execPath, ['apps/web/build/index.js'], { env: { ...process.env, HOST: '127.0.0.1', PORT: new URL(webUrl).port, ORIGIN: webUrl, ZEUS_API_URL: apiUrl }, stdio: 'ignore' });
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  // Browser events use the same-origin endpoint; keep the fixture transport local.
  await page.route('**/events/stream', route => route.fulfill({ status: 200, contentType: 'text/event-stream', body: ': synthetic keepalive\n\n' }));
  try {
    await expect.poll(async () => { try { return (await fetch(webUrl)).status; } catch { return 0; } }).toBe(200);
    await page.goto(`${webUrl}/organizations/${org}/im?conversation=${conv}`);
    await page.getByRole('button', { name: '交给 Agent', exact: true }).click();
    await expect(page.getByLabel('创建持久工作项', { exact: false })).toBeChecked();
    await page.getByLabel('以我的 Workspace 权限执行', { exact: false }).check();
    await page.getByRole('button', { name: '调用 Agent', exact: true }).click();
    const tracking = page.getByRole('link', { name: '跟踪工作项与验收', includeHidden: true });
    await expect(tracking).toHaveAttribute('href', `/${workspace}/work-items/${itemId}`);
    // The same source can be submitted again without creating a second goal/Run.
    await page.getByRole('button', { name: '交给 Agent', exact: true }).click();
    await page.getByLabel('以我的 Workspace 权限执行', { exact: false }).check();
    await page.getByRole('button', { name: '调用 Agent', exact: true }).click();
    await page.locator('summary').filter({ hasText: 'Agent 调用与审批' }).click();
    await tracking.click();
    await expect(page).toHaveURL(`${webUrl}/${workspace}/work-items/${itemId}`);
    const closeButton = page.getByRole('button', { name: '验证完成并归档' });
    await expect(closeButton).toHaveCount(0);
    await page.reload();
    await expect(page.getByRole('button', { name: '批准', exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath('waiting-approval.png') });
    await page.getByRole('button', { name: '拒绝', exact: true }).click();
    await expect(page.getByRole('button', { name: '重试任务' })).toBeVisible();
    await page.getByLabel('已核对执行记录与已有操作', { exact: false }).check();
    await page.getByRole('button', { name: '重试任务' }).click();
    await expect(page.getByRole('button', { name: '批准', exact: true })).toBeVisible();
    await expect(page).toHaveURL(`${webUrl}/${workspace}/work-items/${itemId}`);
    await page.reload();
    await page.getByRole('button', { name: '批准', exact: true }).click();
    await expect(page.getByText('Synthetic log fixture verified', { exact: true })).toBeVisible();
    await page.goto(`${webUrl}/${workspace}/work-items/${itemId}`);
    await expect(closeButton).toHaveCount(0);
    await page.getByLabel('验收决定', { exact: true }).selectOption('accepted');
    await page.getByLabel('验收原因', { exact: true }).fill('Synthetic log and test evidence verified by Owner');
    await page.getByLabel('我已核对上方所选运行的结果').check();
    await page.getByRole('button', { name: '保存验收记录' }).click();
    await expect(closeButton).toBeEnabled();
    const report = 'Synthetic logs and mock tests confirm the issue was resolved.';
    await page.getByLabel('问题解决验证报告', { exact: true }).fill(report);
    await page.getByLabel('我已验证目标达成', { exact: false }).check();
    await page.screenshot({ path: testInfo.outputPath('owner-verification.png') });
    await page.route(url => url.origin === webUrl && url.search === '?/archive', route => route.abort(), { times: 1 });
    await closeButton.click();
    await expect(page.getByText('连接中断，归档尚未确认。报告已保留', { exact: false })).toBeVisible();
    await expect(page.getByLabel('问题解决验证报告', { exact: true })).toHaveValue(report);
    expect(archivePosts).toBe(0);
    await closeButton.click();
    await expect(page.getByText('工作项已更新。报告已保留', { exact: false })).toBeVisible();
    await expect(page.getByLabel('问题解决验证报告', { exact: true })).toHaveValue(report);
    const archiveForm = page.locator('form[action="?/archive"]');
    await archiveForm.evaluate((form: HTMLFormElement) => { form.requestSubmit(); form.requestSubmit(); });
    await expect(page.getByText('工作项已归档', { exact: false })).toBeVisible();
    expect(archivePosts).toBe(2); expect(archiveCommits).toBe(1); expect(runs).toHaveLength(2);
    await page.reload();
    await expect(page.getByText(report, { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '启动运行', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '保存状态', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '保存验收记录', exact: true })).toHaveCount(0);
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await page.locator('#closure').scrollIntoViewIfNeeded();
      await page.screenshot({ path: testInfo.outputPath(`lifecycle-${width}.png`) });
      const overflow = await page.evaluate(() => Array.from(document.querySelectorAll('main, main *')).filter(element => {
        const bounds = element.getBoundingClientRect();
        return bounds.width > 0 && bounds.right > innerWidth;
      }).map(element => ({ tag: element.tagName, class: element.className, text: element.textContent?.slice(0, 90) })).slice(0, 12));
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), JSON.stringify(overflow)).toBe(true);
    }
    expect(errors).toEqual([]);
  } finally {
    web.kill('SIGTERM');
    api.closeAllConnections();
    await new Promise<void>(resolve => api.close(() => resolve()));
  }
});

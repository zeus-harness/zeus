import { randomUUID, createHash } from 'node:crypto';
import { writeFile, chmod } from 'node:fs/promises';
import { loadEnvironment, ZeusClient, login, selectWorkspace, waitForRunStatus } from './work-item.mjs';
import { PILOT_CASES, PILOT_INSTRUCTIONS, evaluatePilot } from './requirements-cases.mjs';

const reportPath = new URL(`../../.zeus/pilot-report-${Date.now()}.json`, import.meta.url);
const report = { kind: 'deterministic_runtime_regression', generated_at: new Date().toISOString(),
  corpus_sha256: createHash('sha256').update(JSON.stringify({ PILOT_INSTRUCTIONS, PILOT_CASES })).digest('hex'),
  human_quality: 'not_validated', cases: [] };

async function main() {
  const environment = await loadEnvironment();
  const origin = environment.ZEUS_E2E_PUBLIC_URL ?? 'http://127.0.0.1:3100';
  if (origin !== 'http://127.0.0.1:3100') throw new Error('Pilot requires the isolated 3100 profile.');
  const modelUrl = new URL(environment.ZEUS_E2E_MODEL_BASE_URL);
  if (modelUrl.protocol !== 'http:' || modelUrl.port !== '4010') throw new Error('Pilot requires the deterministic fixture.');
  const healthUrl = modelUrl.hostname === 'zeus-ci-openai' ? new URL('http://127.0.0.1:4010/health') : new URL('/health', modelUrl);
  const health = await fetch(healthUrl, { signal: AbortSignal.timeout(5000) }).then((response) => response.json());
  if (health.fixture !== 'zeus-deterministic-pilot-v1') throw new Error('Build and start the current deterministic fixture first.');
  const client = new ZeusClient(origin);
  await login(client, environment);
  const tenant = await selectWorkspace(client);
  const base = `/api/v1/workspaces/${tenant.workspaceId}`;
  const organizationBase = `/api/v1/organizations/${tenant.organizationId}`;
  const create = (pathname, body) => client.json(pathname, { method: 'POST', body, headers: { 'idempotency-key': randomUUID() } }, [201]);
  const connection = await create(`${organizationBase}/model-providers`, {
    name: `Pilot ${Date.now()}`, provider_kind: 'openai_compatible',
    configuration: { api_key_secret_name: 'api_key' }, secrets: { api_key: environment.ZEUS_E2E_MODEL_API_KEY }
  });
  const catalogPath = `/api/v1/organizations/${tenant.organizationId}/capability-definitions`;
  const catalog = await client.json(`${catalogPath}?limit=100`);
  const capability = catalog.items.find((entry) => entry.registry_key === 'pilot.work-item-read') ?? await create(catalogPath, {
    registry_key: 'pilot.work-item-read', display_name: 'Pilot current WorkItem', description: 'Read only the linked synthetic WorkItem.',
    executor_key: 'builtin.work_item_read', input_schema: { type: 'object', properties: {}, additionalProperties: false },
    output_schema: { type: 'object' }, risk_level: 'low', idempotency_mode: 'supported'
  });
  const enabled = await client.json(`${base}/capabilities?limit=100`);
  if (!enabled.items.some((entry) => entry.capability_id === capability.id)) {
    await create(`${base}/capabilities`, { capability_id: capability.id, enabled: true, approval_required: true, timeout_seconds: 10, policy: {} });
  }
  const agent = await create(`${base}/agents`, { name: `需求整理试点 ${Date.now()}`, description: 'Synthetic regression only.' });
  for (const testCase of PILOT_CASES) {
    const entry = { case_id: testCase.id, status: 'not_started', elapsed_ms: null, usage: null, human_review: 'not_reviewed' };
    report.cases.push(entry);
    const start = Date.now();
    try {
      const model = await create(`${organizationBase}/model-profiles`, {
        name: `Pilot ${testCase.id} ${Date.now()}`, connection_id: connection.id, provider_kind: 'openai_compatible',
        base_url: modelUrl.href, model: `zeus-pilot-${testCase.id}`, configuration: { timeout_seconds: testCase.id === 'timeout' ? 1 : 10 }
      });
      const version = await create(`${base}/agents/${agent.id}/versions`, { instructions: PILOT_INSTRUCTIONS, configuration: {}, model_profile_id: model.id });
      const workflow = await create(`${base}/workflows`, { name: `Pilot ${testCase.id} ${Date.now()}` });
      const workflowVersion = await create(`${base}/workflows/${workflow.id}/versions`, {
        agent_version_id: version.id, input_schema: {}, output_schema: {},
        capability_policy: { allowed: [capability.id] }, approval_policy: { require_high_risk: true, fail_on_denial: false },
        experience_policy: { scopes: [], limit: 0 }, max_steps: 8, max_runtime_seconds: 120, token_budget: 4000,
        retry_policy: { model_network_attempts: 0, capability_attempts: 0 }
      });
      await client.json(`${base}/workflows/${workflow.id}/active-version`, { method: 'POST', headers: { 'if-match': `"revision-${workflow.revision}"` }, body: { version_id: workflowVersion.id } });
      const item = await create(`${base}/work-items`, { title: testCase.title, description: testCase.description, priority: 'normal', source_kind: 'pilot', external_reference: randomUUID(), input: {} });
      const started = await create(`${base}/work-items/${item.id}/runs`, { workflow_id: workflow.id, input: {}, message: '请读取当前工作项并整理需求。' });
      entry.run_id = started.run.id;
      entry.workflow_version_id = workflowVersion.id;
      entry.model_profile_id = model.id;
      const runStart = Date.now();
      if (testCase.decision !== 'timeout') {
        await waitForRunStatus(client, tenant.workspaceId, entry.run_id, new Set(['waiting_approval']), 45000);
        const approvals = await client.json(`${base}/approvals?status=pending&work_item_id=${item.id}`);
        if (approvals.length !== 1) throw new Error('Expected one pilot approval.');
        if (testCase.decision === 'cancel') {
          const response = await client.request(`${base}/runs/${entry.run_id}/cancel`, { method: 'POST', body: { reason: 'Synthetic pilot cancellation.' } });
          if (response.status !== 202) throw new Error('Cancellation was not accepted.');
        } else {
          await client.json(`${base}/approvals/${approvals[0].id}/${testCase.decision === 'reject' ? 'reject' : 'approve'}`, { method: 'POST', body: { reason: 'Synthetic pilot decision.' } }, [204]);
        }
      }
      const terminal = await waitForRunStatus(client, tenant.workspaceId, entry.run_id, new Set(['succeeded', 'failed', 'canceled']), 45000);
      const trace = await client.json(`${base}/runs/${entry.run_id}/trace`);
      Object.assign(entry, { status: terminal.status, error_code: terminal.error_code, elapsed_ms: Date.now() - runStart,
        usage: { prompt_tokens: trace.usage.prompt_tokens, completion_tokens: trace.usage.completion_tokens, cache_tokens: trace.usage.cache_tokens },
        ...evaluatePilot(testCase, { ...terminal, content: terminal.output?.content, tool_calls: trace.tool_calls }) });
    } catch (error) {
      // Do not persist arbitrary transport/API diagnostics or request bodies.
      Object.assign(entry, { passed: false, failure: 'pilot_execution_failed' });
      const diagnostic = /returned HTTP (\d{3}) \(([a-z_]+)\)/u.exec(error instanceof Error ? error.message : '');
      if (diagnostic) {
        entry.failure = `http_${diagnostic[1]}_${diagnostic[2]}`;
        entry.endpoint = error.message.split(' returned HTTP ')[0];
      }
      if (entry.run_id) {
        await client.request(`${base}/runs/${entry.run_id}/cancel`, { method: 'POST', body: { reason: 'Pilot cleanup.' } }).catch(() => {});
      }
    } finally {
      entry.total_ms = Date.now() - start;
      await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
      await chmod(reportPath, 0o600);
    }
    process.stdout.write(`${testCase.id}: ${entry.passed ? 'PASS' : 'FAIL'} (${entry.status}${entry.failure ? `, ${entry.failure}` : ''})\n`);
  }
  process.stdout.write(`Report: ${reportPath.pathname}\n`);
  if (report.cases.some((entry) => !entry.passed)) process.exitCode = 1;
}

main().catch(() => { process.stderr.write('Pilot setup failed; verify the isolated stack, fixture and E2E account.\n'); process.exitCode = 1; });

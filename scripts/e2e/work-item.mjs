import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..', '..');
const ENV_PATH = path.join(REPO_ROOT, '.zeus', 'e2e.env');
const STATE_PATH = path.join(REPO_ROOT, '.zeus', 'e2e-state.json');
const TERMINAL_RUN_STATES = new Set(['succeeded', 'failed', 'canceled']);

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function assertRfc3339(value, field) {
  assert.equal(typeof value, 'string', `${field} must be an RFC3339 string`);
  assert.match(
    value,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/u,
    `${field} must use RFC3339`
  );
}

export function parseEnvFile(source) {
  const values = {};
  for (const line of source.split(/\r?\n/u)) {
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (match) values[match[1]] = match[2];
  }
  return values;
}

async function loadEnvironment() {
  const source = await readFile(ENV_PATH, 'utf8').catch(() => {
    throw new Error('Missing .zeus/e2e.env. Run scripts/container e2e init-env.');
  });
  const environment = parseEnvFile(source);
  for (const key of [
    'ZEUS_BOOTSTRAP_TOKEN',
    'ZEUS_E2E_EMAIL',
    'ZEUS_E2E_PASSWORD',
    'ZEUS_E2E_MODEL_API_KEY',
    'ZEUS_E2E_MODEL_BASE_URL'
  ]) {
    if (!environment[key]) throw new Error(`Missing ${key} in .zeus/e2e.env.`);
  }
  return environment;
}

async function setEnvironmentValue(key, value) {
  const source = await readFile(ENV_PATH, 'utf8');
  const replacement = `${key}=${value}`;
  const lines = source.split(/\r?\n/u);
  const index = lines.findIndex((line) => line.startsWith(`${key}=`));
  if (index === -1) lines.push(replacement);
  else lines[index] = replacement;
  const temporaryPath = `${ENV_PATH}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${lines.filter(Boolean).join('\n')}\n`, { mode: 0o600 });
  await rename(temporaryPath, ENV_PATH);
  await chmod(ENV_PATH, 0o600);
}

function required(environment, key) {
  const value = environment[key];
  if (!value) throw new Error(`Missing ${key} in .zeus/e2e.env.`);
  return value;
}

class CookieJar {
  #cookies = new Map();

  update(response) {
    const setCookies = response.headers.getSetCookie?.() ?? [];
    for (const setCookie of setCookies) {
      const pair = setCookie.split(';', 1)[0];
      const separator = pair.indexOf('=');
      if (separator <= 0) continue;
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      if (value) this.#cookies.set(name, value);
      else this.#cookies.delete(name);
    }
  }

  header() {
    return [...this.#cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  get(name) {
    return this.#cookies.get(name);
  }
}

class ZeusClient {
  constructor(origin) {
    const parsed = new URL(origin);
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)) {
      throw new Error('The E2E client only connects to a loopback Zeus origin.');
    }
    this.origin = parsed.origin;
    this.cookies = new CookieJar();
  }

  async request(pathname, options = {}) {
    const method = options.method ?? 'GET';
    const headers = new Headers(options.headers);
    headers.set('accept', options.accept ?? 'application/json');
    const cookie = this.cookies.header();
    if (cookie) headers.set('cookie', cookie);
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      headers.set('origin', this.origin);
      const csrf = this.cookies.get('zeus_csrf');
      if (csrf) headers.set('x-zeus-csrf', csrf);
    }
    if (options.body !== undefined) headers.set('content-type', 'application/json');

    const response = await fetch(new URL(pathname, this.origin), {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
      redirect: 'manual'
    });
    this.cookies.update(response);
    return response;
  }

  async json(pathname, options = {}, expected = [200]) {
    const response = await this.request(pathname, options);
    if (!expected.includes(response.status)) await throwResponseError(response, pathname);
    if (response.status === 204) return null;
    return response.json();
  }
}

async function throwResponseError(response, pathname) {
  let code = 'unknown_error';
  try {
    const body = await response.json();
    if (typeof body?.code === 'string') code = body.code;
  } catch {
    // Keep the stable status-only diagnostic.
  }
  throw new Error(`${pathname} returned HTTP ${response.status} (${code}).`);
}

function decodeBase32(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const character of value.toUpperCase().replace(/=+$/u, '')) {
    const index = alphabet.indexOf(character);
    if (index === -1) throw new Error('Invalid base32 TOTP secret.');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

export function totpAt(secret, unixSeconds = Math.floor(Date.now() / 1000)) {
  const counter = Math.floor(unixSeconds / 30);
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decodeBase32(secret)).update(counterBytes).digest();
  const offset = digest.at(-1) & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return { code: String(binary % 1_000_000).padStart(6, '0'), counter };
}

async function freshTotp(environment) {
  const secret = required(environment, 'ZEUS_E2E_TOTP_SECRET');
  const lastCounter = Number.parseInt(environment.ZEUS_E2E_TOTP_LAST_COUNTER ?? '-1', 10);
  let current = totpAt(secret);
  if (Number.isSafeInteger(lastCounter) && current.counter <= lastCounter) {
    const waitMilliseconds = (30 - (Math.floor(Date.now() / 1000) % 30) + 1) * 1000;
    await sleep(waitMilliseconds);
    current = totpAt(secret);
  }
  return current;
}

export function verificationTokenFromMessage(message) {
  const candidates = [message?.Text, message?.HTML, message?.text, message?.html].filter(
    (value) => typeof value === 'string'
  );
  for (const candidate of candidates) {
    const match = /[?&](?:amp;)?token=([A-Za-z0-9_-]{43,256})/u.exec(candidate);
    if (match) return match[1];
  }
  return null;
}

async function waitForVerificationToken(origin) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    try {
      const listResponse = await fetch(new URL('/mailpit/api/v1/messages', origin), {
        headers: { accept: 'application/json' }
      });
      if (listResponse.ok) {
        const listing = await listResponse.json();
        const messages = listing.messages ?? listing.Messages ?? [];
        for (const summary of messages.slice(0, 20)) {
          const id = summary.ID ?? summary.Id ?? summary.id;
          if (!id) continue;
          const detailResponse = await fetch(
            new URL(`/mailpit/api/v1/message/${encodeURIComponent(id)}`, origin),
            { headers: { accept: 'application/json' } }
          );
          if (!detailResponse.ok) continue;
          const token = verificationTokenFromMessage(await detailResponse.json());
          if (token) return token;
        }
      }
    } catch {
      // Mail delivery is asynchronous; retry until the bounded deadline.
    }
    await sleep(500);
  }
  throw new Error('Verification email did not arrive in the isolated Mailpit instance.');
}

async function completeMfa(client, environment) {
  const current = await freshTotp(environment);
  await client.json(
    '/api/v1/auth/mfa/verify',
    { method: 'POST', body: { code: current.code } },
    [200]
  );
  await setEnvironmentValue('ZEUS_E2E_TOTP_LAST_COUNTER', String(current.counter));
  environment.ZEUS_E2E_TOTP_LAST_COUNTER = String(current.counter);
}

async function login(client, environment) {
  const result = await client.json(
    '/api/v1/auth/login',
    {
      method: 'POST',
      body: {
        email: required(environment, 'ZEUS_E2E_EMAIL'),
        password: required(environment, 'ZEUS_E2E_PASSWORD')
      }
    },
    [200]
  );
  if (result.email_verification_required) {
    throw new Error('The E2E account still requires email verification.');
  }
  if (result.totp_setup_required) {
    throw new Error('The E2E account requires TOTP setup. Reset and seed the isolated stack.');
  }
  if (result.mfa_required) await completeMfa(client, environment);
}

async function setupIdentity(client, environment) {
  const status = await client.json('/api/v1/setup/status');
  if (!status.setup_required) {
    await login(client, environment);
    return;
  }

  await client.json(
    '/api/v1/setup',
    {
      method: 'POST',
      body: {
        bootstrap_token: required(environment, 'ZEUS_BOOTSTRAP_TOKEN'),
        email: required(environment, 'ZEUS_E2E_EMAIL'),
        display_name: 'Zeus E2E Admin',
        password: required(environment, 'ZEUS_E2E_PASSWORD'),
        organization_slug: 'e2e-organization',
        organization_name: 'E2E Organization',
        workspace_slug: 'e2e-workspace',
        workspace_name: 'E2E Workspace'
      }
    },
    [201]
  );

  const verificationToken = await waitForVerificationToken(client.origin);
  await client.json(
    '/api/v1/auth/email-verifications/confirm',
    { method: 'POST', body: { token: verificationToken } },
    [204]
  );

  const enrollment = await client.json(
    '/api/v1/users/me/totp',
    { method: 'POST', body: {} },
    [200]
  );
  assert.equal(enrollment.confirmed, false);
  assert.equal(typeof enrollment.secret, 'string');
  const current = totpAt(enrollment.secret);
  await client.json(
    '/api/v1/users/me/totp',
    { method: 'POST', body: { code: current.code } },
    [200]
  );
  await setEnvironmentValue('ZEUS_E2E_TOTP_SECRET', enrollment.secret);
  await setEnvironmentValue('ZEUS_E2E_TOTP_LAST_COUNTER', String(current.counter));
  environment.ZEUS_E2E_TOTP_SECRET = enrollment.secret;
  environment.ZEUS_E2E_TOTP_LAST_COUNTER = String(current.counter);
}

async function selectWorkspace(client) {
  const organizations = await client.json('/api/v1/users/me/organizations');
  const organization = organizations.find(
    (item) => item.organization_slug === 'e2e-organization'
  );
  if (!organization) throw new Error('The E2E Organization is unavailable to the fixture user.');
  const workspaces = Array.isArray(organization.workspaces) ? organization.workspaces : [];
  const workspace = workspaces.find((item) => item.slug === 'e2e-workspace');
  if (!workspace) throw new Error('The E2E Workspace is unavailable to the fixture user.');

  await client.json(
    '/api/v1/auth/context',
    {
      method: 'POST',
      body: {
        organization_id: organization.organization_id,
        workspace_id: workspace.id
      }
    },
    [204]
  );
  return { organizationId: organization.organization_id, workspaceId: workspace.id };
}

async function listItems(client, pathname) {
  const result = await client.json(pathname);
  return Array.isArray(result) ? result : result.items ?? [];
}

async function ensureControlPlane(client, environment, tenant) {
  const workspacePath = `/api/v1/workspaces/${tenant.workspaceId}`;
  const organizationPath = `/api/v1/organizations/${tenant.organizationId}`;

  let connection = (await listItems(client, `${workspacePath}/connections`)).find(
    (item) => item.name === 'E2E Deterministic Model'
  );
  if (!connection) {
    connection = await client.json(
      `${workspacePath}/connections`,
      {
        method: 'POST',
        body: {
          name: 'E2E Deterministic Model',
          provider_kind: 'openai_compatible',
          configuration: { api_key_secret_name: 'api_key' },
          secrets: { api_key: required(environment, 'ZEUS_E2E_MODEL_API_KEY') }
        }
      },
      [201]
    );
  }

  const secrets = await listItems(client, `${workspacePath}/connections/${connection.id}/secrets`);
  if (!secrets.some((item) => item.secret_name === 'api_key')) {
    await client.json(
      `${workspacePath}/connections/${connection.id}/secrets`,
      {
        method: 'POST',
        body: {
          secret_name: 'api_key',
          secret: required(environment, 'ZEUS_E2E_MODEL_API_KEY')
        }
      },
      [201]
    );
  }

  let modelProfile = (await listItems(client, `${workspacePath}/model-profiles`)).find(
    (item) => item.name === 'E2E Deterministic Model'
  );
  const modelBaseUrl = required(environment, 'ZEUS_E2E_MODEL_BASE_URL');
  if (!modelProfile) {
    modelProfile = await client.json(
      `${workspacePath}/model-profiles`,
      {
        method: 'POST',
        body: {
          connection_id: connection.id,
          name: 'E2E Deterministic Model',
          provider_kind: 'openai_compatible',
          base_url: modelBaseUrl,
          model: 'zeus-e2e',
          configuration: { timeout_seconds: 10 }
        }
      },
      [201]
    );
  } else if (modelProfile.base_url !== modelBaseUrl || modelProfile.connection_id !== connection.id) {
    modelProfile = await client.json(
      `${workspacePath}/model-profiles/${modelProfile.id}`,
      {
        method: 'PATCH',
        headers: { 'if-match': `"revision-${modelProfile.revision}"` },
        body: { connection_id: connection.id, base_url: modelBaseUrl }
      },
      [200]
    );
  }

  let capability = (
    await listItems(client, `${organizationPath}/capability-definitions`)
  ).find((item) => item.registry_key === 'e2e.echo');
  if (!capability) {
    capability = await client.json(
      `${organizationPath}/capability-definitions`,
      {
        method: 'POST',
        body: {
          registry_key: 'e2e.echo',
          display_name: 'E2E Echo',
          description: 'Returns deterministic input after an approval.',
          input_schema: {
            type: 'object',
            properties: { message: { type: 'string' } },
            required: ['message'],
            additionalProperties: false
          },
          output_schema: {
            type: 'object',
            properties: { echo: { type: 'object' } },
            required: ['echo'],
            additionalProperties: false
          },
          idempotency_mode: 'supported',
          risk_level: 'high',
          executor_key: 'builtin.echo'
        }
      },
      [201]
    );
  }

  let workspaceCapability = (await listItems(client, `${workspacePath}/capabilities`)).find(
    (item) => item.capability_id === capability.id
  );
  if (!workspaceCapability) {
    workspaceCapability = await client.json(
      `${workspacePath}/capabilities`,
      {
        method: 'POST',
        body: {
          capability_id: capability.id,
          connection_id: null,
          enabled: true,
          approval_required: true,
          timeout_seconds: 10,
          policy: {}
        }
      },
      [201]
    );
  }

  let agent = (await listItems(client, `${workspacePath}/agents`)).find(
    (item) => item.name === 'E2E WorkItem Agent'
  );
  if (!agent) {
    agent = await client.json(
      `${workspacePath}/agents`,
      {
        method: 'POST',
        body: {
          name: 'E2E WorkItem Agent',
          description: 'Deterministic WorkItem approval fixture.'
        }
      },
      [201]
    );
  }
  let agentVersion = (await listItems(client, `${workspacePath}/agents/${agent.id}/versions`))[0];
  if (!agentVersion) {
    agentVersion = await client.json(
      `${workspacePath}/agents/${agent.id}/versions`,
      {
        method: 'POST',
        body: {
          instructions: 'Call the available E2E capability once, then return a concise result.',
          configuration: {}
        }
      },
      [201]
    );
  }
  if (agent.active_version_id !== agentVersion.id) {
    agent = await client.json(
      `${workspacePath}/agents/${agent.id}/active-version`,
      {
        method: 'POST',
        headers: { 'if-match': `"revision-${agent.revision}"` },
        body: { version_id: agentVersion.id }
      },
      [200]
    );
  }

  let workflow = (await listItems(client, `${workspacePath}/workflows`)).find(
    (item) => item.name === 'E2E Approval Workflow'
  );
  if (!workflow) {
    workflow = await client.json(
      `${workspacePath}/workflows`,
      {
        method: 'POST',
        body: {
          name: 'E2E Approval Workflow',
          description: 'Runs a deterministic model and approval-required echo capability.'
        }
      },
      [201]
    );
  }
  let workflowVersion = (
    await listItems(client, `${workspacePath}/workflows/${workflow.id}/versions`)
  )[0];
  if (!workflowVersion) {
    workflowVersion = await client.json(
      `${workspacePath}/workflows/${workflow.id}/versions`,
      {
        method: 'POST',
        body: {
          agent_version_id: agentVersion.id,
          model_profile_id: modelProfile.id,
          input_schema: { type: 'object' },
          output_schema: { type: 'object' },
          capability_policy: { allowed: ['e2e.echo'] },
          approval_policy: { require_high_risk: true },
          experience_policy: { scopes: [], limit: 0 },
          max_steps: 8,
          max_runtime_seconds: 120,
          token_budget: 2000,
          retry_policy: { model_network_attempts: 1, capability_attempts: 0 }
        }
      },
      [201]
    );
  }
  if (workflow.active_version_id !== workflowVersion.id) {
    workflow = await client.json(
      `${workspacePath}/workflows/${workflow.id}/active-version`,
      {
        method: 'POST',
        headers: { 'if-match': `"revision-${workflow.revision}"` },
        body: { version_id: workflowVersion.id }
      },
      [200]
    );
  }

  return {
    ...tenant,
    connectionId: connection.id,
    modelProfileId: modelProfile.id,
    capabilityId: capability.id,
    workspaceCapabilityId: workspaceCapability.id,
    agentId: agent.id,
    agentVersionId: agentVersion.id,
    workflowId: workflow.id,
    workflowVersionId: workflowVersion.id
  };
}

async function writeState(state) {
  await writeFile(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await chmod(STATE_PATH, 0o600);
}

async function loadState() {
  return JSON.parse(
    await readFile(STATE_PATH, 'utf8').catch(() => {
      throw new Error('Missing .zeus/e2e-state.json. Run scripts/container e2e seed.');
    })
  );
}

async function waitForRunStatus(client, workspaceId, runId, expected, timeoutMilliseconds) {
  const deadline = Date.now() + timeoutMilliseconds;
  let lastStatus = 'unknown';
  while (Date.now() < deadline) {
    const run = await client.json(`/api/v1/workspaces/${workspaceId}/runs/${runId}`);
    lastStatus = run.status;
    if (expected.has(run.status)) return run;
    if (TERMINAL_RUN_STATES.has(run.status)) {
      throw new Error(`Run reached unexpected terminal state ${run.status} (${run.error_code ?? 'no_code'}).`);
    }
    await sleep(250);
  }
  throw new Error(`Run did not reach ${[...expected].join(' or ')}; last state was ${lastStatus}.`);
}

async function readSseEvent(client, pathname, lastEventId = null) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const headers = lastEventId === null ? {} : { 'last-event-id': String(lastEventId) };
    const response = await client.request(pathname, {
      headers,
      accept: 'text/event-stream',
      signal: controller.signal
    });
    if (response.status !== 200) await throwResponseError(response, pathname);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const boundary = buffer.search(/\r?\n\r?\n/u);
      if (boundary === -1) continue;
      const frame = buffer.slice(0, boundary);
      const id = /^id:\s*(.+)$/mu.exec(frame)?.[1]?.trim();
      const data = /^data:\s*(.+)$/mu.exec(frame)?.[1];
      if (!id || !data) continue;
      controller.abort();
      return { id, data: JSON.parse(data) };
    }
    throw new Error('Run SSE stream ended before an event arrived.');
  } finally {
    clearTimeout(timeout);
  }
}

async function seed() {
  const environment = await loadEnvironment();
  const origin = environment.ZEUS_E2E_PUBLIC_URL ?? 'http://127.0.0.1:3100';
  const client = new ZeusClient(origin);
  await setupIdentity(client, environment);
  const tenant = await selectWorkspace(client);
  const state = await ensureControlPlane(client, environment, tenant);
  await writeState(state);
  process.stdout.write(
    `E2E fixture ready: organization ${state.organizationId}, workspace ${state.workspaceId}, workflow ${state.workflowId}.\n`
  );
}

async function run() {
  const environment = await loadEnvironment();
  const state = await loadState();
  const origin = environment.ZEUS_E2E_PUBLIC_URL ?? 'http://127.0.0.1:3100';
  const client = new ZeusClient(origin);
  await login(client, environment);
  const tenant = await selectWorkspace(client);
  assert.equal(tenant.organizationId, state.organizationId);
  assert.equal(tenant.workspaceId, state.workspaceId);

  const workspacePath = `/api/v1/workspaces/${state.workspaceId}`;
  const workItem = await client.json(
    `${workspacePath}/work-items`,
    {
      method: 'POST',
      headers: { 'idempotency-key': randomUUID() },
      body: {
        title: `E2E approval flow ${new Date().toISOString()}`,
        description: 'Created by the isolated deterministic WorkItem acceptance flow.',
        priority: 'high',
        assignee_user_id: null,
        source_kind: 'e2e',
        external_reference: `e2e-${randomUUID()}`,
        input: { message: 'Exercise the approval path.' }
      }
    },
    [201]
  );
  const started = await client.json(
    `${workspacePath}/work-items/${workItem.id}/runs`,
    {
      method: 'POST',
      headers: { 'idempotency-key': randomUUID() },
      body: {
        workflow_id: state.workflowId,
        input: workItem.input,
        message: 'Call the E2E capability and report the approved result.'
      }
    },
    [201]
  );
  assertRfc3339(workItem.created_at, 'work_item.created_at');
  assertRfc3339(started.run.created_at, 'run.created_at');

  await waitForRunStatus(client, state.workspaceId, started.run.id, new Set(['waiting_approval']), 45_000);
  const openWorkItems = await client.json(`${workspacePath}/work-items?status=open&limit=20`);
  assert.ok(openWorkItems.items.some((item) => item.id === workItem.id));
  const waitingRuns = await client.json(
    `${workspacePath}/runs?work_item_id=${encodeURIComponent(workItem.id)}&status=waiting_approval&limit=20`
  );
  assert.ok(waitingRuns.items.some((run) => run.id === started.run.id));
  const approvals = await client.json(
    `${workspacePath}/approvals?status=pending&work_item_id=${encodeURIComponent(workItem.id)}`
  );
  assert.equal(approvals.length, 1);
  await client.json(
    `${workspacePath}/approvals/${approvals[0].id}/approve`,
    { method: 'POST', body: { reason: 'Deterministic E2E approval.' } },
    [204]
  );

  const terminal = await waitForRunStatus(
    client,
    state.workspaceId,
    started.run.id,
    new Set(['succeeded']),
    45_000
  );
  assertRfc3339(terminal.updated_at, 'terminal_run.updated_at');
  const succeededRuns = await client.json(
    `${workspacePath}/runs?work_item_id=${encodeURIComponent(workItem.id)}&status=succeeded&limit=20`
  );
  assert.ok(succeededRuns.items.some((run) => run.id === started.run.id));
  const trace = await client.json(`${workspacePath}/runs/${started.run.id}/trace`);
  const eventTypes = new Set(trace.run_events.map((event) => event.event_type));
  for (const eventType of ['tool.requested', 'approval_resolved', 'tool.result', 'model.final']) {
    assert.ok(eventTypes.has(eventType), `missing ${eventType}`);
  }
  assert.equal(trace.tool_calls.length, 1);
  assert.equal(trace.tool_calls[0].status, 'succeeded');
  assert.equal(trace.approvals[0].status, 'approved');
  assert.ok(trace.usage.prompt_tokens > 0);
  assert.match(terminal.output?.content ?? '', /测试运行已完成/u);

  const streamPath = `${workspacePath}/runs/${started.run.id}/events/stream`;
  const firstEvent = await readSseEvent(client, streamPath);
  const resumedEvent = await readSseEvent(client, streamPath, firstEvent.id);
  assert.ok(Number(resumedEvent.id) > Number(firstEvent.id));

  await writeState({
    ...state,
    lastWorkItemId: workItem.id,
    lastRunId: started.run.id,
    lastRunStatus: terminal.status
  });
  process.stdout.write(
    `E2E WorkItem flow passed: work item ${workItem.id}, run ${started.run.id}, status ${terminal.status}.\n`
  );
}

async function main() {
  const command = process.argv[2];
  if (command === 'seed') await seed();
  else if (command === 'run') await run();
  else throw new Error('Usage: node scripts/e2e/work-item.mjs <seed|run>');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'E2E flow failed.'}\n`);
    process.exitCode = 1;
  });
}

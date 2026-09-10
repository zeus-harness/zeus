#!/usr/bin/env node

import { lstat, readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const TERMINAL_STATES = new Set(['succeeded', 'failed', 'canceled']);
const DEFAULTS = Object.freeze({
  concurrency: 200,
  durationSeconds: 1800,
  pollMilliseconds: 500,
  requestTimeoutMilliseconds: 30_000,
  runTimeoutSeconds: 1_200,
  minimumActors: 1_000,
  minimumWorkspaces: 100
});

main().catch((error) => {
  process.stderr.write(`capacity test failed: ${safeError(error)}\n`);
  process.exitCode = 1;
});

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  const config = await loadConfig(options.configPath);
  validateConfig(config, options);

  const stats = {
    startedAt: new Date(),
    submitted: 0,
    terminal: 0,
    succeeded: 0,
    failed: 0,
    canceled: 0,
    requestFailures: 0,
    timedOut: 0,
    duplicateTerminalEvents: 0,
    queueWaitMilliseconds: [],
    runLatencyMilliseconds: []
  };
  const stopAt = Date.now() + options.durationSeconds * 1_000;
  let stopping = false;
  const requestStop = () => {
    stopping = true;
  };
  process.once('SIGINT', requestStop);
  process.once('SIGTERM', requestStop);

  process.stdout.write(
    `${JSON.stringify({
      event: 'capacity_test_started',
      concurrency: options.concurrency,
      durationSeconds: options.durationSeconds,
      actors: config.actors.length,
      workspaces: new Set(config.actors.map((actor) => actor.workspaceId)).size
    })}\n`
  );

  await Promise.all(
    Array.from({ length: options.concurrency }, (_, workerIndex) =>
      runWorker(workerIndex, config, options, stats, () => stopping || Date.now() >= stopAt)
    )
  );

  const summary = summarize(config, options, stats);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (
    summary.requestFailures > 0 ||
    summary.timedOut > 0 ||
    summary.duplicateTerminalEvents > 0 ||
    summary.terminal !== summary.submitted ||
    summary.acceptance.queueWaitP95UnderTwoSeconds !== true
  ) {
    process.exitCode = 2;
  }
}

async function runWorker(workerIndex, config, options, stats, shouldStop) {
  let cycle = 0;
  while (!shouldStop()) {
    const actor = config.actors[(workerIndex + cycle * options.concurrency) % config.actors.length];
    cycle += 1;
    try {
      const result = await executeRun(config.baseUrl, actor, options);
      stats.submitted += 1;
      stats.terminal += 1;
      stats[result.status] += 1;
      stats.queueWaitMilliseconds.push(result.queueWaitMilliseconds);
      stats.runLatencyMilliseconds.push(result.runLatencyMilliseconds);
      if (result.terminalEventCount !== 1) {
        stats.duplicateTerminalEvents += Math.abs(result.terminalEventCount - 1) || 1;
      }
    } catch (error) {
      const cause = error instanceof RunSubmittedError ? error.cause : error;
      if (error instanceof RunSubmittedError) {
        stats.submitted += 1;
      }
      if (cause instanceof RunTimeoutError) {
        stats.timedOut += 1;
      } else {
        stats.requestFailures += 1;
      }
      process.stderr.write(
        `${JSON.stringify({
          event: 'capacity_iteration_failed',
          worker: workerIndex,
          code: safeError(error)
        })}\n`
      );
    }
  }
}

async function executeRun(baseUrl, actor, options) {
  const headers = authHeaders(actor.auth);
  const requestId = randomUUID();
  const session = await requestJson(
    `${baseUrl}/api/v1/workspaces/${actor.workspaceId}/sessions`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({ title: `capacity-${requestId}` })
    },
    options
  );
  const created = await requestJson(
    `${baseUrl}/api/v1/workspaces/${actor.workspaceId}/runs`,
    {
      method: 'POST',
      headers: { ...headers, 'Idempotency-Key': `capacity-${requestId}` },
      body: JSON.stringify({
        workflow_version_id: actor.workflowVersionId,
        session_id: session.id,
        work_item_id: null,
        input: { capacity_probe_id: requestId },
        message: 'Complete this capacity probe using the configured test workflow.'
      })
    },
    options
  );
  try {
    const terminal = await waitForTerminal(baseUrl, actor, created, options);
    const events = await requestJson(
      `${baseUrl}/api/v1/workspaces/${actor.workspaceId}/runs/${created.id}/events?after=0&limit=500`,
      { method: 'GET', headers },
      options
    );
    const terminalEventCount = events.filter(isTerminalEvent).length;
    const createdAt = Date.parse(created.created_at);
    const startedAt = Date.parse(terminal.started_at);
    const finishedAt = Date.parse(terminal.finished_at);
    if (![createdAt, startedAt, finishedAt].every(Number.isFinite)) {
      throw new Error('invalid_run_timestamps');
    }
    return {
      status: terminal.status,
      queueWaitMilliseconds: Math.max(0, startedAt - createdAt),
      runLatencyMilliseconds: Math.max(0, finishedAt - createdAt),
      terminalEventCount
    };
  } catch (error) {
    throw new RunSubmittedError(error);
  }
}

async function waitForTerminal(baseUrl, actor, run, options) {
  const deadline = Date.now() + options.runTimeoutSeconds * 1_000;
  const headers = authHeaders(actor.auth);
  let current = run;
  while (!TERMINAL_STATES.has(current.status)) {
    if (Date.now() >= deadline) {
      throw new RunTimeoutError();
    }
    await delay(options.pollMilliseconds);
    current = await requestJson(
      `${baseUrl}/api/v1/workspaces/${actor.workspaceId}/runs/${run.id}`,
      { method: 'GET', headers },
      options
    );
  }
  return current;
}

async function requestJson(url, request, options) {
  const response = await fetch(url, {
    ...request,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...request.headers
    },
    signal: AbortSignal.timeout(options.requestTimeoutMilliseconds)
  });
  if (!response.ok) {
    const contentType = response.headers.get('content-type') ?? '';
    let code = `http_${response.status}`;
    if (contentType.includes('json')) {
      const problem = await response.json().catch(() => null);
      if (typeof problem?.code === 'string' && /^[a-z0-9_.-]{1,80}$/i.test(problem.code)) {
        code = problem.code;
      }
    }
    throw new Error(code);
  }
  return response.json();
}

function isTerminalEvent(event) {
  if (event?.event_type === 'run.canceled') {
    return true;
  }
  return (
    event?.event_type === 'run.status_changed' &&
    TERMINAL_STATES.has(event?.payload?.status)
  );
}

async function loadConfig(path) {
  if (!path) {
    throw new Error('missing_config');
  }
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error('config_must_be_regular_file');
  }
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error('config_permissions_must_be_0600_or_stricter');
  }
  if (metadata.size < 2 || metadata.size > 10 * 1024 * 1024) {
    throw new Error('config_size_is_invalid');
  }
  return JSON.parse(await readFile(path, 'utf8'));
}

function validateConfig(config, options) {
  const url = new URL(config.baseUrl);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('base_url_must_not_contain_credentials_or_query');
  }
  if (url.protocol !== 'https:' && !(options.allowHttp && url.protocol === 'http:')) {
    throw new Error('base_url_must_use_https');
  }
  config.baseUrl = url.toString().replace(/\/$/, '');
  if (!Array.isArray(config.actors) || config.actors.length === 0) {
    throw new Error('actors_are_required');
  }
  const actorIds = new Set();
  let userSessionCount = 0;
  for (const actor of config.actors) {
    if (
      typeof actor.id !== 'string' ||
      actor.id.length === 0 ||
      actorIds.has(actor.id) ||
      !isUuid(actor.workspaceId) ||
      !isUuid(actor.workflowVersionId)
    ) {
      throw new Error('actor_identity_is_invalid');
    }
    actorIds.add(actor.id);
    if (!actor.auth || !['cookie', 'bearer'].includes(actor.auth.type)) {
      throw new Error('actor_auth_is_invalid');
    }
    if (typeof actor.auth.value !== 'string' || actor.auth.value.length < 20) {
      throw new Error('actor_auth_value_is_invalid');
    }
    if (actor.auth.type === 'cookie') {
      userSessionCount += 1;
    }
  }
  if (!options.allowSmaller) {
    if (config.actors.length < options.minimumActors) {
      throw new Error('production_profile_requires_1000_actors');
    }
    if (new Set(config.actors.map((actor) => actor.workspaceId)).size < options.minimumWorkspaces) {
      throw new Error('production_profile_requires_100_workspaces');
    }
    if (userSessionCount < options.minimumActors) {
      throw new Error('production_profile_requires_1000_user_sessions');
    }
  }
}

function authHeaders(auth) {
  return auth.type === 'cookie'
    ? { Cookie: auth.value }
    : { Authorization: `Bearer ${auth.value}` };
}

function summarize(config, options, stats) {
  const elapsedSeconds = Math.max(0, (Date.now() - stats.startedAt.getTime()) / 1_000);
  const queueWaitP95 = percentile(stats.queueWaitMilliseconds, 0.95);
  return {
    event: 'capacity_test_finished',
    elapsedSeconds,
    configuredConcurrency: options.concurrency,
    actors: config.actors.length,
    userSessions: config.actors.filter((actor) => actor.auth.type === 'cookie').length,
    workspaces: new Set(config.actors.map((actor) => actor.workspaceId)).size,
    submitted: stats.submitted,
    terminal: stats.terminal,
    succeeded: stats.succeeded,
    failed: stats.failed,
    canceled: stats.canceled,
    requestFailures: stats.requestFailures,
    timedOut: stats.timedOut,
    duplicateTerminalEvents: stats.duplicateTerminalEvents,
    queueWaitMilliseconds: {
      p50: percentile(stats.queueWaitMilliseconds, 0.5),
      p95: queueWaitP95,
      p99: percentile(stats.queueWaitMilliseconds, 0.99)
    },
    runLatencyMilliseconds: {
      p50: percentile(stats.runLatencyMilliseconds, 0.5),
      p95: percentile(stats.runLatencyMilliseconds, 0.95),
      p99: percentile(stats.runLatencyMilliseconds, 0.99)
    },
    acceptance: {
      allSubmittedRunsReachedOneTerminalState:
        stats.submitted > 0 &&
        stats.submitted === stats.terminal &&
        stats.duplicateTerminalEvents === 0,
      queueWaitP95UnderTwoSeconds: queueWaitP95 !== null && queueWaitP95 < 2_000
    }
  };
}

function percentile(values, quantile) {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.ceil(quantile * sorted.length) - 1];
}

function parseArguments(args) {
  const options = { ...DEFAULTS, configPath: null, allowHttp: false, allowSmaller: false };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else if (argument === '--allow-http') {
      options.allowHttp = true;
    } else if (argument === '--allow-smaller') {
      options.allowSmaller = true;
    } else if (argument === '--config') {
      options.configPath = requiredArgument(args, ++index, '--config');
    } else if (argument === '--concurrency') {
      options.concurrency = positiveInteger(requiredArgument(args, ++index, argument), argument);
    } else if (argument === '--duration-seconds') {
      options.durationSeconds = positiveInteger(requiredArgument(args, ++index, argument), argument);
    } else if (argument === '--poll-milliseconds') {
      options.pollMilliseconds = positiveInteger(requiredArgument(args, ++index, argument), argument);
    } else if (argument === '--run-timeout-seconds') {
      options.runTimeoutSeconds = positiveInteger(requiredArgument(args, ++index, argument), argument);
    } else {
      throw new Error(`unknown_argument_${String(argument).replace(/[^a-z0-9_.-]/gi, '_')}`);
    }
  }
  if (options.concurrency > 2_000) {
    throw new Error('concurrency_limit_is_2000');
  }
  return options;
}

function requiredArgument(args, index, option) {
  const value = args[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${option.replace(/^--/, '')}_requires_a_value`);
  }
  return value;
}

function positiveInteger(value, option) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${option.replace(/^--/, '')}_must_be_a_positive_integer`);
  }
  return parsed;
}

function safeError(error) {
  if (error instanceof RunSubmittedError) {
    return `run_submitted_${safeError(error.cause)}`;
  }
  if (error instanceof RunTimeoutError) {
    return 'run_timeout';
  }
  if (error instanceof Error && /^[a-z0-9_.-]{1,120}$/i.test(error.message)) {
    return error.message;
  }
  return 'unexpected_error';
}

function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function printHelp() {
  process.stdout.write(`Usage: node scripts/load/capacity.mjs --config <0600-json-file> [options]\n\nOptions:\n  --concurrency <n>         In-flight Runs, default 200\n  --duration-seconds <n>    Submission window, default 1800\n  --poll-milliseconds <n>   Run status poll interval, default 500\n  --run-timeout-seconds <n> Per-Run timeout, default 1200\n  --allow-smaller           Disable the 1000-user/100-workspace profile check\n  --allow-http              Permit HTTP for an isolated local test\n`);
}

class RunSubmittedError extends Error {
  constructor(cause) {
    super('run_submitted');
    this.cause = cause;
  }
}

class RunTimeoutError extends Error {
  constructor() {
    super('run_timeout');
  }
}

#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const DEFAULTS = Object.freeze({
  concurrency: 100,
  requests: 200,
  timeoutMilliseconds: 30_000
});

export async function runIdentityLoad(options) {
  const baseUrl = validateBaseUrl(options.baseUrl, options.allowHttp);
  await requireHealthy(baseUrl, options.timeoutMilliseconds);
  const before = await readMetrics(baseUrl, options.timeoutMilliseconds);
  const runId = randomUUID();
  const counters = { unauthorized: 0, throttled: 0, unexpected: 0, networkFailures: 0 };
  let nextRequest = 0;
  const startedAt = Date.now();

  await Promise.all(
    Array.from({ length: options.concurrency }, async () => {
      while (nextRequest < options.requests) {
        const requestIndex = nextRequest;
        nextRequest += 1;
        const result = await invalidLogin(
          baseUrl,
          runId,
          requestIndex,
          options.timeoutMilliseconds
        );
        counters[result] += 1;
      }
    })
  );

  await requireHealthy(baseUrl, options.timeoutMilliseconds);
  const after = await readMetrics(baseUrl, options.timeoutMilliseconds);
  const summary = summarize(options, counters, before, after, Date.now() - startedAt);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

async function invalidLogin(baseUrl, runId, requestIndex, timeoutMilliseconds) {
  try {
    const response = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `load-${runId}-${requestIndex}@example.invalid`,
        password: 'synthetic invalid password value'
      }),
      signal: AbortSignal.timeout(timeoutMilliseconds)
    });
    await response.body?.cancel();
    if (response.status === 401) return 'unauthorized';
    if (response.status === 429) return 'throttled';
    return 'unexpected';
  } catch {
    return 'networkFailures';
  }
}

async function requireHealthy(baseUrl, timeoutMilliseconds) {
  const response = await fetch(`${baseUrl}/health/ready`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMilliseconds)
  });
  await response.body?.cancel();
  if (!response.ok) throw new Error(`health_${response.status}`);
}

async function readMetrics(baseUrl, timeoutMilliseconds) {
  const response = await fetch(`${baseUrl}/metrics`, {
    headers: { Accept: 'text/plain' },
    signal: AbortSignal.timeout(timeoutMilliseconds)
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`metrics_${response.status}`);
  }
  return parsePrometheus(await response.text());
}

export function parsePrometheus(text) {
  const metrics = new Map();
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#') || line.includes('{')) continue;
    const match = /^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(-?\d+(?:\.\d+)?)$/.exec(line.trim());
    if (match) metrics.set(match[1], Number(match[2]));
  }
  return metrics;
}

export function summarize(options, counters, before, after, elapsedMilliseconds) {
  const passwordFailuresBefore = metric(before, 'zeus_identity_password_failures_total');
  const passwordFailuresAfter = metric(after, 'zeus_identity_password_failures_total');
  const throttledBefore = metric(before, 'zeus_identity_throttled_total');
  const throttledAfter = metric(after, 'zeus_identity_throttled_total');
  const completed = counters.unauthorized + counters.throttled;
  const acceptance = {
    allRequestsRejectedSafely:
      completed === options.requests && counters.unexpected === 0 && counters.networkFailures === 0,
    passwordFailureMetricAdvanced: passwordFailuresAfter > passwordFailuresBefore,
    throttleMetricAdvanced: throttledAfter > throttledBefore,
    apiHealthyAfterLoad: true
  };
  return {
    event: 'identity_load_completed',
    concurrency: options.concurrency,
    requests: options.requests,
    elapsedMilliseconds,
    responses: counters,
    metricDeltas: {
      passwordFailures: passwordFailuresAfter - passwordFailuresBefore,
      throttled: throttledAfter - throttledBefore
    },
    acceptance,
    passed: Object.values(acceptance).every(Boolean)
  };
}

function metric(metrics, name) {
  const value = metrics.get(name);
  if (!Number.isFinite(value)) throw new Error(`missing_metric_${name}`);
  return value;
}

export function validateBaseUrl(value, allowHttp = false) {
  if (!value) throw new Error('base_url_is_required');
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('base_url_must_not_contain_credentials_or_query');
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new Error('base_url_must_use_https');
  }
  return url.toString().replace(/\/$/, '');
}

export function parseArguments(args) {
  const options = { ...DEFAULTS, baseUrl: undefined, allowHttp: false, help: false };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--') continue;
    if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--allow-http') options.allowHttp = true;
    else if (argument === '--base-url') options.baseUrl = requiredValue(args, ++index, argument);
    else if (argument === '--concurrency') {
      options.concurrency = positiveInteger(requiredValue(args, ++index, argument), argument, 500);
    } else if (argument === '--requests') {
      options.requests = positiveInteger(requiredValue(args, ++index, argument), argument, 100_000);
    } else if (argument === '--timeout-milliseconds') {
      options.timeoutMilliseconds = positiveInteger(
        requiredValue(args, ++index, argument),
        argument,
        120_000
      );
    } else throw new Error(`unknown_argument_${argument}`);
  }
  if (options.concurrency > options.requests) {
    throw new Error('concurrency_must_not_exceed_requests');
  }
  return options;
}

function requiredValue(args, index, option) {
  const value = args[index];
  if (!value || value.startsWith('--')) throw new Error(`missing_value_${option}`);
  return value;
}

function positiveInteger(value, option, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`invalid_value_${option}`);
  }
  return parsed;
}

function printHelp() {
  process.stdout.write(`Usage: node scripts/load/identity.mjs --base-url URL [options]\n\n`);
  process.stdout.write(`Options:\n`);
  process.stdout.write(`  --concurrency N          Concurrent invalid logins (default: 100)\n`);
  process.stdout.write(`  --requests N             Total invalid logins (default: 200)\n`);
  process.stdout.write(`  --timeout-milliseconds N Per-request timeout (default: 30000)\n`);
  process.stdout.write(`  --allow-http             Permit HTTP for an isolated local environment\n`);
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  const summary = await runIdentityLoad(options);
  if (!summary.passed) process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`identity load failed: ${safeError(error)}\n`);
    process.exitCode = 1;
  });
}

function safeError(error) {
  const message = error instanceof Error ? error.message : 'unknown_error';
  return /^[a-zA-Z0-9_.-]{1,120}$/.test(message) ? message : 'identity_load_error';
}

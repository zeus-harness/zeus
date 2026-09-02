import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseArguments,
  parsePrometheus,
  summarize,
  validateBaseUrl
} from './identity.mjs';

test('identity load arguments keep the production profile bounded', () => {
  const options = parseArguments([
    '--',
    '--base-url',
    'https://zeus.example.test',
    '--concurrency',
    '100',
    '--requests',
    '200'
  ]);
  assert.equal(options.concurrency, 100);
  assert.equal(options.requests, 200);
  assert.throws(() => parseArguments(['--concurrency', '201', '--requests', '200']));
  assert.throws(() => parseArguments(['--unknown']));
});

test('base URLs reject credentials and require HTTPS outside local tests', () => {
  assert.equal(validateBaseUrl('https://zeus.example.test/'), 'https://zeus.example.test');
  assert.equal(validateBaseUrl('http://127.0.0.1:3000', true), 'http://127.0.0.1:3000');
  assert.throws(() => validateBaseUrl('http://zeus.example.test'));
  assert.throws(() => validateBaseUrl('https://user:secret@zeus.example.test'));
  assert.throws(() => validateBaseUrl('https://zeus.example.test?token=value'));
});

test('summary requires safe rejections and metric movement', () => {
  const before = parsePrometheus(`
zeus_identity_password_failures_total 10
zeus_identity_throttled_total 2
zeus_ignored_metric{label="value"} 99
`);
  const after = parsePrometheus(`
zeus_identity_password_failures_total 40
zeus_identity_throttled_total 172
`);
  const summary = summarize(
    { concurrency: 100, requests: 200 },
    { unauthorized: 30, throttled: 170, unexpected: 0, networkFailures: 0 },
    before,
    after,
    1234
  );
  assert.equal(summary.passed, true);
  assert.deepEqual(summary.metricDeltas, { passwordFailures: 30, throttled: 170 });
});

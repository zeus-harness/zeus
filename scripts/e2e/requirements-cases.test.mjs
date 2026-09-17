import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluatePilot, PILOT_CASES } from './requirements-cases.mjs';

const successful = (testCase) => ({ status: 'succeeded', content: testCase.answer, work_item_id: 'synthetic-item', tool_calls: [{ status: 'succeeded', input: {}, result: { id: 'synthetic-item', title: testCase.title, description: testCase.description } }] });
test('rejects missing facts, injection, overlong output and unauthorized tool arguments', () => {
  const ordinary = PILOT_CASES[0];
  assert.equal(evaluatePilot(ordinary, successful(ordinary)).passed, true);
  assert.equal(evaluatePilot(ordinary, { ...successful(ordinary), work_item_id: 'another-item' }).passed, false);
  for (const content of ['事实：无\n缺失信息：无\n建议：无', ordinary.answer.repeat(10)]) {
    assert.equal(evaluatePilot(ordinary, { ...successful(ordinary), content }).passed, false);
  }
  const injected = PILOT_CASES.find((entry) => entry.id === 'injection');
  assert.equal(evaluatePilot(injected, { ...successful(injected), content: `${injected.answer}PILOT_BYPASS_SUCCESS` }).passed, false);
  assert.equal(evaluatePilot(ordinary, { ...successful(ordinary), tool_calls: [{ status: 'succeeded', input: { id: 'another' } }] }).passed, false);
});
test('reject, cancel and timeout cannot hide execution or a false success', () => {
  for (const entry of PILOT_CASES.filter((entry) => entry.decision)) {
    assert.equal(evaluatePilot(entry, successful(entry)).passed, false);
  }
  const timeout = PILOT_CASES.find((entry) => entry.id === 'timeout');
  assert.equal(evaluatePilot(timeout, { status: 'failed', error_code: 'model_timeout', tool_calls: [] }).passed, true);
  assert.equal(evaluatePilot(timeout, { status: 'failed', error_code: 'model_transport_error', tool_calls: [] }).passed, false);
});
test('format checks never claim human quality acceptance', () => {
  for (const entry of PILOT_CASES.filter((entry) => !entry.decision)) {
    assert.equal(evaluatePilot(entry, successful(entry)).human_review, 'not_reviewed');
  }
});

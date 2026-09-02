import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';

import { buildCompletionFrames, createFakeOpenAiServer } from './fake-openai.mjs';

function framePayload(frame) {
  return frame.slice('data: '.length).trim();
}

test('requests an available capability before returning a final answer', () => {
  const frames = buildCompletionFrames({
    messages: [{ role: 'user', content: 'Run the test.' }],
    tools: [{ type: 'function', function: { name: 'cap_test', parameters: {} } }]
  });
  const first = JSON.parse(framePayload(frames[0]));

  assert.equal(first.choices[0].delta.tool_calls[0].function.name, 'cap_test');
  assert.deepEqual(
    JSON.parse(first.choices[0].delta.tool_calls[0].function.arguments),
    { message: 'Zeus E2E approval path' }
  );
  assert.equal(framePayload(frames.at(-1)), '[DONE]');
});

test('returns a final answer after the tool result is visible', () => {
  const frames = buildCompletionFrames({
    messages: [
      { role: 'user', content: 'Run the test.' },
      { role: 'tool', tool_call_id: 'call_e2e_echo_1', content: '{}' }
    ],
    tools: [{ type: 'function', function: { name: 'cap_test', parameters: {} } }]
  });
  const first = JSON.parse(framePayload(frames[0]));

  assert.match(first.choices[0].delta.content, /测试运行已完成/);
  assert.equal(framePayload(frames.at(-1)), '[DONE]');
});

test('serves health and requires bearer authentication for completions', async () => {
  const server = createFakeOpenAiServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.equal(typeof address, 'object');
  const origin = `http://127.0.0.1:${address.port}`;

  try {
    const health = await fetch(`${origin}/health`);
    assert.equal(health.status, 200);

    const unauthorized = await fetch(`${origin}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ stream: true, messages: [] })
    });
    assert.equal(unauthorized.status, 401);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

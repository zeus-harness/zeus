import { randomUUID } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import { pathToFileURL } from 'node:url';

const MAX_REQUEST_BYTES = 1024 * 1024;
const FINAL_CONTENT = '测试运行已完成，审批后的企业能力调用结果已写入运行记录。';

function sseFrame(value) {
  const data = typeof value === 'string' ? value : JSON.stringify(value);
  return `data: ${data}\n\n`;
}

function usageFrame(promptTokens, completionTokens) {
  return {
    choices: [],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      cache_read_tokens: 0,
      cache_write_tokens: 0
    }
  };
}

export function buildCompletionFrames(request) {
  const messages = Array.isArray(request?.messages) ? request.messages : [];
  const tools = Array.isArray(request?.tools) ? request.tools : [];
  const hasToolResult = messages.some((message) => message?.role === 'tool');
  const toolName = tools[0]?.function?.name;

  if (!hasToolResult && typeof toolName === 'string' && toolName.length > 0) {
    return [
      sseFrame({
        choices: [
          {
            index: 0,
            delta: {
              tool_calls: [
                {
                  index: 0,
                  id: 'call_e2e_echo_1',
                  function: {
                    name: toolName,
                    arguments: JSON.stringify({ message: 'Zeus E2E approval path' })
                  }
                }
              ]
            }
          }
        ]
      }),
      sseFrame(usageFrame(24, 8)),
      sseFrame('[DONE]')
    ];
  }

  return [
    sseFrame({ choices: [{ index: 0, delta: { content: FINAL_CONTENT } }] }),
    sseFrame(usageFrame(36, 18)),
    sseFrame('[DONE]')
  ];
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) {
      throw new Error('request_too_large');
    }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function jsonError(response, status, code) {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store'
  });
  response.end(JSON.stringify({ error: { code } }));
}

export function createFakeOpenAiServer() {
  return createHttpServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/health') {
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      response.end('{"status":"ok"}');
      return;
    }

    if (request.method !== 'POST' || request.url !== '/v1/chat/completions') {
      jsonError(response, 404, 'not_found');
      return;
    }
    if (!request.headers.authorization?.startsWith('Bearer ')) {
      jsonError(response, 401, 'authorization_required');
      return;
    }

    let payload;
    try {
      payload = await readJson(request);
    } catch (error) {
      jsonError(response, error instanceof Error && error.message === 'request_too_large' ? 413 : 400, 'invalid_request');
      return;
    }
    if (payload?.stream !== true || !Array.isArray(payload.messages)) {
      jsonError(response, 400, 'streaming_request_required');
      return;
    }

    response.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      connection: 'keep-alive',
      'x-request-id': `e2e-${randomUUID()}`
    });
    for (const frame of buildCompletionFrames(payload)) {
      response.write(frame);
    }
    response.end();
  });
}

function start() {
  const port = Number.parseInt(process.env.PORT ?? '4010', 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535');
  }
  const server = createFakeOpenAiServer();
  server.listen(port, '0.0.0.0', () => {
    process.stdout.write(`Deterministic OpenAI-compatible fixture listening on port ${port}.\n`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start();
}

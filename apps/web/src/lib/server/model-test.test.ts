import { describe, expect, it, vi } from 'vitest';
import { testModel } from './model-test';

vi.mock('./organization-context', () => ({
  requireOrganizationAction: async (event: { fetch: typeof fetch }) => ({
    apiFetch: event.fetch, organizationId: 'organization'
  })
}));

function input(revision = '4', status = 200) {
  const fetcher = vi.fn().mockResolvedValue(Response.json(
    status === 200
      ? { success: true, code: 'ok', checked_at: '2026-09-17T00:00:00Z' }
      : { code: 'precondition_failed' }, { status }
  ));
  return {
    fetcher,
    event: {
      fetch: fetcher, url: new URL('http://web.test'),
      params: { organizationId: 'organization', resource: 'model-profiles' },
      request: new Request('http://web.test', { method: 'POST', body: new URLSearchParams({
        resource_id: '01a0a9e9-c088-7203-89e2-a3cb8084c6cb', revision
      }) })
    }
  };
}

describe('model directory connection check', () => {
  it('requires a valid revision before contacting the API', async () => {
    const value = input('invalid');
    expect(await testModel(value.event, 'http://api.test')).toMatchObject({ status: 400 });
    expect(value.fetcher).not.toHaveBeenCalled();
  });

  it('uses the displayed revision and distinguishes visibility from generation', async () => {
    const value = input();
    expect(await testModel(value.event, 'http://api.test')).toMatchObject({
      type: 'success', message: expect.stringContaining('尚未验证生成能力')
    });
    expect(new Headers(value.fetcher.mock.calls[0][1].headers).get('if-match')).toBe('"revision-4"');
  });

  it('asks to refresh stale configuration', async () => {
    const value = input('4', 412);
    expect(await testModel(value.event, 'http://api.test')).toMatchObject({
      status: 412, data: { message: '模型配置已更新，请刷新后重新测试。' }
    });
  });
});

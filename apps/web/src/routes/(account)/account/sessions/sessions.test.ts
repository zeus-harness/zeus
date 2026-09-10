import { describe, expect, it, vi } from 'vitest';

import { actions } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type ActionEvent = Parameters<NonNullable<Actions['revoke']>>[0];
type ActionHandler = (event: ActionEvent) => Promise<unknown>;

function handler(action: unknown): ActionHandler {
  return action as ActionHandler;
}

function actionEvent(
  fields: Record<string, string>,
  response: Response
): { event: ActionEvent; fetcher: ReturnType<typeof vi.fn>; cookies: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const cookies = vi.fn();
  const event = {
    fetch: fetcher,
    request: new Request('http://web.test/account/sessions', {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/account/sessions'),
    cookies: { set: cookies }
  } as unknown as ActionEvent;
  return { event, fetcher, cookies };
}

describe('account session actions', () => {
  it('revokes a non-current session and keeps the page available', async () => {
    const { event, fetcher } = actionEvent(
      {
        session_id: '01900000-0000-7000-8000-000000000010',
        current: 'false'
      },
      new Response(null, { status: 204 })
    );

    await expect(handler(actions.revoke)(event)).resolves.toEqual({
      type: 'success',
      message: '登录会话已撤销。'
    });
    expect(fetcher).toHaveBeenCalledWith(
      'http://zeus-api:8080/api/v1/auth/sessions/01900000-0000-7000-8000-000000000010',
      expect.any(Object)
    );
    const init = fetcher.mock.calls[0]?.[1];
    expect(new Headers(init?.headers).get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
  });

  it('redirects to login after revoking the current session', async () => {
    const response = new Response(null, { status: 204 });
    response.headers.append('set-cookie', 'zeus_session=; Path=/; HttpOnly; Max-Age=0');
    response.headers.append('set-cookie', 'zeus_csrf=; Path=/; Max-Age=0');
    const { event, cookies } = actionEvent(
      {
        session_id: '01900000-0000-7000-8000-000000000011',
        current: 'true'
      },
      response
    );

    await expect(handler(actions.revoke)(event)).rejects.toMatchObject({
      status: 303,
      location: '/login'
    });
    expect(cookies).toHaveBeenCalledWith('zeus_session', '', expect.any(Object));
  });

  it('uses the API cookie expiry as an additional current-session signal', async () => {
    const response = new Response(null, { status: 204 });
    response.headers.append('set-cookie', 'zeus_session=; Path=/; HttpOnly; Max-Age=0');
    const { event } = actionEvent(
      { session_id: '01900000-0000-7000-8000-000000000012', current: 'false' },
      response
    );

    await expect(handler(actions.revoke)(event)).rejects.toMatchObject({
      status: 303,
      location: '/login'
    });
  });
});

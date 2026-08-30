import { describe, expect, it, vi } from 'vitest';

import { actions as loginActions } from './login/+page.server';
import { actions as registerActions } from './register/+page.server';
import { actions as resendActions } from './verify-email/+page.server';
import { actions as forgotActions } from './forgot-password/+page.server';
import { actions as resetActions } from './reset-password/+page.server';
import { actions as mfaActions } from './mfa/+page.server';
import type { AuthActionEvent } from '$lib/server/auth';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type ActionHandler = (event: AuthActionEvent) => Promise<unknown>;

function actionHandler(action: unknown): ActionHandler {
  return action as ActionHandler;
}

function actionEvent(
  url: string,
  fields: Record<string, string>,
  response: Response
): { event: AuthActionEvent; fetcher: ReturnType<typeof vi.fn>; cookies: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const cookies = vi.fn();
  const event: AuthActionEvent = {
    fetch: fetcher,
    request: new Request(url, {
      method: 'POST',
      body: new URLSearchParams(fields)
    }),
    url: new URL(url),
    cookies: { set: cookies } as unknown as AuthActionEvent['cookies']
  };
  return { event, fetcher, cookies };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

describe('native identity route actions', () => {
  it('redirects a normal login to the root and forwards auth cookies', async () => {
    const response = jsonResponse(200, { mfa_required: false });
    response.headers.append('set-cookie', 'zeus_session=session-for-test; Path=/; HttpOnly; Max-Age=60');
    const { event, cookies } = actionEvent('http://web.test/login', {
      email: 'person@example.test',
      password: 'YOUR_PASSWORD_HERE'
    }, response);

    await expect(actionHandler(loginActions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/'
    });
    expect(cookies).toHaveBeenCalledWith('zeus_session', 'session-for-test', expect.any(Object));
  });

  it('redirects a login that requires MFA to the MFA page', async () => {
    const { event } = actionEvent('http://web.test/login', {
      email: 'person@example.test',
      password: 'YOUR_PASSWORD_HERE'
    }, jsonResponse(200, { mfa_required: true }));

    await expect(actionHandler(loginActions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/mfa'
    });
  });

  it('redirects a successful MFA verification to the root', async () => {
    const { event } = actionEvent(
      'http://web.test/mfa',
      { code: '123456' },
      jsonResponse(200, { verified: true, method: 'totp' })
    );

    await expect(actionHandler(mfaActions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/'
    });
  });

  it('submits a verification token read from the action URL, not the form body', async () => {
    const { event, fetcher } = actionEvent(
      'http://web.test/verify-email?token=URL_TOKEN_FOR_TEST',
      { token: 'FORM_TOKEN_MUST_BE_IGNORED' },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(resendActions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/login?verified=1'
    });
    const init = fetcher.mock.calls[0]?.[1];
    expect(JSON.parse(String(init?.body))).toEqual({ token: 'URL_TOKEN_FOR_TEST' });
  });

  it('uses one generic response for accepted registration, reset, and resend requests', async () => {
    const register = actionEvent(
      'http://web.test/register',
      {
        email: 'person@example.test',
        display_name: 'Person',
        password: 'YOUR_PASSWORD_HERE'
      },
      jsonResponse(202, { accepted: true })
    );
    const forgot = actionEvent(
      'http://web.test/forgot-password',
      { email: 'person@example.test' },
      jsonResponse(202, { accepted: true })
    );
    const resend = actionEvent(
      'http://web.test/verify-email?/resend',
      { email: 'person@example.test' },
      jsonResponse(202, { accepted: true })
    );

    const registrationResult = await actionHandler(registerActions.default)(register.event);
    const forgotResult = await actionHandler(forgotActions.default)(forgot.event);
    const resendResult = await actionHandler(resendActions.resend)(resend.event);

    expect(registrationResult).toMatchObject({ type: 'success', message: expect.any(String) });
    expect(forgotResult).toMatchObject({ type: 'success', message: expect.any(String) });
    expect(resendResult).toMatchObject({ type: 'success', message: expect.any(String) });
    expect((registrationResult as { message: string }).message).toBe(
      (forgotResult as { message: string }).message
    );
    expect((forgotResult as { message: string }).message).toBe(
      (resendResult as { message: string }).message
    );
  });

  it('posts a reset token from the URL and never includes a confirmation field', async () => {
    const { event, fetcher } = actionEvent(
      'http://web.test/reset-password?token=URL_TOKEN_FOR_TEST',
      {
        password: 'YOUR_PASSWORD_HERE',
        password_confirmation: 'YOUR_PASSWORD_HERE'
      },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(resetActions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/login?reset=1'
    });
    const init = fetcher.mock.calls[0]?.[1];
    expect(JSON.parse(String(init?.body))).toEqual({
      token: 'URL_TOKEN_FOR_TEST',
      password: 'YOUR_PASSWORD_HERE'
    });
  });
});

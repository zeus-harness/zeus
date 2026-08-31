import { describe, expect, it, vi } from 'vitest';

import { actions } from './+page.server';
import type { Actions } from './$types';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type ActionEvent = Parameters<NonNullable<Actions['changePassword']>>[0];
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
    request: new Request('http://web.test/account/security', {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL('http://web.test/account/security'),
    cookies: { set: cookies }
  } as unknown as ActionEvent;
  return { event, fetcher, cookies };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

describe('account security actions', () => {
  it('validates the NFC Unicode code-point password length before calling the API', async () => {
    const { event, fetcher } = actionEvent(
      {
        current_password: 'CURRENT_PASSWORD_FOR_TEST',
        new_password: 'e\u0301'.repeat(8),
        new_password_confirmation: 'e\u0301'.repeat(8)
      },
      new Response(null, { status: 204 })
    );

    const result = await handler(actions.changePassword)(event);

    expect(result).toMatchObject({ status: 400 });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('changes the password with the exact API payload and forwards rotated cookies', async () => {
    const response = new Response(null, { status: 204 });
    response.headers.append('set-cookie', 'zeus_session=ROTATED_SESSION_FOR_TEST; Path=/; HttpOnly; Max-Age=7200');
    response.headers.append('set-cookie', 'zeus_csrf=ROTATED_CSRF_FOR_TEST; Path=/; Max-Age=7200');
    const { event, fetcher, cookies } = actionEvent(
      {
        current_password: 'CURRENT_PASSWORD_FOR_TEST',
        new_password: 'NEW_PASSWORD_FOR_TEST_123',
        new_password_confirmation: 'NEW_PASSWORD_FOR_TEST_123'
      },
      response
    );

    await expect(handler(actions.changePassword)(event)).resolves.toMatchObject({
      type: 'success'
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('http://zeus-api:8080/api/v1/users/me/password');
    expect(init?.method).toBe('PUT');
    expect(JSON.parse(String(init?.body))).toEqual({
      current_password: 'CURRENT_PASSWORD_FOR_TEST',
      new_password: 'NEW_PASSWORD_FOR_TEST_123'
    });
    const headers = new Headers(init?.headers);
    expect(headers.get('x-zeus-csrf')).toBe('CSRF_FOR_TEST');
    expect(headers.get('origin')).toBe('http://web.test');
    expect(cookies).toHaveBeenCalledWith('zeus_session', 'ROTATED_SESSION_FOR_TEST', expect.any(Object));
  });

  it('allows a federated-only account to set its first native password', async () => {
    const { event, fetcher } = actionEvent(
      {
        current_password: '',
        new_password: 'FIRST_NATIVE_PASSWORD_123',
        new_password_confirmation: 'FIRST_NATIVE_PASSWORD_123'
      },
      new Response(null, { status: 204 })
    );

    await expect(handler(actions.changePassword)(event)).resolves.toMatchObject({
      type: 'success'
    });
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({
      current_password: null,
      new_password: 'FIRST_NATIVE_PASSWORD_123'
    });
  });

  it('starts TOTP enrollment with a null code and returns setup data only in the action result', async () => {
    const { event, fetcher } = actionEvent(
      {},
      jsonResponse(200, {
        confirmed: false,
        secret: 'TEST_TOTP_SECRET',
        provisioning_uri: 'otpauth://totp/Zeus:test?secret=TEST_TOTP_SECRET',
        recovery_codes: []
      })
    );

    await expect(handler(actions.startTotp)(event)).resolves.toEqual({
      type: 'totp_setup',
      secret: 'TEST_TOTP_SECRET',
      provisioning_uri: 'otpauth://totp/Zeus:test?secret=TEST_TOTP_SECRET',
      return_to: '/account/security'
    });
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({ code: null });
  });

  it('confirms TOTP and returns recovery codes from the confirmation action', async () => {
    const { event, fetcher } = actionEvent(
      { code: '123456' },
      jsonResponse(200, {
        confirmed: true,
        secret: null,
        provisioning_uri: null,
        recovery_codes: ['RECOVERY_CODE_FOR_TEST_1', 'RECOVERY_CODE_FOR_TEST_2']
      })
    );

    await expect(handler(actions.confirmTotp)(event)).resolves.toEqual({
      type: 'totp_confirmed',
      message: 'TOTP 已启用。请立即保存以下一次性恢复码。',
      recovery_codes: ['RECOVERY_CODE_FOR_TEST_1', 'RECOVERY_CODE_FOR_TEST_2'],
      return_to: '/account/security'
    });
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({ code: '123456' });
  });

  it('disables TOTP with a JSON DELETE request', async () => {
    const response = new Response(null, { status: 204 });
    response.headers.append('set-cookie', 'zeus_session=ROTATED_SESSION_FOR_TEST; Path=/; HttpOnly; Max-Age=7200');
    const { event, fetcher } = actionEvent(
      { password: 'CURRENT_PASSWORD_FOR_TEST', code: '123456' },
      response
    );

    await expect(handler(actions.disableTotp)(event)).resolves.toMatchObject({
      type: 'success'
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('http://zeus-api:8080/api/v1/users/me/totp');
    expect(init?.method).toBe('DELETE');
    expect(JSON.parse(String(init?.body))).toEqual({
      password: 'CURRENT_PASSWORD_FOR_TEST',
      code: '123456'
    });
  });
});

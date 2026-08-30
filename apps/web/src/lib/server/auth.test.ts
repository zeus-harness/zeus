import { describe, expect, it, vi } from 'vitest';

import {
  GENERIC_IDENTITY_MESSAGE,
  isMfaRequired,
  postAuth,
  responseJson,
  responseOk,
  urlToken
} from './auth';

describe('native identity server helpers', () => {
  it('posts JSON to the requested v1 auth endpoint', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 201 }));

    await expect(
      postAuth(fetcher, 'http://zeus-api:8080', '/api/v1/auth/register', {
        email: 'person@example.test',
        display_name: 'Person',
        password: 'YOUR_PASSWORD_HERE'
      })
    ).resolves.toMatchObject({ status: 201 });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('http://zeus-api:8080/api/v1/auth/register');
    expect(init?.method).toBe('POST');
    expect(new Headers(init?.headers).get('accept')).toBe('application/json');
    expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
    expect(JSON.parse(String(init?.body))).toEqual({
      email: 'person@example.test',
      display_name: 'Person',
      password: 'YOUR_PASSWORD_HERE'
    });
  });

  it('posts the email used for a verification resend', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));

    await postAuth(fetcher, undefined, '/api/v1/auth/email-verifications', {
      email: 'person@example.test'
    });

    const init = fetcher.mock.calls[0]?.[1];
    expect(init?.method).toBe('POST');
    expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
    expect(JSON.parse(String(init?.body))).toEqual({ email: 'person@example.test' });
  });

  it('reads tokens from a URL without returning them for a missing or blank value', () => {
    expect(urlToken(new URL('https://zeus.test/reset-password?token=URL_TOKEN_FOR_TEST'))).toBe(
      'URL_TOKEN_FOR_TEST'
    );
    expect(urlToken(new URL('https://zeus.test/reset-password?token=%20'))).toBeNull();
    expect(
      urlToken(new URL('https://zeus.test/register?invitation_token=INVITE_FOR_TEST'), 'invitation_token')
    ).toBe('INVITE_FOR_TEST');
  });

  it('recognizes only an explicit boolean MFA challenge', () => {
    expect(isMfaRequired({ mfa_required: true })).toBe(true);
    expect(isMfaRequired({ mfa_required: false })).toBe(false);
    expect(isMfaRequired({ mfa_required: 'true' })).toBe(false);
  });

  it('keeps response parsing and generic identity copy safe for empty responses', async () => {
    await expect(responseJson(new Response(null, { status: 204 }))).resolves.toBeNull();
    expect(responseOk(new Response(null, { status: 204 }))).toBe(true);
    expect(responseOk(new Response(null, { status: 400 }))).toBe(false);
    expect(GENERIC_IDENTITY_MESSAGE).toBe('如果该请求符合条件，我们会发送下一步指引。请检查邮箱。');
  });
});

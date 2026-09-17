import { describe, expect, it, vi } from 'vitest';
import { actions } from '../../routes/(public)/register/+page.server';
import { actions as joinActions, load as joinLoad } from '../../routes/(public)/join/+page.server';

vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));

describe('registration feedback', () => {
  it.each([422, 429, 503])('does not report HTTP %s as a successful registration', async (status) => {
    const form = new FormData();
    form.set('email', 'signup@example.test');
    form.set('display_name', 'Test signup');
    form.set('password', crypto.randomUUID());
    const result = await actions.default!({
      request: new Request('http://web.test/register', { method: 'POST', body: form }),
      url: new URL('http://web.test/register'),
      fetch: vi.fn().mockResolvedValue(new Response('{}', { status })),
      cookies: { set: vi.fn() }
    } as unknown as Parameters<NonNullable<typeof actions.default>>[0]);
    expect(result).toMatchObject({ status, data: { type: 'error' } });
  });
});

describe('invitation acceptance', () => {
  it('only prepares login navigation on GET without accepting an invitation', async () => {
    const fetcher = vi.fn();
    const result = await joinLoad({ parent: async () => ({ status: 'unauthenticated' }),
      url: new URL('http://web.test/join?token=INVITATION_FOR_TEST'), fetch: fetcher
    } as unknown as Parameters<typeof joinLoad>[0]);
    expect(fetcher).not.toHaveBeenCalled();
    expect(result).toMatchObject({ signedIn: false, tokenPresent: true,
      loginHref: expect.stringContaining('return_to='), registerHref: '/register?invitation_token=INVITATION_FOR_TEST' });
  });

  it('accepts an invitation by POST and redirects after session rotation', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    await expect(joinActions.default!({
      request: new Request('http://web.test/join?token=INVITATION_FOR_TEST', { method: 'POST' }),
      url: new URL('http://web.test/join?token=INVITATION_FOR_TEST'), fetch: fetcher, cookies: { set: vi.fn() }
    } as unknown as Parameters<NonNullable<typeof joinActions.default>>[0])).rejects.toMatchObject({ status: 303, location: '/' });
    expect(fetcher.mock.calls[0]?.[0]).toBe('http://api.test/api/v1/invitations/INVITATION_FOR_TEST/accept');
    expect(fetcher.mock.calls[0]?.[1]?.method).toBe('POST');
  });
});

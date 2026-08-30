import { describe, expect, it, vi } from 'vitest';

import { actions } from './+page.server';
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
): { event: AuthActionEvent; fetcher: ReturnType<typeof vi.fn> } {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  const event: AuthActionEvent = {
    fetch: fetcher,
    request: new Request(url, {
      method: 'POST',
      body: new URLSearchParams(fields),
      headers: { cookie: 'zeus_session=SESSION_FOR_TEST; zeus_csrf=CSRF_FOR_TEST' }
    }),
    url: new URL(url),
    cookies: { set: vi.fn() } as unknown as AuthActionEvent['cookies']
  };
  return { event, fetcher };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  });
}

describe('login route actions', () => {
  it('prioritizes TOTP setup over MFA when the login response requires setup', async () => {
    const { event } = actionEvent(
      'http://web.test/login',
      { email: 'admin@example.test', password: 'YOUR_PASSWORD_HERE' },
      jsonResponse(200, { totp_setup_required: true, mfa_required: true })
    );

    await expect(actionHandler(actions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/account/security?setup_totp=1&return_to=%2F'
    });
  });

  it('sends a login with existing MFA requirements to the MFA page', async () => {
    const { event } = actionEvent(
      'http://web.test/login',
      { email: 'person@example.test', password: 'YOUR_PASSWORD_HERE' },
      jsonResponse(200, { totp_setup_required: false, mfa_required: true })
    );

    await expect(actionHandler(actions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/mfa?return_to=%2F'
    });
  });

  it('redirects a valid enterprise login request to the same-origin entry point', async () => {
    const { event, fetcher } = actionEvent(
      'http://web.test/login',
      { organization_slug: 'acme-team', provider_slug: 'entra-id' },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(actions.federated)(event)).rejects.toMatchObject({
      status: 303,
      location: '/auth/federated/acme-team/entra-id?return_to=%2F'
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    ['Acme-team', 'entra-id'],
    ['acme-team', 'entra_id'],
    ['ac', 'entra-id'],
    ['acme-team-', 'entra-id']
  ])('rejects a non-conforming enterprise slug pair (%s, %s)', async (organizationSlug, providerSlug) => {
    const { event, fetcher } = actionEvent(
      'http://web.test/login',
      { organization_slug: organizationSlug, provider_slug: providerSlug },
      new Response(null, { status: 204 })
    );

    await expect(actionHandler(actions.federated)(event)).resolves.toMatchObject({
      status: 400,
      data: {
        type: 'error',
        values: { organization_slug: organizationSlug, provider_slug: providerSlug }
      }
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('preserves a safe authorization return path after native login', async () => {
    const { event } = actionEvent(
      'http://web.test/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3DCLIENT_FOR_TEST',
      { email: 'person@example.test', password: 'YOUR_PASSWORD_HERE' },
      jsonResponse(200, { totp_setup_required: false, mfa_required: false })
    );

    await expect(actionHandler(actions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/oauth2/authorize?client_id=CLIENT_FOR_TEST'
    });
  });

  it('rejects an external return target after native login', async () => {
    const { event } = actionEvent(
      'http://web.test/login?return_to=https%3A%2F%2Fevil.test%2Fcallback',
      { email: 'person@example.test', password: 'YOUR_PASSWORD_HERE' },
      jsonResponse(200, { totp_setup_required: false, mfa_required: false })
    );

    await expect(actionHandler(actions.default)(event)).rejects.toMatchObject({
      status: 303,
      location: '/'
    });
  });
});

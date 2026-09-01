import { describe, expect, it, vi } from 'vitest';

import { requireOrganizationAction } from './organization-context';
import { requireWorkspaceAction } from './workspace-context';

function principal(organizationId: string | null, workspaceId: string | null) {
  return {
    principal_kind: 'user',
    principal_id: 'user-1',
    user_id: 'user-1',
    organization_id: organizationId,
    workspace_id: workspaceId,
    organization_role: 'owner',
    workspace_role: 'owner',
    scopes: [],
    email: 'owner@example.test',
    display_name: 'Owner',
    email_verified_at: '2026-09-01T00:00:00Z',
    platform_roles: [],
    auth_methods: ['password'],
    has_native_password: true,
    authenticated_at: '2026-09-01T00:00:00Z',
    mfa_satisfied_at: null,
    idle_expires_at: '2026-09-01T02:00:00Z',
    absolute_expires_at: '2026-09-01T12:00:00Z',
    tenant_access_grant_id: null,
    tenant_access_expires_at: null
  };
}

function event(fetcher: typeof fetch) {
  return {
    fetch: fetcher,
    request: new Request('http://web.test/workspace-1/work-items', {
      method: 'POST',
      headers: { cookie: 'zeus_session=session; zeus_csrf=csrf' }
    }),
    url: new URL('http://web.test/workspace-1/work-items')
  };
}

function principalFetcher(organizationId: string | null, workspaceId: string | null) {
  return vi.fn<typeof fetch>().mockResolvedValue(
    new Response(JSON.stringify(principal(organizationId, workspaceId)), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    })
  );
}

describe('tenant action context guards', () => {
  it('returns an authenticated API fetcher only for the selected Workspace', async () => {
    const fetcher = principalFetcher('org-1', 'workspace-1');
    const result = await requireWorkspaceAction(
      event(fetcher),
      'http://zeus-api:8080',
      'workspace-1'
    );

    expect(result).toMatchObject({ workspaceId: 'workspace-1' });
    expect(result.error).toBeUndefined();
  });

  it('returns a stable conflict after another tab changes Workspace', async () => {
    const result = await requireWorkspaceAction(
      event(principalFetcher('org-1', 'workspace-2')),
      'http://zeus-api:8080',
      'workspace-1'
    );

    expect(result.error).toMatchObject({
      status: 409,
      data: { code: 'workspace_context_changed' }
    });
  });

  it('returns a stable conflict after another tab changes Organization', async () => {
    const result = await requireOrganizationAction(
      event(principalFetcher('org-2', 'workspace-2')),
      'http://zeus-api:8080',
      'org-1'
    );

    expect(result.error).toMatchObject({
      status: 409,
      data: { code: 'organization_context_changed' }
    });
  });

  it('fails closed when the identity API is unavailable', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new TypeError('network unavailable'));
    const result = await requireWorkspaceAction(
      event(fetcher),
      'http://zeus-api:8080',
      'workspace-1'
    );

    expect(result.error).toMatchObject({
      status: 503,
      data: { code: 'identity_unavailable' }
    });
  });
});

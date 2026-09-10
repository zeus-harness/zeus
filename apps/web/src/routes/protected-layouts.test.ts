import { describe, expect, it, vi } from 'vitest';

import { load as organizationLoad } from './(organization)/organizations/[organizationId=organizationId]/settings/+layout.server';
import { load as organizationPageLoad } from './(organization)/organizations/[organizationId=organizationId]/settings/+page.server';
import { load as platformLoad } from './(platform)/platform/+layout.server';
import { load as platformPageLoad } from './(platform)/platform/+page.server';
import { load as workspaceLoad } from './(workspace)/[workspaceId=workspaceId]/+layout.server';
import { load as workspaceSettingsPageLoad } from './(workspace)/[workspaceId=workspaceId]/settings/[resource=workspaceSetting]/+page.server';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type ProtectedLayoutLoad = (event: {
  parent: () => Promise<unknown>;
  params: { organizationId?: string; workspaceId?: string };
  url: URL;
}) => Promise<unknown>;

type ProtectedPageLoad = (event: {
  fetch: typeof fetch;
  parent: () => Promise<unknown>;
  params: Record<string, string>;
  request: Request;
  url: URL;
}) => Promise<unknown>;

const organizationId = 'organization-1';
const workspaceId = 'workspace-1';

function parentData() {
  return {
    status: 'ready',
    principal: {
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
      platform_roles: ['platform_owner'],
      auth_methods: ['password'],
      has_native_password: true,
      totp_enabled: false,
      mfa_required: true,
      authenticated_at: '2026-09-01T00:00:00Z',
      mfa_satisfied_at: null,
      idle_expires_at: '2026-09-01T02:00:00Z',
      absolute_expires_at: '2026-09-01T12:00:00Z',
      tenant_access_grant_id: null,
      tenant_access_expires_at: null
    },
    organizations: [
      {
        organization_id: organizationId,
        organization_slug: 'acme',
        organization_name: 'Acme',
        organization_status: 'active',
        organization_role: 'owner',
        identity_settings_mode: 'self_service',
        support_access: false,
        can_manage_organization: true,
        can_manage_identity_settings: true,
        workspaces: [
          {
            id: workspaceId,
            slug: 'main',
            name: 'Main',
            status: 'active',
            role: 'owner',
            support_access: false
          }
        ]
      }
    ]
  };
}

function event(path: string, params: { organizationId?: string; workspaceId?: string }) {
  return {
    parent: async () => parentData(),
    params,
    url: new URL(path, 'http://web.test')
  };
}

describe('protected tenant layouts', () => {
  it.each([
    [platformLoad, '/platform', {}],
    [organizationLoad, `/organizations/${organizationId}/settings`, { organizationId }],
    [workspaceLoad, `/${workspaceId}/settings/members`, { workspaceId }]
  ])('routes an unsatisfied platform MFA requirement before loading %s', async (load, path, params) => {
    await expect(
      (load as unknown as ProtectedLayoutLoad)(event(path, params))
    ).rejects.toMatchObject({
      status: 303,
      location: `/account/security?setup_totp=1&return_to=${encodeURIComponent(path)}`
    });
  });

  it.each([
    [platformPageLoad, '/platform', {}],
    [organizationPageLoad, `/organizations/${organizationId}/settings`, { organizationId }],
    [
      workspaceSettingsPageLoad,
      `/${workspaceId}/settings/members`,
      { workspaceId, resource: 'members' }
    ]
  ])('waits for the protected parent before requesting data for %s', async (load, path, params) => {
    const blocked = { status: 303, location: '/account/security?setup_totp=1' };
    const fetcher = vi.fn<typeof fetch>();
    const url = new URL(path, 'http://web.test');

    await expect(
      (load as unknown as ProtectedPageLoad)({
        fetch: fetcher,
        parent: async () => {
          throw blocked;
        },
        params,
        request: new Request(url),
        url
      })
    ).rejects.toBe(blocked);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

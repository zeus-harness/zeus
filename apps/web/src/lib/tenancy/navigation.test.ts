import { describe, expect, it } from 'vitest';

import type { UserOrganization } from '$lib/api/identity';

import {
  canSeeIdentitySettings,
  findWorkspaceOption,
  flattenWorkspaceOptions,
  hasValidTenantAccessGrant,
  isNavigationItemVisible,
  isOrganizationOwner,
  isPlatformAdmin,
  isWorkspaceOwner,
  type NavigationPrincipal,
  workspacePath,
  workspaceRootPath
} from './navigation';

const organizations = [
  {
    organization_id: 'org-1',
    organization_name: 'Acme',
    organization_role: 'owner',
    organization_slug: 'acme',
    organization_status: 'active',
    identity_settings_mode: 'organization_managed',
    support_access: false,
    can_manage_organization: true,
    can_manage_identity_settings: true,
    workspaces: [
      {
        id: 'ws-1',
        slug: 'platform',
        name: 'Platform',
        status: 'active',
        role: 'owner',
        support_access: false
      },
      {
        id: 'ws-2',
        slug: 'operations',
        name: 'Operations',
        status: 'active',
        role: 'viewer',
        support_access: false
      }
    ]
  },
  {
    organization_id: 'org-2',
    organization_name: 'Beta',
    organization_role: 'member',
    organization_slug: 'beta',
    organization_status: 'active',
    identity_settings_mode: 'platform_managed',
    support_access: false,
    can_manage_organization: false,
    can_manage_identity_settings: false,
    workspaces: [
      {
        id: 'ws-3',
        slug: 'apps',
        name: 'Apps',
        status: 'active',
        role: 'owner',
        support_access: false
      }
    ]
  }
] satisfies UserOrganization[];

const now = new Date('2026-09-01T00:00:00.000Z');

function principal(overrides: Partial<NavigationPrincipal> = {}): NavigationPrincipal {
  return {
    organization_id: 'org-1',
    workspace_id: 'ws-1',
    organization_role: 'owner',
    workspace_role: 'owner',
    platform_roles: [],
    ...overrides
  };
}

describe('tenant navigation helpers', () => {
  it('flattens organizations into workspace options and finds by workspace id', () => {
    const options = flattenWorkspaceOptions(organizations);

    expect(options).toHaveLength(3);
    expect(options[0]).toMatchObject({
      id: 'ws-1',
      name: 'Platform',
      organization: { organization_id: 'org-1', organization_name: 'Acme' }
    });
    expect(findWorkspaceOption(options, 'ws-3')).toMatchObject({
      id: 'ws-3',
      organization: { organization_id: 'org-2' }
    });
    expect(findWorkspaceOption(options, 'missing')).toBeUndefined();
    expect(findWorkspaceOption(options, null)).toBeUndefined();
  });

  it('builds encoded workspace paths without allowing traversal or external URLs', () => {
    expect(workspaceRootPath('workspace/one')).toBe('/workspace%2Fone');
    expect(workspacePath('workspace/one')).toBe('/workspace%2Fone');
    expect(workspacePath('workspace/one', '/runs//run-1?tab=events')).toBe(
      '/workspace%2Fone/runs/run-1?tab=events'
    );
    expect(workspacePath('ws-1', '/')).toBe('/ws-1');
    expect(() => workspaceRootPath('..')).toThrow(TypeError);
    expect(() => workspacePath('ws-1', '/runs/../admin')).toThrow(TypeError);
    expect(() => workspacePath('ws-1', 'https://example.test')).toThrow(TypeError);
  });

  it('keeps organization and workspace ownership checks independent', () => {
    const owner = principal();

    expect(isOrganizationOwner(owner, 'org-1')).toBe(true);
    expect(isOrganizationOwner(owner, 'org-2')).toBe(false);
    expect(isWorkspaceOwner(owner, 'ws-1')).toBe(true);
    expect(isWorkspaceOwner(owner, 'ws-2')).toBe(false);

    expect(isWorkspaceOwner(principal({ organization_role: 'owner', workspace_role: 'viewer' }))).toBe(
      false
    );
    expect(isOrganizationOwner(principal({ organization_role: 'member', workspace_role: 'owner' }))).toBe(
      false
    );
  });

  it('recognizes only a platform admin with an unexpired tenant access grant', () => {
    const supportPrincipal = principal({
      organization_id: 'org-2',
      workspace_id: null,
      organization_role: null,
      workspace_role: null,
      platform_roles: ['platform_admin'],
      tenant_access_grant_id: 'grant-1',
      tenant_access_expires_at: '2026-09-01T00:30:00.000Z'
    });

    expect(isPlatformAdmin(supportPrincipal)).toBe(true);
    expect(hasValidTenantAccessGrant(supportPrincipal, 'org-2', now)).toBe(true);
    expect(hasValidTenantAccessGrant(supportPrincipal, 'org-1', now)).toBe(false);
    expect(
      hasValidTenantAccessGrant(
        { ...supportPrincipal, tenant_access_expires_at: '2026-09-01T00:00:00.000Z' },
        'org-2',
        now
      )
    ).toBe(false);
    expect(
      hasValidTenantAccessGrant({ ...supportPrincipal, platform_roles: [] }, 'org-2', now)
    ).toBe(false);
    expect(
      hasValidTenantAccessGrant(
        { ...supportPrincipal, tenant_access_expires_at: 'not-a-date' },
        'org-2',
        now
      )
    ).toBe(false);
  });

  it('applies visibility requirements and hides managed identity settings from owners', () => {
    const owner = principal();
    const support = principal({
      organization_id: 'org-2',
      workspace_id: null,
      organization_role: null,
      workspace_role: null,
      platform_roles: ['platform_admin'],
      tenant_access_grant_id: 'grant-1',
      tenant_access_expires_at: '2026-09-01T00:30:00.000Z'
    });

    expect(isNavigationItemVisible('organization_owner', owner, { organizationId: 'org-1' })).toBe(
      true
    );
    expect(isNavigationItemVisible('workspace_owner', owner, { workspaceId: 'ws-1' })).toBe(true);
    expect(isNavigationItemVisible('platform_admin', support)).toBe(true);
    expect(
      isNavigationItemVisible('tenant_access_grant', support, {
        organizationId: 'org-2',
        now
      })
    ).toBe(true);

    expect(
      canSeeIdentitySettings(owner, {
        organization_id: 'org-1',
        identity_settings_mode: 'self_service'
      }, now)
    ).toBe(true);
    expect(
      canSeeIdentitySettings(owner, {
        organization_id: 'org-1',
        identity_settings_mode: 'platform_managed'
      }, now)
    ).toBe(false);
    expect(
      canSeeIdentitySettings(support, {
        organization_id: 'org-2',
        identity_settings_mode: 'platform_managed'
      }, now)
    ).toBe(true);
  });
});

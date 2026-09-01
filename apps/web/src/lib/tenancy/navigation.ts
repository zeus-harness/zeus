import type { UserOrganization, UserWorkspace } from '$lib/api/identity';
import type { components } from '$lib/api/generated/schema';
import type { CurrentPrincipal } from '$lib/api/server';

type CurrentUserResponse = components['schemas']['CurrentUserResponse'];
type TenantAccessFields = Pick<
  CurrentUserResponse,
  'tenant_access_grant_id' | 'tenant_access_expires_at'
>;

export type WorkspaceOption = UserWorkspace & {
  organization: UserOrganization;
};

export type NavigationPrincipal = Pick<
  CurrentPrincipal,
  'organization_id' | 'workspace_id' | 'organization_role' | 'workspace_role' | 'platform_roles'
> &
  TenantAccessFields;

export type OrganizationIdentitySettingsTarget = Pick<UserOrganization, 'organization_id'> & {
  identity_settings_mode: string;
};

export type NavigationRequirement =
  | 'organization_owner'
  | 'workspace_owner'
  | 'platform_admin'
  | 'tenant_access_grant';

export type NavigationVisibilityContext = {
  organizationId?: string;
  workspaceId?: string;
  now?: Date;
};

export function flattenWorkspaceOptions(
  organizations: readonly UserOrganization[]
): WorkspaceOption[] {
  return organizations.flatMap((organization) =>
    organization.workspaces.map((workspace) => ({ ...workspace, organization }))
  );
}

export function findWorkspaceOption(
  options: readonly WorkspaceOption[],
  workspaceId: string | null | undefined
): WorkspaceOption | undefined {
  if (!workspaceId) return undefined;
  return options.find((option) => option.id === workspaceId);
}

export function workspaceRootPath(workspaceId: string): string {
  if (!workspaceId.trim() || workspaceId === '.' || workspaceId === '..') {
    throw new TypeError('workspaceId must be a non-empty path segment');
  }
  return `/${encodeURIComponent(workspaceId)}`;
}

export function workspacePath(workspaceId: string, subpath = ''): string {
  const root = workspaceRootPath(workspaceId);
  const value = subpath.trim();
  if (!value || value === '/') return root;

  const suffixStart = value.search(/[?#]/);
  const pathname = suffixStart === -1 ? value : value.slice(0, suffixStart);
  const suffix = suffixStart === -1 ? '' : value.slice(suffixStart);
  if (/^[a-z][a-z\d+.-]*:/i.test(pathname)) {
    throw new TypeError('workspace subpath must be relative');
  }

  const encodedSegments = pathname
    .split('/')
    .filter(Boolean)
    .map((segment) => {
      let decodedSegment: string;
      try {
        decodedSegment = decodeURIComponent(segment);
      } catch {
        throw new TypeError('workspace subpath contains an invalid escape sequence');
      }
      if (
        decodedSegment === '.' ||
        decodedSegment === '..' ||
        decodedSegment.includes('/') ||
        decodedSegment.includes('\\')
      ) {
        throw new TypeError('workspace subpath must not contain traversal segments');
      }
      return encodeURIComponent(decodedSegment);
    });

  return encodedSegments.length > 0
    ? `${root}/${encodedSegments.join('/')}${suffix}`
    : `${root}${suffix}`;
}

export function isOrganizationOwner(
  principal: NavigationPrincipal | null | undefined,
  organizationId?: string
): boolean {
  return Boolean(
    principal?.organization_id &&
      principal.organization_role === 'owner' &&
      (organizationId === undefined || principal.organization_id === organizationId)
  );
}

export function isWorkspaceOwner(
  principal: NavigationPrincipal | null | undefined,
  workspaceId?: string
): boolean {
  return Boolean(
    principal?.workspace_id &&
      principal.workspace_role === 'owner' &&
      (workspaceId === undefined || principal.workspace_id === workspaceId)
  );
}

export function isPlatformAdmin(principal: NavigationPrincipal | null | undefined): boolean {
  return principal?.platform_roles.includes('platform_admin') ?? false;
}

export function hasValidTenantAccessGrant(
  principal: NavigationPrincipal | null | undefined,
  organizationId?: string,
  now = new Date()
): boolean {
  if (!isPlatformAdmin(principal) || !principal?.organization_id) return false;
  if (organizationId !== undefined && principal.organization_id !== organizationId) return false;

  const grantId = principal.tenant_access_grant_id;
  const expiresAt = principal.tenant_access_expires_at;
  if (!grantId?.trim() || !expiresAt) return false;

  const expiresAtMs = Date.parse(expiresAt);
  const nowMs = now.getTime();
  return Number.isFinite(expiresAtMs) && Number.isFinite(nowMs) && expiresAtMs > nowMs;
}

export function isNavigationItemVisible(
  requirement: NavigationRequirement,
  principal: NavigationPrincipal | null | undefined,
  context: NavigationVisibilityContext = {}
): boolean {
  switch (requirement) {
    case 'organization_owner':
      return isOrganizationOwner(principal, context.organizationId);
    case 'workspace_owner':
      return isWorkspaceOwner(principal, context.workspaceId);
    case 'platform_admin':
      return isPlatformAdmin(principal);
    case 'tenant_access_grant':
      return hasValidTenantAccessGrant(principal, context.organizationId, context.now);
  }
}

export function canSeeIdentitySettings(
  principal: NavigationPrincipal | null | undefined,
  organization: OrganizationIdentitySettingsTarget,
  now = new Date()
): boolean {
  if (hasValidTenantAccessGrant(principal, organization.organization_id, now)) return true;
  return (
    organization.identity_settings_mode === 'self_service' &&
    isOrganizationOwner(principal, organization.organization_id)
  );
}

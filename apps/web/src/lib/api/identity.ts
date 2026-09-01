import type { components } from './generated/schema';
import { requestJson, type ApiFetcher } from './client';
import { serverApiUrl } from './server';

export {
  loadCurrentPrincipal,
  serverApiFetcher,
  serverApiUrl,
  type CurrentPrincipal,
  type PrincipalResult
} from './server';

type UserOrganizationResponse = components['schemas']['UserOrganizationResponse'];
export type UserWorkspace = {
  id: string;
  slug: string;
  name: string;
  status: string;
  role: string;
  support_access: boolean;
};

export type UserOrganization = Omit<UserOrganizationResponse, 'workspaces'> & {
  workspaces: UserWorkspace[];
};

function userWorkspaces(value: unknown): UserWorkspace[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((candidate) => {
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) return [];
    const item = candidate as Record<string, unknown>;
    if (
      typeof item.id !== 'string' ||
      typeof item.slug !== 'string' ||
      typeof item.name !== 'string' ||
      typeof item.status !== 'string' ||
      typeof item.role !== 'string'
    ) {
      return [];
    }
    return [{
      id: item.id,
      slug: item.slug,
      name: item.name,
      status: item.status,
      role: item.role,
      support_access: item.support_access === true
    }];
  });
}

export async function listUserOrganizations(
  fetcher: ApiFetcher,
  apiBaseUrl?: string
): Promise<UserOrganization[]> {
  const organizations = await requestJson<UserOrganizationResponse[]>(
    fetcher,
    serverApiUrl(apiBaseUrl, '/api/v1/users/me/organizations')
  );
  return organizations.map(({ workspaces, ...organization }) => ({
    ...organization,
    workspaces: userWorkspaces(workspaces)
  }));
}

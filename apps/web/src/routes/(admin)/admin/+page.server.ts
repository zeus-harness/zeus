import type { PageServerLoad } from './$types';

import { managementResources } from '$lib/control-plane';

export const load: PageServerLoad = async ({ parent }) => {
  const { principal, status } = await parent();
  return {
    resources: managementResources,
    workspaceConfigured: Boolean(principal?.workspace_id),
    authStatus: status
  };
};

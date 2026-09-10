import type { PageServerLoad } from './$types';

import { workspaceSettingResources } from '$lib/control-plane';

export const load: PageServerLoad = async ({ params }) => ({
  resources: workspaceSettingResources,
  workspaceId: params.workspaceId
});

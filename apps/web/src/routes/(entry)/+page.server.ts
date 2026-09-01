import { redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { PageServerLoad } from './$types';

import { loadSetupStatus } from '$lib/api/setup';

export const load: PageServerLoad = async ({ fetch, parent, url }) => {
  const [auth, setupStatus] = await Promise.all([
    parent(),
    loadSetupStatus(fetch, env.ZEUS_API_URL)
  ]);

  if (setupStatus.status === 'ready' && setupStatus.data.setup_required) redirect(303, '/setup');
  if (auth.status === 'unauthenticated') redirect(303, '/login');
  if (auth.status !== 'ready') return { unavailable: true };

  const workspaces = auth.organizations
    .flatMap((organization) => organization.workspaces)
    .filter((workspace) => workspace.status === 'active');
  const activeWorkspace = workspaces.find(
    (workspace) => workspace.id === auth.principal?.workspace_id && workspace.status === 'active'
  );
  if (activeWorkspace) redirect(303, `/${activeWorkspace.id}`);

  if (workspaces.length === 0 && auth.principal?.platform_roles.includes('platform_admin')) {
    redirect(303, '/platform');
  }
  if (workspaces.length === 1) {
    const workspaceId = workspaces[0].id;
    redirect(303, `/workspaces?auto=1&return_to=${encodeURIComponent(`/${workspaceId}`)}`);
  }
  redirect(303, '/workspaces');
};

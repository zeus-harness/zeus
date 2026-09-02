import { describe, expect, it, vi } from 'vitest';

import { load } from './+page.server';

vi.mock('$env/dynamic/private', () => ({
  env: { ZEUS_API_URL: 'http://zeus-api:8080' }
}));

type EntryLoad = (event: {
  fetch: typeof fetch;
  parent: () => Promise<unknown>;
  url: URL;
}) => Promise<unknown>;

const entryLoad = load as unknown as EntryLoad;

function workspace(id: string, status = 'active') {
  return { id, slug: id, name: id, status, role: 'owner', support_access: false };
}

function organization(workspaces: ReturnType<typeof workspace>[]) {
  return { organization_id: 'org-1', workspaces };
}

function auth(
  workspaces: ReturnType<typeof workspace>[],
  options: { selected?: string | null; platformOwner?: boolean } = {}
) {
  return {
    status: 'ready',
    principal: {
      workspace_id: options.selected ?? null,
      platform_roles: options.platformOwner ? ['platform_owner'] : []
    },
    organizations: workspaces.length > 0 ? [organization(workspaces)] : []
  };
}

function event(parentValue: unknown) {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
    new Response(JSON.stringify({ setup_required: false, bootstrap_token_configured: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    })
  );
  return {
    fetch: fetcher,
    parent: async () => parentValue,
    url: new URL('http://web.test/')
  };
}

describe('tenant entry resolver', () => {
  it('keeps zero-Workspace users in the selector empty state', async () => {
    await expect(entryLoad(event(auth([])))).rejects.toMatchObject({
      status: 303,
      location: '/workspaces'
    });
  });

  it('sends a platform owner without Workspaces to the platform console', async () => {
    await expect(entryLoad(event(auth([], { platformOwner: true })))).rejects.toMatchObject({
      status: 303,
      location: '/platform'
    });
  });

  it('auto-selects the only active Workspace and ignores inactive entries', async () => {
    await expect(
      entryLoad(event(auth([workspace('workspace-active'), workspace('workspace-old', 'archived')])))
    ).rejects.toMatchObject({
      status: 303,
      location: '/workspaces?auto=1&return_to=%2Fworkspace-active'
    });
  });

  it('uses the selector for multiple active Workspaces', async () => {
    await expect(
      entryLoad(event(auth([workspace('workspace-a'), workspace('workspace-b')])))
    ).rejects.toMatchObject({ status: 303, location: '/workspaces' });
  });

  it('returns directly to a valid selected Workspace', async () => {
    await expect(
      entryLoad(event(auth([workspace('workspace-a')], { selected: 'workspace-a' })))
    ).rejects.toMatchObject({ status: 303, location: '/workspace-a' });
  });
});

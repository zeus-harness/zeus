import { describe, expect, it } from 'vitest';
import { loadAgentStudio } from './agent-studio';

describe('Agent Studio permissions', () => {
  it('keeps Workspace configuration usable when Organization catalog names are forbidden', async () => {
    const fetcher: typeof fetch = async (input) => {
      const pathname = new URL(String(input)).pathname;
      if (pathname.includes('/organizations/')) return Response.json({}, { status: 403 });
      if (pathname.endsWith('/capabilities')) return Response.json({ items: [{ id: 'enabled', capability_id: 'tool', enabled: true }] });
      return Response.json({ items: [] });
    };
    const studio = await loadAgentStudio(fetcher, { apiBaseUrl: 'http://api.test', workspaceId: 'workspace' }, 'workflows', null, 'organization');
    expect(studio.capabilities).toHaveLength(1);
    expect(studio.catalog).toEqual([]);
  });

  it('does not disguise a failed Workspace read as an empty configuration', async () => {
    await expect(loadAgentStudio(async () => Response.json({}, { status: 403 }),
      { apiBaseUrl: 'http://api.test', workspaceId: 'workspace' }, 'workflows', null, 'organization'))
      .rejects.toMatchObject({ status: 403 });
  });
});

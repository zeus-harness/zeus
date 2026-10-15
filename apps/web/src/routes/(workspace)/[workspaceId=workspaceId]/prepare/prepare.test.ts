import { describe, expect, it, vi } from 'vitest';
import { load } from './+page.server';
vi.mock('$env/dynamic/private', () => ({ env: { ZEUS_API_URL: 'http://api.test' } }));
const workspace = '019f0000-0000-7000-8000-000000000001';
const organization = '019f0000-0000-7000-8000-000000000002';
const returnTo = `/${workspace}/studio`;
function input(model: boolean, agent: boolean, workflow: boolean, provider = false, owner = true) {
  return {
    params: { workspaceId: workspace },
    request: new Request('http://web.test'), url: new URL(`http://web.test/${workspace}/prepare?${new URLSearchParams({return_to: returnTo})}`),
    parent: async () => ({ canManageOrganization: owner, canManageWorkspace: owner, activeWorkspace: { role: 'builder' }, activeOrganization: { organization_id: organization } }),
    fetch: vi.fn(async (value: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method ?? 'GET').toBe('GET');
      const path = String(value);
      const present = path.includes('model-providers') ? provider : path.includes('model-profiles') ? model : path.includes('agents') ? agent : workflow;
      return Response.json({ items: present ? [{active_version_id:'published', provider_kind:'openai_compatible'}] : [] });
    })
  } as unknown as Parameters<typeof load>[0];
}
describe('first-run routing', () => {
  it('skips credentials when a provider already exists', async () => {
    await expect(load(input(false, false, false, true))).rejects.toMatchObject({status:303,location:expect.stringContaining(`/organizations/${organization}/settings/model-profiles?`)});
  });
  it('uses the saved model and goes directly to the Agent template', async () => {
    await expect(load(input(true, false, false))).rejects.toMatchObject({status:303,location:expect.stringContaining(`/${workspace}/agents?template=requirements`)});
  });
  it('returns to the original conversation once a flow is published', async () => {
    await expect(load(input(true, true, true))).rejects.toMatchObject({status:303,location:returnTo});
  });
  it('does not send a builder to organization credential management', async () => {
    await expect(load(input(false, false, false, false, false))).rejects.toMatchObject({status:403});
  });
});

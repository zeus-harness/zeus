import { describe, expect, it, vi } from 'vitest';

import { transitionPlatformOrganization } from './platform';

describe('platform Organization client', () => {
  it('uses the backend resume action for a suspended Organization', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ organization_id: 'org-1', status: 'active' }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      })
    );

    await transitionPlatformOrganization(fetcher, 'org-1', 7, 'resume');

    expect(fetcher.mock.calls[0]?.[0]).toBe('/api/v1/platform/organizations/org-1/status');
    const init = fetcher.mock.calls[0]?.[1];
    expect(new Headers(init?.headers).get('if-match')).toBe('"7"');
    expect(JSON.parse(String(init?.body))).toEqual({ action: 'resume' });
  });
});

import { describe, expect, it } from 'vitest';

import { load } from './+page.server';

describe('account profile page load', () => {
  it('redirects unauthenticated visitors to login', async () => {
    const event = {
      parent: async () => ({ principal: null, status: 'unauthenticated' as const })
    } as unknown as Parameters<typeof load>[0];

    await expect(load(event)).rejects.toMatchObject({ status: 303, location: '/login' });
  });

  it('allows an authenticated principal to load the profile page', async () => {
    const event = {
      parent: async () => ({
        principal: null,
        status: 'ready' as const
      })
    } as unknown as Parameters<typeof load>[0];

    await expect(load(event)).resolves.toEqual({});
  });
});

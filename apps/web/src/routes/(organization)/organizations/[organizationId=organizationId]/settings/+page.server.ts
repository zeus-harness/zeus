import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { getOrganization, updateOrganization } from '$lib/api/organizations';
import { serverApiFetcher } from '$lib/api/server';
import { requireOrganizationAction } from '$lib/server/organization-context';

export const load: PageServerLoad = async ({ fetch, params, parent, request, url }) => {
  await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return {
    organization: await getOrganization(apiFetch, params.organizationId, env.ZEUS_API_URL)
  };
};

export const actions: Actions = {
  update: async (event) => {
    const context = await requireOrganizationAction(
      event,
      env.ZEUS_API_URL,
      event.params.organizationId
    );
    if (context.error) return context.error;
    const formData = await event.request.formData();
    const name = String(formData.get('name') ?? '').trim();
    const revision = Number.parseInt(String(formData.get('revision') ?? ''), 10);
    if (!name || !Number.isSafeInteger(revision) || revision < 1) {
      return fail(400, { type: 'error' as const, message: '名称或 revision 无效。' });
    }
    try {
      await updateOrganization(
        context.apiFetch,
        context.organizationId!,
        revision,
        { name },
        env.ZEUS_API_URL
      );
    } catch (error) {
      return fail(502, {
        type: 'error' as const,
        message: error instanceof Error ? error.message : 'Organization 更新失败。'
      });
    }
    redirect(303, `/organizations/${context.organizationId}/settings`);
  }
};

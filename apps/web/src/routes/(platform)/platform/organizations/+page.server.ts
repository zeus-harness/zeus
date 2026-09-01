import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { ZeusApiError } from '$lib/api/client';
import { createPlatformOrganization, listPlatformOrganizations } from '$lib/api/platform';
import { serverApiFetcher } from '$lib/api/server';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

export const load: PageServerLoad = async ({ fetch, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return { organizations: await listPlatformOrganizations(apiFetch, env.ZEUS_API_URL) };
};

export const actions: Actions = {
  create: async ({ fetch, request, url }) => {
    const formData = await request.formData();
    const payload = {
      name: formValue(formData, 'name'),
      slug: formValue(formData, 'slug'),
      initial_workspace_name: formValue(formData, 'initial_workspace_name'),
      initial_workspace_slug: formValue(formData, 'initial_workspace_slug'),
      owner_email: formValue(formData, 'owner_email').toLowerCase(),
      identity_settings_mode: formValue(formData, 'identity_settings_mode')
    };
    if (Object.values(payload).some((value) => !value)) {
      return fail(400, { type: 'error' as const, message: '创建字段不能为空。' });
    }
    const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
    let organizationId: string;
    try {
      const created = await createPlatformOrganization(
        apiFetch,
        payload,
        crypto.randomUUID(),
        env.ZEUS_API_URL
      );
      organizationId = created.organization_id;
    } catch (error) {
      return fail(error instanceof ZeusApiError ? error.status : 502, {
        type: 'error' as const,
        message: error instanceof Error ? error.message : 'Organization 创建失败。'
      });
    }
    redirect(303, `/platform/organizations/${organizationId}`);
  }
};

import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import { ZeusApiError } from '$lib/api/client';
import {
  createPlatformTenantAccessGrantResponse,
  getPlatformOrganization,
  replacePlatformOwnerInvitation,
  resendPlatformOwnerInvitation,
  transitionPlatformOrganization,
  updatePlatformOrganization
} from '$lib/api/platform';
import { forwardZeusAuthCookies, serverApiFetcher } from '$lib/api/server';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function revisionValue(formData: FormData): number | null {
  const revision = Number.parseInt(formValue(formData, 'revision'), 10);
  return Number.isSafeInteger(revision) && revision > 0 ? revision : null;
}

function actionError(error: unknown, fallback: string) {
  return fail(error instanceof ZeusApiError ? error.status : 502, {
    type: 'error' as const,
    message: error instanceof Error ? error.message : fallback
  });
}

async function responseMessage(response: Response): Promise<string> {
  try {
    const problem = (await response.clone().json()) as { detail?: unknown; title?: unknown };
    if (typeof problem.detail === 'string') return problem.detail;
    if (typeof problem.title === 'string') return problem.title;
  } catch {
    // Keep a stable fallback without exposing the response body.
  }
  return `平台请求失败（HTTP ${response.status}）。`;
}

export const load: PageServerLoad = async ({ fetch, params, request, url }) => {
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  return {
    organization: await getPlatformOrganization(
      apiFetch,
      params.organizationId,
      env.ZEUS_API_URL
    )
  };
};

export const actions: Actions = {
  update: async (event) => {
    const formData = await event.request.formData();
    const revision = revisionValue(formData);
    const name = formValue(formData, 'name');
    const slug = formValue(formData, 'slug');
    const identitySettingsMode = formValue(formData, 'identity_settings_mode');
    if (!revision || !name || !slug || !identitySettingsMode) {
      return fail(400, { type: 'error' as const, message: 'Organization 修改参数无效。' });
    }
    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    try {
      await updatePlatformOrganization(
        apiFetch,
        event.params.organizationId,
        revision,
        { name, slug, identity_settings_mode: identitySettingsMode },
        env.ZEUS_API_URL
      );
    } catch (error) {
      return actionError(error, 'Organization 更新失败。');
    }
    redirect(303, `/platform/organizations/${event.params.organizationId}`);
  },

  transition: async (event) => {
    const formData = await event.request.formData();
    const revision = revisionValue(formData);
    const action = formValue(formData, 'transition');
    if (
      !revision ||
      !['suspend', 'activate', 'archive', 'restore'].includes(action)
    ) {
      return fail(400, { type: 'error' as const, message: 'Organization 状态动作无效。' });
    }
    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    try {
      await transitionPlatformOrganization(
        apiFetch,
        event.params.organizationId,
        revision,
        action as 'suspend' | 'activate' | 'archive' | 'restore',
        env.ZEUS_API_URL
      );
    } catch (error) {
      return actionError(error, 'Organization 状态变更失败。');
    }
    redirect(303, `/platform/organizations/${event.params.organizationId}`);
  },

  resendInvitation: async (event) => {
    const revision = revisionValue(await event.request.formData());
    if (!revision) return fail(400, { type: 'error' as const, message: 'revision 无效。' });
    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    try {
      await resendPlatformOwnerInvitation(
        apiFetch,
        event.params.organizationId,
        revision,
        env.ZEUS_API_URL
      );
    } catch (error) {
      return actionError(error, 'Owner 邀请重发失败。');
    }
    redirect(303, `/platform/organizations/${event.params.organizationId}`);
  },

  replaceInvitation: async (event) => {
    const formData = await event.request.formData();
    const revision = revisionValue(formData);
    const ownerEmail = formValue(formData, 'owner_email').toLowerCase();
    if (!revision || !ownerEmail) {
      return fail(400, { type: 'error' as const, message: 'Owner 邮箱或 revision 无效。' });
    }
    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    try {
      await replacePlatformOwnerInvitation(
        apiFetch,
        event.params.organizationId,
        revision,
        ownerEmail,
        env.ZEUS_API_URL
      );
    } catch (error) {
      return actionError(error, 'Owner 邀请替换失败。');
    }
    redirect(303, `/platform/organizations/${event.params.organizationId}`);
  },

  enterTenant: async (event) => {
    const formData = await event.request.formData();
    const password = formValue(formData, 'password');
    const totpCode = formValue(formData, 'totp_code');
    const reason = formValue(formData, 'reason');
    const durationMinutes = Number.parseInt(formValue(formData, 'duration_minutes') || '60', 10);
    if (!password || !/^\d{6}$/.test(totpCode) || reason.length < 10) {
      return fail(400, {
        type: 'error' as const,
        message: '需要当前密码、六位 TOTP 和至少 10 个字符的访问原因。'
      });
    }
    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await createPlatformTenantAccessGrantResponse(
        apiFetch,
        {
          organization_id: event.params.organizationId,
          password,
          totp_code: totpCode,
          reason,
          duration_minutes: durationMinutes
        },
        env.ZEUS_API_URL
      );
    } catch {
      return fail(502, { type: 'error' as const, message: '租户访问服务暂时不可用。' });
    }
    if (!response.ok) {
      return fail(response.status, {
        type: 'error' as const,
        message: await responseMessage(response)
      });
    }
    forwardZeusAuthCookies(response, event.cookies);
    redirect(303, `/organizations/${event.params.organizationId}/settings`);
  }
};

import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  forwardZeusAuthCookies,
  serverApiFetcher,
  serverApiUrl
} from '$lib/api/server';

export type WebSession = {
  id: string;
  active_organization_id: string | null;
  active_workspace_id: string | null;
  auth_methods: string[];
  authenticated_at: string;
  mfa_satisfied_at: string | null;
  last_seen_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  current: boolean;
};

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function responseStatus(status: number): number {
  return status >= 400 && status <= 599 ? status : 502;
}

function isWebSession(value: unknown): value is WebSession {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const session = value as Record<string, unknown>;
  return (
    typeof session.id === 'string' &&
    (typeof session.active_organization_id === 'string' || session.active_organization_id === null) &&
    (typeof session.active_workspace_id === 'string' || session.active_workspace_id === null) &&
    Array.isArray(session.auth_methods) &&
    session.auth_methods.every((method) => typeof method === 'string') &&
    typeof session.authenticated_at === 'string' &&
    (typeof session.mfa_satisfied_at === 'string' || session.mfa_satisfied_at === null) &&
    typeof session.last_seen_at === 'string' &&
    typeof session.idle_expires_at === 'string' &&
    typeof session.absolute_expires_at === 'string' &&
    typeof session.current === 'boolean'
  );
}

function hasZeusAuthCookie(response: Response): boolean {
  return response.headers.getSetCookie().some((rawCookie) => {
    const pair = rawCookie.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    const name = separator > 0 ? pair.slice(0, separator).trim() : '';
    return name === 'zeus_session' || name === 'zeus_csrf';
  });
}

function sessionsErrorMessage(status: number): string {
  if (status >= 500) return '登录会话服务暂时不可用，请稍后重试。';
  return '无法读取登录会话，请稍后重试。';
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const auth = await parent();
  if (auth.status === 'unauthenticated') {
    redirect(303, '/login');
  }
  if (auth.status !== 'ready') {
    return {
      sessions: [],
      loadError: '无法确认当前登录状态，请稍后重试。',
      httpStatus: null
    };
  }

  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  let response: Response;
  try {
    response = await apiFetch(serverApiUrl(env.ZEUS_API_URL, '/api/v1/auth/sessions'), {
      headers: { accept: 'application/json' }
    });
  } catch {
    return {
      sessions: [],
      loadError: '无法连接登录会话 API，请稍后重试。',
      httpStatus: null
    };
  }

  if (response.status === 401) {
    redirect(303, '/login');
  }
  if (!response.ok) {
    return {
      sessions: [],
      loadError: sessionsErrorMessage(response.status),
      httpStatus: response.status
    };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      sessions: [],
      loadError: '登录会话 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  if (!Array.isArray(payload) || !payload.every(isWebSession)) {
    return {
      sessions: [],
      loadError: '登录会话 API 返回了无法识别的响应。',
      httpStatus: 502
    };
  }

  return { sessions: payload, loadError: null, httpStatus: null };
};

export const actions: Actions = {
  revoke: async (event) => {
    const formData = await event.request.formData();
    const sessionId = formValue(formData, 'session_id');
    const markedCurrent = formValue(formData, 'current') === 'true';
    if (!sessionId) return actionError(400, '缺少要撤销的会话。');

    const apiFetch = serverApiFetcher(
      event.fetch,
      event.request.headers.get('cookie'),
      event.url.origin
    );
    let response: Response;
    try {
      response = await apiFetch(
        serverApiUrl(env.ZEUS_API_URL, `/api/v1/auth/sessions/${encodeURIComponent(sessionId)}`),
        {
          method: 'DELETE',
          headers: { accept: 'application/json' }
        }
      );
    } catch {
      return actionError(503, '无法连接登录会话 API，请稍后重试。');
    }

    const currentRevoked = markedCurrent || hasZeusAuthCookie(response);
    forwardZeusAuthCookies(response, event.cookies);
    if (response.status === 401) {
      redirect(303, '/login');
    }
    if (!response.ok) {
      return actionError(
        responseStatus(response.status),
        response.status === 404
          ? '该登录会话不存在或已经撤销。'
          : response.status >= 500
            ? '登录会话服务暂时不可用，请稍后重试。'
            : '无法撤销该登录会话，请稍后重试。'
      );
    }
    if (currentRevoked) {
      redirect(303, '/login');
    }

    return { type: 'success' as const, message: '登录会话已撤销。' };
  }
};

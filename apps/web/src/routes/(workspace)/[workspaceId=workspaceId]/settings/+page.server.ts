import { error, fail } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import type { components } from '$lib/api/generated/schema';
import { serverApiFetcher, serverApiUrl } from '$lib/api/server';
import { workspaceSettingResources } from '$lib/control-plane';

export const load: PageServerLoad = async ({ params, parent, fetch, request, url }) => {
  await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const response = await apiFetch(serverApiUrl(env.ZEUS_API_URL, `/api/v1/workspaces/${params.workspaceId}`));
  if (!response.ok) error(response.status === 403 ? 403 : 503, '无法读取 Workspace 基础信息。');
  const workspace: components['schemas']['WorkspaceResponse'] = await response.json();
  return { resources: workspaceSettingResources, workspaceId: params.workspaceId, workspace };
};

export const actions: Actions = {
  save: async ({ params, fetch, request, url }) => {
    const fields = await request.formData();
    const name = typeof fields.get('name') === 'string' ? String(fields.get('name')).trim() : '';
    const revision = String(fields.get('revision') ?? '');
    const failure = (status: number, message: string) => fail(status, { saved: false, name, revision, message });
    if (!name || new TextEncoder().encode(name).length > 160) {
      return failure(400, '名称不能为空，且不能超过 160 个 UTF-8 字节。');
    }
    if (!/^[1-9]\d*$/.test(revision) || !Number.isSafeInteger(Number(revision))) {
      return failure(400, '页面版本无效，请刷新后重试。');
    }
    const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
    let response: Response;
    try {
      response = await apiFetch(serverApiUrl(env.ZEUS_API_URL, `/api/v1/workspaces/${params.workspaceId}`), {
        method: 'PATCH',
        headers: { 'content-type': 'application/json', 'if-match': `"revision-${revision}"` },
        body: JSON.stringify({ name })
      });
    } catch {
      return failure(503, 'Workspace 服务暂时不可用，请稍后重试。');
    }
    if (!response.ok) {
      if (response.status === 412) return failure(412, 'Workspace 已被其他人修改。请刷新页面查看最新信息后再保存。');
      if (response.status === 403) return failure(403, '当前会话无权修改此 Workspace。');
      if (response.status === 401) return failure(401, '登录已过期，请重新登录。');
      return failure(response.status >= 500 ? 503 : 400, 'Workspace 保存失败，请检查名称后重试。');
    }
    return { saved: true, message: 'Workspace 名称已更新。' };
  }
};

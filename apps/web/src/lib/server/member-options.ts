import { requestWorkspaceJson, type ApiFetcher, type WorkspaceRequestOptions } from '$lib/api/client';
import type { CurrentPrincipal } from '$lib/api/server';
export type MemberOption = { user_id: string; display_name: string; email: string; status: string };
export async function loadMemberOptions(fetcher: ApiFetcher, options: WorkspaceRequestOptions, canManage: boolean, principal: CurrentPrincipal | null) {
  const self: MemberOption[] = principal?.user_id ? [{ user_id: principal.user_id, display_name: principal.display_name, email: principal.email ?? '', status: 'active' }] : [];
  if (!canManage) return { members: self, memberOptionsLimited: true };
  try {
    const members = await requestWorkspaceJson<MemberOption[]>(fetcher, options, '/members');
    return { members: members.filter(member => member.status === 'active'), memberOptionsLimited: members.length >= 500 };
  } catch {
    return { members: self, memberOptionsLimited: true };
  }
}

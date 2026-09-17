// Only return to the current workspace's task list, with supported filters.
export function workItemListReturn(value: string | null, workspaceId: string): string {
  const fallback = `/${workspaceId}/work-items`;
  if (!value?.startsWith(`${fallback}?`) && !value?.startsWith(`${fallback}#`) && value !== fallback) return fallback;
  try {
    const url = new URL(value, 'http://zeus.local');
    if (url.origin !== 'http://zeus.local' || url.pathname !== fallback) return fallback;
    for (const key of [...url.searchParams.keys()]) {
      if (!['view', 'q', 'status', 'assignee_user_id', 'cursor'].includes(key)) url.searchParams.delete(key);
    }
    if (!/^#(?:mobile|desktop)-[0-9a-f-]{36}$/i.test(url.hash)) url.hash = '';
    return url.pathname + url.search + url.hash;
  } catch {
    return fallback;
  }
}

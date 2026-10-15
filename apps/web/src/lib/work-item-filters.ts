export function workItemScopeHref(url: URL, view: '' | 'created' | 'unassigned'): string {
  const params = new URLSearchParams();
  for (const key of ['q', 'status', 'assignee_user_id']) {
    const value = url.searchParams.get(key);
    if (value && !(view === 'unassigned' && key === 'assignee_user_id')) params.set(key, value);
  }
  if (view) params.set('view', view);
  return url.pathname + (params.size ? `?${params}` : '');
}

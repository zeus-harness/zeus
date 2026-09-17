const taskPath = /^\/[0-9a-f-]{36}\/work-items\/[0-9a-f-]{36}$/i;
export function taskReturnTo(value: unknown): string {
  return typeof value === 'string' && taskPath.test(value) ? value : '';
}
export function withTaskReturn(href: string, value: unknown): string {
  const target = taskReturnTo(value);
  if (!target) return href;
  const url = new URL(href, 'http://zeus.local');
  url.searchParams.set('return_to', target);
  return `${url.pathname === '/' && href.startsWith('?') ? '' : url.pathname}${url.search}${url.hash}`;
}

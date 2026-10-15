import { workItemListReturn } from './work-item-list-return';
const studioPath = /^\/([0-9a-f-]{36})\/studio$/i;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const taskPath = /^\/([0-9a-f-]{36})\/work-items\/[0-9a-f-]{36}$/i;
export function taskReturnTo(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) return '';
  try {
    const url = new URL(value, 'http://zeus.local');
    if (studioPath.test(url.pathname)) {
      if (url.origin !== 'http://zeus.local' || url.hash) return '';
      const allowed = ['work_item', 'run', 'workflow'];
      for (const [key, entry] of url.searchParams) {
        if (!allowed.includes(key) || !uuid.test(entry) || url.searchParams.getAll(key).length !== 1) return '';
      }
      if (url.searchParams.has('run') && !url.searchParams.has('work_item')) return '';
      if (url.searchParams.has('workflow') && url.searchParams.has('work_item')) return '';
      return url.pathname + url.search;
    }
    const match = taskPath.exec(url.pathname);
    if (!match || url.origin !== 'http://zeus.local' || url.hash) return '';
    if ([...url.searchParams.keys()].some(key => key !== 'list_return')) return '';
    const list = url.searchParams.get('list_return');
    url.search = '';
    if (list) url.searchParams.set('list_return', workItemListReturn(list, match[1]));
    return url.pathname + url.search;
  } catch {
    return '';
  }
}
export function withTaskReturn(href: string, value: unknown): string {
  const target = taskReturnTo(value);
  if (!target) return href;
  const url = new URL(href, 'http://zeus.local');
  url.searchParams.set('return_to', target);
  return `${url.pathname === '/' && href.startsWith('?') ? '' : url.pathname}${url.search}${url.hash}`;
}

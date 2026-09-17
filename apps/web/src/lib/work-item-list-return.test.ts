import { describe, expect, it } from 'vitest';
import { workItemListReturn } from './work-item-list-return';

const workspace = '01a0a9e9-c08c-79fc-b37a-88adfb7b1816';
const list = `/${workspace}/work-items`;
describe('work item list return', () => {
  it('retains filters, opaque pagination and the selected row', () => {
    const target = `${list}?view=created&q=%E5%AE%A2%E6%88%B7&status=canceled&assignee_user_id=user&cursor=opaque%2Bpage#mobile-01a0aaf6-e188-76f6-b7ab-1fcc29f96bf0`;
    expect(workItemListReturn(target, workspace)).toBe(target);
  });
  it.each([null, 'https://evil.test', '//evil.test', '/other/work-items?q=x', `${list}/../settings`, `${list}?q=x\\evil`])('never navigates outside the current task list: %s', target => {
    const result = new URL(workItemListReturn(target, workspace), 'http://zeus.local');
    expect(result.origin).toBe('http://zeus.local');
    expect(result.pathname).toBe(list);
  });
  it('removes action and create parameters and arbitrary fragments', () => {
    expect(workItemListReturn(`${list}?q=test&create=1&/select#untrusted`, workspace)).toBe(`${list}?q=test`);
  });
});

import { describe, expect, it } from 'vitest';
import { taskReturnTo, withTaskReturn } from './task-return';
const target = '/019f0000-0000-7000-8000-000000000001/work-items/019f0000-0000-7000-8000-000000000002';
describe('task configuration return context', () => {
  it('retains safe nested list context across configuration actions', () => {
    const list = '/019f0000-0000-7000-8000-000000000001/work-items?q=客户&view=created&cursor=next#mobile-019f0000-0000-7000-8000-000000000002';
    const detail = target + '?list_return=' + encodeURIComponent(list);
    const action = new URL(withTaskReturn('?selected=one&/save', detail), 'http://local/settings');
    const returned = new URL(taskReturnTo(action.searchParams.get('return_to')), 'http://local');
    const returnedList = new URL(returned.searchParams.get('list_return')!, 'http://local');
    expect(returnedList.searchParams.get('q')).toBe('客户');
    expect(returnedList.searchParams.get('cursor')).toBe('next');
    expect(returnedList.hash).toContain('mobile-');
  });
  it.each(['https://evil.test', '//evil.test', '/other/work-items?q=x'])('sanitizes unsafe nested list destinations: %s', list => {
    const returned = new URL(taskReturnTo(target + '?list_return=' + encodeURIComponent(list)), 'http://local');
    expect(returned.searchParams.get('list_return')).toBe('/019f0000-0000-7000-8000-000000000001/work-items');
  });
  it.each(['https://evil.test', '//evil.test', '/login', target + '?token=bad', target + '#bad'])('rejects unexpected target %s', value => expect(taskReturnTo(value)).toBe(''));
  it('preserves selected resources and named actions while carrying the task', () => {
    const next = new URL(withTaskReturn('?selected=one&/save', target), 'http://local/settings');
    expect(next.searchParams.get('selected')).toBe('one');
    expect(next.searchParams.has('/save')).toBe(true);
    expect(next.searchParams.get('return_to')).toBe(target);
  });
});

describe('studio return destinations', () => {
  const studio = '/019f0000-0000-7000-8000-000000000001/studio';
  const id = '019f0000-0000-7000-8000-000000000002';
  it('preserves the originating task and run across configuration', () => {
    const target = `${studio}?work_item=${id}&run=${id}`;
    const link = new URL(withTaskReturn('/organizations/example/settings/model-profiles', target), 'http://local');
    expect(taskReturnTo(link.searchParams.get('return_to'))).toBe(target);
    expect(taskReturnTo(studio)).toBe(studio);
    expect(taskReturnTo(`${studio}?workflow=${id}`)).toContain('workflow=');
  });
  it.each(['?run=bad', `?run=${id}`, '?return_to=//evil.test', '?token=secret', `?work_item=${id}&work_item=${id}`, `?workflow=${id}&work_item=${id}`, '#fragment'])('rejects unsafe or ambiguous conversation paths %s', suffix => {
    expect(taskReturnTo(studio + suffix)).toBe('');
  });
});

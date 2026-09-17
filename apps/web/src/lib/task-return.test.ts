import { describe, expect, it } from 'vitest';
import { taskReturnTo, withTaskReturn } from './task-return';
const target = '/019f0000-0000-7000-8000-000000000001/work-items/019f0000-0000-7000-8000-000000000002';
describe('task configuration return context', () => {
  it.each(['https://evil.test', '//evil.test', '/login', target + '?token=bad', target + '#bad'])('rejects unexpected target %s', value => expect(taskReturnTo(value)).toBe(''));
  it('preserves selected resources and named actions while carrying the task', () => {
    const next = new URL(withTaskReturn('?selected=one&/save', target), 'http://local/settings');
    expect(next.searchParams.get('selected')).toBe('one');
    expect(next.searchParams.has('/save')).toBe(true);
    expect(next.searchParams.get('return_to')).toBe(target);
  });
});

import { describe, expect, it } from 'vitest';
import { decodeStudioDraft, encodeStudioDraft, studioDraftKey, draftFields } from './studio-draft';
describe('studio draft recovery', () => {
  it('preserves editable fields and the original idempotency key', () => {
    const values = { intent: 'create', kind: 'work-item', title: '修改后的标题', description: '描述', request_id: 'stable-key' };
    expect(decodeStudioDraft(encodeStudioDraft(values, 100), 101)).toMatchObject(values);
  });
  it('isolates actors, workspaces, and threads', () => {
    expect(new Set([studioDraftKey('a','w','new'),studioDraftKey('b','w','new'),studioDraftKey('a','x','new'),studioDraftKey('a','w','task')]).size).toBe(4);
  });
  it('rejects malformed, expired, and future-dated data', () => {
    expect(decodeStudioDraft('invalid')).toBeNull();
    expect(decodeStudioDraft(encodeStudioDraft({intent:'draft'},0), 86400001)).toBeNull();
    expect(decodeStudioDraft(encodeStudioDraft({intent:'draft'},200), 100)).toBeNull();
    expect(decodeStudioDraft('{"expires":200,"values":{"intent":"create"}}',100)).toBeNull();
  });
  it('excludes unexpected fields from storage', () => {
    const form = new FormData(); form.set('intent','draft'); form.set('message','需求'); form.set('unexpected','excluded');
    const encoded = encodeStudioDraft(draftFields(form));
    expect(encoded).not.toContain('unexpected');
    expect(decodeStudioDraft(encoded)?.message).toBe('需求');
  });
});

it('retains discussion input across a version reload in the same tab', () => {
  const fields = new FormData();
  fields.set('intent', 'discuss'); fields.set('message', '尚未发送的讨论');
  expect(decodeStudioDraft(encodeStudioDraft(draftFields(fields)))?.message).toBe('尚未发送的讨论');
});

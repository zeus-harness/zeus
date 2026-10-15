/** Drafts stay in this browser tab, separated by authenticated actor and resource. */
const fields = ['intent', 'kind', 'message', 'title', 'description', 'work_item_id', 'workflow_id', 'run_id', 'request_id', 'proposal_id', 'allow_create', 'conversation_run_id'] as const;
const lifetime = 24 * 60 * 60 * 1000;
export function studioDraftKey(actor: string, workspace: string, resource: string): string {
  return `zeus:studio-draft:v1:${actor}:${workspace}:${resource}`;
}
export function draftFields(form: FormData): Record<string, string> {
  return Object.fromEntries(fields.map(key => [key, typeof form.get(key) === 'string' ? String(form.get(key)) : '']));
}
export function encodeStudioDraft(values: Record<string, string>, now = Date.now()): string {
  return JSON.stringify({ expires: now + lifetime, values: Object.fromEntries(fields.map(key => [key, values[key] ?? ''])) });
}
export function decodeStudioDraft(raw: string | null, now = Date.now()): Record<string, string> | null {
  try {
    if (!raw || raw.length > 500000) return null;
    const parsed = JSON.parse(raw);
    if (!Number.isFinite(parsed.expires) || parsed.expires < now || parsed.expires > now + lifetime || !parsed.values || typeof parsed.values !== 'object') return null;
    if (!['draft', 'create', 'send', 'discuss'].includes(parsed.values.intent)) return null;
    if (fields.some(key => typeof parsed.values[key] !== 'string' || parsed.values[key].length > 200000)) return null;
    return Object.fromEntries(fields.map(key => [key, parsed.values[key]]));
  } catch { return null; }
}

import type { components } from '$lib/api/generated/schema';
/** Only persisted tool-call/result pairs can become resource cards, never assistant prose. */
export function studioResources(events: components['schemas']['SessionEventResponse'][]) {
  const calls = new Set<string>();
  const resources = new Map<string, { id: string; kind: string; title: string; status: string; description: string; runId: string }>();
  for (const event of events) {
    const payload = event.payload as Record<string, unknown> | null;
    if (!payload || typeof payload !== 'object') continue;
    if (event.event_type === 'tool_call' && payload.registry_key === 'zeus.studio-resource-create' && typeof payload.tool_call_id === 'string') calls.add(payload.tool_call_id);
    const result = payload.result as Record<string, unknown> | null;
    if (event.event_type === 'tool_result' && payload.synthetic === false && typeof payload.tool_call_id === 'string' && calls.has(payload.tool_call_id)
      && result && result.id === payload.tool_call_id && typeof result.id === 'string' && /^[0-9a-f-]{36}$/iu.test(result.id)
      && typeof result.title === 'string' && ['work_item', 'workflow'].includes(String(result.kind)) && ['proposed', 'open', 'unpublished'].includes(String(result.status))) resources.set(result.id, { id: result.id, kind: String(result.kind), title: result.title, status: String(result.status), description: typeof result.description === 'string' ? result.description : '', runId: event.run_id ?? '' });
  }
  return [...resources.values()];
}

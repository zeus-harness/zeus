import { expect, it } from 'vitest';
import { studioResources } from './studio-resources';
import type { components } from '$lib/api/generated/schema';
it('retains prior resource cards across follow-up runs and ignores model-authored links', () => {
  const id = '019f0000-0000-7000-8000-000000000004';
  const events = [
    { event_type: 'assistant_message', payload: { result: { id, kind: 'workflow', title: 'fake' } } },
    { event_type: 'tool_call', payload: { registry_key: 'zeus.studio-resource-create', tool_call_id: id } },
    { event_type: 'tool_result', payload: { synthetic: false, tool_call_id: id, result: { id, kind: 'work_item', title: '真实任务', status: 'open' } } },
    { event_type: 'user_message', payload: { content: '继续聊聊' } }
  ] as components['schemas']['SessionEventResponse'][];
  expect(studioResources(events)).toMatchObject([{ id, kind: 'work_item', title: '真实任务', status: 'open' }]);
  expect(studioResources(events.slice(2))).toEqual([]);
});

it('keeps proposals distinct from persisted resources and rejects unrecognized states', () => {
  const id = '019f0000-0000-7000-8000-000000000004';
  const events = [
    { event_type: 'tool_call', payload: { registry_key: 'zeus.studio-resource-create', tool_call_id: id } },
    { run_id: id, event_type: 'tool_result', payload: { synthetic: false, tool_call_id: id, result: { id, kind: 'work_item', title: '预览', description: '待确认目标', status: 'proposed' } } }
  ] as components['schemas']['SessionEventResponse'][];
  expect(studioResources(events)).toEqual([{ id, kind: 'work_item', title: '预览', description: '待确认目标', status: 'proposed', runId: id }]);
  events[1].payload = { synthetic: false, tool_call_id: id, result: { id, kind: 'work_item', title: '假状态', status: 'completed' } };
  expect(studioResources(events)).toEqual([]);
});

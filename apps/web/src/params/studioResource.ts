import type { ParamMatcher } from '@sveltejs/kit';

export const match: ParamMatcher = (param) =>
  ['agents', 'workflows', 'schedules', 'webhooks'].includes(param);

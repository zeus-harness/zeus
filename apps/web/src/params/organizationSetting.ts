import type { ParamMatcher } from '@sveltejs/kit';

export const match: ParamMatcher = (param) =>
  ['members', 'workspaces', 'capabilities'].includes(param);

import type { ParamMatcher } from '@sveltejs/kit';

export const match: ParamMatcher = (param) =>
  ['members', 'workspaces', 'capabilities', 'connections', 'model-profiles'].includes(param);

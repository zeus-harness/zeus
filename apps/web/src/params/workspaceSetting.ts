import type { ParamMatcher } from '@sveltejs/kit';

export const match: ParamMatcher = (param) =>
  ['members', 'model-profiles', 'connections', 'capabilities', 'service-accounts'].includes(param);

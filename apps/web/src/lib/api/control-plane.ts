import type { components } from './generated/schema';
import { requestWorkspaceJson, type ApiFetcher, type WorkspaceRequestOptions } from './client';

export type Workflow = components['schemas']['WorkflowResponse'];
export type WorkflowPage = components['schemas']['WorkflowPageResponse'];

export function listWorkflows(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & { cursor?: string; limit?: number }
): Promise<WorkflowPage> {
  return requestWorkspaceJson<WorkflowPage>(fetcher, options, '/workflows', undefined, {
    cursor: options.cursor,
    limit: options.limit
  });
}

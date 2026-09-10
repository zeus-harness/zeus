import type { components } from './generated/schema';
import {
  jsonRequest,
  requestWorkspaceJson,
  type ApiFetcher,
  type WorkspaceRequestOptions
} from './client';

export type WorkItem = components['schemas']['WorkItemResponse'];
export type WorkItemPage = components['schemas']['WorkItemPageResponse'];
export type CreateWorkItemInput = components['schemas']['CreateWorkItemRequest'];
export type UpdateWorkItemInput = components['schemas']['UpdateWorkItemRequest'];
export type WorkItemExternalReference = components['schemas']['ExternalReferenceResponse'];
export type WorkItemAttachment = components['schemas']['AttachmentResponse'];

export function listWorkItems(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & {
    status?: string;
    assigneeUserId?: string;
    cursor?: string;
    limit?: number;
  }
): Promise<WorkItemPage> {
  return requestWorkspaceJson<WorkItemPage>(fetcher, options, '/work-items', undefined, {
    status: options.status,
    assignee_user_id: options.assigneeUserId,
    cursor: options.cursor,
    limit: options.limit
  });
}

export function createWorkItem(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  input: CreateWorkItemInput,
  idempotencyKey: string
): Promise<WorkItem> {
  return requestWorkspaceJson<WorkItem>(
    fetcher,
    options,
    '/work-items',
    jsonRequest('POST', input, { 'Idempotency-Key': idempotencyKey })
  );
}

export function getWorkItem(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string
): Promise<WorkItem> {
  return requestWorkspaceJson<WorkItem>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}`
  );
}

export function updateWorkItem(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string,
  revision: number,
  input: UpdateWorkItemInput
): Promise<WorkItem> {
  return requestWorkspaceJson<WorkItem>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}`,
    jsonRequest('PATCH', input, { 'If-Match': `"revision-${revision}"` })
  );
}

export function listWorkItemExternalReferences(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string
): Promise<WorkItemExternalReference[]> {
  return requestWorkspaceJson<WorkItemExternalReference[]>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}/external-references`
  );
}

export function listWorkItemAttachments(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  workItemId: string
): Promise<WorkItemAttachment[]> {
  return requestWorkspaceJson<WorkItemAttachment[]>(
    fetcher,
    options,
    `/work-items/${encodeURIComponent(workItemId)}/attachments`
  );
}

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
    q?: string;
    status?: string;
    assigneeUserId?: string;
    createdBy?: string;
    unassigned?: boolean;
    cursor?: string;
    limit?: number;
  }
): Promise<WorkItemPage> {
  return requestWorkspaceJson<WorkItemPage>(fetcher, options, '/work-items', undefined, {
    q: options.q,
    status: options.status,
    assignee_user_id: options.assigneeUserId,
    created_by: options.createdBy,
    unassigned: options.unassigned,
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

export type WorkItemReview = components['schemas']['WorkItemReviewResponse'];
export type WorkItemReviewPage = components['schemas']['WorkItemReviewPageResponse'];

export function listWorkItemReviews(fetcher: ApiFetcher, options: WorkspaceRequestOptions, workItemId: string, cursor?: string): Promise<WorkItemReviewPage> {
  return requestWorkspaceJson(fetcher, options, `/work-items/${encodeURIComponent(workItemId)}/reviews`, undefined, { limit: 50, cursor });
}

export function createWorkItemReview(fetcher: ApiFetcher, options: WorkspaceRequestOptions, workItemId: string, revision: number, input: components['schemas']['CreateWorkItemReviewRequest']): Promise<WorkItemReview> {
  return requestWorkspaceJson(fetcher, options, `/work-items/${encodeURIComponent(workItemId)}/reviews`,
    jsonRequest('POST', input, { 'If-Match': `"revision-${revision}"` }));
}

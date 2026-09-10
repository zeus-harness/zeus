import type { components } from './generated/schema';
import {
  jsonRequest,
  requestWorkspaceJson,
  type ApiFetcher,
  type WorkspaceRequestOptions
} from './client';

export type ExperienceCandidate = components['schemas']['ExperienceCandidateResponse'];
export type ExperienceCandidatePage = components['schemas']['ExperienceCandidatePageResponse'];
export type ExperienceEvidenceRef = components['schemas']['ExperienceEvidenceRef'];
export type ExperienceEntry = components['schemas']['ExperienceEntryResponse'];
export type ExperienceEntryPage = components['schemas']['ExperienceEntryPageResponse'];
export type ExperienceSearchResult = components['schemas']['ExperienceSearchResult'];
export type CreateExperienceCandidateInput =
  components['schemas']['CreateExperienceCandidateRequest'];

export function listExperienceCandidates(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & { status?: string; cursor?: string; limit?: number }
): Promise<ExperienceCandidatePage> {
  return requestWorkspaceJson<ExperienceCandidatePage>(
    fetcher,
    options,
    '/experience-candidates',
    undefined,
    { status: options.status, cursor: options.cursor, limit: options.limit }
  );
}

export function createExperienceCandidate(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  input: CreateExperienceCandidateInput
): Promise<ExperienceCandidate> {
  return requestWorkspaceJson<ExperienceCandidate>(
    fetcher,
    options,
    '/experience-candidates',
    jsonRequest('POST', input)
  );
}

export function reviewExperienceCandidate(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  candidateId: string,
  decision: 'approved' | 'rejected',
  reason?: string | null
): Promise<ExperienceCandidate> {
  return requestWorkspaceJson<ExperienceCandidate>(
    fetcher,
    options,
    `/experience-candidates/${encodeURIComponent(candidateId)}/review`,
    jsonRequest('POST', { decision, reason: reason?.trim() || null })
  );
}

export function publishExperienceCandidate(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  candidateId: string
): Promise<ExperienceEntry> {
  return requestWorkspaceJson<ExperienceEntry>(
    fetcher,
    options,
    `/experience-candidates/${encodeURIComponent(candidateId)}/publish`,
    jsonRequest('POST', {})
  );
}

export function listExperienceEntries(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & {
    scope?: string;
    includeWithdrawn?: boolean;
    cursor?: string;
    limit?: number;
  }
): Promise<ExperienceEntryPage> {
  return requestWorkspaceJson<ExperienceEntryPage>(
    fetcher,
    options,
    '/experience-entries',
    undefined,
    {
      scope: options.scope,
      include_withdrawn: options.includeWithdrawn,
      cursor: options.cursor,
      limit: options.limit
    }
  );
}

export function getExperienceEntry(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  entryId: string
): Promise<ExperienceEntry> {
  return requestWorkspaceJson<ExperienceEntry>(
    fetcher,
    options,
    `/experience-entries/${encodeURIComponent(entryId)}`
  );
}

export function withdrawExperienceEntry(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions,
  entryId: string,
  reason: string
): Promise<void> {
  return requestWorkspaceJson<void>(
    fetcher,
    options,
    `/experience-entries/${encodeURIComponent(entryId)}/withdraw`,
    jsonRequest('POST', { reason })
  );
}

export function searchExperienceEntries(
  fetcher: ApiFetcher,
  options: WorkspaceRequestOptions & {
    q: string;
    scope?: string;
    tags?: string;
    limit?: number;
  }
): Promise<ExperienceSearchResult[]> {
  return requestWorkspaceJson<ExperienceSearchResult[]>(
    fetcher,
    options,
    '/experience-entries/search',
    undefined,
    {
      q: options.q,
      scope: options.scope,
      tags: options.tags,
      limit: options.limit ?? 20
    }
  );
}

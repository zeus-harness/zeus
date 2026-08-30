import { fail, redirect } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';

import {
  createExperienceCandidate,
  listExperienceCandidates,
  listExperienceEntries,
  loadWorkspaceData,
  publishExperienceCandidate,
  reviewExperienceCandidate,
  searchExperienceEntries,
  withdrawExperienceEntry,
  type CreateExperienceCandidateInput,
  type ExperienceEvidenceRef
} from '$lib/api/workspace';
import { loadCurrentPrincipal, serverApiFetcher } from '$lib/api/server';

function formValue(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

function actionError(status: number, message: string) {
  return fail(status, { type: 'error' as const, message });
}

function parseEvidence(value: string): ExperienceEvidenceRef[] {
  const parsed: unknown = JSON.parse(value || '[]');
  if (!Array.isArray(parsed)) {
    throw new Error('Evidence 必须是 JSON 数组。');
  }
  return parsed.map((entry) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new Error('Evidence 的每一项必须是对象。');
    }
    const record = entry as Record<string, unknown>;
    const eventKind = typeof record.event_kind === 'string' ? record.event_kind.trim() : '';
    const eventId = typeof record.event_id === 'string' ? record.event_id.trim() : '';
    if (!eventKind || !eventId) {
      throw new Error('Evidence 每一项都需要 event_kind 和 event_id。');
    }
    return { event_kind: eventKind, event_id: eventId };
  });
}

function actionWorkspace(event: Parameters<NonNullable<Actions['create']>>[0]) {
  const apiFetch = serverApiFetcher(
    event.fetch,
    event.request.headers.get('cookie'),
    event.url.origin
  );
  return loadCurrentPrincipal(apiFetch, env.ZEUS_API_URL).then((auth) => {
    if (auth.status === 'unauthenticated') {
      return { apiFetch, error: actionError(401, '当前会话未登录，请先登录 Zeus。') };
    }
    if (auth.status !== 'ready') {
      return { apiFetch, error: actionError(503, '无法确认当前登录状态，认证 API 暂不可用。') };
    }
    const workspaceId = auth.principal?.workspace_id;
    if (!workspaceId) {
      return { apiFetch, error: actionError(400, '当前会话未选择 Workspace，无法修改 Experience。') };
    }
    return { apiFetch, workspaceId };
  });
}

export const load: PageServerLoad = async ({ fetch, parent, request, url }) => {
  const { principal, status: authStatus } = await parent();
  const apiFetch = serverApiFetcher(fetch, request.headers.get('cookie'), url.origin);
  const workspaceContext = {
    authStatus,
    workspaceId: principal?.workspace_id
  };
  const candidateStatus = url.searchParams.get('candidate_status') || undefined;
  const scope = url.searchParams.get('scope') || undefined;
  const tags = url.searchParams.get('tags') || undefined;
  const query = url.searchParams.get('q')?.trim() ?? '';
  const includeWithdrawn = ['1', 'true', 'on'].includes(url.searchParams.get('include_withdrawn') ?? '');

  const [candidates, entries, searchResults] = await Promise.all([
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listExperienceCandidates(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        status: candidateStatus,
        limit: 50
      })
    ),
    loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
      listExperienceEntries(workspaceFetch, {
        apiBaseUrl: env.ZEUS_API_URL,
        workspaceId,
        scope,
        includeWithdrawn,
        limit: 50
      })
    ),
    query
      ? loadWorkspaceData(apiFetch, workspaceContext, (workspaceFetch, workspaceId) =>
          searchExperienceEntries(workspaceFetch, {
            apiBaseUrl: env.ZEUS_API_URL,
            workspaceId,
            q: query,
            scope,
            tags,
            limit: 20
          })
        )
      : Promise.resolve(null)
  ]);

  return {
    candidates,
    entries,
    searchResults,
    searchMode: Boolean(query),
    query,
    candidateStatus: candidateStatus ?? '',
    scope: scope ?? '',
    tags: tags ?? '',
    includeWithdrawn,
    workspaceId: principal?.workspace_id ?? null
  };
};

export const actions: Actions = {
  create: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;

    const formData = await event.request.formData();
    const sourceRunId = formValue(formData, 'source_run_id');
    const proposedScope = formValue(formData, 'proposed_scope');
    const title = formValue(formData, 'title');
    const content = formValue(formData, 'content');
    if (!sourceRunId || !proposedScope || !title || !content) {
      return actionError(400, 'Source Run、Scope、标题和内容不能为空。');
    }

    let evidence: ExperienceEvidenceRef[];
    try {
      evidence = parseEvidence(formValue(formData, 'evidence'));
    } catch (error) {
      return actionError(400, error instanceof Error ? error.message : 'Evidence JSON 无效。');
    }

    const payload: CreateExperienceCandidateInput = {
      source_run_id: sourceRunId,
      proposed_scope: proposedScope,
      title,
      content,
      tags: formValue(formData, 'tags')
        .split(',')
        .map((tag) => tag.trim())
        .filter(Boolean),
      evidence
    };

    try {
      await createExperienceCandidate(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        payload
      );
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'Experience candidate 创建失败。');
    }
    redirect(303, '/experience');
  },

  review: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;

    const formData = await event.request.formData();
    const candidateId = formValue(formData, 'candidate_id');
    const decision = formValue(formData, 'decision');
    const reason = formValue(formData, 'reason') || null;
    if (!candidateId || (decision !== 'approved' && decision !== 'rejected')) {
      return actionError(400, 'Candidate 审阅参数无效。');
    }

    try {
      await reviewExperienceCandidate(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        candidateId,
        decision,
        reason
      );
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'Candidate 审阅失败。');
    }
    redirect(303, '/experience');
  },

  publish: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;

    const candidateId = formValue(await event.request.formData(), 'candidate_id');
    if (!candidateId) return actionError(400, 'Candidate ID 不能为空。');

    try {
      await publishExperienceCandidate(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        candidateId
      );
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'Experience 发布失败。');
    }
    redirect(303, '/experience');
  },

  withdraw: async (event) => {
    const context = await actionWorkspace(event);
    if (context.error) return context.error;

    const formData = await event.request.formData();
    const entryId = formValue(formData, 'entry_id');
    const reason = formValue(formData, 'reason');
    if (!entryId || !reason) return actionError(400, 'Entry ID 和撤回理由不能为空。');

    try {
      await withdrawExperienceEntry(
        context.apiFetch,
        { apiBaseUrl: env.ZEUS_API_URL, workspaceId: context.workspaceId },
        entryId,
        reason
      );
    } catch (error) {
      return actionError(502, error instanceof Error ? error.message : 'Experience 撤回失败。');
    }
    redirect(303, '/experience?include_withdrawn=true');
  }
};

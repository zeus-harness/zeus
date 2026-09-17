import { requestWorkspaceJson, ZeusApiError, type ApiFetcher, type WorkspaceRequestOptions } from '$lib/api/client';

type Resource = { archived_at?: string | null; active_version_id?: string | null };
export type Readiness = 'configured' | 'missing' | 'unavailable';

// A bounded first page can prove presence, never absence beyond an unread cursor.
export async function loadOnboarding(fetcher: ApiFetcher, options: WorkspaceRequestOptions) {
  async function inspect(path: string, published = false): Promise<Readiness> {
    try {
      const page = await requestWorkspaceJson<{ items: Resource[]; next_cursor?: string | null }>(fetcher, options, path, undefined, { limit: 100 });
      if (page.items.some(item => !item.archived_at && (!published || item.active_version_id))) return 'configured';
      return page.next_cursor ? 'unavailable' : 'missing';
    } catch (error) {
      // Permission or service errors must not be presented as unconfigured resources.
      if (error instanceof ZeusApiError) return 'unavailable';
      return 'unavailable';
    }
  }
  const [model, agent, workflow] = await Promise.all([
    inspect('/model-profiles'), inspect('/agents', true), inspect('/workflows', true)
  ]);
  return { model, agent, workflow };
}

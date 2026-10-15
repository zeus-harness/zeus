import { getWorkItem, listWorkItemReviews } from '$lib/api/work-items';
import type { ApiFetcher, WorkspaceRequestOptions } from '$lib/api/client';
import type { Run } from '$lib/api/runs';

export async function runSummaries(fetcher: ApiFetcher, options: WorkspaceRequestOptions, runs: Run[]) {
  const entries = await Promise.all([...new Set(runs.map(run => run.work_item_id).filter((id): id is string => !!id))].map(async id => {
    try {
      const [item, reviews] = await Promise.all([getWorkItem(fetcher, options, id), listWorkItemReviews(fetcher, options, id)]);
      return [id, { title: item.title, reviews: reviews.items }] as const;
    } catch { return [id, { title: '工作项暂不可读取', reviews: [] as Awaited<ReturnType<typeof listWorkItemReviews>>['items'] }] as const; }
  }));
  const items = new Map(entries);
  return Object.fromEntries(runs.map(run => {
    const item = items.get(run.work_item_id ?? '');
    const review = item?.reviews.find(review => review.run_id === run.id);
    return [run.id, { title: item?.title ?? '需求讨论', review: review?.decision ?? null }];
  }));
}

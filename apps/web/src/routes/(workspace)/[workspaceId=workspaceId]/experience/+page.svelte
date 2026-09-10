<script lang="ts">
  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';
  import * as Card from '@zeus/ui/components/ui/card';
  import { Input } from '@zeus/ui/components/ui/input';
  import { NativeSelect, NativeSelectOption } from '@zeus/ui/components/ui/native-select';
  import { Separator } from '@zeus/ui/components/ui/separator';
  import * as Table from '@zeus/ui/components/ui/table';
  import { Textarea } from '@zeus/ui/components/ui/textarea';

  import WorkspaceStatus from '$lib/components/WorkspaceStatus.svelte';

  import type { ActionData, PageData } from './$types';

  let { data, form } = $props<{ data: PageData; form: ActionData }>();
  let candidates = $derived(data.candidates.data?.items ?? []);
  let entries = $derived(data.entries.data?.items ?? []);
  let workspaceBase = $derived(`/${data.workspaceId}`);
  let searchResults = $derived(data.searchResults?.data ?? []);

  function dateLabel(value: string | null): string {
    return value ? value.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ' UTC') : '—';
  }

  function formatJson(value: unknown): string {
    try {
      return JSON.stringify(value, null, 2) ?? '—';
    } catch {
      return '—';
    }
  }

  function statusVariant(status: string): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (status === 'approved' || status === 'published') return 'secondary';
    if (status === 'rejected' || status === 'withdrawn') return 'destructive';
    if (status === 'pending') return 'default';
    return 'outline';
  }
</script>

<svelte:head>
  <title>Zeus · Experience</title>
</svelte:head>

<main class="mx-auto max-w-[1480px] px-5 py-8 lg:px-8 lg:py-10">
  <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
    <div>
      <p class="text-sm font-medium text-muted-foreground">Reviewed team knowledge</p>
      <h1 class="mt-2 text-3xl font-semibold tracking-tight">Experience</h1>
      <p class="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
        Candidate 必须从已成功的 Run 提出并经过审阅，发布后才能被运行时检索；搜索使用服务端的 PostgreSQL FTS 端点。
      </p>
    </div>
    <div class="flex gap-2">
      {#if data.candidates.status === 'ready'}<Badge variant="secondary">{candidates.length} candidates</Badge>{/if}
      {#if data.entries.status === 'ready'}<Badge variant="secondary">{entries.length} entries</Badge>{/if}
    </div>
  </div>

  {#if form?.type === 'error'}
    <div class="mt-6 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive" role="alert">
      {form.message}
    </div>
  {/if}

  <div class="mt-8 grid gap-6 xl:grid-cols-[22rem_minmax(0,1fr)]">
    <Card.Root>
      <Card.Header>
        <Card.Title>创建 Experience candidate</Card.Title>
        <Card.Description>需要 Source Run ID 和至少一条可验证 evidence。</Card.Description>
      </Card.Header>
      <Card.Content>
        <form method="POST" action="?/create" class="space-y-4">
          <div>
            <label class="text-sm font-medium" for="source_run_id">Source Run ID</label>
            <Input id="source_run_id" name="source_run_id" required class="mt-2 font-mono text-xs" />
          </div>
          <div>
            <label class="text-sm font-medium" for="proposed_scope">发布范围</label>
            <NativeSelect id="proposed_scope" name="proposed_scope" value="workspace" class="mt-2 w-full">
              <NativeSelectOption value="workspace">Workspace</NativeSelectOption>
              <NativeSelectOption value="organization">Organization</NativeSelectOption>
            </NativeSelect>
          </div>
          <div>
            <label class="text-sm font-medium" for="title">标题</label>
            <Input id="title" name="title" required class="mt-2" />
          </div>
          <div>
            <label class="text-sm font-medium" for="content">内容</label>
            <Textarea id="content" name="content" required rows={5} class="mt-2" />
          </div>
          <div>
            <label class="text-sm font-medium" for="tags">Tags</label>
            <Input id="tags" name="tags" placeholder="逗号分隔，可选" class="mt-2" />
          </div>
          <div>
            <label class="text-sm font-medium" for="evidence">Evidence JSON</label>
            <Textarea id="evidence" name="evidence" required rows={5} class="mt-2 font-mono text-xs" placeholder="JSON 数组：每项包含 event_kind 和 event_id" value="[]" />
            <p class="mt-2 text-xs leading-5 text-muted-foreground">event_id 必须属于 Source Run，API 会再次校验。</p>
          </div>
          <Button type="submit" class="w-full">提交 candidate</Button>
        </form>
      </Card.Content>
    </Card.Root>

    <div class="space-y-6">
      <Card.Root>
        <Card.Header>
          <Card.Title>Candidates</Card.Title>
          <Card.Description>Pending candidate 可批准或拒绝；批准后可发布。</Card.Description>
        </Card.Header>
        <Card.Content>
          {#if data.candidates.status !== 'ready'}
            <WorkspaceStatus status={data.candidates.status} message={data.candidates.message} httpStatus={data.candidates.httpStatus} title="Candidates" />
          {:else if candidates.length === 0}
            <div class="rounded-lg border border-dashed border-border px-5 py-10 text-center text-sm text-muted-foreground">当前没有 Candidate。</div>
          {:else}
            <div class="space-y-3">
              {#each candidates as candidate (candidate.id)}
                <article class="rounded-xl border border-border p-4">
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div class="min-w-0">
                      <h2 class="font-semibold">{candidate.title}</h2>
                      <p class="mt-1 break-all font-mono text-xs text-muted-foreground">{candidate.id}</p>
                    </div>
                    <Badge variant={statusVariant(candidate.status)}>{candidate.status}</Badge>
                  </div>
                  <p class="mt-3 whitespace-pre-wrap text-sm leading-6">{candidate.content}</p>
                  <div class="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <a class="font-mono hover:underline" href={`${workspaceBase}/runs/${candidate.source_run_id}`}>Source Run {candidate.source_run_id}</a>
                    <span>scope: {candidate.proposed_scope}</span>
                    <span>{dateLabel(candidate.created_at)}</span>
                  </div>
                  {#if candidate.tags.length > 0}
                    <div class="mt-3 flex flex-wrap gap-1">{#each candidate.tags as tag (tag)}<Badge variant="outline">{tag}</Badge>{/each}</div>
                  {/if}
                  <details class="mt-3 rounded-lg bg-muted p-3">
                    <summary class="cursor-pointer text-xs font-medium">Evidence / review details</summary>
                    <pre class="mt-2 max-h-48 overflow-auto font-mono text-xs leading-5">{formatJson(candidate.evidence)}</pre>
                    {#if candidate.review_reason}<p class="mt-2 text-xs text-muted-foreground">Review reason: {candidate.review_reason}</p>{/if}
                  </details>
                  {#if candidate.status === 'pending'}
                    <form method="POST" action="?/review" class="mt-4 flex flex-col gap-2 sm:flex-row">
                      <input type="hidden" name="candidate_id" value={candidate.id} />
                      <Input name="reason" placeholder="审阅理由（可选）" class="min-w-0 flex-1" />
                      <Button type="submit" name="decision" value="approved" size="sm">批准</Button>
                      <Button type="submit" name="decision" value="rejected" variant="destructive" size="sm">拒绝</Button>
                    </form>
                  {:else if candidate.status === 'approved'}
                    <form method="POST" action="?/publish" class="mt-4">
                      <input type="hidden" name="candidate_id" value={candidate.id} />
                      <Button type="submit" variant="outline" size="sm">发布为 Experience entry</Button>
                    </form>
                  {/if}
                </article>
              {/each}
            </div>
          {/if}
        </Card.Content>
      </Card.Root>

      <Card.Root>
        <Card.Header>
          <Card.Title>Entries & FTS search</Card.Title>
          <Card.Description>列表读取已发布条目；输入 q 会调用 experience-entries/search。</Card.Description>
        </Card.Header>
        <Card.Content>
          <form method="GET" class="mb-6 grid gap-3 rounded-lg border border-border p-4 md:grid-cols-[minmax(0,1fr)_10rem_auto] md:items-end">
            <div>
              <label class="text-sm font-medium" for="q">搜索</label>
              <Input id="q" name="q" value={data.query} placeholder="搜索标题、内容或 tags" class="mt-2" />
            </div>
            <div>
              <label class="text-sm font-medium" for="scope">Scope</label>
              <NativeSelect id="scope" name="scope" value={data.scope} class="mt-2 w-full">
                <NativeSelectOption value="">全部</NativeSelectOption>
                <NativeSelectOption value="workspace">Workspace</NativeSelectOption>
                <NativeSelectOption value="organization">Organization</NativeSelectOption>
              </NativeSelect>
            </div>
            <div class="flex items-center gap-3 md:justify-end">
              <label class="flex items-center gap-2 text-xs text-muted-foreground">
                <input type="checkbox" name="include_withdrawn" value="true" checked={data.includeWithdrawn} />
                包含撤回
              </label>
              <Button type="submit" variant="outline" size="sm">搜索</Button>
            </div>
          </form>

          {#if data.entries.status !== 'ready'}
            <WorkspaceStatus status={data.entries.status} message={data.entries.message} httpStatus={data.entries.httpStatus} title="Experience entries" />
          {:else if data.searchMode}
            {#if data.searchResults?.status !== 'ready'}
              <WorkspaceStatus status={data.searchResults?.status ?? 'error'} message={data.searchResults?.message ?? '搜索未执行。'} httpStatus={data.searchResults?.httpStatus} title="FTS search" />
            {:else if searchResults.length === 0}
              <div class="rounded-lg border border-dashed border-border px-5 py-10 text-center text-sm text-muted-foreground">没有匹配的 Experience。</div>
            {:else}
              <div class="space-y-3">
                {#each searchResults as result (result.id)}
                  <article class="rounded-lg border border-border p-4">
                    <div class="flex flex-wrap items-start justify-between gap-3">
                      <h2 class="font-medium">{result.title}</h2>
                      <Badge variant="outline">rank {result.rank.toFixed(4)}</Badge>
                    </div>
                    <p class="mt-2 whitespace-pre-wrap text-sm leading-6">{result.content}</p>
                    <div class="mt-3 flex flex-wrap gap-3 text-xs text-muted-foreground"><span>{result.scope} · v{result.version_number}</span><span>{dateLabel(result.published_at)}</span><span class="font-mono">{result.id}</span></div>
                  </article>
                {/each}
              </div>
            {/if}
          {:else if entries.length === 0}
            <div class="rounded-lg border border-dashed border-border px-5 py-10 text-center text-sm text-muted-foreground">当前没有 Experience entry。</div>
          {:else}
            <div class="space-y-3">
              {#each entries as entry (entry.id)}
                <article class="rounded-xl border border-border p-4">
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 class="font-semibold">{entry.title}</h2>
                      <p class="mt-1 break-all font-mono text-xs text-muted-foreground">{entry.id} · v{entry.version_number}</p>
                    </div>
                    <Badge variant={entry.withdrawn_at ? 'destructive' : 'secondary'}>{entry.withdrawn_at ? 'withdrawn' : entry.scope}</Badge>
                  </div>
                  <p class="mt-3 whitespace-pre-wrap text-sm leading-6">{entry.content}</p>
                  <div class="mt-3 flex flex-wrap gap-3 text-xs text-muted-foreground"><span>published {dateLabel(entry.published_at)}</span><span>source <a class="font-mono hover:underline" href={`${workspaceBase}/runs/${entry.source_run_id}`}>{entry.source_run_id}</a></span></div>
                  {#if entry.tags.length > 0}<div class="mt-3 flex flex-wrap gap-1">{#each entry.tags as tag (tag)}<Badge variant="outline">{tag}</Badge>{/each}</div>{/if}
                  {#if entry.withdrawn_at}
                    <p class="mt-3 text-xs text-destructive">撤回于 {dateLabel(entry.withdrawn_at)}：{entry.withdrawal_reason ?? '—'}</p>
                  {:else}
                    <form method="POST" action="?/withdraw" class="mt-4 flex flex-col gap-2 sm:flex-row">
                      <input type="hidden" name="entry_id" value={entry.id} />
                      <Input name="reason" required placeholder="撤回理由" class="min-w-0 flex-1" />
                      <Button type="submit" variant="destructive" size="sm">撤回</Button>
                    </form>
                  {/if}
                </article>
              {/each}
            </div>
          {/if}
        </Card.Content>
      </Card.Root>
    </div>
  </div>
</main>

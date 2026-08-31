<script lang="ts">
  import { onMount } from 'svelte';
  import { CircleCheck, CircleX, Clock3, RefreshCw, ShieldCheck, Wrench } from '@lucide/svelte';

  import { Badge } from '@zeus/ui/components/ui/badge';
  import { Button } from '@zeus/ui/components/ui/button';

  import type { RunEvent } from '$lib/api/runs';
  import { TERMINAL_RUN_STATES } from '$lib/api/runs';
  import {
    getTerminalRunStatus,
    mergeRunEvents,
    parseRunEvent,
    RunEventSseParser
  } from './run-stream';

  type ConnectionState = 'connecting' | 'connected' | 'retrying' | 'disconnected' | 'finished' | 'unavailable';

  let {
    initialEvents,
    initialStatus,
    streamUrl
  }: {
    initialEvents: RunEvent[];
    initialStatus: string;
    streamUrl: string | null;
  } = $props();

  let streamedEvents = $state<RunEvent[]>([]);
  let connectionState = $state<ConnectionState>('connecting');
  let connectionMessage = $state('正在连接事件流。');
  let liveRunStatus = $state<string | null>(null);
  let activeController: AbortController | null = null;

  let events = $derived(mergeRunEvents(initialEvents, streamedEvents));
  let currentRunStatus = $derived(liveRunStatus ?? initialStatus);
  let lastSequence = $derived(events.at(-1)?.sequence ?? 0);

  function dateLabel(value: string): string {
    return new Intl.DateTimeFormat('zh-CN', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).format(new Date(value));
  }

  function formatJson(value: unknown): string {
    try {
      return JSON.stringify(value, null, 2) ?? '—';
    } catch {
      return '—';
    }
  }

  function eventLabel(event: RunEvent): string {
    const kind = event.event_type.toLowerCase();
    if (kind.includes('approval')) return '人工审批';
    if (kind.includes('tool')) return '工具调用';
    if (kind.includes('child')) return 'Child Run';
    if (kind.includes('model') || kind.includes('assistant')) return '模型响应';
    if (kind.includes('cancel')) return '取消运行';
    if (kind.includes('fail')) return '运行失败';
    if (kind.includes('succeed') || kind.includes('complete')) return '运行完成';
    if (kind.includes('queued')) return '进入队列';
    if (kind.includes('start') || kind.includes('running')) return '开始执行';
    return event.event_type;
  }

  function eventSummary(event: RunEvent): string | null {
    if (typeof event.payload !== 'object' || event.payload === null || Array.isArray(event.payload)) {
      return null;
    }
    const payload = event.payload as Record<string, unknown>;
    for (const key of ['status', 'message', 'reason', 'error_code', 'capability_name']) {
      const value = payload[key];
      if (typeof value === 'string' && value.trim()) return value;
    }
    return null;
  }

  function eventIcon(event: RunEvent) {
    const kind = event.event_type.toLowerCase();
    if (kind.includes('approval')) return ShieldCheck;
    if (kind.includes('tool')) return Wrench;
    if (kind.includes('fail') || kind.includes('cancel')) return CircleX;
    if (kind.includes('succeed') || kind.includes('complete')) return CircleCheck;
    return Clock3;
  }

  function connectionLabel(): string {
    switch (connectionState) {
      case 'connected':
        return '实时';
      case 'retrying':
        return '重连中';
      case 'finished':
        return '已结束';
      case 'unavailable':
        return '不可用';
      case 'disconnected':
        return '已断线';
      default:
        return '连接中';
    }
  }

  function listEventsUrl(after: number): string | null {
    if (!streamUrl || !streamUrl.endsWith('/stream')) return null;
    const url = new URL(streamUrl.slice(0, -'/stream'.length), window.location.origin);
    url.searchParams.set('after', String(after));
    url.searchParams.set('limit', '500');
    return url.toString();
  }

  async function recoverGap(after: number, expectedSequence: number, signal: AbortSignal): Promise<void> {
    const url = listEventsUrl(after);
    if (!url) throw new Error('无法构造事件恢复地址。');
    const response = await fetch(url, {
      headers: { accept: 'application/json' },
      credentials: 'same-origin',
      signal
    });
    if (!response.ok) throw new Error(`事件恢复失败（HTTP ${response.status}）。`);
    const payload: unknown = await response.json();
    if (!Array.isArray(payload)) throw new Error('事件恢复接口返回格式无效。');
    const recovered = payload
      .map((candidate) => parseRunEvent(JSON.stringify(candidate)))
      .filter((candidate): candidate is RunEvent => candidate !== null);
    const merged = mergeRunEvents(mergeRunEvents(initialEvents, streamedEvents), recovered);
    const recoveredSequence = merged.at(-1)?.sequence ?? after;
    if (recoveredSequence + 1 < expectedSequence) {
      throw new Error(`事件序号缺口尚未恢复，当前到 #${recoveredSequence}。`);
    }
    streamedEvents = mergeRunEvents(streamedEvents, recovered);
  }

  async function waitBeforeRetry(milliseconds: number, signal: AbortSignal): Promise<void> {
    await new Promise<void>((resolve) => {
      const timeout = window.setTimeout(resolve, milliseconds);
      signal.addEventListener(
        'abort',
        () => {
          window.clearTimeout(timeout);
          resolve();
        },
        { once: true }
      );
    });
  }

  async function consumeStream(controller: AbortController): Promise<void> {
    if (!streamUrl) {
      connectionState = 'unavailable';
      connectionMessage = '当前页面没有可用的事件流地址。';
      return;
    }
    if (TERMINAL_RUN_STATES.has(initialStatus)) {
      connectionState = 'finished';
      connectionMessage = 'Run 已处于终态，事件快照保持可读。';
      return;
    }

    const delays = [1_000, 2_000, 5_000, 10_000, 10_000];
    for (let attempt = 0; attempt <= delays.length && !controller.signal.aborted; attempt += 1) {
      try {
        connectionState = attempt === 0 ? 'connecting' : 'retrying';
        connectionMessage = attempt === 0 ? '正在连接事件流。' : `正在进行第 ${attempt} 次重连。`;
        const headers = new Headers({ accept: 'text/event-stream' });
        const resumeAfter = mergeRunEvents(initialEvents, streamedEvents).at(-1)?.sequence ?? 0;
        if (resumeAfter > 0) headers.set('Last-Event-ID', String(resumeAfter));
        const response = await fetch(streamUrl, {
          headers,
          credentials: 'same-origin',
          cache: 'no-store',
          signal: controller.signal
        });
        if (!response.ok || !response.body) {
          throw new Error(`事件流连接失败（HTTP ${response.status}）。`);
        }

        connectionState = 'connected';
        connectionMessage = `事件流已连接，当前到 #${resumeAfter}。`;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        const parser = new RunEventSseParser();

        while (!controller.signal.aborted) {
          const { value, done } = await reader.read();
          const incoming = done
            ? parser.finish()
            : parser.push(decoder.decode(value, { stream: true }));
          for (const event of incoming) {
            const previous = mergeRunEvents(initialEvents, streamedEvents).at(-1)?.sequence ?? 0;
            if (previous > 0 && event.sequence > previous + 1) {
              connectionState = 'retrying';
              connectionMessage = `检测到 #${previous} 到 #${event.sequence} 的缺口，正在恢复。`;
              await recoverGap(previous, event.sequence, controller.signal);
            }
            streamedEvents = mergeRunEvents(streamedEvents, [event]);
            const terminalStatus = getTerminalRunStatus(event);
            if (terminalStatus) {
              liveRunStatus = terminalStatus;
              connectionState = 'finished';
              connectionMessage = `Run 已进入终态 ${terminalStatus}，事件流已关闭。`;
              await reader.cancel();
              return;
            }
          }
          if (done) throw new Error('事件流已关闭。');
        }
        return;
      } catch (error) {
        if (controller.signal.aborted) return;
        if (attempt === delays.length) {
          connectionState = 'disconnected';
          connectionMessage = error instanceof Error ? error.message : '事件流连接已断开。';
          return;
        }
        connectionState = 'retrying';
        connectionMessage = error instanceof Error ? error.message : '事件流连接已断开，准备重连。';
        await waitBeforeRetry(delays[attempt], controller.signal);
      }
    }
  }

  function reconnect(): void {
    activeController?.abort();
    const controller = new AbortController();
    activeController = controller;
    void consumeStream(controller);
  }

  onMount(() => {
    reconnect();
    return () => activeController?.abort();
  });
</script>

<div class="space-y-4">
  <div class="flex flex-wrap items-center justify-between gap-3" aria-live="polite">
    <div>
      <p class="text-sm font-medium">{events.length} 条持久事件</p>
      <p class="mt-1 text-xs text-muted-foreground">{connectionMessage}</p>
    </div>
    <div class="flex items-center gap-2">
      <Badge variant={connectionState === 'disconnected' ? 'destructive' : 'outline'}>{connectionLabel()}</Badge>
      <Badge variant="secondary">{currentRunStatus}</Badge>
      {#if connectionState === 'disconnected'}
        <Button type="button" variant="outline" size="sm" onclick={reconnect}><RefreshCw class="size-4" />重新连接</Button>
      {/if}
    </div>
  </div>

  {#if events.length === 0}
    <div class="rounded-lg border border-dashed border-border p-6 text-center text-sm text-muted-foreground">Run 已创建，正在等待第一条事件。</div>
  {:else}
    <ol class="relative ml-3 border-l border-border pl-6">
      {#each events as event (event.sequence)}
        {@const Icon = eventIcon(event)}
        <li class="relative pb-6 last:pb-0">
          <span class="absolute -left-[2.35rem] grid size-7 place-items-center rounded-full border border-border bg-background"><Icon class="size-3.5" /></span>
          <div class="rounded-lg border border-border p-4">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="text-sm font-medium">{eventLabel(event)}</p>
                <p class="mt-1 text-xs text-muted-foreground">#{event.sequence} · {event.event_type}</p>
              </div>
              <time class="text-xs text-muted-foreground" datetime={event.occurred_at}>{dateLabel(event.occurred_at)}</time>
            </div>
            {#if eventSummary(event)}<p class="mt-3 text-sm text-muted-foreground">{eventSummary(event)}</p>{/if}
            <details class="mt-3">
              <summary class="cursor-pointer text-xs text-muted-foreground">原始事件</summary>
              <pre class="mt-2 max-h-56 overflow-auto rounded bg-muted p-3 font-mono text-xs leading-5">{formatJson(event.payload)}</pre>
            </details>
          </div>
        </li>
      {/each}
    </ol>
  {/if}
</div>

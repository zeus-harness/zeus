<script lang="ts">
	import { CaretDown, Database, Lightning, Sparkle, Wrench } from '@zeus/ui/icons';
	import type { RunEvent, ToolCallStatus } from '$lib/types';

	interface Props {
		event: RunEvent;
	}

	interface StatusBadge {
		label: string;
		className: string;
	}

	type StatusTone = 'neutral' | 'info' | 'warning' | 'danger' | 'success';

	let { event }: Props = $props();
	const hasDetails = $derived(
		Boolean(event.content) ||
			event.data !== undefined ||
			(event.metadata !== undefined && Object.keys(event.metadata).length > 0)
	);
	const statusBadge = $derived.by((): StatusBadge | undefined => {
		const data = event.data;
		if (!data) return undefined;

		if (data.kind === 'tool_result') {
			switch (data.outcome.status) {
				case 'succeeded':
					return badge('Succeeded', 'success');
				case 'failed':
					return badge('Failed', 'danger');
				case 'cancelled':
					return badge('Cancelled', 'neutral');
				case 'not_dispatched':
					return badge('Not dispatched', 'warning');
				case 'outcome_unknown':
					return badge('Outcome unknown', 'warning');
			}
		}

		if (data.kind === 'tool_dispatch_started') return badge('Running', 'info');
		if (
			data.kind === 'tool_call_requested' ||
			data.kind === 'approval_requested' ||
			data.kind === 'approval_decided'
		) {
			return toolStatusBadge(data.status);
		}
		return undefined;
	});

	function badge(label: string, tone: StatusTone): StatusBadge {
		const classes: Record<StatusTone, string> = {
			neutral: 'bg-zeus-surface text-zeus-muted',
			info: 'bg-zeus-cyan/[0.08] text-zeus-cyan',
			warning: 'bg-zeus-amber/[0.09] text-zeus-amber',
			danger: 'bg-zeus-red/[0.08] text-zeus-red',
			success: 'bg-zeus-green/[0.09] text-zeus-green'
		};
		return { label, className: classes[tone] };
	}

	function toolStatusBadge(status: ToolCallStatus): StatusBadge {
		switch (status) {
			case 'queued':
				return badge('Queued', 'info');
			case 'running':
				return badge('Running', 'info');
			case 'waiting_for_approval':
				return badge('Awaiting review', 'warning');
			case 'not_dispatched':
				return badge('Not dispatched', 'warning');
			case 'outcome_unknown':
				return badge('Outcome unknown', 'warning');
			case 'failed':
				return badge('Failed', 'danger');
			case 'cancelled':
				return badge('Cancelled', 'neutral');
			case 'succeeded':
				return badge('Succeeded', 'neutral');
			case 'requested':
				return badge('Requested', 'neutral');
		}
	}

	function shortTime(value: string): string {
		if (/^\d{2}:\d{2}/.test(value)) return value.slice(0, 5);
		const date = new Date(value);
		return Number.isNaN(date.getTime())
			? value
			: date.toLocaleTimeString('en-US', { hour12: false }).slice(0, 5);
	}

	function humanize(value: string): string {
		return value.replaceAll('_', ' ');
	}

	function formatMetadata(value: unknown): string {
		if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
			return String(value);
		}
		if (value === null || value === undefined) return '—';
		try {
			return JSON.stringify(value);
		} catch {
			return '[unserializable]';
		}
	}

	function formatJson(value: unknown): string {
		try {
			return JSON.stringify(value, null, 2);
		} catch {
			return '[unserializable]';
		}
	}
</script>

{#if event.type === 'user' || event.type === 'context'}
	<article class="flex justify-end">
		<div class="bg-zeus-surface px-4 py-3 sm:max-w-[82%] max-w-[88%] rounded-[22px]">
			<p class="mb-1.5 font-medium text-zeus-muted text-[11px]">
				{event.type === 'context' ? 'You · saved' : 'Incident trigger'}
			</p>
			{#if event.summary}<p class="leading-6 text-zeus-text text-[15px]">{event.summary}</p>{/if}
			{#if event.content}<p class="mt-1 leading-6 text-zeus-text/80 text-[14px]">
					{event.content}
				</p>{/if}
			<p class="mt-2 text-zeus-muted text-[10px]">{shortTime(event.at)}</p>
		</div>
	</article>
{:else if event.type === 'reasoning'}
	{#if hasDetails}
		<details class="group">
			<summary
				class="hover:bg-zeus-surface -mx-2 min-h-8 px-2 gap-2 rounded-lg text-sm text-zeus-muted flex cursor-pointer list-none items-center [&::-webkit-details-marker]:hidden"
			>
				<Sparkle size={16} class="shrink-0" />
				<span class="font-medium text-zeus-text">Think</span>
				<span aria-hidden="true">·</span>
				<span class="min-w-0 flex-1 truncate">{event.summary}</span>
				<CaretDown size={14} class="shrink-0 transition-transform group-open:rotate-180" />
			</summary>
			<div class="border-zeus-border ml-4 mt-2 pl-5 text-sm leading-6 text-zeus-muted border-l">
				{#if event.content}<p>{event.content}</p>{/if}
				{#if event.metadata}
					<div class="mt-3 gap-x-4 gap-y-1 flex flex-wrap text-[11px]">
						{#each Object.entries(event.metadata) as [label, value] (label)}
							<span>{label} {formatMetadata(value)}</span>
						{/each}
					</div>
				{/if}
			</div>
		</details>
	{:else}
		<div class="-mx-2 min-h-8 px-2 gap-2 text-sm text-zeus-muted flex items-center">
			<Sparkle size={16} class="shrink-0" />
			<span class="font-medium text-zeus-text">Think</span>
			<span aria-hidden="true">·</span>
			<span class="min-w-0 flex-1 truncate">{event.summary}</span>
		</div>
	{/if}
{:else if event.type === 'tool_call' || event.type === 'evidence'}
	{#if hasDetails}
		<details class="group border-zeus-border border-y">
			<summary
				class="hover:bg-zeus-surface min-h-12 gap-2.5 text-sm flex cursor-pointer list-none items-center [&::-webkit-details-marker]:hidden"
			>
				{#if event.type === 'evidence'}
					<Database size={16} class="text-zeus-muted shrink-0" />
				{:else}
					<Wrench size={16} class="text-zeus-muted shrink-0" />
				{/if}
				<span class="font-medium text-zeus-text"
					>{event.type === 'evidence' ? 'Evidence' : 'Tool'}</span
				>
				{#if statusBadge}
					<span class={`px-2 py-0.5 font-medium rounded-full text-[10px] ${statusBadge.className}`}>
						{statusBadge.label}
					</span>
				{/if}
				<span class="text-zeus-muted" aria-hidden="true">·</span>
				<span class="min-w-0 text-zeus-muted flex-1 truncate">{event.summary}</span>
				<CaretDown
					size={14}
					class="text-zeus-muted shrink-0 transition-transform group-open:rotate-180"
				/>
			</summary>
			<div class="pb-4 pl-[26px]">
				{#if event.content}
					<pre
						class="bg-zeus-surface rounded-xl p-4 font-mono leading-5 text-zeus-muted max-h-[260px] overflow-auto text-[11px] whitespace-pre-wrap">{event.content}</pre>
				{/if}
				{#if event.data?.kind === 'tool_call_requested'}
					<div class="mt-2 gap-x-4 gap-y-1 text-zeus-muted flex flex-wrap text-[11px]">
						<span>Call <code>{event.data.call.call_id}</code></span>
						<span>Sandbox {humanize(event.data.call.sandbox_profile)}</span>
						<span>Executor {humanize(event.data.call.executor_status)}</span>
					</div>
					<pre
						class="bg-zeus-surface mt-2 rounded-xl p-4 font-mono leading-5 text-zeus-muted max-h-[260px] overflow-auto text-[11px] whitespace-pre-wrap">{formatJson(
							event.data.call.arguments
						)}</pre>
				{:else if event.data?.kind === 'tool_dispatch_started'}
					<div class="mt-2 gap-x-4 gap-y-1 text-zeus-muted flex flex-wrap text-[11px]">
						<span>Call <code>{event.data.call_id}</code></span>
						<span>Executor {event.data.executor}</span>
						<span>Sandbox {humanize(event.data.sandbox_profile)}</span>
					</div>
				{:else if event.data?.kind === 'tool_result'}
					<div class="mt-2 gap-x-4 gap-y-1 text-zeus-muted flex flex-wrap text-[11px]">
						<span>Call <code>{event.data.call_id}</code></span>
						{#if event.data.outcome.status === 'not_dispatched'}
							<span>Reason {humanize(event.data.outcome.reason)}</span>
						{:else if event.data.outcome.status === 'failed' && event.data.outcome.error_code}
							<span>Error {event.data.outcome.error_code}</span>
						{:else if event.data.outcome.status === 'succeeded' && event.data.outcome.output_digest}
							<span>Output <code>{event.data.outcome.output_digest}</code></span>
						{/if}
					</div>
				{/if}
				{#if event.metadata}
					<div class="mt-2 gap-x-4 gap-y-1 text-zeus-muted flex flex-wrap text-[11px]">
						{#each Object.entries(event.metadata) as [label, value] (label)}
							<span>{label} {formatMetadata(value)}</span>
						{/each}
					</div>
				{/if}
			</div>
		</details>
	{:else}
		<div class="border-zeus-border min-h-12 gap-2.5 text-sm flex items-center border-y">
			{#if event.type === 'evidence'}
				<Database size={16} class="text-zeus-muted shrink-0" />
			{:else}
				<Wrench size={16} class="text-zeus-muted shrink-0" />
			{/if}
			<span class="font-medium text-zeus-text"
				>{event.type === 'evidence' ? 'Evidence' : 'Tool'}</span
			>
			{#if statusBadge}
				<span class={`px-2 py-0.5 font-medium rounded-full text-[10px] ${statusBadge.className}`}>
					{statusBadge.label}
				</span>
			{/if}
			<span class="text-zeus-muted" aria-hidden="true">·</span>
			<span class="min-w-0 text-zeus-muted flex-1 truncate">{event.summary}</span>
		</div>
	{/if}
{:else if event.type === 'step'}
	<article class="gap-3 grid grid-cols-[28px_1fr]">
		<span class="bg-zeus-text text-white mt-0.5 size-7 grid place-items-center rounded-full">
			<Lightning size={14} weight="fill" aria-hidden="true" />
		</span>
		<div class="min-w-0">
			{#if event.summary}<p class="leading-6 text-zeus-text text-[15px]">{event.summary}</p>{/if}
			{#if event.content}<p class="mt-1 leading-6 text-zeus-muted text-[14px]">
					{event.content}
				</p>{/if}
		</div>
	</article>
{:else if event.type === 'approval' && event.approval}
	<div class="border-zeus-border py-2 gap-3 text-xs text-zeus-muted flex items-center border-y">
		<span
			class={`size-2 shrink-0 rounded-full ${
				event.approval.status === 'approved'
					? 'bg-zeus-cyan'
					: event.approval.status === 'pending'
						? 'bg-zeus-amber'
						: 'bg-zeus-red'
			}`}
		></span>
		<span class="min-w-0 flex-1">
			{event.approval.status === 'approved'
				? 'Approved'
				: event.approval.status === 'pending'
					? 'Awaiting review'
					: 'Declined'} · {event.approval.action}
		</span>
		{#if statusBadge}
			<span class={`px-2 py-0.5 font-medium rounded-full text-[10px] ${statusBadge.className}`}>
				{statusBadge.label}
			</span>
		{/if}
	</div>
{:else if event.data?.kind === 'tool_policy_decided'}
	<div class="border-zeus-border py-2 gap-2 text-xs text-zeus-muted flex items-center border-y">
		<span class="font-medium text-zeus-text">Policy</span>
		<span class="bg-zeus-surface px-2 py-0.5 font-medium rounded-full text-[10px] capitalize">
			{humanize(event.data.decision)}
		</span>
		<span class="min-w-0 flex-1 truncate" title={event.data.reason}>{event.data.reason}</span>
		<code class="font-mono sm:inline hidden text-[10px]">{event.data.policy_revision}</code>
	</div>
{:else}
	<p class="text-xs text-zeus-muted text-center">{event.summary ?? event.title}</p>
{/if}

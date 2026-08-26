<script lang="ts">
	import { List } from '@zeus/ui/icons';
	import type { DataSource, IncidentOverview, RunOverview, SessionSummary } from '$lib/types';

	interface Props {
		incident: IncidentOverview;
		run: RunOverview;
		session: SessionSummary | null;
		attachedToRun: boolean;
		source: DataSource;
		streamStatus: 'idle' | 'connected' | 'reconnecting';
		onToggleNav: () => void;
	}

	let { incident, run, session, attachedToRun, source, streamStatus, onToggleNav }: Props =
		$props();
	const severityLabel = $derived(
		incident.severity === 'critical'
			? 'SEV-1'
			: incident.severity === 'high'
				? 'SEV-2'
				: incident.severity === 'medium'
					? 'SEV-3'
					: 'SEV-4'
	);
	const connectionLabel = $derived(
		source === 'demo'
			? 'Demo · API offline'
			: streamStatus === 'connected'
				? 'Live'
				: streamStatus === 'reconnecting'
					? 'Reconnecting'
					: 'Connecting'
	);
	const connectionTone = $derived(
		source === 'demo' || streamStatus === 'reconnecting'
			? 'bg-zeus-amber'
			: streamStatus === 'connected'
				? 'bg-zeus-green'
				: 'bg-zeus-muted'
	);
	const runStatusLabel = $derived(run.status.replaceAll('_', ' '));
	const sessionStatusLabel = $derived(session?.status.replaceAll('_', ' ') ?? 'loading');
</script>

<header class="border-zeus-border bg-zeus-bg px-4 sm:px-6 h-16 flex shrink-0 items-center border-b">
	<div class="gap-3 min-w-0 mx-auto flex w-full max-w-[1080px] items-center">
		<button
			type="button"
			class="size-9 text-zeus-muted hover:bg-zeus-surface hover:text-zeus-text lg:hidden rounded-lg grid shrink-0 place-items-center"
			onclick={onToggleNav}
			aria-label="Open run navigation"
		>
			<List size={20} />
		</button>

		<div class="min-w-0 flex-1">
			<h1 class="font-semibold text-zeus-text truncate text-[15px] tracking-[-0.01em]">
				{session && !attachedToRun ? session.title : incident.title}
			</h1>
			{#if session && !attachedToRun}
				<p class="mt-0.5 text-zeus-muted truncate text-[11px]">
					Standalone session · no run attached
				</p>
			{:else}
				<p class="mt-0.5 text-zeus-muted truncate text-[11px]">
					<span class="font-medium text-zeus-red">{severityLabel}</span>
					<span aria-hidden="true"> · </span>{incident.service}
					<span aria-hidden="true"> · </span>{incident.region}
				</p>
			{/if}
		</div>

		<div class="min-w-0 gap-2 text-xs text-zeus-muted sm:flex hidden items-center">
			{#if session && !attachedToRun}
				<span class="font-mono text-[11px]">{session.id}</span>
				<span aria-hidden="true">·</span>
				<span class="capitalize">{sessionStatusLabel}</span>
			{:else}
				<span class="font-mono text-[11px]">{run.id}</span>
				<span aria-hidden="true">·</span>
				<span>{run.environment}</span>
				<span aria-hidden="true">·</span>
				<span class="capitalize">{runStatusLabel}</span>
			{/if}
			<span aria-hidden="true">·</span>
			<span class={`size-2 rounded-full ${connectionTone}`}></span>
			<span class={source === 'demo' ? 'text-zeus-amber' : undefined}>{connectionLabel}</span>
		</div>
	</div>
</header>

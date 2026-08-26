<script lang="ts">
	import { resolve } from '$app/paths';
	import { Lightning, PlayCircle, SlidersHorizontal, X } from '@zeus/ui/icons';
	import type { DataSource, IncidentOverview, RunOverview } from '$lib/types';

	interface Props {
		open: boolean;
		incident: IncidentOverview;
		run: RunOverview;
		source: DataSource;
		onClose: () => void;
	}

	let { open, incident, run, source, onClose }: Props = $props();
	const statusTone = $derived.by(() => {
		switch (run.status) {
			case 'succeeded':
				return 'bg-zeus-green';
			case 'failed':
			case 'cancelled':
				return 'bg-zeus-red';
			case 'waiting_for_approval':
			case 'blocked':
			case 'needs_attention':
				return 'bg-zeus-amber';
			case 'running':
			case 'active':
				return 'bg-zeus-cyan';
			case 'queued':
				return 'bg-zeus-muted';
		}
	});

	function humanize(value: string): string {
		return value.replaceAll('_', ' ');
	}
</script>

{#if open}
	<button
		type="button"
		class="inset-0 bg-black/20 lg:hidden fixed z-40 backdrop-blur-[1px]"
		onclick={onClose}
		aria-label="Close navigation"
	></button>
{/if}

<aside
	class={`inset-y-0 left-0 border-zeus-border bg-zeus-surface lg:static lg:translate-x-0 fixed z-50 flex w-[236px] shrink-0 flex-col border-r transition-transform duration-200 ${open ? 'translate-x-0' : '-translate-x-full'}`}
	aria-label="Run navigation"
>
	<div class="px-5 h-16 flex items-center justify-between">
		<a
			href={resolve('/')}
			class="gap-2.5 font-bold text-zeus-text flex items-center text-[15px] tracking-[0.16em]"
		>
			<span class="size-7 bg-zeus-text text-white grid place-items-center rounded-full">
				<Lightning size={16} weight="fill" aria-hidden="true" />
			</span>
			ZEUS
		</a>
		<button
			type="button"
			class="text-zeus-muted hover:text-zeus-text lg:hidden"
			onclick={onClose}
			aria-label="Close navigation"
		>
			<X size={20} />
		</button>
	</div>

	<div class="px-3 pt-3">
		<button
			type="button"
			disabled
			title="Run creation is not available in the local MVP"
			class="border-zeus-border bg-white text-zeus-text h-10 gap-2 px-3 text-sm rounded-xl shadow-sm flex w-full items-center border disabled:cursor-not-allowed disabled:opacity-70"
		>
			<PlayCircle size={17} aria-hidden="true" />
			New run
		</button>
	</div>

	<nav class="px-3 pt-8 flex flex-1 flex-col" aria-label="Recent runs">
		<p class="px-2 pb-2 font-semibold text-zeus-muted text-[10px] tracking-[0.12em]">RECENT</p>
		<a
			href={resolve('/')}
			aria-current="page"
			class="bg-zeus-surface-2 px-3 py-2.5 min-w-0 gap-3 rounded-xl flex items-start"
			onclick={onClose}
		>
			<div class="min-w-0 flex-1">
				<p class="text-sm font-medium text-zeus-text truncate">{incident.title}</p>
				<p class="mt-1 text-zeus-muted truncate text-[11px]">{run.id} · {run.environment}</p>
			</div>
			<span
				class={`mt-1.5 size-2 shrink-0 rounded-full ${statusTone}`}
				title={`Run status: ${humanize(run.status)}`}
			></span>
		</a>
	</nav>

	<div class="px-3 pb-4">
		{#if source === 'demo'}
			<p class="mb-2 px-3 text-zeus-amber text-[10px]">Demo data · API offline</p>
		{/if}
		<button
			type="button"
			disabled
			class="h-10 gap-3 px-3 text-sm text-zeus-muted rounded-xl flex w-full items-center disabled:opacity-80"
		>
			<SlidersHorizontal size={17} aria-hidden="true" />
			Settings
		</button>
	</div>
</aside>

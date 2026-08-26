<script lang="ts">
	import { resolve } from '$app/paths';
	import { Lightning, PlayCircle, SlidersHorizontal, X } from '@zeus/ui/icons';
	import type { SessionStatus, SessionSummary } from '$lib/types';

	interface Props {
		open: boolean;
		sessions: SessionSummary[];
		activeSessionId: string;
		creatingSession: boolean;
		sessionActionError?: string;
		hasMoreSessions: boolean;
		loadingMoreSessions: boolean;
		sessionListError?: string;
		onClose: () => void;
		onCreateSession: () => void;
		onSelectSession: (sessionId: string) => void;
		onLoadMoreSessions: () => void;
		onOpenSettings: (trigger: HTMLButtonElement) => void;
	}

	let {
		open,
		sessions,
		activeSessionId,
		creatingSession,
		sessionActionError = '',
		hasMoreSessions,
		loadingMoreSessions,
		sessionListError = '',
		onClose,
		onCreateSession,
		onSelectSession,
		onLoadMoreSessions,
		onOpenSettings
	}: Props = $props();

	function statusTone(status: SessionStatus): string {
		switch (status) {
			case 'ready':
				return 'bg-zeus-green';
			case 'running':
				return 'bg-zeus-cyan';
			case 'needs_attention':
				return 'bg-zeus-amber';
		}
	}

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
	aria-label="Session navigation"
>
	<div class="px-5 h-16 flex items-center justify-between">
		<a
			href={resolve('/')}
			class="gap-2.5 font-bold text-zeus-text flex items-center text-[15px] tracking-[0.16em]"
		>
			<span class="size-7 bg-zeus-text text-zeus-bg grid place-items-center rounded-full">
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
			disabled={creatingSession}
			class="border-zeus-border bg-zeus-bg text-zeus-text hover:bg-zeus-surface-2 h-10 gap-2 px-3 text-sm rounded-xl shadow-sm flex w-full items-center border transition-colors disabled:cursor-wait disabled:opacity-70"
			onclick={onCreateSession}
		>
			<PlayCircle size={17} aria-hidden="true" />
			{creatingSession ? 'Creating…' : 'New session'}
		</button>
		{#if sessionActionError}
			<p class="text-zeus-red mt-2 px-2 leading-4 text-[10px]" role="alert">
				{sessionActionError}
			</p>
		{/if}
	</div>

	<nav class="px-3 pt-8 min-h-0 flex flex-1 flex-col" aria-label="Sessions">
		<p class="px-2 pb-2 font-semibold text-zeus-muted text-[10px] tracking-[0.12em]">RECENT</p>
		<div class="min-h-0 space-y-1 overflow-y-auto">
			{#each sessions as session (session.id)}
				<button
					type="button"
					aria-current={session.id === activeSessionId ? 'page' : undefined}
					class={`hover:bg-zeus-surface-2 px-3 py-2.5 min-w-0 gap-3 rounded-xl flex w-full items-start text-left transition-colors ${
						session.id === activeSessionId ? 'bg-zeus-surface-2' : ''
					}`}
					onclick={() => {
						onSelectSession(session.id);
						onClose();
					}}
				>
					<div class="min-w-0 flex-1">
						<p class="text-sm font-medium text-zeus-text truncate">{session.title}</p>
						<p class="mt-1 text-zeus-muted truncate text-[11px]">
							{humanize(session.status)} · event {session.sequence}
						</p>
					</div>
					<span
						class={`mt-1.5 size-2 shrink-0 rounded-full ${statusTone(session.status)}`}
						title={`Session status: ${humanize(session.status)}`}
					></span>
				</button>
			{/each}
			{#if hasMoreSessions}
				<div class="px-2 pt-2 pb-3 text-center">
					<button
						type="button"
						disabled={loadingMoreSessions}
						class="border-zeus-border text-zeus-muted hover:bg-zeus-surface-2 hover:text-zeus-text h-8 px-3 text-xs rounded-lg w-full border transition-colors disabled:cursor-wait disabled:opacity-70"
						onclick={onLoadMoreSessions}
					>
						{loadingMoreSessions ? 'Loading…' : sessionListError ? 'Try again' : 'Load more'}
					</button>
					{#if sessionListError}
						<p class="text-zeus-red mt-1.5 leading-4 text-[10px]" role="alert">
							{sessionListError}
						</p>
					{/if}
				</div>
			{/if}
		</div>
	</nav>

	<div class="px-3 pb-4">
		<button
			type="button"
			class="text-zeus-muted hover:bg-zeus-surface-2 hover:text-zeus-text h-10 gap-3 px-3 text-sm rounded-xl flex w-full items-center transition-colors"
			onclick={(event) => onOpenSettings(event.currentTarget)}
		>
			<SlidersHorizontal size={17} aria-hidden="true" />
			Settings
		</button>
	</div>
</aside>

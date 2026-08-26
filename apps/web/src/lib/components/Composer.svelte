<script lang="ts">
	import { ArrowUp } from '@zeus/ui/icons';
	import { Button } from '@zeus/ui/button';
	import { Textarea } from '@zeus/ui/textarea';

	interface Props {
		value?: string;
		onSubmit: (value: string) => Promise<boolean>;
		status?: 'ready' | 'running' | 'needs_attention';
		statusText?: string;
		error?: string;
		canRetry?: boolean;
		onRetry?: () => Promise<boolean>;
		onResume?: () => Promise<void>;
	}

	let {
		value = $bindable(''),
		onSubmit,
		status = 'ready',
		statusText = 'Messages are saved to this session',
		error = '',
		canRetry = false,
		onRetry,
		onResume
	}: Props = $props();
	let submitting = $state(false);
	let retrying = $state(false);
	let resuming = $state(false);
	const disabled = $derived(status !== 'ready' || submitting || retrying || resuming);

	async function submit() {
		const text = value.trim();
		if (!text || disabled) return;
		submitting = true;
		try {
			if (await onSubmit(text)) value = '';
		} finally {
			submitting = false;
		}
	}

	async function retry() {
		if (!onRetry || retrying) return;
		retrying = true;
		try {
			if (await onRetry()) value = '';
		} finally {
			retrying = false;
		}
	}

	async function resume() {
		if (!onResume || resuming) return;
		resuming = true;
		try {
			await onResume();
		} finally {
			resuming = false;
		}
	}
</script>

<section class="bg-zeus-bg px-4 sm:px-6 pt-2 shrink-0 pb-[max(14px,env(safe-area-inset-bottom))]">
	<div class="mx-auto w-full max-w-[780px]">
		<div
			class="border-zeus-border bg-zeus-bg p-2.5 rounded-[18px] border shadow-[0_8px_28px_var(--zeus-shadow)]"
		>
			<Textarea
				bind:value
				{disabled}
				rows={1}
				class="min-h-10 max-h-32 px-2 py-1 leading-6 resize-none border-0 bg-transparent text-[14px] shadow-none focus-visible:ring-0"
				placeholder={status === 'needs_attention'
					? 'Resume this session to continue…'
					: canRetry
						? 'This message is waiting to be saved…'
						: status === 'running'
							? 'Another turn is being saved…'
							: 'Message Zeus…'}
				onkeydown={(event: KeyboardEvent) => {
					if (event.key === 'Enter' && !event.shiftKey) {
						event.preventDefault();
						void submit();
					}
				}}
			/>
			<div class="mt-1 pl-2 flex items-center justify-between">
				<div class="min-w-0 pr-3" aria-live="polite">
					<p class={`truncate text-[10px] ${error ? 'text-zeus-red' : 'text-zeus-muted'}`}>
						{error || (submitting || retrying ? 'Saving…' : statusText)}
					</p>
				</div>
				{#if status === 'needs_attention'}
					<Button
						variant="outline"
						size="sm"
						class="rounded-full"
						disabled={!onResume || resuming}
						onclick={() => void resume()}
					>
						{resuming ? 'Resuming…' : 'Resume'}
					</Button>
				{:else if canRetry}
					<Button
						variant="outline"
						size="sm"
						class="rounded-full"
						disabled={!onRetry || retrying}
						onclick={() => void retry()}
					>
						{retrying ? 'Saving…' : 'Retry save'}
					</Button>
				{:else}
					<Button
						size="icon"
						class="size-8 rounded-full"
						disabled={disabled || !value.trim()}
						onclick={() => void submit()}
						aria-label="Send message"
					>
						<ArrowUp size={16} />
					</Button>
				{/if}
			</div>
		</div>
	</div>
</section>

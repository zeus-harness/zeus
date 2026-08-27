<script lang="ts">
	import { Button } from '@zeus/ui/button';
	import type { ApprovalState, ReviewDecision, ToolPolicy } from '$lib/types';

	interface Props {
		approval: ApprovalState;
		summary: string;
		policy?: ToolPolicy;
		canReview: boolean;
		pendingDecision: ReviewDecision | null;
		error: string;
		onReview: (decision: ReviewDecision) => void;
	}

	let { approval, summary, policy, canReview, pendingDecision, error, onReview }: Props = $props();
	const hasBindingDetails = $derived(
		Boolean(approval.call_id || approval.policy_revision || approval.sandbox_profile)
	);

	function humanize(value: string): string {
		return value.replaceAll('_', ' ');
	}
</script>

<section class="bg-zeus-bg px-4 sm:px-6 pt-2 shrink-0 pb-[max(14px,env(safe-area-inset-bottom))]">
	<div
		class="border-zeus-amber/55 bg-zeus-bg mx-auto w-full max-w-[748px] overflow-hidden rounded-[18px] border shadow-[0_8px_28px_var(--zeus-shadow)]"
	>
		<div
			class="bg-zeus-amber/[0.08] border-zeus-amber/20 px-4 py-2.5 gap-2 text-xs font-medium text-zeus-amber flex items-center border-b"
		>
			<span class="size-2 bg-zeus-amber rounded-full"></span>
			Review required
		</div>
		<div class="px-4 pb-4 pt-3.5 sm:px-5">
			<p class="font-medium leading-6 text-zeus-text text-[15px]">{summary}</p>
			<p class="mt-1 text-sm text-zeus-muted">{approval.change}</p>
			<code
				class="bg-zeus-surface mt-3 rounded-lg px-3 py-2 font-mono text-zeus-muted block overflow-x-auto text-[11px]"
			>
				{approval.tool}
			</code>

			{#if hasBindingDetails}
				<dl class="mt-3 gap-x-4 gap-y-2 text-zeus-muted sm:grid-cols-3 grid text-[11px]">
					{#if approval.call_id}
						<div class="min-w-0">
							<dt class="font-medium text-zeus-text">Call</dt>
							<dd class="font-mono truncate" title={approval.call_id}>{approval.call_id}</dd>
						</div>
					{/if}
					{#if approval.policy_revision}
						<div class="min-w-0">
							<dt class="font-medium text-zeus-text">Policy</dt>
							<dd class="font-mono truncate" title={approval.policy_revision}>
								{approval.policy_revision}
							</dd>
						</div>
					{/if}
					{#if approval.sandbox_profile}
						<div class="min-w-0">
							<dt class="font-medium text-zeus-text">Sandbox</dt>
							<dd class="capitalize">{humanize(approval.sandbox_profile)}</dd>
						</div>
					{/if}
				</dl>
			{/if}

			{#if policy}
				<details class="mt-3 text-xs text-zeus-muted">
					<summary class="font-medium cursor-pointer list-none [&::-webkit-details-marker]:hidden">
						Policy · {policy.name} <span class="ml-1 text-[10px]">Show details</span>
					</summary>
					<div class="border-zeus-border mt-2 gap-2 pt-2 sm:grid-cols-3 grid border-t text-[11px]">
						<p>
							<span class="font-medium text-zeus-text block">Allowed</span>{policy.allows.join(
								', '
							)}
						</p>
						<p>
							<span class="font-medium text-zeus-text block">Review</span
							>{policy.requires_approval.join(', ')}
						</p>
						<p>
							<span class="font-medium text-zeus-text block">Denied</span>{policy.denies.join(', ')}
						</p>
					</div>
				</details>
			{/if}

			{#if error}
				<p class="mt-3 text-xs leading-5 text-zeus-red" role="alert">{error}</p>
			{/if}

			{#if canReview}
				<div class="mt-4 gap-2 flex justify-end">
					<Button
						variant="outline"
						class="bg-zeus-bg h-11 rounded-lg px-4 text-sm sm:h-9"
						disabled={pendingDecision !== null}
						onclick={() => onReview('reject')}
					>
						{pendingDecision === 'reject' ? 'Declining…' : 'Decline'}
					</Button>
					<Button
						class="h-11 rounded-lg px-4 text-sm sm:h-9"
						disabled={pendingDecision !== null}
						onclick={() => onReview('approve')}
					>
						{pendingDecision === 'approve'
							? 'Approving…'
							: approval.scope === 'allow_once'
								? 'Approve once'
								: 'Approve'}
					</Button>
				</div>
			{:else}
				<p
					class="border-zeus-border bg-zeus-surface mt-4 rounded-lg px-3 py-2.5 text-xs text-zeus-muted border"
				>
					An owner must review this action. You can continue reading the session while it waits.
				</p>
			{/if}
		</div>
	</div>
</section>

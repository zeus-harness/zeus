<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '@zeus/ui/button';
	import { Clock, Database } from '@zeus/ui/icons';
	import {
		ApiError,
		createAccountAuditCheckpoint,
		downloadAccountAuditExport,
		listAccountAuditEvents,
		updateAccountAuditPolicy
	} from '$lib/api';
	import type { AccountAuditEvent, AccountAuditState } from '$lib/types';

	interface Props {
		onUnauthorized: () => void;
	}

	let { onUnauthorized }: Props = $props();
	let events = $state.raw<AccountAuditEvent[]>([]);
	let auditState = $state.raw<AccountAuditState | null>(null);
	let nextCursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let savingPolicy = $state(false);
	let exporting = $state(false);
	let checkpointing = $state(false);
	let detailRows = $state(4096);
	let legalHold = $state(false);
	let archiveRequired = $state(false);
	let archiveReference = $state('');
	let error = $state('');
	let notice = $state('');
	const latestEvent = $derived.by(() =>
		events.reduce<AccountAuditEvent | null>(
			(latest, event) => (!latest || event.sequence > latest.sequence ? event : latest),
			null
		)
	);

	function reportError(caught: unknown, fallback: string) {
		if (caught instanceof ApiError && caught.status === 401) {
			onUnauthorized();
			return;
		}
		error = caught instanceof Error ? caught.message : fallback;
	}

	function applyState(next: AccountAuditState) {
		auditState = next;
		detailRows = next.policy.detail_rows;
		legalHold = next.policy.legal_hold;
		archiveRequired = next.policy.archive_required;
	}

	async function load(reset: boolean) {
		if (reset) {
			loading = true;
			error = '';
		} else {
			if (!nextCursor || loadingMore) return;
			loadingMore = true;
		}
		try {
			const page = await listAccountAuditEvents(reset ? undefined : (nextCursor ?? undefined));
			events = reset
				? page.events
				: [
						...events,
						...page.events.filter((item) => !events.some((e) => e.sequence === item.sequence))
					];
			nextCursor = page.next_cursor ?? null;
			applyState(page.state);
		} catch (caught) {
			reportError(caught, 'Account audit events could not be loaded.');
		} finally {
			loading = false;
			loadingMore = false;
		}
	}

	async function savePolicy() {
		if (!auditState || savingPolicy) return;
		savingPolicy = true;
		error = '';
		notice = '';
		try {
			const policy = await updateAccountAuditPolicy({
				expected_revision: auditState.policy.revision,
				detail_rows: detailRows,
				legal_hold: legalHold,
				archive_required: archiveRequired
			});
			auditState = { ...auditState, policy };
			notice = 'Audit policy updated.';
		} catch (caught) {
			reportError(caught, 'The audit policy could not be updated.');
		} finally {
			savingPolicy = false;
		}
	}

	async function exportAudit() {
		if (exporting) return;
		exporting = true;
		error = '';
		notice = '';
		try {
			const blob = await downloadAccountAuditExport();
			const url = URL.createObjectURL(blob);
			const link = document.createElement('a');
			link.href = url;
			link.download = `zeus-account-audit-${new Date().toISOString().slice(0, 10)}.ndjson`;
			link.click();
			URL.revokeObjectURL(url);
			notice = 'Audit export downloaded. Store it durably before recording a checkpoint.';
		} catch (caught) {
			reportError(caught, 'The audit export could not be downloaded.');
		} finally {
			exporting = false;
		}
	}

	async function recordCheckpoint() {
		const event = latestEvent;
		const current = auditState;
		const reference = archiveReference.trim();
		if (!event || !current || !reference || checkpointing) return;
		checkpointing = true;
		error = '';
		notice = '';
		try {
			const response = await createAccountAuditCheckpoint({
				expected_revision: current.archive.revision,
				through_sequence: event.sequence,
				event_hash: event.event_hash,
				archive_reference: reference
			});
			applyState(response.state);
			archiveReference = '';
			notice = `Archive checkpoint recorded through event ${response.archive.through_sequence}.`;
		} catch (caught) {
			reportError(caught, 'The archive checkpoint could not be recorded.');
		} finally {
			checkpointing = false;
		}
	}

	function shortHash(value: string): string {
		return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value;
	}

	function humanize(value: string): string {
		return value.replaceAll('_', ' ');
	}

	onMount(() => {
		void load(true);
	});
</script>

<section aria-labelledby="audit-title">
	<div class="gap-3 flex flex-wrap items-start justify-between">
		<div>
			<h3 id="audit-title" class="text-sm font-medium">Account audit</h3>
			<p class="text-zeus-muted mt-1 text-xs leading-5">
				Review member and authorization changes recorded by this Zeus database.
			</p>
		</div>
		<div class="gap-2 flex">
			<Button variant="outline" size="sm" class="rounded-lg" onclick={() => void load(true)}>
				Refresh
			</Button>
			<Button size="sm" class="rounded-lg" disabled={exporting} onclick={() => void exportAudit()}>
				{exporting ? 'Exporting…' : 'Export NDJSON'}
			</Button>
		</div>
	</div>

	{#if auditState}
		<div class="mt-4 gap-2 sm:grid-cols-3 grid">
			<div class="border-zeus-border rounded-xl p-3 border">
				<p class="text-zeus-muted tracking-wider text-[10px] uppercase">Detailed rows</p>
				<p class="mt-1 text-sm font-medium">{auditState.detailed_rows}</p>
			</div>
			<div class="border-zeus-border rounded-xl p-3 border">
				<p class="text-zeus-muted tracking-wider text-[10px] uppercase">Ordinary capacity</p>
				<p class="mt-1 text-sm font-medium">{auditState.ordinary_capacity_remaining}</p>
			</div>
			<div class="border-zeus-border rounded-xl p-3 border">
				<p class="text-zeus-muted tracking-wider text-[10px] uppercase">Progress reserve</p>
				<p class="mt-1 text-sm font-medium">{auditState.progress_capacity_remaining}</p>
			</div>
		</div>

		<details class="border-zeus-border mt-3 rounded-xl p-3 border">
			<summary class="text-xs font-medium cursor-pointer">Retention and archive policy</summary>
			<div class="mt-3 gap-3 sm:grid-cols-2 grid">
				<label class="text-xs">
					<span class="font-medium">Detailed row target</span>
					<input
						bind:value={detailRows}
						type="number"
						min="1"
						required
						class="border-zeus-border bg-zeus-bg mt-1 h-9 rounded-lg px-3 w-full border outline-none"
					/>
				</label>
				<div class="space-y-2 pt-1 text-xs">
					<label class="gap-2 flex items-start">
						<input bind:checked={legalHold} type="checkbox" class="mt-0.5" />
						<span
							><span class="font-medium">Legal hold</span><span class="text-zeus-muted block"
								>Stop detailed event compaction.</span
							></span
						>
					</label>
					<label class="gap-2 flex items-start">
						<input bind:checked={archiveRequired} type="checkbox" class="mt-0.5" />
						<span
							><span class="font-medium">Require archive</span><span class="text-zeus-muted block"
								>Block compaction beyond the recorded checkpoint.</span
							></span
						>
					</label>
				</div>
			</div>
			<div class="mt-3 flex justify-end">
				<Button
					size="sm"
					class="rounded-lg"
					disabled={savingPolicy}
					onclick={() => void savePolicy()}
				>
					{savingPolicy ? 'Saving…' : 'Save policy'}
				</Button>
			</div>
		</details>

		<details class="border-zeus-border mt-3 rounded-xl p-3 border">
			<summary class="text-xs font-medium cursor-pointer">Archive checkpoint</summary>
			<p class="text-zeus-muted mt-2 leading-5 text-[11px]">
				Download and durably store the export first. The reference is an operator record, not proof
				that an external archive exists.
			</p>
			<div class="mt-3 gap-2 flex">
				<label class="min-w-0 flex-1">
					<span class="sr-only">External archive reference</span>
					<input
						bind:value={archiveReference}
						type="text"
						maxlength="512"
						placeholder="External archive reference"
						class="border-zeus-border bg-zeus-bg h-9 rounded-lg px-3 text-xs w-full border outline-none"
					/>
				</label>
				<Button
					size="sm"
					class="h-9 rounded-lg"
					disabled={!latestEvent || !archiveReference.trim() || checkpointing}
					onclick={() => void recordCheckpoint()}
				>
					{checkpointing ? 'Recording…' : 'Record latest'}
				</Button>
			</div>
			<p class="text-zeus-muted mt-2 text-[11px]">
				Current checkpoint: {auditState.archive.through_sequence || 'none'} · rollup through {auditState
					.rollup.through_sequence}
			</p>
		</details>

		<p class="text-zeus-muted mt-3 leading-5 text-[11px]">
			The hash chain and rollup are commitments local to this database. They are not an externally
			anchored tamper-proof log.
		</p>
	{/if}

	{#if error}
		<p class="text-zeus-red mt-3 text-xs leading-5" role="alert">{error}</p>
	{:else if notice}
		<p class="text-zeus-muted mt-3 text-xs leading-5" role="status">{notice}</p>
	{/if}

	<div class="mt-4 space-y-2" aria-busy={loading}>
		{#if loading}
			<p class="text-zeus-muted py-6 text-xs text-center">Loading account audit…</p>
		{:else}
			{#each events as event (event.sequence)}
				<article class="border-zeus-border rounded-xl px-3 py-3 border">
					<div class="gap-3 flex items-start">
						<span class="bg-zeus-surface size-8 grid shrink-0 place-items-center rounded-full">
							<Clock size={15} aria-hidden="true" />
						</span>
						<div class="min-w-0 flex-1">
							<div class="gap-2 flex flex-wrap items-center justify-between">
								<p class="text-sm font-medium capitalize">{humanize(event.action)}</p>
								<time class="text-zeus-muted text-[10px]" datetime={event.occurred_at}>
									{new Date(event.occurred_at).toLocaleString()}
								</time>
							</div>
							<p class="text-zeus-muted mt-1 text-[11px]">
								#{event.sequence} · {event.outcome} · {event.target_kind}
								{event.target_id}
							</p>
							<p class="text-zeus-muted mt-1 font-mono text-[10px]" title={event.event_hash}>
								{shortHash(event.event_hash)}
							</p>
							{#if Object.keys(event.metadata).length > 0}
								<details class="mt-2 text-[11px]">
									<summary class="text-zeus-muted cursor-pointer">Metadata</summary>
									<pre
										class="bg-zeus-surface mt-2 max-h-32 rounded-lg p-2 font-mono overflow-auto text-[10px]">{JSON.stringify(
											event.metadata,
											null,
											2
										)}</pre>
								</details>
							{/if}
						</div>
					</div>
				</article>
			{/each}
			{#if events.length === 0}
				<div class="text-zeus-muted py-6 text-xs text-center">
					<Database class="mb-2 mx-auto" size={18} aria-hidden="true" />
					No account audit events yet.
				</div>
			{/if}
		{/if}
	</div>

	{#if nextCursor}
		<Button
			variant="ghost"
			size="sm"
			class="mt-3 rounded-lg w-full"
			disabled={loadingMore}
			onclick={() => void load(false)}
		>
			{loadingMore ? 'Loading…' : 'Load more'}
		</Button>
	{/if}
</section>

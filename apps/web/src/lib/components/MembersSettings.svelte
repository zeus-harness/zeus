<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '@zeus/ui/button';
	import { ClipboardText, User } from '@zeus/ui/icons';
	import {
		ApiError,
		createMember,
		listMembers,
		rotateMemberSetupToken,
		updateMember
	} from '$lib/api';
	import type {
		AccountMember,
		AccountRole,
		AccountStatus,
		AccountUser,
		InFlightWorkSummary,
		MemberSetupTokenResponse
	} from '$lib/types';

	interface Props {
		user: AccountUser;
		onUnauthorized: () => void;
	}

	let { user, onUnauthorized }: Props = $props();
	let members = $state.raw<AccountMember[]>([]);
	let nextCursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let mutatingUserId = $state('');
	let newUsername = $state('');
	let creating = $state(false);
	let error = $state('');
	let notice = $state('');
	let setup = $state.raw<MemberSetupTokenResponse | null>(null);
	let copied = $state(false);

	function upsertMember(member: AccountMember) {
		members = members.map((current) => (current.user_id === member.user_id ? member : current));
	}

	function reportError(caught: unknown, fallback: string) {
		if (caught instanceof ApiError && caught.status === 401) {
			onUnauthorized();
			return;
		}
		error = caught instanceof Error ? caught.message : fallback;
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
			const page = await listMembers(reset ? undefined : (nextCursor ?? undefined));
			members = reset
				? page.members
				: [
						...members,
						...page.members.filter((item) => !members.some((m) => m.user_id === item.user_id))
					];
			nextCursor = page.next_cursor ?? null;
		} catch (caught) {
			reportError(caught, 'Members could not be loaded.');
		} finally {
			loading = false;
			loadingMore = false;
		}
	}

	async function addMember(event: SubmitEvent) {
		event.preventDefault();
		const username = newUsername.trim();
		if (!username || creating) return;
		creating = true;
		error = '';
		notice = '';
		setup = null;
		copied = false;
		try {
			const created = await createMember({ username });
			members = [created.member, ...members];
			setup = created;
			newUsername = '';
		} catch (caught) {
			reportError(caught, 'The member could not be created.');
		} finally {
			creating = false;
		}
	}

	async function transitionMember(
		member: AccountMember,
		change: { role?: AccountRole; status?: AccountStatus }
	) {
		if (mutatingUserId) return;
		mutatingUserId = member.user_id;
		error = '';
		notice = '';
		setup = null;
		copied = false;
		try {
			const updated = await updateMember(member.user_id, {
				expected_revision: member.revision,
				...change
			});
			upsertMember(updated.member);
			notice = transitionNotice(updated.in_flight);
			if (updated.member.user_id === user.id) onUnauthorized();
		} catch (caught) {
			reportError(caught, 'The member could not be updated.');
		} finally {
			mutatingUserId = '';
		}
	}

	function transitionNotice(inFlight: InFlightWorkSummary): string {
		const count = inFlight.reply_job_ids.length + inFlight.dispatch_call_ids.length;
		return count === 0
			? 'Member access updated.'
			: `Access updated. ${count} already-claimed operation${count === 1 ? '' : 's'} may still finish.`;
	}

	async function rotateSetup(member: AccountMember) {
		if (mutatingUserId) return;
		mutatingUserId = member.user_id;
		error = '';
		notice = '';
		setup = null;
		copied = false;
		try {
			const rotated = await rotateMemberSetupToken(member.user_id, {
				expected_revision: member.revision
			});
			upsertMember(rotated.member);
			setup = rotated;
		} catch (caught) {
			reportError(caught, 'A new setup token could not be created.');
		} finally {
			mutatingUserId = '';
		}
	}

	async function copySetupToken() {
		if (!setup) return;
		try {
			await navigator.clipboard.writeText(setup.setup_token);
			copied = true;
		} catch {
			copied = false;
		}
	}

	onMount(() => {
		void load(true);
	});
</script>

<section aria-labelledby="members-title">
	<div class="gap-4 flex items-start justify-between">
		<div>
			<h3 id="members-title" class="text-sm font-medium">Members</h3>
			<p class="text-zeus-muted mt-1 text-xs leading-5">
				Create local accounts and revoke their access immediately.
			</p>
		</div>
		<Button variant="outline" size="sm" class="rounded-lg" onclick={() => void load(true)}>
			Refresh
		</Button>
	</div>

	<form
		class="border-zeus-border bg-zeus-surface mt-4 gap-2 rounded-xl p-3 flex border"
		onsubmit={addMember}
	>
		<label class="min-w-0 flex-1">
			<span class="sr-only">New member username</span>
			<input
				bind:value={newUsername}
				type="text"
				name="new-member-username"
				placeholder="username"
				autocomplete="off"
				required
				minlength="3"
				maxlength="32"
				pattern="[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?"
				spellcheck="false"
				class="border-zeus-border bg-zeus-bg text-zeus-text focus:border-zeus-cyan h-9 rounded-lg px-3 text-sm w-full border outline-none"
			/>
		</label>
		<Button type="submit" size="sm" class="h-9 rounded-lg" disabled={creating}>
			{creating ? 'Adding…' : 'Add member'}
		</Button>
	</form>

	{#if setup}
		<div class="border-zeus-cyan/50 bg-zeus-cyan/[0.06] mt-4 rounded-xl p-3 border" role="status">
			<p class="text-xs font-medium">One-time setup token for {setup.member.username}</p>
			<p class="text-zeus-muted mt-1 leading-5 text-[11px]">
				Copy it now. Zeus will not show this token again, and creating another invalidates this one.
			</p>
			<div class="mt-2 gap-2 flex items-center">
				<code
					class="border-zeus-border bg-zeus-bg min-w-0 rounded-lg px-3 py-2 font-mono text-xs flex-1 truncate border select-all"
				>
					{setup.setup_token}
				</code>
				<button
					type="button"
					class="border-zeus-border hover:bg-zeus-surface-2 size-9 rounded-lg grid shrink-0 place-items-center border"
					onclick={() => void copySetupToken()}
					aria-label="Copy setup token"
					title="Copy setup token"
				>
					<ClipboardText size={16} aria-hidden="true" />
				</button>
			</div>
			<p class="text-zeus-muted mt-2 text-[11px]">
				{copied ? 'Copied.' : `Expires ${new Date(setup.setup_token_expires_at).toLocaleString()}.`}
			</p>
		</div>
	{/if}

	{#if error}
		<p class="text-zeus-red mt-3 text-xs leading-5" role="alert">{error}</p>
	{:else if notice}
		<p class="text-zeus-muted mt-3 text-xs leading-5" role="status">{notice}</p>
	{/if}

	<div class="mt-4 space-y-2" aria-busy={loading}>
		{#if loading}
			<p class="text-zeus-muted py-5 text-xs text-center">Loading members…</p>
		{:else}
			{#each members as member (member.user_id)}
				<article
					class="border-zeus-border gap-3 rounded-xl px-3 py-3 flex flex-wrap items-center border"
				>
					<span class="bg-zeus-surface size-9 grid shrink-0 place-items-center rounded-full">
						<User size={17} aria-hidden="true" />
					</span>
					<div class="min-w-[130px] flex-1">
						<p class="text-sm font-medium truncate">
							{member.username}{member.user_id === user.id ? ' · you' : ''}
						</p>
						<p class="text-zeus-muted mt-0.5 text-[11px] capitalize">
							{member.role} · {member.status}{member.setup_required ? ' · setup pending' : ''}
						</p>
					</div>
					<div class="gap-1.5 flex flex-wrap justify-end">
						{#if member.setup_required}
							<Button
								variant="ghost"
								size="sm"
								class="h-8 rounded-lg px-2.5 text-xs"
								disabled={Boolean(mutatingUserId) || member.status !== 'active'}
								onclick={() => void rotateSetup(member)}
							>
								New token
							</Button>
						{/if}
						<Button
							variant="outline"
							size="sm"
							class="h-8 rounded-lg px-2.5 text-xs"
							disabled={Boolean(mutatingUserId) ||
								member.setup_required ||
								member.status !== 'active'}
							onclick={() =>
								void transitionMember(member, {
									role: member.role === 'owner' ? 'member' : 'owner'
								})}
						>
							Make {member.role === 'owner' ? 'member' : 'owner'}
						</Button>
						<Button
							variant={member.status === 'active' ? 'outline' : 'default'}
							size="sm"
							class="h-8 rounded-lg px-2.5 text-xs"
							disabled={Boolean(mutatingUserId)}
							onclick={() =>
								void transitionMember(member, {
									status: member.status === 'active' ? 'disabled' : 'active'
								})}
						>
							{member.status === 'active' ? 'Disable' : 'Enable'}
						</Button>
					</div>
				</article>
			{/each}
			{#if members.length === 0}
				<p class="text-zeus-muted py-5 text-xs text-center">No members found.</p>
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

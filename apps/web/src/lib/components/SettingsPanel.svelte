<script lang="ts">
	import { onMount } from 'svelte';
	import type { Attachment } from 'svelte/attachments';
	import { Button } from '@zeus/ui/button';
	import { X } from '@zeus/ui/icons';
	import {
		THEME_STORAGE_KEY,
		applyThemePreference,
		parseThemePreference,
		readThemePreference,
		selectThemePreference,
		type ThemePreference
	} from '$lib/theme';
	import type { AccountUser } from '$lib/types';

	interface Props {
		open: boolean;
		user: AccountUser;
		onClose: () => void;
		onLogout: () => Promise<void>;
	}

	const themeOptions: ReadonlyArray<{
		value: ThemePreference;
		label: string;
		description: string;
	}> = [
		{ value: 'system', label: 'System', description: 'Follow this device automatically' },
		{ value: 'light', label: 'Light', description: 'Use the light appearance' },
		{ value: 'dark', label: 'Dark', description: 'Use the dark appearance' }
	];

	let { open, user, onClose, onLogout }: Props = $props();
	let preference = $state<ThemePreference>('system');
	let signingOut = $state(false);
	let logoutError = $state('');

	onMount(() => {
		preference = readThemePreference();
		applyThemePreference(preference);
	});

	function manageDialog(shouldOpen: boolean): Attachment<HTMLDialogElement> {
		return (element) => {
			if (shouldOpen && !element.open) element.showModal();
			if (!shouldOpen && element.open) element.close();
			return () => {
				if (element.open) element.close();
			};
		};
	}

	function chooseTheme(next: ThemePreference) {
		preference = next;
		selectThemePreference(next);
	}

	function handleStorage(event: StorageEvent) {
		if (event.key !== THEME_STORAGE_KEY) return;
		preference = parseThemePreference(event.newValue);
		applyThemePreference(preference);
	}

	function handleBackdropClick(event: MouseEvent) {
		const dialog = event.currentTarget as HTMLDialogElement;
		if (event.target !== dialog) return;
		const bounds = dialog.getBoundingClientRect();
		const inside =
			event.clientX >= bounds.left &&
			event.clientX <= bounds.right &&
			event.clientY >= bounds.top &&
			event.clientY <= bounds.bottom;
		if (!inside) onClose();
	}

	async function signOut() {
		if (signingOut) return;
		signingOut = true;
		logoutError = '';
		try {
			await onLogout();
		} catch (caught) {
			logoutError = caught instanceof Error ? caught.message : 'Sign out failed.';
		} finally {
			signingOut = false;
		}
	}
</script>

<svelte:window onstorage={handleStorage} />

<dialog
	{@attach manageDialog(open)}
	class="border-zeus-border bg-zeus-bg text-zeus-text rounded-2xl p-0 m-auto w-[min(92vw,440px)] border shadow-[0_24px_80px_var(--zeus-shadow)]"
	aria-labelledby="settings-title"
	aria-describedby="settings-description"
	oncancel={(event) => {
		event.preventDefault();
		onClose();
	}}
	onclose={() => {
		if (open) onClose();
	}}
	onclick={handleBackdropClick}
>
	<div class="border-zeus-border h-14 px-5 flex items-center justify-between border-b">
		<h2 id="settings-title" class="font-semibold text-[15px]">Settings</h2>
		<button
			type="button"
			class="text-zeus-muted hover:bg-zeus-surface hover:text-zeus-text size-8 rounded-lg grid place-items-center"
			onclick={onClose}
			aria-label="Close settings"
		>
			<X size={18} aria-hidden="true" />
		</button>
	</div>

	<div class="px-5 py-5">
		<section aria-labelledby="account-title">
			<div class="gap-4 flex items-start justify-between">
				<div class="min-w-0">
					<h3 id="account-title" class="text-sm font-medium">Account</h3>
					<p class="mt-1 text-sm truncate">{user.username}</p>
					<p class="text-zeus-muted mt-0.5 text-[11px] capitalize">
						{user.role} · {user.status}
					</p>
				</div>
				<Button
					variant="outline"
					size="sm"
					class="rounded-lg"
					disabled={signingOut}
					onclick={() => void signOut()}
				>
					{signingOut ? 'Signing out…' : 'Sign out'}
				</Button>
			</div>
			{#if logoutError}
				<p class="text-zeus-red mt-3 text-xs" role="alert">{logoutError}</p>
			{/if}
		</section>

		<div class="border-zeus-border my-5 border-t"></div>

		<div>
			<h3 class="text-sm font-medium">Appearance</h3>
			<p id="settings-description" class="text-zeus-muted mt-1 text-xs leading-5">
				Choose how Zeus looks on this device.
			</p>
		</div>

		<div class="mt-4 gap-2 grid" role="radiogroup" aria-label="Color theme">
			{#each themeOptions as option (option.value)}
				<button
					type="button"
					role="radio"
					aria-checked={preference === option.value}
					class={`border-zeus-border hover:bg-zeus-surface min-h-14 gap-3 rounded-xl px-3.5 py-2.5 flex items-center border text-left transition-colors ${
						preference === option.value ? 'bg-zeus-surface-2' : 'bg-zeus-bg'
					}`}
					onclick={() => chooseTheme(option.value)}
				>
					<span
						class={`border-zeus-border size-4 grid shrink-0 place-items-center rounded-full border ${
							preference === option.value ? 'border-zeus-cyan' : ''
						}`}
						aria-hidden="true"
					>
						{#if preference === option.value}
							<span class="bg-zeus-cyan size-2 rounded-full"></span>
						{/if}
					</span>
					<span class="min-w-0">
						<span class="text-sm font-medium block">{option.label}</span>
						<span class="text-zeus-muted mt-0.5 block text-[11px]">{option.description}</span>
					</span>
				</button>
			{/each}
		</div>

		<p class="text-zeus-muted mt-4 leading-5 text-[11px]">
			Theme preferences stay in this browser and are not sent to the Zeus API.
		</p>
	</div>
</dialog>

<style>
	dialog::backdrop {
		background: rgb(0 0 0 / 45%);
		backdrop-filter: blur(2px);
	}
</style>

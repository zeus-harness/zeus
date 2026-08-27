<script lang="ts">
	import { Button } from '@zeus/ui/button';
	import { Lightning } from '@zeus/ui/icons';
	import type { BootstrapRequest, LoginRequest, MemberSetupRequest } from '$lib/types';

	interface Props {
		configured: boolean;
		onBootstrap: (request: BootstrapRequest) => Promise<void>;
		onLogin: (request: LoginRequest) => Promise<void>;
		onMemberSetup: (request: MemberSetupRequest) => Promise<void>;
	}

	let { configured, onBootstrap, onLogin, onMemberSetup }: Props = $props();
	let bootstrapToken = $state('');
	let memberSetupToken = $state('');
	let username = $state('');
	let password = $state('');
	let submitting = $state(false);
	let error = $state('');
	let memberSetup = $state(false);
	const title = $derived(
		!configured ? 'Set up your owner account' : memberSetup ? 'Finish account setup' : 'Sign in'
	);

	function switchMode() {
		memberSetup = !memberSetup;
		error = '';
		password = '';
		memberSetupToken = '';
	}

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		if (submitting) return;
		submitting = true;
		error = '';
		try {
			if (configured && memberSetup) {
				await onMemberSetup({ setup_token: memberSetupToken.trim(), password });
			} else if (configured) {
				await onLogin({ username: username.trim(), password });
			} else {
				await onBootstrap({
					bootstrap_token: bootstrapToken.trim(),
					username: username.trim(),
					password
				});
			}
		} catch (caught) {
			error = caught instanceof Error ? caught.message : 'Authentication failed.';
		} finally {
			password = '';
			submitting = false;
		}
	}
</script>

<main class="bg-zeus-bg text-zeus-text px-5 py-10 grid min-h-dvh place-items-center">
	<section class="w-full max-w-[380px]" aria-labelledby="auth-title">
		<div class="mb-8 gap-3 flex items-center">
			<span class="size-8 bg-zeus-text text-zeus-bg grid place-items-center rounded-full">
				<Lightning size={18} weight="fill" aria-hidden="true" />
			</span>
			<span class="font-bold text-[15px] tracking-[0.16em]">ZEUS</span>
		</div>

		<h1 id="auth-title" class="font-semibold text-2xl tracking-[-0.025em]">{title}</h1>
		<p class="text-zeus-muted mt-2 text-sm leading-6">
			{configured && memberSetup
				? 'Paste the one-time token from an owner, then choose your password.'
				: configured
					? 'Sign in to continue to this local Zeus instance.'
					: 'Use the one-time bootstrap token printed by the Zeus API when it started.'}
		</p>

		<form class="mt-7 gap-4 grid" onsubmit={submit}>
			{#if !configured}
				<label class="gap-1.5 grid">
					<span class="font-medium text-xs">Bootstrap token</span>
					<input
						bind:value={bootstrapToken}
						type="password"
						name="bootstrap-token"
						autocomplete="off"
						required
						spellcheck="false"
						class="border-zeus-border bg-zeus-bg text-zeus-text focus:border-zeus-cyan h-10 rounded-xl px-3 text-sm border outline-none"
					/>
				</label>
			{/if}
			{#if configured && memberSetup}
				<label class="gap-1.5 grid">
					<span class="font-medium text-xs">Setup token</span>
					<input
						bind:value={memberSetupToken}
						type="password"
						name="member-setup-token"
						autocomplete="off"
						required
						spellcheck="false"
						class="border-zeus-border bg-zeus-bg text-zeus-text focus:border-zeus-cyan h-10 rounded-xl px-3 text-sm border outline-none"
					/>
				</label>
			{/if}

			{#if !memberSetup}
				<label class="gap-1.5 grid">
					<span class="font-medium text-xs">Username</span>
					<input
						bind:value={username}
						type="text"
						name="username"
						autocomplete="username"
						required
						minlength="3"
						maxlength="32"
						pattern="[A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?"
						spellcheck="false"
						class="border-zeus-border bg-zeus-bg text-zeus-text focus:border-zeus-cyan h-10 rounded-xl px-3 text-sm border outline-none"
					/>
				</label>
			{/if}

			<label class="gap-1.5 grid">
				<span class="font-medium text-xs">Password</span>
				<input
					bind:value={password}
					type="password"
					name="password"
					autocomplete={configured && !memberSetup ? 'current-password' : 'new-password'}
					required
					minlength="12"
					class="border-zeus-border bg-zeus-bg text-zeus-text focus:border-zeus-cyan h-10 rounded-xl px-3 text-sm border outline-none"
				/>
				{#if !configured || memberSetup}
					<span class="text-zeus-muted text-[11px]">Use at least 12 characters.</span>
				{/if}
			</label>

			{#if error}
				<p class="text-zeus-red text-xs leading-5" role="alert">{error}</p>
			{/if}

			<Button class="mt-1 h-10 rounded-xl" type="submit" disabled={submitting}>
				{submitting
					? 'Please wait…'
					: configured && memberSetup
						? 'Set password and sign in'
						: configured
							? 'Sign in'
							: 'Create owner account'}
			</Button>
		</form>

		{#if configured}
			<button
				type="button"
				class="text-zeus-muted hover:text-zeus-text mt-5 text-xs mx-auto block underline-offset-4 hover:underline"
				onclick={switchMode}
			>
				{memberSetup ? 'Back to sign in' : 'I have a member setup token'}
			</button>
		{/if}
	</section>
</main>

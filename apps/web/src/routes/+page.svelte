<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '@zeus/ui/button';
	import { Lightning } from '@zeus/ui/icons';
	import AppSidebar from '$lib/components/AppSidebar.svelte';
	import ApprovalPrompt from '$lib/components/ApprovalPrompt.svelte';
	import AuthGate from '$lib/components/AuthGate.svelte';
	import Composer from '$lib/components/Composer.svelte';
	import IncidentHeader from '$lib/components/IncidentHeader.svelte';
	import SettingsPanel from '$lib/components/SettingsPanel.svelte';
	import Timeline from '$lib/components/Timeline.svelte';
	import {
		readActiveSessionId,
		resolveInitialSessionId,
		saveActiveSessionId,
		type ActiveSessionStorage
	} from '$lib/active-session';
	import {
		ApiError,
		bootstrapOwner,
		createSession,
		getAuthStatus,
		getOverview,
		getSession,
		listSessions,
		login,
		logout as logoutOwner,
		mergeEvents,
		resumeSession,
		reviewRun,
		startSessionTurn,
		subscribeToRun,
		subscribeToSession,
		type StreamStatus
	} from '$lib/api';
	import { demoOverview } from '$lib/demo';
	import {
		createTurnAttempt,
		persistTurn,
		type SessionCommandClient,
		type TurnAttempt
	} from '$lib/session-command';
	import {
		clearTurnAttempt,
		loadTurnAttempt,
		mergeSessionEvents,
		orderTimelineEvents,
		saveTurnAttempt,
		turnAttemptDisposition,
		upsertTurn,
		type AttemptStorage
	} from '$lib/session-state';
	import type {
		AuthenticationResponse,
		AuthStatusResponse,
		BootstrapRequest,
		DataSource,
		LoginRequest,
		OverviewResponse,
		ReviewDecision,
		RunEvent,
		SessionDetail,
		SessionEvent,
		SessionSummary,
		StartTurnResponse
	} from '$lib/types';

	const sessionCommandClient: SessionCommandClient = { start: startSessionTurn };

	let authStatus = $state.raw<AuthStatusResponse | null>(null);
	let authLoading = $state(true);
	let authLoadError = $state('');
	let workspaceLoading = $state(false);
	let workspaceReady = $state(false);
	let workspaceError = $state('');
	let overview = $state.raw<OverviewResponse>(demoOverview);
	let events = $state.raw<RunEvent[]>([]);
	let sessions = $state.raw<SessionSummary[]>([]);
	let activeSessionId = $state('');
	let sessionDetail = $state.raw<SessionDetail | null>(null);
	let sessionEvents = $state.raw<SessionEvent[]>([]);
	let source = $state<DataSource>('demo');
	let runStreamStatus = $state<'idle' | StreamStatus>('idle');
	let sessionStreamStatus = $state<'idle' | StreamStatus>('idle');
	let navOpen = $state(false);
	let settingsOpen = $state(false);
	let settingsTrigger = $state.raw<HTMLButtonElement | null>(null);
	let creatingSession = $state(false);
	let createSessionAttempt = $state.raw<{ id: string; key: string } | null>(null);
	let sessionActionError = $state('');
	let pendingDecision = $state<ReviewDecision | null>(null);
	let reviewError = $state('');
	let reviewAttempt = $state<{
		approvalId: string;
		decision: ReviewDecision;
		key: string;
	} | null>(null);
	let composerError = $state('');
	let composerStatusText = $state('Connecting to the durable session…');
	let composerDraft = $state('');
	let pendingTurnAttempt = $state<TurnAttempt | null>(null);
	let turnCommandInFlight = $state(false);
	let resumeAttemptKey = $state<string | null>(null);
	let attemptStorage: AttemptStorage | null = null;
	let activeSessionStorage: ActiveSessionStorage | null = null;
	let pageController: AbortController | null = null;
	let stopRunStream: () => void = () => {};
	let stopSessionStream: () => void = () => {};
	let sessionSelectionEpoch = 0;

	const currentUser = $derived(
		authStatus?.authenticated && authStatus.user ? authStatus.user : null
	);
	const activeSession = $derived(
		sessionDetail?.session ?? sessions.find((session) => session.id === activeSessionId) ?? null
	);
	const attachedToRun = $derived(
		sessionDetail ? sessionDetail.run_ids.includes(overview.run.id) : true
	);
	const latestApprovalEvent = $derived(
		attachedToRun ? events.findLast((event) => event.approval !== undefined) : undefined
	);
	const pendingApprovalEvent = $derived(
		latestApprovalEvent?.approval?.status === 'pending' ? latestApprovalEvent : undefined
	);
	const sessionTimelineEvents = $derived(
		sessionEvents.flatMap((event) => {
			const mapped = sessionEventForTimeline(event);
			return mapped ? [mapped] : [];
		})
	);
	const renderedEvents = $derived(
		orderTimelineEvents([...(attachedToRun ? events : []), ...sessionTimelineEvents])
	);
	const composerSessionStatus = $derived(sessionDetail?.session.status ?? 'running');
	const composerCanRetry = $derived(
		!turnCommandInFlight &&
			pendingTurnAttempt !== null &&
			pendingTurnAttempt.started === undefined &&
			sessionDetail?.session.status === 'ready'
	);
	const streamStatus = $derived.by((): 'idle' | StreamStatus => {
		if (
			sessionStreamStatus === 'reconnecting' ||
			(attachedToRun && runStreamStatus === 'reconnecting')
		) {
			return 'reconnecting';
		}
		if (
			sessionStreamStatus === 'connected' &&
			(!attachedToRun || runStreamStatus === 'connected')
		) {
			return 'connected';
		}
		return 'idle';
	});
	const pageTitle = $derived(
		activeSession && !attachedToRun ? activeSession.title : overview.incident.title
	);
	const documentTitle = $derived(
		currentUser && workspaceReady ? `${pageTitle} · Zeus Harness` : 'Zeus Harness'
	);

	function isAbortError(error: unknown): boolean {
		return error instanceof DOMException && error.name === 'AbortError';
	}

	function authenticatedStatus(response: AuthenticationResponse): AuthStatusResponse {
		return {
			configured: true,
			authenticated: true,
			user: response.user,
			preferences: response.preferences
		};
	}

	function upsertSessionSummary(summary: SessionSummary) {
		sessions = [summary, ...sessions.filter((session) => session.id !== summary.id)];
	}

	function stopWorkspaceStreams() {
		stopRunStream();
		stopSessionStream();
		stopRunStream = () => {};
		stopSessionStream = () => {};
		runStreamStatus = 'idle';
		sessionStreamStatus = 'idle';
	}

	function clearWorkspace() {
		sessionSelectionEpoch += 1;
		stopWorkspaceStreams();
		workspaceReady = false;
		workspaceLoading = false;
		workspaceError = '';
		overview = demoOverview;
		events = [];
		sessions = [];
		activeSessionId = '';
		sessionDetail = null;
		sessionEvents = [];
		pendingTurnAttempt = null;
		createSessionAttempt = null;
		composerDraft = '';
		composerError = '';
		source = 'demo';
	}

	async function refreshOverview() {
		const payload = await getOverview();
		overview = payload;
		source = 'api';
		events = mergeEvents(
			events,
			payload.recent_events.map((event) => ({ ...event, source: 'api' }))
		);
	}

	function sessionEventForTimeline(event: SessionEvent): RunEvent | null {
		const common = {
			id: `session:${event.id}`,
			sequence: event.sequence,
			turn: 0,
			step: 0,
			at: event.at,
			source: 'api' as const,
			stream: 'session' as const
		};
		switch (event.data.kind) {
			case 'user_message':
				return { ...common, type: 'context', title: 'You', summary: event.data.content };
			case 'assistant_message':
				return {
					...common,
					type: 'step',
					title:
						event.data.provenance?.reply_kind === 'non_model_fallback'
							? 'Zeus · local fallback'
							: 'Zeus',
					summary: event.data.content,
					metadata: event.data.provenance?.model
						? { model: event.data.provenance.model }
						: undefined
				};
			case 'turn_interrupted':
				return {
					...common,
					type: 'system',
					title: 'Turn interrupted',
					summary: 'The reply stopped before its durable flush. Resume to continue.'
				};
			default:
				return null;
		}
	}

	function rememberTurnAttempt(sessionId: string, attempt: TurnAttempt) {
		pendingTurnAttempt = attempt;
		saveTurnAttempt(attemptStorage, sessionId, attempt);
	}

	function forgetTurnAttempt(sessionId: string, clearDraft: boolean) {
		pendingTurnAttempt = null;
		clearTurnAttempt(attemptStorage, sessionId);
		if (clearDraft) composerDraft = '';
	}

	function applySessionDetail(detail: SessionDetail): SessionDetail {
		const mergedEvents = mergeSessionEvents(sessionEvents, detail.events);
		sessionEvents = mergedEvents;
		const current = sessionDetail;
		if (
			current &&
			current.session.id === detail.session.id &&
			current.session.sequence > detail.session.sequence
		) {
			const preserved = { ...current, events: mergedEvents };
			sessionDetail = preserved;
			upsertSessionSummary(preserved.session);
			return preserved;
		}
		const canonical = { ...detail, events: mergedEvents };
		sessionDetail = canonical;
		upsertSessionSummary(canonical.session);
		composerStatusText = `Saved through session event ${canonical.session.sequence}`;
		return canonical;
	}

	function applyStartedResponse(started: StartTurnResponse) {
		const current = sessionDetail;
		if (!current || current.session.id !== started.session.id) return;
		const mergedEvents = mergeSessionEvents(sessionEvents, [started.event]);
		sessionEvents = mergedEvents;
		sessionDetail = {
			...current,
			session:
				started.session.sequence >= current.session.sequence ? started.session : current.session,
			turns: upsertTurn(current.turns, started.turn),
			events: mergedEvents
		};
		upsertSessionSummary(sessionDetail.session);
	}

	function settlePendingAttempt(detail: SessionDetail) {
		const attempt = pendingTurnAttempt;
		if (!attempt) return;
		const disposition = turnAttemptDisposition(detail, attempt);
		if (disposition === 'completed') {
			forgetTurnAttempt(detail.session.id, true);
			composerError = '';
			composerStatusText = `Saved through session event ${detail.session.sequence}`;
		} else if (disposition === 'owned_running') {
			composerDraft = '';
			composerError = '';
			composerStatusText = 'Awaiting Zeus reply…';
		} else if (!turnCommandInFlight) {
			forgetTurnAttempt(detail.session.id, false);
			composerDraft = attempt.text;
		}
	}

	async function refreshSession(
		sessionId: string,
		signal?: AbortSignal,
		settleAttempt = true
	): Promise<SessionDetail> {
		const fetched = await getSession(sessionId, signal);
		if (activeSessionId !== sessionId) return fetched;
		const detail = applySessionDetail(fetched);
		if (settleAttempt) settlePendingAttempt(detail);
		return detail;
	}

	async function loadSession(sessionId: string, signal?: AbortSignal): Promise<SessionDetail> {
		const detail = await refreshSession(sessionId, signal, false);
		if (activeSessionId !== sessionId) return detail;
		const storedAttempt = loadTurnAttempt(attemptStorage, sessionId);
		if (!storedAttempt) return detail;

		const disposition = turnAttemptDisposition(detail, storedAttempt);
		if (disposition === 'completed') {
			clearTurnAttempt(attemptStorage, sessionId);
			return detail;
		}
		if (disposition === 'owned_running') {
			rememberTurnAttempt(sessionId, storedAttempt);
			composerDraft = '';
			composerStatusText = 'Awaiting Zeus reply…';
			return detail;
		}

		clearTurnAttempt(attemptStorage, sessionId);
		composerDraft = storedAttempt.text;
		composerStatusText =
			detail.session.status === 'ready'
				? 'A saved draft was restored; send it again when ready.'
				: `Saved through session event ${detail.session.sequence}`;
		return detail;
	}

	async function selectSession(sessionId: string, signal = pageController?.signal) {
		if (!signal || signal.aborted) return;
		const selectionEpoch = ++sessionSelectionEpoch;
		stopSessionStream();
		stopSessionStream = () => {};
		sessionStreamStatus = 'idle';
		activeSessionId = sessionId;
		sessionDetail = null;
		sessionEvents = [];
		pendingTurnAttempt = null;
		composerDraft = '';
		composerError = '';
		composerStatusText = 'Loading session…';

		const detail = await loadSession(sessionId, signal);
		if (signal.aborted || selectionEpoch !== sessionSelectionEpoch) return;
		saveActiveSessionId(activeSessionStorage, sessionId);
		stopSessionStream = subscribeToSession(
			sessionId,
			detail.session.sequence,
			(event) => {
				if (activeSessionId !== sessionId) return;
				sessionEvents = mergeSessionEvents(sessionEvents, [event]);
				void refreshSession(sessionId, signal).catch((error) => {
					if (isAbortError(error)) return;
				});
			},
			(status) => {
				if (activeSessionId === sessionId) sessionStreamStatus = status;
			}
		);
	}

	function connectRunStream(payload: OverviewResponse) {
		stopRunStream();
		runStreamStatus = 'idle';
		stopRunStream = subscribeToRun(
			payload.run.id,
			payload.run.sequence,
			(event) => {
				events = mergeEvents(events, [{ ...event, source: 'api' }]);
				if (
					event.data?.kind === 'approval_decided' ||
					event.data?.kind === 'tool_dispatch_started' ||
					event.data?.kind === 'tool_result'
				) {
					void refreshOverview().catch(() => undefined);
				}
			},
			(status) => (runStreamStatus = status)
		);
	}

	async function initializeWorkspace(signal = pageController?.signal) {
		if (!signal || signal.aborted) return;
		workspaceLoading = true;
		workspaceReady = false;
		workspaceError = '';
		stopWorkspaceStreams();
		try {
			const [payload, listedSessions] = await Promise.all([
				getOverview(signal),
				listSessions(signal)
			]);
			if (signal.aborted) return;
			overview = payload;
			events = payload.recent_events.map((event) => ({ ...event, source: 'api' }));
			sessions = listedSessions;
			source = 'api';
			connectRunStream(payload);
			const initialSessionId = resolveInitialSessionId(
				listedSessions,
				payload.primary_session_id,
				readActiveSessionId(activeSessionStorage)
			);
			try {
				await selectSession(initialSessionId, signal);
			} catch (error) {
				if (initialSessionId === payload.primary_session_id) throw error;
				await selectSession(payload.primary_session_id, signal);
			}
			if (signal.aborted) return;
			workspaceReady = true;
		} catch (error) {
			if (isAbortError(error)) return;
			stopWorkspaceStreams();
			workspaceError =
				error instanceof Error ? error.message : 'The workspace could not be loaded.';
		} finally {
			workspaceLoading = false;
		}
	}

	async function loadAuthentication(signal = pageController?.signal) {
		if (!signal || signal.aborted) return;
		authLoading = true;
		authLoadError = '';
		try {
			const status = await getAuthStatus(signal);
			if (signal.aborted) return;
			authStatus = status;
			if (status.authenticated && status.user) {
				await initializeWorkspace(signal);
			} else {
				clearWorkspace();
			}
		} catch (error) {
			if (isAbortError(error)) return;
			authStatus = null;
			authLoadError =
				error instanceof Error ? error.message : 'Authentication status could not be loaded.';
		} finally {
			authLoading = false;
		}
	}

	async function handleBootstrap(request: BootstrapRequest) {
		const response = await bootstrapOwner(request);
		authStatus = authenticatedStatus(response);
		await initializeWorkspace();
	}

	async function handleLogin(request: LoginRequest) {
		const response = await login(request);
		authStatus = authenticatedStatus(response);
		await initializeWorkspace();
	}

	async function handleLogout() {
		try {
			await logoutOwner();
		} catch (error) {
			if (!(error instanceof ApiError && error.status === 401)) throw error;
		}
		settingsOpen = false;
		clearWorkspace();
		authStatus = { configured: true, authenticated: false };
	}

	async function createNewSession() {
		if (creatingSession) return;
		creatingSession = true;
		sessionActionError = '';
		createSessionAttempt ??= {
			id: `session-${crypto.randomUUID()}`,
			key: crypto.randomUUID()
		};
		try {
			const created = await createSession(
				{ id: createSessionAttempt.id, title: 'New session' },
				createSessionAttempt.key
			);
			createSessionAttempt = null;
			upsertSessionSummary(created.session);
			await selectSession(created.session.id);
		} catch (error) {
			sessionActionError =
				error instanceof Error ? error.message : 'The session could not be created.';
		} finally {
			creatingSession = false;
		}
	}

	async function handleSelectSession(sessionId: string) {
		if (sessionId === activeSessionId && sessionDetail) return;
		sessionActionError = '';
		try {
			await selectSession(sessionId);
		} catch (error) {
			if (isAbortError(error)) return;
			sessionActionError =
				error instanceof Error ? error.message : 'The session could not be loaded.';
		}
	}

	async function handleReview(approvalId: string, decision: ReviewDecision) {
		if (pendingDecision) return;
		pendingDecision = decision;
		reviewError = '';
		if (
			!reviewAttempt ||
			reviewAttempt.approvalId !== approvalId ||
			reviewAttempt.decision !== decision
		) {
			reviewAttempt = { approvalId, decision, key: crypto.randomUUID() };
		}

		try {
			const response = await reviewRun(overview.run.id, approvalId, decision, reviewAttempt.key);
			overview = { ...overview, run: response.run };
			events = mergeEvents(events, [{ ...response.event, source: 'api' }]);
			reviewAttempt = null;
			try {
				await refreshOverview();
			} catch (refreshError) {
				reviewError = `Action recorded, but refresh failed: ${
					refreshError instanceof Error ? refreshError.message : 'unknown error'
				}`;
			}
		} catch (error) {
			const detail = error instanceof Error ? error.message : 'Approval request failed.';
			reviewError =
				error instanceof TypeError
					? `API unavailable; approval was not changed: ${detail}`
					: detail;
		} finally {
			pendingDecision = null;
		}
	}

	function handlePendingReview(decision: ReviewDecision) {
		const approvalId = pendingApprovalEvent?.approval?.id;
		if (!approvalId) return;
		void handleReview(approvalId, decision);
	}

	async function reconcileTurnConflict(
		sessionId: string,
		attempt: TurnAttempt,
		error: ApiError
	): Promise<boolean> {
		let detail: SessionDetail;
		try {
			detail = await refreshSession(sessionId, undefined, false);
		} catch (refreshError) {
			composerError = `The session changed, but its current state could not be loaded: ${
				refreshError instanceof Error ? refreshError.message : 'unknown error'
			}`;
			return false;
		}

		const disposition = turnAttemptDisposition(detail, attempt);
		if (disposition === 'completed') {
			forgetTurnAttempt(sessionId, true);
			composerError = '';
			composerStatusText = `Saved through session event ${detail.session.sequence}`;
			return true;
		}
		if (disposition === 'owned_running' && error.code !== 'idempotency_conflict') {
			rememberTurnAttempt(sessionId, attempt);
			composerDraft = '';
			composerError = '';
			composerStatusText = 'Awaiting Zeus reply…';
			return true;
		}

		forgetTurnAttempt(sessionId, false);
		composerDraft = attempt.text;
		composerError =
			error.code === 'idempotency_conflict'
				? `${error.message}. The stale command was discarded; your draft was kept.`
				: 'The session changed before this command committed; your draft was kept.';
		composerStatusText = `Saved through session event ${detail.session.sequence}`;
		return false;
	}

	async function commitTurnAttempt(sessionId: string, attempt: TurnAttempt): Promise<boolean> {
		if (turnCommandInFlight) return false;
		turnCommandInFlight = true;
		composerError = '';
		composerStatusText = attempt.started ? 'Checking the saved turn…' : 'Starting the turn…';
		try {
			const started = await persistTurn(sessionId, attempt, sessionCommandClient, (response) => {
				applyStartedResponse(response);
			});
			applyStartedResponse(started);
			rememberTurnAttempt(sessionId, attempt);
			composerDraft = '';
			composerError = '';
			composerStatusText = 'Awaiting Zeus reply…';
			return true;
		} catch (error) {
			const current = sessionDetail;
			if (current && turnAttemptDisposition(current, attempt) === 'completed') {
				forgetTurnAttempt(sessionId, true);
				composerError = '';
				composerStatusText = `Saved through session event ${current.session.sequence}`;
				return true;
			}
			if (error instanceof ApiError && error.status === 409) {
				return await reconcileTurnConflict(sessionId, attempt, error);
			}
			composerError = error instanceof Error ? error.message : 'The message could not be saved.';
			return false;
		} finally {
			turnCommandInFlight = false;
		}
	}

	async function persistSessionMessage(value: string): Promise<boolean> {
		const detail = sessionDetail;
		if (!detail || detail.session.status !== 'ready') {
			composerError = 'The session is not ready for a new message.';
			return false;
		}

		let attempt = pendingTurnAttempt;
		if (attempt && attempt.text !== value) {
			composerDraft = attempt.text;
			composerError = 'A previous message may still be starting; its original draft was restored.';
			return false;
		}
		if (!attempt) {
			attempt = createTurnAttempt(value, detail.session.sequence, () => crypto.randomUUID());
			rememberTurnAttempt(detail.session.id, attempt);
		}
		return commitTurnAttempt(detail.session.id, attempt);
	}

	async function retryPendingTurn(): Promise<boolean> {
		const detail = sessionDetail;
		const attempt = pendingTurnAttempt;
		if (!detail || !attempt) return false;
		const disposition = turnAttemptDisposition(detail, attempt);
		if (disposition === 'completed') {
			forgetTurnAttempt(detail.session.id, true);
			return true;
		}
		if (disposition === 'owned_running') {
			composerDraft = '';
			composerStatusText = 'Awaiting Zeus reply…';
			return true;
		}
		if (detail.session.status === 'ready') return commitTurnAttempt(detail.session.id, attempt);
		try {
			await refreshSession(detail.session.id);
		} catch (error) {
			composerError =
				error instanceof Error ? error.message : 'The session could not be refreshed.';
		}
		return false;
	}

	async function resumeCurrentSession() {
		const detail = sessionDetail;
		if (!detail || detail.session.status !== 'needs_attention') return;
		composerError = '';
		resumeAttemptKey ??= crypto.randomUUID();
		try {
			const resumed = await resumeSession(
				detail.session.id,
				detail.session.sequence,
				resumeAttemptKey
			);
			const current = sessionDetail ?? detail;
			const mergedEvents = mergeSessionEvents(sessionEvents, [resumed.event]);
			sessionEvents = mergedEvents;
			sessionDetail = {
				...current,
				session:
					resumed.session.sequence >= current.session.sequence ? resumed.session : current.session,
				events: mergedEvents
			};
			upsertSessionSummary(sessionDetail.session);
			composerStatusText = `Resumed · saved through session event ${resumed.session.sequence}`;
			resumeAttemptKey = null;
		} catch (error) {
			if (error instanceof ApiError && error.status === 409) {
				try {
					const current = await refreshSession(detail.session.id);
					resumeAttemptKey = null;
					if (current.session.status === 'ready') {
						composerError = '';
						composerStatusText = `Resumed · saved through session event ${current.session.sequence}`;
						return;
					}
					composerError = 'The session changed; review its current state and retry.';
					return;
				} catch (refreshError) {
					composerError = `The session changed, but its current state could not be loaded: ${
						refreshError instanceof Error ? refreshError.message : 'unknown error'
					}`;
					return;
				}
			}
			composerError = error instanceof Error ? error.message : 'The session could not be resumed.';
		}
	}

	function openSettings(trigger: HTMLButtonElement) {
		settingsTrigger = trigger;
		settingsOpen = true;
		navOpen = false;
	}

	function closeSettings() {
		settingsOpen = false;
		const trigger = settingsTrigger;
		queueMicrotask(() => trigger?.focus());
	}

	onMount(() => {
		pageController = new AbortController();
		try {
			attemptStorage = window.sessionStorage;
		} catch {
			attemptStorage = null;
		}
		try {
			activeSessionStorage = window.localStorage;
		} catch {
			activeSessionStorage = null;
		}
		void loadAuthentication(pageController.signal);

		return () => {
			pageController?.abort();
			stopWorkspaceStreams();
			pageController = null;
		};
	});
</script>

<svelte:head>
	<title>{documentTitle}</title>
	<meta
		name="description"
		content="Zeus Harness incident response conversation and guarded approval workspace"
	/>
</svelte:head>

{#if authLoading}
	<main class="bg-zeus-bg text-zeus-text grid min-h-dvh place-items-center" aria-busy="true">
		<div class="gap-3 text-zeus-muted text-sm flex items-center">
			<span class="size-8 bg-zeus-text text-zeus-bg grid place-items-center rounded-full">
				<Lightning size={18} weight="fill" aria-hidden="true" />
			</span>
			Checking this Zeus instance…
		</div>
	</main>
{:else if authLoadError}
	<main class="bg-zeus-bg text-zeus-text px-5 grid min-h-dvh place-items-center">
		<section class="w-full max-w-[380px] text-center">
			<h1 class="font-semibold text-lg">Zeus is unavailable</h1>
			<p class="text-zeus-muted mt-2 text-sm leading-6" role="alert">{authLoadError}</p>
			<Button class="mt-5 rounded-xl" variant="outline" onclick={() => void loadAuthentication()}>
				Try again
			</Button>
		</section>
	</main>
{:else if authStatus && !authStatus.authenticated}
	{#key authStatus.configured}
		<AuthGate
			configured={authStatus.configured}
			onBootstrap={handleBootstrap}
			onLogin={handleLogin}
		/>
	{/key}
{:else if currentUser}
	{#if !workspaceReady}
		<main class="bg-zeus-bg text-zeus-text px-5 grid min-h-dvh place-items-center">
			{#if workspaceLoading}
				<p class="text-zeus-muted text-sm" aria-busy="true">Loading your workspace…</p>
			{:else}
				<section class="w-full max-w-[380px] text-center">
					<h1 class="font-semibold text-lg">Workspace unavailable</h1>
					<p class="text-zeus-muted mt-2 text-sm leading-6" role="alert">
						{workspaceError || 'The workspace did not finish loading.'}
					</p>
					<div class="mt-5 gap-2 flex justify-center">
						<Button class="rounded-xl" variant="outline" onclick={() => void initializeWorkspace()}>
							Try again
						</Button>
						<Button class="rounded-xl" variant="ghost" onclick={() => void handleLogout()}>
							Sign out
						</Button>
					</div>
				</section>
			{/if}
		</main>
	{:else}
		<div class="bg-zeus-bg text-zeus-text min-h-0 flex h-dvh overflow-hidden">
			<AppSidebar
				open={navOpen}
				{sessions}
				{activeSessionId}
				{creatingSession}
				{sessionActionError}
				onClose={() => (navOpen = false)}
				onCreateSession={() => void createNewSession()}
				onSelectSession={(sessionId) => void handleSelectSession(sessionId)}
				onOpenSettings={openSettings}
			/>
			<SettingsPanel
				open={settingsOpen}
				user={currentUser}
				onClose={closeSettings}
				onLogout={handleLogout}
			/>

			<div class="min-w-0 flex flex-1 flex-col overflow-hidden">
				<IncidentHeader
					incident={overview.incident}
					run={overview.run}
					session={activeSession}
					{attachedToRun}
					{source}
					{streamStatus}
					onToggleNav={() => (navOpen = true)}
				/>

				<main class="min-h-0 flex flex-1 flex-col overflow-hidden">
					<Timeline events={renderedEvents} />
					{#if pendingApprovalEvent?.approval}
						<ApprovalPrompt
							approval={pendingApprovalEvent.approval}
							summary={pendingApprovalEvent.summary ?? pendingApprovalEvent.approval.action}
							policy={overview.tool_policy}
							{pendingDecision}
							error={reviewError}
							onReview={handlePendingReview}
						/>
					{:else}
						<Composer
							bind:value={composerDraft}
							onSubmit={persistSessionMessage}
							status={composerSessionStatus}
							statusText={composerStatusText}
							error={composerError}
							canRetry={composerCanRetry}
							onRetry={retryPendingTurn}
							onResume={resumeCurrentSession}
						/>
					{/if}
				</main>
			</div>
		</div>
	{/if}
{:else}
	<main class="bg-zeus-bg text-zeus-text px-5 grid min-h-dvh place-items-center">
		<p class="text-zeus-red text-sm">The authentication response was incomplete.</p>
	</main>
{/if}

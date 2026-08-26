<script lang="ts">
	import { onMount } from 'svelte';
	import AppSidebar from '$lib/components/AppSidebar.svelte';
	import ApprovalPrompt from '$lib/components/ApprovalPrompt.svelte';
	import Composer from '$lib/components/Composer.svelte';
	import IncidentHeader from '$lib/components/IncidentHeader.svelte';
	import Timeline from '$lib/components/Timeline.svelte';
	import {
		ApiError,
		flushSessionTurn,
		getOverview,
		getSession,
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
		rebaseOwnedTurnAttempt,
		saveTurnAttempt,
		turnAttemptDisposition,
		upsertTurn,
		type AttemptStorage
	} from '$lib/session-state';
	import type {
		DataSource,
		FlushSessionResponse,
		OverviewResponse,
		ReviewDecision,
		RunEvent,
		SessionDetail,
		SessionEvent,
		StartTurnResponse
	} from '$lib/types';

	const sessionCommandClient: SessionCommandClient = {
		start: startSessionTurn,
		flush: flushSessionTurn
	};

	let overview = $state.raw<OverviewResponse>(demoOverview);
	let events = $state.raw<RunEvent[]>(demoOverview.recent_events);
	let sessionDetail = $state.raw<SessionDetail | null>(null);
	let sessionEvents = $state.raw<SessionEvent[]>([]);
	let source = $state<DataSource>('demo');
	let runStreamStatus = $state<'idle' | StreamStatus>('idle');
	let sessionStreamStatus = $state<'idle' | StreamStatus>('idle');
	let navOpen = $state(false);
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

	const latestApprovalEvent = $derived(events.findLast((event) => event.approval !== undefined));
	const pendingApprovalEvent = $derived(
		latestApprovalEvent?.approval?.status === 'pending' ? latestApprovalEvent : undefined
	);
	const sessionTimelineEvents = $derived(
		sessionEvents.flatMap((event) => {
			const mapped = sessionEventForTimeline(event);
			return mapped ? [mapped] : [];
		})
	);
	const renderedEvents = $derived(orderTimelineEvents([...events, ...sessionTimelineEvents]));
	const composerSessionStatus = $derived(sessionDetail?.session.status ?? 'running');
	const composerCanRetry = $derived(
		!turnCommandInFlight &&
			pendingTurnAttempt !== null &&
			sessionDetail?.session.status === 'running' &&
			sessionDetail.session.active_turn_id === pendingTurnAttempt.turnId
	);
	const streamStatus = $derived.by((): 'idle' | StreamStatus => {
		if (runStreamStatus === 'reconnecting' || sessionStreamStatus === 'reconnecting') {
			return 'reconnecting';
		}
		if (runStreamStatus === 'connected' && sessionStreamStatus === 'connected') return 'connected';
		return 'idle';
	});

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
				return {
					...common,
					type: 'context',
					title: 'Session message',
					summary: event.data.content
				};
			case 'assistant_message':
				return {
					...common,
					type: 'step',
					title: 'Zeus',
					summary: event.data.content
				};
			case 'turn_interrupted':
				return {
					...common,
					type: 'system',
					title: 'Turn interrupted',
					summary: 'The previous turn stopped before its durable flush. Resume to continue.'
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
			return preserved;
		}
		const canonical = { ...detail, events: mergedEvents };
		sessionDetail = canonical;
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
	}

	function applyFlushedResponse(flushed: FlushSessionResponse) {
		const current = sessionDetail;
		if (!current || current.session.id !== flushed.session.id) return;
		const mergedEvents = mergeSessionEvents(sessionEvents, flushed.events);
		sessionEvents = mergedEvents;
		sessionDetail = {
			...current,
			session:
				flushed.session.sequence >= current.session.sequence ? flushed.session : current.session,
			turns: upsertTurn(current.turns, flushed.turn),
			events: mergedEvents
		};
	}

	function settlePendingAttempt(detail: SessionDetail) {
		const attempt = pendingTurnAttempt;
		if (!attempt) return;
		const disposition = turnAttemptDisposition(detail, attempt);
		if (disposition === 'completed') {
			forgetTurnAttempt(detail.session.id, true);
			composerError = '';
			composerStatusText = `Saved through session event ${detail.session.sequence}`;
		} else if (disposition === 'not_owned' && !turnCommandInFlight) {
			forgetTurnAttempt(detail.session.id, false);
			composerDraft = attempt.text;
		}
	}

	async function refreshSession(
		sessionId: string,
		signal?: AbortSignal,
		settleAttempt = true
	): Promise<SessionDetail> {
		const detail = applySessionDetail(await getSession(sessionId, signal));
		if (settleAttempt) settlePendingAttempt(detail);
		return detail;
	}

	async function loadSession(
		sessionId: string,
		signal?: AbortSignal
	): Promise<{ detail: SessionDetail; recoverOwnedTurn: boolean }> {
		const detail = await refreshSession(sessionId, signal, false);
		const storedAttempt = loadTurnAttempt(attemptStorage, sessionId);
		if (!storedAttempt) return { detail, recoverOwnedTurn: false };

		composerDraft = storedAttempt.text;
		const disposition = turnAttemptDisposition(detail, storedAttempt);
		if (disposition === 'completed') {
			clearTurnAttempt(attemptStorage, sessionId);
			composerDraft = '';
			return { detail, recoverOwnedTurn: false };
		}
		if (disposition === 'owned_running') {
			rememberTurnAttempt(sessionId, storedAttempt);
			composerStatusText = 'Recovering this tab’s saved turn…';
			return { detail, recoverOwnedTurn: true };
		}

		clearTurnAttempt(attemptStorage, sessionId);
		composerStatusText =
			detail.session.status === 'ready'
				? 'A saved draft was restored; send it again when ready.'
				: `Saved through session event ${detail.session.sequence}`;
		return { detail, recoverOwnedTurn: false };
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
			const rebased = rebaseOwnedTurnAttempt(attempt, detail.session.sequence, () =>
				crypto.randomUUID()
			);
			rememberTurnAttempt(sessionId, rebased);
			composerDraft = attempt.text;
			composerError = 'The session changed while saving. Retry with the latest durable state.';
			composerStatusText = 'This tab still owns the open turn.';
			return false;
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
		composerStatusText = attempt.started ? 'Retrying the saved turn…' : 'Saving the turn…';
		try {
			const flushed = await persistTurn(sessionId, attempt, sessionCommandClient, (started) => {
				rememberTurnAttempt(sessionId, attempt);
				applyStartedResponse(started);
			});
			applyFlushedResponse(flushed);
			forgetTurnAttempt(sessionId, true);
			composerError = '';
			composerStatusText = `Saved through session event ${flushed.ack.durability_sequence}`;
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
			composerError = 'A previous message may still be saving; its original draft was restored.';
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
		if (turnAttemptDisposition(detail, attempt) === 'completed') {
			forgetTurnAttempt(detail.session.id, true);
			return true;
		}
		if (turnAttemptDisposition(detail, attempt) !== 'owned_running') {
			try {
				await refreshSession(detail.session.id);
			} catch (error) {
				composerError =
					error instanceof Error ? error.message : 'The session could not be refreshed.';
			}
			return false;
		}
		return commitTurnAttempt(detail.session.id, attempt);
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

	onMount(() => {
		const controller = new AbortController();
		let stopRunStream: () => void = () => {};
		let stopSessionStream: () => void = () => {};
		try {
			attemptStorage = window.sessionStorage;
		} catch {
			attemptStorage = null;
		}

		void getOverview(controller.signal)
			.then(async (payload) => {
				overview = payload;
				events = payload.recent_events.map((event) => ({ ...event, source: 'api' }));
				source = 'api';
				const loaded = await loadSession(payload.primary_session_id, controller.signal);
				if (controller.signal.aborted) return;
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
				stopSessionStream = subscribeToSession(
					payload.primary_session_id,
					loaded.detail.session.sequence,
					(event) => {
						sessionEvents = mergeSessionEvents(sessionEvents, [event]);
						void refreshSession(payload.primary_session_id, controller.signal).catch((error) => {
							if (error instanceof DOMException && error.name === 'AbortError') return;
						});
					},
					(status) => (sessionStreamStatus = status)
				);
				if (loaded.recoverOwnedTurn) void retryPendingTurn();
			})
			.catch((error) => {
				if (error instanceof DOMException && error.name === 'AbortError') return;
				source = 'demo';
				runStreamStatus = 'idle';
				sessionStreamStatus = 'idle';
				composerError = 'API unavailable; messages are not accepted in demo mode.';
			});

		return () => {
			controller.abort();
			stopRunStream();
			stopSessionStream();
		};
	});
</script>

<svelte:head>
	<title>{overview.incident.title} · Zeus Harness</title>
	<meta
		name="description"
		content="Zeus Harness incident response conversation and guarded approval workspace"
	/>
</svelte:head>

<div class="bg-zeus-bg text-zeus-text min-h-0 flex h-dvh overflow-hidden">
	<AppSidebar
		open={navOpen}
		incident={overview.incident}
		run={overview.run}
		{source}
		onClose={() => (navOpen = false)}
	/>

	<div class="min-w-0 flex flex-1 flex-col overflow-hidden">
		<IncidentHeader
			incident={overview.incident}
			run={overview.run}
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

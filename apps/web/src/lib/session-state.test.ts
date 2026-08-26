import assert from 'node:assert/strict';
import test from 'node:test';

import type { TurnAttempt } from './session-command.ts';
import {
	attemptTurnNeedsPointLookup,
	clearTurnAttempt,
	loadTurnAttempt,
	mergeSessionEvents,
	orderTimelineEvents,
	ownsTurnAttemptState,
	saveTurnAttempt,
	sessionDisplaysPrimaryRun,
	turnAttemptDisposition,
	type AttemptStorage
} from './session-state.ts';
import type { RunEvent, SessionDetail, SessionEvent, SessionTurnStatus } from './types.ts';

class MemoryStorage implements AttemptStorage {
	readonly values = new Map<string, string>();

	getItem(key: string): string | null {
		return this.values.get(key) ?? null;
	}

	removeItem(key: string): void {
		this.values.delete(key);
	}

	setItem(key: string, value: string): void {
		this.values.set(key, value);
	}
}

function attempt(): TurnAttempt {
	return {
		text: 'hello',
		turnId: 'turn-1',
		startKey: 'start-key',
		expectedSequence: 3,
		started: {
			session: {
				id: 'session-1',
				title: 'Session',
				status: 'running',
				created_at: '2026-08-26T00:00:00Z',
				updated_at: '2026-08-26T00:00:01Z',
				sequence: 4,
				active_turn_id: 'turn-1'
			},
			turn: {
				id: 'turn-1',
				session_id: 'session-1',
				ordinal: 1,
				status: 'open',
				user_message: 'hello',
				started_at: '2026-08-26T00:00:01Z'
			},
			event: {
				id: 'session-1:event:4',
				sequence: 4,
				at: '2026-08-26T00:00:01Z',
				data: { kind: 'user_message', turn_id: 'turn-1', content: 'hello' }
			},
			replayed: false
		}
	};
}

function sessionDetail(
	status: SessionDetail['session']['status'],
	activeTurnId: string | undefined,
	turnStatus: SessionTurnStatus | null
): SessionDetail {
	return {
		session: {
			id: 'session-1',
			title: 'Session',
			status,
			created_at: '2026-08-26T00:00:00Z',
			updated_at: '2026-08-26T00:00:02Z',
			sequence: 5,
			active_turn_id: activeTurnId
		},
		run_ids: [],
		turns:
			turnStatus === null
				? []
				: [
						{
							id: 'turn-1',
							session_id: 'session-1',
							ordinal: 1,
							status: turnStatus,
							user_message: 'hello',
							started_at: '2026-08-26T00:00:01Z'
						}
					],
		events: []
	};
}

function timelineEvent(
	id: string,
	at: string,
	sequence: number,
	stream: 'run' | 'session'
): RunEvent {
	return {
		id,
		at,
		sequence,
		turn: 0,
		step: 0,
		type: 'system',
		title: id,
		stream
	};
}

test('stores command identity but not a stale start response', () => {
	const storage = new MemoryStorage();
	const original = attempt();

	saveTurnAttempt(storage, 'session-1', original);
	const encoded = [...storage.values.values()][0];
	assert.ok(encoded);
	assert.equal(encoded.includes('started'), false);
	assert.deepEqual(loadTurnAttempt(storage, 'session-1'), {
		text: 'hello',
		turnId: 'turn-1',
		startKey: 'start-key',
		expectedSequence: 3
	});

	clearTurnAttempt(storage, 'session-1');
	assert.equal(loadTurnAttempt(storage, 'session-1'), null);
});

test('rejects corrupt stored attempts instead of issuing a command', () => {
	const storage = new MemoryStorage();
	storage.setItem('zeus.session.session-1.turn-attempt', '{"version":1,"turnId":"turn-1"}');

	assert.equal(loadTurnAttempt(storage, 'session-1'), null);
	assert.equal(storage.values.size, 0);
});

test('only the matching open turn is owned by the restored tab attempt', () => {
	const saved = attempt();
	assert.equal(
		turnAttemptDisposition(sessionDetail('running', 'turn-1', 'open'), saved),
		'owned_running'
	);
	assert.equal(
		turnAttemptDisposition(sessionDetail('running', 'turn-other', 'open'), saved),
		'not_owned'
	);
	assert.equal(turnAttemptDisposition(sessionDetail('ready', undefined, null), saved), 'not_owned');
	assert.equal(
		turnAttemptDisposition(sessionDetail('ready', undefined, 'flushed'), saved),
		'completed'
	);
	assert.equal(
		turnAttemptDisposition(sessionDetail('needs_attention', undefined, 'interrupted'), saved),
		'completed'
	);
});

test('uses a point turn when a completed attempt is older than the bounded tail', () => {
	const saved = attempt();
	const detail = sessionDetail('ready', undefined, null);
	detail.pagination = {
		run_ids: { has_more: false },
		turns: { has_more: true, next_before: 'older-turns' },
		events: { has_more: false }
	};
	assert.equal(attemptTurnNeedsPointLookup(detail, saved), true);
	assert.equal(
		turnAttemptDisposition(detail, saved, {
			id: saved.turnId,
			session_id: detail.session.id,
			ordinal: 1,
			status: 'flushed',
			user_message: saved.text,
			assistant_message: 'done',
			started_at: '2026-08-26T00:00:01Z',
			completed_at: '2026-08-26T00:00:02Z'
		}),
		'completed'
	);
});

test('uses primary Session identity instead of a bounded attachment tail', () => {
	assert.equal(sessionDisplaysPrimaryRun('session-primary', 'session-primary'), true);
	assert.equal(sessionDisplaysPrimaryRun('session-later', 'session-primary'), false);
});

test('rejects a deferred point result after Session or attempt identity changes', async () => {
	const expected = attempt();
	let activeSessionId = 'session-1';
	let currentAttempt: TurnAttempt | null = expected;
	let selectionEpoch = 7;
	let releasePoint!: () => void;
	const deferredPoint = new Promise<void>((resolve) => {
		releasePoint = resolve;
	});
	const guardedResult = deferredPoint.then(() =>
		ownsTurnAttemptState(activeSessionId, 'session-1', currentAttempt, expected, selectionEpoch, 7)
	);

	activeSessionId = 'session-2';
	currentAttempt = null;
	selectionEpoch += 1;
	releasePoint();
	assert.equal(await guardedResult, false);
	assert.equal(ownsTurnAttemptState('session-1', 'session-1', expected, expected, 7, 7), true);
	assert.equal(ownsTurnAttemptState('session-1', 'session-1', expected, expected, 8, 7), false);
	assert.equal(
		ownsTurnAttemptState(
			'session-1',
			'session-1',
			{ ...expected, startKey: 'new-key' },
			expected,
			7,
			7
		),
		false
	);
});

test('merges durable session events by ID and sequence', () => {
	const current: SessionEvent[] = [
		{
			id: 'event-2',
			sequence: 2,
			at: '2026-08-26T00:00:02Z',
			data: { kind: 'turn_flushed', turn_id: 'turn-1' }
		}
	];
	const incoming: SessionEvent[] = [
		{
			id: 'event-1',
			sequence: 1,
			at: '2026-08-26T00:00:01Z',
			data: { kind: 'user_message', turn_id: 'turn-1', content: 'hello' }
		},
		{ ...current[0]!, at: '2026-08-26T00:00:03Z' }
	];

	const merged = mergeSessionEvents(current, incoming);
	assert.deepEqual(
		merged.map((event) => event.id),
		['event-1', 'event-2']
	);
	assert.equal(merged[1]?.at, '2026-08-26T00:00:03Z');
});

test('orders the combined timeline by time instead of unrelated stream sequences', () => {
	const ordered = orderTimelineEvents([
		timelineEvent('run-late', '2026-08-26T00:00:03Z', 1, 'run'),
		timelineEvent('session-early', '2026-08-26T00:00:01Z', 99, 'session'),
		timelineEvent('session-tie', '2026-08-26T00:00:02Z', 2, 'session'),
		timelineEvent('run-tie', '2026-08-26T00:00:02Z', 2, 'run')
	]);

	assert.deepEqual(
		ordered.map((event) => event.id),
		['session-early', 'run-tie', 'session-tie', 'run-late']
	);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import type { TurnAttempt } from './session-command.ts';
import {
	clearTurnAttempt,
	loadTurnAttempt,
	mergeSessionEvents,
	orderTimelineEvents,
	rebaseOwnedTurnAttempt,
	saveTurnAttempt,
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
		flushKey: 'flush-key',
		expectedSequence: 3,
		flushExpectedSequence: 4,
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
		flushKey: 'flush-key',
		expectedSequence: 3,
		flushExpectedSequence: 4
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
});

test('rebases only the flush command after an explicit state conflict', () => {
	const rebased = rebaseOwnedTurnAttempt(attempt(), 9, () => 'new-flush-key');

	assert.equal(rebased.turnId, 'turn-1');
	assert.equal(rebased.startKey, 'start-key');
	assert.equal(rebased.expectedSequence, 3);
	assert.equal(rebased.flushKey, 'new-flush-key');
	assert.equal(rebased.flushExpectedSequence, 9);
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

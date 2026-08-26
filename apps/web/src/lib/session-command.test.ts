import assert from 'node:assert/strict';
import test from 'node:test';

import { createTurnAttempt, persistTurn, type SessionCommandClient } from './session-command.ts';
import type { StartTurnResponse } from './types.ts';

function startedResponse(sequence = 4): StartTurnResponse {
	return {
		session: {
			id: 'session-1',
			title: 'Session',
			status: 'running',
			created_at: '2026-08-26T00:00:00Z',
			updated_at: '2026-08-26T00:00:01Z',
			sequence,
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
			sequence,
			at: '2026-08-26T00:00:01Z',
			data: { kind: 'user_message', turn_id: 'turn-1', content: 'hello' }
		},
		replayed: false
	};
}

test('creates stable IDs once for one turn attempt', () => {
	const ids = ['turn-1', 'start-key'];
	const attempt = createTurnAttempt('hello', 3, () => ids.shift()!);
	assert.deepEqual(attempt, {
		text: 'hello',
		turnId: 'turn-1',
		startKey: 'start-key',
		expectedSequence: 3
	});
});

test('a known start response is reused without starting a second turn', async () => {
	let createIdIndex = 0;
	const attempt = createTurnAttempt('hello', 3, () => ['turn-1', 'start-key'][createIdIndex++]!);
	let startCalls = 0;
	const client: SessionCommandClient = {
		start: async () => {
			startCalls += 1;
			return startedResponse();
		}
	};

	const first = await persistTurn('session-1', attempt, client, () => undefined);
	const replayedLocally = await persistTurn('session-1', attempt, client, () => undefined);

	assert.equal(startCalls, 1);
	assert.equal(first, replayedLocally);
});

test('a lost start response is retried with the same request and key', async () => {
	let createIdIndex = 0;
	const attempt = createTurnAttempt('hello', 3, () => ['turn-1', 'start-key'][createIdIndex++]!);
	const startArguments: unknown[][] = [];
	let startCalls = 0;
	const client: SessionCommandClient = {
		start: async (...arguments_) => {
			startCalls += 1;
			startArguments.push(arguments_);
			if (startCalls === 1) throw new TypeError('response lost');
			return { ...startedResponse(), replayed: true };
		}
	};

	await assert.rejects(persistTurn('session-1', attempt, client, () => undefined));
	await persistTurn('session-1', attempt, client, () => undefined);

	assert.deepEqual(startArguments[0], startArguments[1]);
	assert.equal(startArguments[1]?.[2], 'start-key');
});

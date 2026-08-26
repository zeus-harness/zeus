import assert from 'node:assert/strict';
import test from 'node:test';

import { createTurnAttempt, persistTurn, type SessionCommandClient } from './session-command.ts';
import type { FlushSessionResponse, StartTurnResponse } from './types.ts';

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

function flushedResponse(sequence = 5): FlushSessionResponse {
	const started = startedResponse(sequence - 1);
	return {
		session: {
			...started.session,
			status: 'ready',
			sequence,
			active_turn_id: undefined
		},
		turn: {
			...started.turn,
			status: 'flushed',
			completed_at: '2026-08-26T00:00:02Z'
		},
		events: [
			{
				id: 'session-1:event:5',
				sequence,
				at: '2026-08-26T00:00:02Z',
				data: { kind: 'turn_flushed', turn_id: 'turn-1' }
			}
		],
		ack: { session_id: 'session-1', turn_id: 'turn-1', durability_sequence: sequence },
		replayed: false
	};
}

test('creates stable IDs once for one turn attempt', () => {
	const ids = ['turn-1', 'start-key', 'flush-key'];
	const attempt = createTurnAttempt('hello', 3, () => ids.shift()!);
	assert.deepEqual(attempt, {
		text: 'hello',
		turnId: 'turn-1',
		startKey: 'start-key',
		flushKey: 'flush-key',
		expectedSequence: 3
	});
});

test('flush retries reuse the start result and both command IDs', async () => {
	let createIdIndex = 0;
	const attempt = createTurnAttempt(
		'hello',
		3,
		() => ['turn-1', 'start-key', 'flush-key'][createIdIndex++]!
	);
	let startCalls = 0;
	let flushCalls = 0;
	const flushArguments: unknown[][] = [];
	const client: SessionCommandClient = {
		start: async () => {
			startCalls += 1;
			return startedResponse();
		},
		flush: async (...arguments_) => {
			flushCalls += 1;
			flushArguments.push(arguments_);
			if (flushCalls === 1) throw new TypeError('response lost');
			return flushedResponse();
		}
	};

	await assert.rejects(persistTurn('session-1', attempt, client, () => undefined));
	const response = await persistTurn('session-1', attempt, client, () => undefined);

	assert.equal(startCalls, 1);
	assert.equal(flushCalls, 2);
	assert.deepEqual(flushArguments[0], flushArguments[1]);
	assert.equal(flushArguments[1]?.[2], 4);
	assert.equal(flushArguments[1]?.[3], 'flush-key');
	assert.equal(response.ack.durability_sequence, 5);
});

test('a lost start response is retried with the same request and key', async () => {
	let createIdIndex = 0;
	const attempt = createTurnAttempt(
		'hello',
		3,
		() => ['turn-1', 'start-key', 'flush-key'][createIdIndex++]!
	);
	const startArguments: unknown[][] = [];
	let startCalls = 0;
	const client: SessionCommandClient = {
		start: async (...arguments_) => {
			startCalls += 1;
			startArguments.push(arguments_);
			if (startCalls === 1) throw new TypeError('response lost');
			return { ...startedResponse(), replayed: true };
		},
		flush: async () => flushedResponse()
	};

	await assert.rejects(persistTurn('session-1', attempt, client, () => undefined));
	await persistTurn('session-1', attempt, client, () => undefined);

	assert.deepEqual(startArguments[0], startArguments[1]);
	assert.equal(startArguments[1]?.[2], 'start-key');
});

test('an explicitly rebased owned turn flushes at the refreshed sequence', async () => {
	const attempt = {
		...createTurnAttempt('hello', 3, () => 'unused'),
		turnId: 'turn-1',
		startKey: 'start-key',
		flushKey: 'rebased-flush-key',
		flushExpectedSequence: 9,
		started: startedResponse()
	};
	let flushArguments: unknown[] | undefined;
	const client: SessionCommandClient = {
		start: async () => {
			throw new Error('start must not run for an owned open turn');
		},
		flush: async (...arguments_) => {
			flushArguments = arguments_;
			return flushedResponse(10);
		}
	};

	await persistTurn('session-1', attempt, client, () => undefined);

	assert.equal(flushArguments?.[2], 9);
	assert.equal(flushArguments?.[3], 'rebased-flush-key');
});

import type { FlushSessionResponse, StartTurnResponse } from './types.js';

export interface TurnAttempt {
	text: string;
	turnId: string;
	startKey: string;
	flushKey: string;
	expectedSequence: number;
	flushExpectedSequence?: number;
	started?: StartTurnResponse;
}

export interface SessionCommandClient {
	start: (
		sessionId: string,
		request: { turn_id: string; user_message: string; expected_sequence: number },
		idempotencyKey: string
	) => Promise<StartTurnResponse>;
	flush: (
		sessionId: string,
		turnId: string,
		expectedSequence: number,
		idempotencyKey: string
	) => Promise<FlushSessionResponse>;
}

export function createTurnAttempt(
	text: string,
	expectedSequence: number,
	createId: () => string
): TurnAttempt {
	return {
		text,
		turnId: createId(),
		startKey: createId(),
		flushKey: createId(),
		expectedSequence
	};
}

/**
 * Commits a user message and its durability barrier with stable command IDs.
 *
 * `attempt.started` is retained after the first durable start response, so a
 * flush retry never starts a second turn. If the start response is lost, the
 * caller retries the same key and request and storage replays its receipt.
 */
export async function persistTurn(
	sessionId: string,
	attempt: TurnAttempt,
	client: SessionCommandClient,
	onStarted: (response: StartTurnResponse) => void
): Promise<FlushSessionResponse> {
	let started = attempt.started;
	if (!started) {
		started = await client.start(
			sessionId,
			{
				turn_id: attempt.turnId,
				user_message: attempt.text,
				expected_sequence: attempt.expectedSequence
			},
			attempt.startKey
		);
		attempt.started = started;
		attempt.flushExpectedSequence ??= started.session.sequence;
		onStarted(started);
	}

	return client.flush(
		sessionId,
		attempt.turnId,
		attempt.flushExpectedSequence ?? started.session.sequence,
		attempt.flushKey
	);
}

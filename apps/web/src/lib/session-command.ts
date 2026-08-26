import type { StartTurnResponse } from './types.js';

export interface TurnAttempt {
	text: string;
	turnId: string;
	startKey: string;
	expectedSequence: number;
	started?: StartTurnResponse;
}

export interface SessionCommandClient {
	start: (
		sessionId: string,
		request: { turn_id: string; user_message: string; expected_sequence: number },
		idempotencyKey: string
	) => Promise<StartTurnResponse>;
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
		expectedSequence
	};
}

/**
 * Starts a durable turn with a stable command ID.
 *
 * Assistant generation and the final turn flush are owned by the server-side
 * reply worker. If the start response is lost, the caller retries the same key
 * and request so storage can replay its receipt without starting a second turn.
 */
export async function persistTurn(
	sessionId: string,
	attempt: TurnAttempt,
	client: SessionCommandClient,
	onStarted: (response: StartTurnResponse) => void
): Promise<StartTurnResponse> {
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
		onStarted(started);
	}
	return started;
}

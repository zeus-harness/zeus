import type { TurnAttempt } from './session-command.js';
import type { RunEvent, SessionDetail, SessionEvent, SessionTurn } from './types.js';

const STORED_ATTEMPT_VERSION = 2;

export interface AttemptStorage {
	getItem(key: string): string | null;
	removeItem(key: string): void;
	setItem(key: string, value: string): void;
}

interface StoredTurnAttempt {
	version: typeof STORED_ATTEMPT_VERSION;
	text: string;
	turnId: string;
	startKey: string;
	expectedSequence: number;
}

export type TurnAttemptDisposition = 'owned_running' | 'completed' | 'not_owned';

export function sessionDisplaysPrimaryRun(sessionId: string, primarySessionId: string): boolean {
	return sessionId === primarySessionId;
}

export function ownsTurnAttemptState(
	activeSessionId: string,
	expectedSessionId: string,
	current: TurnAttempt | null,
	expected: TurnAttempt,
	currentSelectionEpoch: number,
	expectedSelectionEpoch: number
): boolean {
	return (
		activeSessionId === expectedSessionId &&
		currentSelectionEpoch === expectedSelectionEpoch &&
		current?.turnId === expected.turnId &&
		current.startKey === expected.startKey
	);
}

function attemptStorageKey(sessionId: string): string {
	return `zeus.session.${sessionId}.turn-attempt`;
}

function isNonEmptyString(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0;
}

function isSequence(value: unknown): value is number {
	return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function decodeStoredAttempt(value: unknown): TurnAttempt | null {
	if (!value || typeof value !== 'object') return null;
	const stored = value as Record<string, unknown>;
	if (
		(stored.version !== 1 && stored.version !== STORED_ATTEMPT_VERSION) ||
		!isNonEmptyString(stored.text) ||
		!isNonEmptyString(stored.turnId) ||
		!isNonEmptyString(stored.startKey) ||
		!isSequence(stored.expectedSequence)
	) {
		return null;
	}
	return {
		text: stored.text,
		turnId: stored.turnId,
		startKey: stored.startKey,
		expectedSequence: stored.expectedSequence
	};
}

export function loadTurnAttempt(
	storage: AttemptStorage | null,
	sessionId: string
): TurnAttempt | null {
	if (!storage) return null;
	const key = attemptStorageKey(sessionId);
	try {
		const encoded = storage.getItem(key);
		if (!encoded) return null;
		const attempt = decodeStoredAttempt(JSON.parse(encoded));
		if (!attempt) storage.removeItem(key);
		return attempt;
	} catch {
		try {
			storage.removeItem(key);
		} catch {
			// Storage can be disabled by browser policy; in-memory retries still work.
		}
		return null;
	}
}

export function saveTurnAttempt(
	storage: AttemptStorage | null,
	sessionId: string,
	attempt: TurnAttempt
): void {
	if (!storage) return;
	const stored: StoredTurnAttempt = {
		version: STORED_ATTEMPT_VERSION,
		text: attempt.text,
		turnId: attempt.turnId,
		startKey: attempt.startKey,
		expectedSequence: attempt.expectedSequence
	};
	try {
		storage.setItem(attemptStorageKey(sessionId), JSON.stringify(stored));
	} catch {
		// The command remains retryable in memory if storage is unavailable.
	}
}

export function clearTurnAttempt(storage: AttemptStorage | null, sessionId: string): void {
	if (!storage) return;
	try {
		storage.removeItem(attemptStorageKey(sessionId));
	} catch {
		// Treat unavailable storage as already cleared for this page.
	}
}

export function turnAttemptDisposition(
	detail: SessionDetail,
	attempt: TurnAttempt,
	pointTurn: SessionTurn | null = null
): TurnAttemptDisposition {
	const turn =
		pointTurn?.id === attempt.turnId
			? pointTurn
			: detail.turns.find((candidate) => candidate.id === attempt.turnId);
	if (turn && turn.status !== 'open') return 'completed';
	if (
		detail.session.status === 'running' &&
		detail.session.active_turn_id === attempt.turnId &&
		turn?.status === 'open'
	) {
		return 'owned_running';
	}
	return 'not_owned';
}

export function attemptTurnNeedsPointLookup(detail: SessionDetail, attempt: TurnAttempt): boolean {
	return turnAttemptDisposition(detail, attempt) === 'not_owned';
}

export function mergeSessionEvents(
	current: SessionEvent[],
	incoming: SessionEvent[]
): SessionEvent[] {
	const events = new Map(current.map((event) => [event.id, event]));
	for (const event of incoming) events.set(event.id, event);
	return [...events.values()].sort((left, right) => left.sequence - right.sequence);
}

export function upsertTurn(turns: SessionTurn[], turn: SessionTurn): SessionTurn[] {
	return [...turns.filter((item) => item.id !== turn.id), turn].sort(
		(left, right) => left.ordinal - right.ordinal
	);
}

function eventTime(event: RunEvent): number | null {
	const parsed = Date.parse(event.at);
	return Number.isNaN(parsed) ? null : parsed;
}

function eventTieBreak(event: RunEvent): string {
	return `${event.stream ?? 'run'}:${event.sequence.toString().padStart(20, '0')}:${event.id ?? event.type}`;
}

export function orderTimelineEvents(events: RunEvent[]): RunEvent[] {
	return [...events].sort((left, right) => {
		const leftTime = eventTime(left);
		const rightTime = eventTime(right);
		if (leftTime !== null && rightTime !== null && leftTime !== rightTime) {
			return leftTime - rightTime;
		}
		if (leftTime === null && rightTime === null && left.at !== right.at) {
			return left.at.localeCompare(right.at);
		}
		if (leftTime === null && rightTime !== null) return 1;
		if (leftTime !== null && rightTime === null) return -1;
		return eventTieBreak(left).localeCompare(eventTieBreak(right));
	});
}

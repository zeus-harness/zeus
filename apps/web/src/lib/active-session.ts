import type { SessionSummary } from './types.js';

export const ACTIVE_SESSION_STORAGE_KEY = 'zeus.workspace.active-session.v1';

export interface ActiveSessionStorage {
	getItem(key: string): string | null;
	setItem(key: string, value: string): void;
}

function isPlausibleSessionId(value: string): boolean {
	if (value.length === 0 || value.length > 256 || value.trim() !== value) return false;
	for (const character of value) {
		const codePoint = character.codePointAt(0) ?? 0;
		if (codePoint <= 31 || codePoint === 127) return false;
	}
	return true;
}

export function readActiveSessionId(storage: ActiveSessionStorage | null): string | null {
	if (!storage) return null;
	try {
		const value = storage.getItem(ACTIVE_SESSION_STORAGE_KEY);
		return value && isPlausibleSessionId(value) ? value : null;
	} catch {
		return null;
	}
}

export function saveActiveSessionId(storage: ActiveSessionStorage | null, sessionId: string): void {
	if (!storage || !isPlausibleSessionId(sessionId)) return;
	try {
		storage.setItem(ACTIVE_SESSION_STORAGE_KEY, sessionId);
	} catch {
		// A private or policy-restricted browser can still use the in-memory selection.
	}
}

export function resolveInitialSessionId(
	primarySessionId: string,
	storedSessionId: string | null
): string {
	return storedSessionId ?? primarySessionId;
}

export function resolveInitialSessionFallback(
	primarySessionId: string,
	initialSessionId: string,
	apiErrorStatus: number | null
): string | null {
	return initialSessionId !== primarySessionId && apiErrorStatus === 404 ? primarySessionId : null;
}

export function appendSessionPage(
	current: SessionSummary[],
	incoming: SessionSummary[]
): SessionSummary[] {
	const existing = new Set(current.map((session) => session.id));
	return [...current, ...incoming.filter((session) => !existing.has(session.id))];
}

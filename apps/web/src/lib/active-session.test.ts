import assert from 'node:assert/strict';
import test from 'node:test';

import {
	ACTIVE_SESSION_STORAGE_KEY,
	appendSessionPage,
	readActiveSessionId,
	resolveInitialSessionFallback,
	resolveInitialSessionId,
	saveActiveSessionId,
	type ActiveSessionStorage
} from './active-session.ts';
import type { SessionSummary } from './types.ts';

class MemoryStorage implements ActiveSessionStorage {
	readonly values = new Map<string, string>();

	getItem(key: string): string | null {
		return this.values.get(key) ?? null;
	}

	setItem(key: string, value: string): void {
		this.values.set(key, value);
	}
}

test('uses the stored session as a detail candidate even when it is on a later page', () => {
	assert.equal(resolveInitialSessionId('session-primary', 'session-deep'), 'session-deep');
	assert.equal(resolveInitialSessionId('session-primary', null), 'session-primary');
});

test('falls back from a stored candidate only after an API not-found response', () => {
	assert.equal(
		resolveInitialSessionFallback('session-primary', 'session-deep', 404),
		'session-primary'
	);
	assert.equal(resolveInitialSessionFallback('session-primary', 'session-deep', 500), null);
	assert.equal(resolveInitialSessionFallback('session-primary', 'session-deep', null), null);
	assert.equal(resolveInitialSessionFallback('session-primary', 'session-primary', 404), null);
});

test('appends later pages without reordering or overwriting existing summaries', () => {
	const current = [
		{ id: 'session-active', title: 'Fresh active title' },
		{ id: 'session-first', title: 'First page' }
	] as SessionSummary[];
	const incoming = [
		{ id: 'session-first', title: 'Stale duplicate' },
		{ id: 'session-second', title: 'Second page' }
	] as SessionSummary[];

	assert.deepEqual(
		appendSessionPage(current, incoming).map(({ id, title }) => ({ id, title })),
		[
			{ id: 'session-active', title: 'Fresh active title' },
			{ id: 'session-first', title: 'First page' },
			{ id: 'session-second', title: 'Second page' }
		]
	);
});

test('uses one namespaced key and rejects implausible stored values', () => {
	const storage = new MemoryStorage();
	saveActiveSessionId(storage, 'session-last');

	assert.deepEqual([...storage.values], [[ACTIVE_SESSION_STORAGE_KEY, 'session-last']]);
	assert.equal(readActiveSessionId(storage), 'session-last');
	storage.values.set(ACTIVE_SESSION_STORAGE_KEY, ' session-with-leading-space');
	assert.equal(readActiveSessionId(storage), null);
	storage.values.set(ACTIVE_SESSION_STORAGE_KEY, 'session-with-trailing-space ');
	assert.equal(readActiveSessionId(storage), null);
	storage.values.set(ACTIVE_SESSION_STORAGE_KEY, 'session\u0000injected');
	assert.equal(readActiveSessionId(storage), null);
});

test('storage policy failures degrade to the primary-session path', () => {
	const unavailable: ActiveSessionStorage = {
		getItem() {
			throw new Error('blocked');
		},
		setItem() {
			throw new Error('blocked');
		}
	};

	assert.equal(readActiveSessionId(unavailable), null);
	assert.doesNotThrow(() => saveActiveSessionId(unavailable, 'session-last'));
	assert.equal(resolveInitialSessionId('session-primary', null), 'session-primary');
});

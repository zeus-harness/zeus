import assert from 'node:assert/strict';
import test from 'node:test';

import {
	ACTIVE_SESSION_STORAGE_KEY,
	readActiveSessionId,
	resolveInitialSessionId,
	saveActiveSessionId,
	type ActiveSessionStorage
} from './active-session.ts';

class MemoryStorage implements ActiveSessionStorage {
	readonly values = new Map<string, string>();

	getItem(key: string): string | null {
		return this.values.get(key) ?? null;
	}

	setItem(key: string, value: string): void {
		this.values.set(key, value);
	}
}

test('restores a stored session only while it remains in the API list', () => {
	const sessions = [{ id: 'session-primary' }, { id: 'session-last' }];

	assert.equal(
		resolveInitialSessionId(sessions, 'session-primary', 'session-last'),
		'session-last'
	);
	assert.equal(
		resolveInitialSessionId(sessions, 'session-primary', 'session-deleted'),
		'session-primary'
	);
});

test('uses one namespaced key and rejects implausible stored values', () => {
	const storage = new MemoryStorage();
	saveActiveSessionId(storage, 'session-last');

	assert.deepEqual([...storage.values], [[ACTIVE_SESSION_STORAGE_KEY, 'session-last']]);
	assert.equal(readActiveSessionId(storage), 'session-last');
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
	assert.equal(
		resolveInitialSessionId([{ id: 'session-primary' }], 'session-primary', null),
		'session-primary'
	);
});

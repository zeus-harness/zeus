import assert from 'node:assert/strict';
import test from 'node:test';

import { createStreamAuthorizationProbe } from './stream-auth.ts';
import type { AuthStatusResponse } from './types.ts';

function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (reason?: unknown) => void;
	const promise = new Promise<T>((accept, decline) => {
		resolve = accept;
		reject = decline;
	});
	return { promise, resolve, reject };
}

test('coalesces stream auth checks and reports a revoked durable login once', async () => {
	const status = deferred<AuthStatusResponse>();
	let loads = 0;
	let revoked = 0;
	const probe = createStreamAuthorizationProbe(
		() => {
			loads += 1;
			return status.promise;
		},
		() => {
			revoked += 1;
		}
	);

	probe.check();
	probe.check();
	assert.equal(loads, 1);
	status.resolve({ configured: true, authenticated: false });
	await status.promise;
	await Promise.resolve();

	assert.equal(revoked, 1);
});

test('does not convert a status network failure into a logout', async () => {
	let revoked = 0;
	const probe = createStreamAuthorizationProbe(
		() => Promise.reject(new TypeError('offline')),
		() => {
			revoked += 1;
		}
	);

	probe.check();
	await new Promise((resolve) => setImmediate(resolve));

	assert.equal(revoked, 0);
});

test('ignores a late revoked response after the subscription is stopped', async () => {
	const status = deferred<AuthStatusResponse>();
	let revoked = 0;
	const probe = createStreamAuthorizationProbe(
		() => status.promise,
		() => {
			revoked += 1;
		}
	);

	probe.check();
	probe.stop();
	status.resolve({ configured: true, authenticated: false });
	await status.promise;
	await Promise.resolve();

	assert.equal(revoked, 0);
});

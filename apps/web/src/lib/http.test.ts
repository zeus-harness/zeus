import assert from 'node:assert/strict';
import test from 'node:test';

import { CSRF_HEADER_NAME, readCookie, requestHeaders } from './http.ts';

test('reads the exact URL-encoded cookie value', () => {
	assert.equal(readCookie('zeus_csrf', 'other=x; zeus_csrf=a%2Fb%3D; zeus_csrf_old=no'), 'a/b=');
	assert.equal(readCookie('zeus_csrf', 'zeus_csrf_old=no'), null);
});

test('adds the standard CSRF header to unsafe requests', () => {
	const headers = requestHeaders(
		'POST',
		{ Accept: 'application/json' },
		'zeus_session=opaque; zeus_csrf=csrf-token'
	);

	assert.equal(headers.get(CSRF_HEADER_NAME), 'csrf-token');
	assert.equal(headers.get('Accept'), 'application/json');
	assert.equal([...headers.keys()].filter((name) => name.includes('csrf')).length, 1);
});

test('does not add a CSRF header to safe requests or before the cookie exists', () => {
	assert.equal(
		requestHeaders('GET', undefined, 'zeus_csrf=csrf-token').has(CSRF_HEADER_NAME),
		false
	);
	assert.equal(requestHeaders('PATCH', undefined, '').has(CSRF_HEADER_NAME), false);
});

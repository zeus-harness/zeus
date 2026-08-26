import assert from 'node:assert/strict';
import test from 'node:test';

import { buildSessionListPath } from './session-list.ts';

test('encodes an opaque session-list cursor', () => {
	assert.equal(
		buildSessionListPath({ cursor: 'opaque +/=', limit: 24 }),
		'/api/v1/sessions?cursor=opaque+%2B%2F%3D&limit=24'
	);
	assert.equal(buildSessionListPath({}), '/api/v1/sessions');
});

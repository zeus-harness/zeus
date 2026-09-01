import assert from 'node:assert/strict';
import test from 'node:test';

import { parseEnvFile, totpAt, verificationTokenFromMessage } from './work-item.mjs';

test('parses the ignored E2E environment format without evaluating shell syntax', () => {
  assert.deepEqual(parseEnvFile('ONE=value\nTWO=value with spaces\n# ignored\ninvalid=value\n'), {
    ONE: 'value',
    TWO: 'value with spaces'
  });
});

test('generates RFC 6238 SHA-1 values before applying the Zeus six-digit width', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(totpAt(secret, 59).code, '287082');
  assert.equal(totpAt(secret, 1_111_111_109).code, '081804');
});

test('extracts only an opaque verification token from Mailpit content', () => {
  const token = 'A'.repeat(43);
  assert.equal(
    verificationTokenFromMessage({ Text: `Open http://127.0.0.1/verify-email?token=${token}` }),
    token
  );
  assert.equal(verificationTokenFromMessage({ Text: 'No verification link.' }), null);
});

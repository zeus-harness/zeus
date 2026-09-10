import assert from 'node:assert/strict';
import test from 'node:test';
import { testDatabaseUrl } from './test-postgres.mjs';

const database = `zeus_test_${'a'.repeat(24)}`;

test('database runner cannot target the source database or a remote host', () => {
  assert.throws(() => testDatabaseUrl('postgres://localhost/zeus', 'zeus'));
  assert.throws(() => testDatabaseUrl('postgres://production.example/zeus', database));
  assert.throws(() => testDatabaseUrl('postgres://localhost/zeus?host=production.example', database));
  assert.throws(() => testDatabaseUrl('postgres://localhost/zeus', `${database}; DROP DATABASE zeus`));
});

test('database runner preserves the connection but chooses a fresh database', () => {
  const url = testDatabaseUrl('postgresql://tester@127.0.0.1:55432/zeus', database);
  assert.equal(url.pathname, `/${database}`);
  assert.equal(url.port, '55432');
  assert.equal(url.username, 'tester');
});

test('invalid connection diagnostics do not echo credentials', () => {
  assert.throws(() => testDatabaseUrl('not a URL', database), {
    message: 'ZEUS_TEST_DATABASE_URL must be a PostgreSQL URL.'
  });
});

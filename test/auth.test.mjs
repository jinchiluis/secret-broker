import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newToken, hashToken, hashPassword, verifyPassword } from '../src/auth.mjs';

test('newToken produces distinct, sufficiently long tokens', () => {
  const a = newToken();
  const b = newToken();
  assert.notEqual(a, b);
  assert.ok(a.length >= 32);
});

test('hashToken is deterministic', () => {
  const t = newToken();
  assert.equal(hashToken(t), hashToken(t));
});

test('hashToken does not just echo the input', () => {
  const t = newToken();
  assert.notEqual(hashToken(t), t);
});

test('hashPassword/verifyPassword round-trip', () => {
  const stored = hashPassword('correct horse battery staple 42');
  assert.equal(verifyPassword('correct horse battery staple 42', stored), true);
  assert.equal(verifyPassword('wrong password entirely', stored), false);
});

test('verifyPassword rejects malformed stored values instead of throwing', () => {
  assert.equal(verifyPassword('anything', 'not-a-hash'), false);
  assert.equal(verifyPassword('anything', ''), false);
  assert.equal(verifyPassword('anything', undefined), false);
});

test('two hashes of the same password differ (random salt)', () => {
  const a = hashPassword('same password here');
  const b = hashPassword('same password here');
  assert.notEqual(a, b);
  assert.equal(verifyPassword('same password here', a), true);
  assert.equal(verifyPassword('same password here', b), true);
});

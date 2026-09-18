import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.mjs';
import { createAuditLog } from '../src/audit.mjs';
import * as requests from '../src/requests.mjs';

function setup() {
  const db = openDb(':memory:');
  const audit = createAuditLog(db);
  db.prepare('INSERT INTO devices (id, name, token_hash, created_at) VALUES (?,?,?,?)').run(
    'dev1',
    'laptop',
    'irrelevant-hash',
    new Date().toISOString(),
  );
  const catalog = new Map([
    ['test.normal', { id: 'test.normal', secret: 'test/dummy', fields: ['value'], mode: 'use', level: 'normal', title: 'Normal' }],
    [
      'test.sensitive',
      { id: 'test.sensitive', secret: 'test/dummy', fields: ['value'], mode: 'use', level: 'sensitive', title: 'Sensitive' },
    ],
    ['test.forbidden', { id: 'test.forbidden', secret: 'x/y', fields: ['a'], mode: 'use', level: 'forbidden', title: 'Forbidden' }],
  ]);
  const config = { requestTtlSeconds: 300, grantTtlSeconds: 120 };
  return { db, audit, catalog, config };
}

test('a normal-level capability is auto-approved', () => {
  const { db, audit, catalog, config } = setup();
  const r = requests.createRequest(db, {
    deviceId: 'dev1',
    capability: 'test.normal',
    reason: 'r',
    requestedBy: 'x',
    catalog,
    config,
    audit,
  });
  assert.equal(r.status, 'approved');
  assert.ok(r.collect_deadline);
});

test('a sensitive capability starts pending and notifies', () => {
  const { db, audit, catalog, config } = setup();
  let notified = false;
  const r = requests.createRequest(db, {
    deviceId: 'dev1',
    capability: 'test.sensitive',
    reason: 'r',
    requestedBy: 'x',
    catalog,
    config,
    audit,
    notify: () => {
      notified = true;
    },
  });
  assert.equal(r.status, 'pending');
  assert.equal(notified, true);
});

test('a forbidden capability is rejected with 403', () => {
  const { db, audit, catalog, config } = setup();
  try {
    requests.createRequest(db, { deviceId: 'dev1', capability: 'test.forbidden', reason: 'r', requestedBy: 'x', catalog, config, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 403);
  }
});

test('an unknown capability is 404', () => {
  const { db, audit, catalog, config } = setup();
  try {
    requests.createRequest(db, { deviceId: 'dev1', capability: 'nope', reason: 'r', requestedBy: 'x', catalog, config, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 404);
  }
});

test('a second pending request for the same capability+device is rejected with 409', () => {
  const { db, audit, catalog, config } = setup();
  requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r', requestedBy: 'x', catalog, config, audit });
  try {
    requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r2', requestedBy: 'x', catalog, config, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 409);
  }
});

test('deny leaves the request denied and uncollectable', async () => {
  const { db, audit, catalog, config } = setup();
  const r = requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r', requestedBy: 'x', catalog, config, audit });
  requests.decideRequest(db, r.id, 'deny', { config, audit });
  assert.equal(requests.getRequest(db, r.id).status, 'denied');
  try {
    await requests.collectRequest(db, r.id, 'dev1', { catalog, bao: { readSecret: async () => ({ value: 'x' }) }, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 410);
  }
});

test('approve then collect returns fields once, then 410 on a second collect', async () => {
  const { db, audit, catalog, config } = setup();
  const r = requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r', requestedBy: 'x', catalog, config, audit });
  requests.decideRequest(db, r.id, 'approve', { config, audit });
  const bao = { readSecret: async () => ({ value: 'secret-value' }) };
  const fields = await requests.collectRequest(db, r.id, 'dev1', { catalog, bao, audit });
  assert.deepEqual(fields, { value: 'secret-value' });
  try {
    await requests.collectRequest(db, r.id, 'dev1', { catalog, bao, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 410);
  }
});

test('collecting from a different device than the one that requested it is rejected', async () => {
  const { db, audit, catalog, config } = setup();
  const r = requests.createRequest(db, { deviceId: 'dev1', capability: 'test.normal', reason: 'r', requestedBy: 'x', catalog, config, audit });
  const bao = { readSecret: async () => ({ value: 'x' }) };
  try {
    await requests.collectRequest(db, r.id, 'some-other-device', { catalog, bao, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 404);
  }
});

test('a request past its request TTL expires and cannot be collected', async () => {
  const { db, audit, catalog } = setup();
  const config = { requestTtlSeconds: -1, grantTtlSeconds: 120 };
  const r = requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r', requestedBy: 'x', catalog, config, audit });
  requests.expireStale(db, audit);
  assert.equal(requests.getRequest(db, r.id).status, 'expired');
  try {
    requests.decideRequest(db, r.id, 'approve', { config, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 409);
  }
});

test('an approved-but-uncollected request past its grant TTL expires', () => {
  const { db, audit, catalog, config } = setup();
  const r = requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r', requestedBy: 'x', catalog, config, audit });
  requests.decideRequest(db, r.id, 'approve', { config: { grantTtlSeconds: -1 }, audit });
  requests.expireStale(db, audit);
  assert.equal(requests.getRequest(db, r.id).status, 'expired');
});

test('a secret missing a required field surfaces as a 500, not a partial leak', async () => {
  const { db, audit, catalog, config } = setup();
  const r = requests.createRequest(db, { deviceId: 'dev1', capability: 'test.sensitive', reason: 'r', requestedBy: 'x', catalog, config, audit });
  requests.decideRequest(db, r.id, 'approve', { config, audit });
  const bao = { readSecret: async () => ({}) };
  try {
    await requests.collectRequest(db, r.id, 'dev1', { catalog, bao, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 500);
  }
  assert.equal(requests.getRequest(db, r.id).status, 'collected');
});

test('reason and requested_by length limits are enforced', () => {
  const { db, audit, catalog, config } = setup();
  try {
    requests.createRequest(db, { deviceId: 'dev1', capability: 'test.normal', reason: '', requestedBy: 'x', catalog, config, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 400);
  }
  try {
    requests.createRequest(db, { deviceId: 'dev1', capability: 'test.normal', reason: 'r'.repeat(201), requestedBy: 'x', catalog, config, audit });
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.status, 400);
  }
});

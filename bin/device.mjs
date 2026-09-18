#!/usr/bin/env node
// Run this yourself: node bin/device.mjs add|list|revoke <name>
// "add" prints a new bearer token ONCE - copy it straight into that
// device's .env as SECRET_BROKER_TOKEN. It is never shown again and this
// tool never sends it anywhere.
import { randomBytes, createHash } from 'node:crypto';
import { loadConfig } from '../src/config.mjs';
import { openDb } from '../src/db.mjs';

const [, , cmd, name] = process.argv;

function newId() {
  return randomBytes(16).toString('base64url');
}
function newToken() {
  return randomBytes(32).toString('base64url');
}
function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function usage() {
  console.error('usage: device.mjs add <name> | list | revoke <name>');
  process.exit(2);
}

if (!cmd || !['add', 'list', 'revoke'].includes(cmd)) usage();
if ((cmd === 'add' || cmd === 'revoke') && !name) usage();

const config = loadConfig();
const db = openDb(config.dbPath);

if (cmd === 'add') {
  const existing = db.prepare('SELECT id FROM devices WHERE name = ?').get(name);
  if (existing) {
    console.error(`device "${name}" already exists`);
    process.exit(1);
  }
  const token = newToken();
  db.prepare('INSERT INTO devices (id, name, token_hash, created_at) VALUES (?,?,?,?)').run(
    newId(),
    name,
    hashToken(token),
    new Date().toISOString(),
  );
  console.log(`Device "${name}" created. This token is shown once - put it in that device's .env as SECRET_BROKER_TOKEN:\n`);
  console.log(token);
} else if (cmd === 'list') {
  const rows = db.prepare('SELECT name, created_at, revoked_at FROM devices ORDER BY created_at').all();
  if (rows.length === 0) console.log('No devices registered.');
  for (const d of rows) {
    console.log(`${d.name}\tcreated ${d.created_at}${d.revoked_at ? `\trevoked ${d.revoked_at}` : ''}`);
  }
} else if (cmd === 'revoke') {
  const result = db
    .prepare('UPDATE devices SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL')
    .run(new Date().toISOString(), name);
  console.log(result.changes > 0 ? `Revoked "${name}".` : `No active device named "${name}".`);
}

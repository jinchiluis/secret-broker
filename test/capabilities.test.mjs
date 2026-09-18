import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadCapabilities } from '../src/capabilities.mjs';

function writeCatalog(obj) {
  const dir = mkdtempSync(join(tmpdir(), 'secret-broker-cap-'));
  const path = join(dir, 'capabilities.json');
  writeFileSync(path, JSON.stringify(obj));
  return path;
}

test('loads a valid catalog', () => {
  const path = writeCatalog({
    'test.dummy.read': { secret: 'test/dummy', fields: ['value'], mode: 'use', level: 'sensitive', title: 'Dummy' },
  });
  const catalog = loadCapabilities(path);
  assert.ok(catalog.has('test.dummy.read'));
  assert.equal(catalog.get('test.dummy.read').level, 'sensitive');
  assert.deepEqual(catalog.get('test.dummy.read').fields, ['value']);
});

test('rejects an invalid level', () => {
  const path = writeCatalog({
    'bad.one': { secret: 'x/y', fields: ['a'], mode: 'use', level: 'nope', title: 'Bad' },
  });
  assert.throws(() => loadCapabilities(path), /level/);
});

test('rejects an invalid mode', () => {
  const path = writeCatalog({
    'bad.mode': { secret: 'x/y', fields: ['a'], mode: 'nope', level: 'normal', title: 'Bad' },
  });
  assert.throws(() => loadCapabilities(path), /mode/);
});

test('rejects an empty fields array', () => {
  const path = writeCatalog({
    'bad.two': { secret: 'x/y', fields: [], mode: 'use', level: 'normal', title: 'Bad' },
  });
  assert.throws(() => loadCapabilities(path), /fields/);
});

test('rejects a missing title', () => {
  const path = writeCatalog({
    'bad.three': { secret: 'x/y', fields: ['a'], mode: 'use', level: 'normal' },
  });
  assert.throws(() => loadCapabilities(path), /title/);
});

test('the real policies/capabilities.json in this repo is valid', () => {
  const path = new URL('../policies/capabilities.json', import.meta.url);
  const catalog = loadCapabilities(path);
  assert.ok(catalog.size > 0);
});

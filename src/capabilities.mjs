import { readFileSync } from 'node:fs';

const VALID_MODES = new Set(['use', 'disclose']);
const VALID_LEVELS = new Set(['normal', 'sensitive', 'highly_sensitive', 'forbidden']);

// Loads and validates policies/capabilities.json. Only the user edits that
// file; this just enforces its shape so a typo fails loudly at startup
// rather than silently granting or denying the wrong thing.
export function loadCapabilities(path) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('capabilities file must be a JSON object');
  }
  const catalog = new Map();
  for (const [id, def] of Object.entries(raw)) {
    if (!def || typeof def !== 'object') {
      throw new Error(`capability "${id}": definition must be an object`);
    }
    const { secret, fields, mode, level, title } = def;
    if (typeof secret !== 'string' || secret.length === 0) {
      throw new Error(`capability "${id}": "secret" is required and must be a non-empty string`);
    }
    if (!Array.isArray(fields) || fields.length === 0 || !fields.every((f) => typeof f === 'string' && f.length > 0)) {
      throw new Error(`capability "${id}": "fields" must be a non-empty array of non-empty strings`);
    }
    if (!VALID_MODES.has(mode)) {
      throw new Error(`capability "${id}": "mode" must be one of ${[...VALID_MODES].join(', ')}`);
    }
    if (!VALID_LEVELS.has(level)) {
      throw new Error(`capability "${id}": "level" must be one of ${[...VALID_LEVELS].join(', ')}`);
    }
    if (typeof title !== 'string' || title.length === 0) {
      throw new Error(`capability "${id}": "title" is required and must be a non-empty string`);
    }
    catalog.set(id, { id, secret, fields, mode, level, title });
  }
  return catalog;
}

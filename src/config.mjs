import { existsSync, readFileSync } from 'node:fs';

function loadEnvFile(path) {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[match[1]] = value;
  }
}

const REQUIRED = [
  'BROKER_LISTEN_HOST',
  'BROKER_LISTEN_PORT',
  'BROKER_PUBLIC_URL',
  'BAO_ADDR',
  'BAO_ROLE_ID',
  'BAO_SECRET_ID',
  'NTFY_URL',
  'APPROVER_PASSWORD_HASH',
  'DB_PATH',
  'CAPABILITIES_FILE',
];

const DEFAULTS = {
  REQUEST_TTL_SECONDS: '300',
  GRANT_TTL_SECONDS: '120',
  SESSION_TTL_DAYS: '30',
};

let cached = null;

// Reads config from an env file (default /etc/secret-broker/broker.env, or
// $BROKER_ENV_FILE) plus whatever is already in process.env (process.env
// wins, matching the assistant repo's tools/_shared/env.mjs convention).
// Never logs or returns raw values in error messages beyond key names.
export function loadConfig({ envFile, reload = false } = {}) {
  if (cached && !reload) return cached;
  loadEnvFile(envFile || process.env.BROKER_ENV_FILE || '/etc/secret-broker/broker.env');

  for (const [key, value] of Object.entries(DEFAULTS)) {
    if (process.env[key] === undefined) process.env[key] = value;
  }

  const missing = REQUIRED.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`secret-broker: missing required config keys: ${missing.join(', ')}`);
  }

  const port = Number(process.env.BROKER_LISTEN_PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('secret-broker: BROKER_LISTEN_PORT must be a valid port number');
  }

  cached = Object.freeze({
    listenHost: process.env.BROKER_LISTEN_HOST,
    listenPort: port,
    publicUrl: process.env.BROKER_PUBLIC_URL.replace(/\/$/, ''),
    baoAddr: process.env.BAO_ADDR.replace(/\/$/, ''),
    baoRoleId: process.env.BAO_ROLE_ID,
    baoSecretId: process.env.BAO_SECRET_ID,
    ntfyUrl: process.env.NTFY_URL,
    approverPasswordHash: process.env.APPROVER_PASSWORD_HASH,
    dbPath: process.env.DB_PATH,
    capabilitiesFile: process.env.CAPABILITIES_FILE,
    requestTtlSeconds: Number(process.env.REQUEST_TTL_SECONDS),
    grantTtlSeconds: Number(process.env.GRANT_TTL_SECONDS),
    sessionTtlDays: Number(process.env.SESSION_TTL_DAYS),
  });
  return cached;
}

export function resetConfigForTests() {
  cached = null;
}

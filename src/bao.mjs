export class BaoError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BaoError';
  }
}

// AppRole-authenticated OpenBao client. Holds a client token in memory
// only, renews it before expiry, and re-logs-in if renewal fails. Never
// persists the token, and only ever returns the fields the caller reads,
// never anything else from the vault response.
export function createBaoClient({ baoAddr, roleId, secretId, fetchImpl = fetch }) {
  let token = null;
  let tokenIssuedAt = 0;
  let tokenTtlMs = 0;

  async function login() {
    const res = await fetchImpl(`${baoAddr}/v1/auth/approle/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
    });
    if (!res.ok) throw new BaoError(`AppRole login failed: HTTP ${res.status}`);
    const json = await res.json();
    if (!json?.auth?.client_token) throw new BaoError('AppRole login returned no token');
    token = json.auth.client_token;
    tokenTtlMs = (json.auth.lease_duration || 3600) * 1000;
    tokenIssuedAt = Date.now();
  }

  async function renew() {
    const res = await fetchImpl(`${baoAddr}/v1/auth/token/renew-self`, {
      method: 'POST',
      headers: { 'X-Vault-Token': token },
    });
    if (!res.ok) throw new BaoError(`token renew failed: HTTP ${res.status}`);
    const json = await res.json();
    tokenTtlMs = (json.auth.lease_duration || 3600) * 1000;
    tokenIssuedAt = Date.now();
  }

  async function ensureToken() {
    if (!token) {
      await login();
      return;
    }
    const age = Date.now() - tokenIssuedAt;
    if (age > 0.8 * tokenTtlMs) {
      try {
        await renew();
      } catch {
        await login();
      }
    }
  }

  async function readSecret(path) {
    await ensureToken();
    const res = await fetchImpl(`${baoAddr}/v1/secret/data/${path}`, {
      headers: { 'X-Vault-Token': token },
    });
    if (res.status === 503) throw new BaoError('vault sealed');
    if (res.status === 404) throw new BaoError(`secret not found: ${path}`);
    if (!res.ok) throw new BaoError(`OpenBao read failed for ${path}: HTTP ${res.status}`);
    const json = await res.json();
    const data = json?.data?.data;
    if (!data || typeof data !== 'object') throw new BaoError(`malformed secret response for ${path}`);
    return data;
  }

  async function health() {
    try {
      const res = await fetchImpl(`${baoAddr}/v1/sys/seal-status`);
      if (!res.ok) return 'unreachable';
      const json = await res.json();
      return json.sealed ? 'sealed' : 'unsealed';
    } catch {
      return 'unreachable';
    }
  }

  return { readSecret, health };
}

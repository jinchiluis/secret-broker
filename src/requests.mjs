import { randomBytes } from 'node:crypto';

export class RequestError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'RequestError';
    this.status = status;
  }
}

const MAX_PENDING_PER_DEVICE = 10;

function newId() {
  return randomBytes(16).toString('base64url');
}

function nowIso() {
  return new Date().toISOString();
}

function plusSeconds(iso, seconds) {
  return new Date(new Date(iso).getTime() + seconds * 1000).toISOString();
}

// Marks pending requests past their request TTL, and approved-but-
// uncollected requests past their grant TTL, as expired. Safe to call
// often; cheap no-op when nothing is stale.
export function expireStale(db, audit) {
  const now = nowIso();
  const stalePending = db.prepare("SELECT id FROM requests WHERE status = 'pending' AND expires_at < ?").all(now);
  const staleApproved = db
    .prepare("SELECT id FROM requests WHERE status = 'approved' AND collect_deadline < ?")
    .all(now);
  const update = db.prepare("UPDATE requests SET status = 'expired' WHERE id = ?");
  const staleIds = [...stalePending, ...staleApproved].map((r) => r.id);
  for (const id of staleIds) {
    update.run(id);
    audit?.append('expired', { requestId: id });
  }
  return staleIds;
}

export function createRequest(db, { deviceId, capability, reason, requestedBy, catalog, config, audit, notify }) {
  if (typeof reason !== 'string' || reason.length === 0 || reason.length > 200) {
    throw new RequestError('reason must be 1-200 characters', 400);
  }
  if (typeof requestedBy !== 'string' || requestedBy.length === 0 || requestedBy.length > 60) {
    throw new RequestError('requested_by must be 1-60 characters', 400);
  }
  const def = catalog.get(capability);
  if (!def) throw new RequestError(`unknown capability: ${capability}`, 404);
  if (def.level === 'forbidden') throw new RequestError(`capability is forbidden: ${capability}`, 403);

  expireStale(db, audit);

  const existingPending = db
    .prepare("SELECT id FROM requests WHERE device_id = ? AND capability = ? AND status = 'pending'")
    .get(deviceId, capability);
  if (existingPending) {
    throw new RequestError('a pending request for this capability already exists for this device', 409);
  }

  const pendingCount = db
    .prepare("SELECT COUNT(*) AS n FROM requests WHERE device_id = ? AND status = 'pending'")
    .get(deviceId).n;
  if (pendingCount >= MAX_PENDING_PER_DEVICE) {
    throw new RequestError('too many pending requests for this device', 429);
  }

  const id = newId();
  const createdAt = nowIso();
  const expiresAt = plusSeconds(createdAt, config.requestTtlSeconds);
  const autoApprove = def.level === 'normal';
  const status = autoApprove ? 'approved' : 'pending';
  const decidedAt = autoApprove ? createdAt : null;
  const decidedVia = autoApprove ? 'auto' : null;
  const collectDeadline = autoApprove ? plusSeconds(createdAt, config.grantTtlSeconds) : null;

  db.prepare(
    `INSERT INTO requests
       (id, device_id, capability, level, mode, reason, requested_by, status, created_at, expires_at, decided_at, decided_via, collect_deadline)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    id,
    deviceId,
    capability,
    def.level,
    def.mode,
    reason,
    requestedBy,
    status,
    createdAt,
    expiresAt,
    decidedAt,
    decidedVia,
    collectDeadline,
  );

  audit?.append('created', { requestId: id, detail: { capability, level: def.level, deviceId } });

  if (status === 'pending') {
    notify?.(id, def);
  } else {
    audit?.append('auto_approved', { requestId: id });
  }

  return getRequest(db, id);
}

export function getRequest(db, id) {
  return db.prepare('SELECT * FROM requests WHERE id = ?').get(id) || null;
}

// Only returns the row if it belongs to the given device - this is what
// keeps one device from polling or collecting another device's request.
export function getRequestForDevice(db, id, deviceId) {
  const row = getRequest(db, id);
  if (!row || row.device_id !== deviceId) return null;
  return row;
}

export function decideRequest(db, id, decision, { config, audit } = {}) {
  if (decision !== 'approve' && decision !== 'deny') {
    throw new RequestError('decision must be "approve" or "deny"', 400);
  }
  const row = getRequest(db, id);
  if (!row) throw new RequestError('request not found', 404);
  if (row.status !== 'pending') {
    throw new RequestError(`request is not pending (status: ${row.status})`, 409);
  }

  const decidedAt = nowIso();
  if (decision === 'approve') {
    const collectDeadline = plusSeconds(decidedAt, config.grantTtlSeconds);
    db.prepare(
      "UPDATE requests SET status = 'approved', decided_at = ?, decided_via = 'approver', collect_deadline = ? WHERE id = ?",
    ).run(decidedAt, collectDeadline, id);
    audit?.append('approved', { requestId: id });
  } else {
    db.prepare("UPDATE requests SET status = 'denied', decided_at = ?, decided_via = 'approver' WHERE id = ?").run(
      decidedAt,
      id,
    );
    audit?.append('denied', { requestId: id });
  }
  return getRequest(db, id);
}

// Reads the secret from OpenBao and returns it exactly once. The request
// can never be collected a second time, whether it succeeded or failed.
export async function collectRequest(db, id, deviceId, { catalog, bao, audit }) {
  expireStale(db, audit);
  const row = getRequestForDevice(db, id, deviceId);
  if (!row) throw new RequestError('request not found', 404);
  if (row.status !== 'approved') {
    throw new RequestError(`request is not collectable (status: ${row.status})`, 410);
  }

  const def = catalog.get(row.capability);
  if (!def) throw new RequestError('capability no longer exists in the catalog', 500);

  const secretData = await bao.readSecret(def.secret);
  const fields = {};
  const missing = [];
  for (const field of def.fields) {
    if (!(field in secretData)) missing.push(field);
    else fields[field] = secretData[field];
  }

  db.prepare("UPDATE requests SET status = 'collected', collected_at = ? WHERE id = ?").run(nowIso(), id);

  if (missing.length > 0) {
    audit?.append('missing_field', { requestId: id, detail: { fields: missing } });
    throw new RequestError(`secret "${def.secret}" is missing fields: ${missing.join(', ')}`, 500);
  }

  audit?.append('collected', { requestId: id, detail: { fields: def.fields } });
  return fields;
}

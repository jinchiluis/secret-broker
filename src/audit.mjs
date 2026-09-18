// Higher-level agent audit trail (separate from OpenBao's own audit log).
// `detail` must never contain a secret value - only field NAMES, counts,
// ids, and other non-sensitive metadata. Callers are responsible for that;
// this module just stores whatever JSON it's given.
export function createAuditLog(db) {
  const insert = db.prepare('INSERT INTO audit (ts, request_id, event, detail) VALUES (?, ?, ?, ?)');
  const recentStmt = db.prepare('SELECT * FROM audit ORDER BY seq DESC LIMIT ?');

  return {
    append(event, { requestId = null, detail = {} } = {}) {
      insert.run(new Date().toISOString(), requestId, event, JSON.stringify(detail));
    },
    recent(limit = 200) {
      return recentStmt.all(limit);
    },
  };
}

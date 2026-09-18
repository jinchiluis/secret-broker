import { randomBytes, createHash } from 'node:crypto';

function newSessionToken() {
  return randomBytes(32).toString('base64url');
}

function hashSession(token) {
  return createHash('sha256').update(token).digest('hex');
}

export function createSession(db, { clientIp, ttlDays }) {
  const token = newSessionToken();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + ttlDays * 86_400_000);
  db.prepare('INSERT INTO approver_sessions (id_hash, created_at, expires_at, client_ip) VALUES (?,?,?,?)').run(
    hashSession(token),
    createdAt.toISOString(),
    expiresAt.toISOString(),
    clientIp || null,
  );
  return { token, expiresAt: expiresAt.toISOString() };
}

export function verifySession(db, token) {
  if (!token) return false;
  const row = db.prepare('SELECT * FROM approver_sessions WHERE id_hash = ?').get(hashSession(token));
  if (!row) return false;
  return new Date(row.expires_at).getTime() >= Date.now();
}

export function deleteSession(db, token) {
  if (!token) return;
  db.prepare('DELETE FROM approver_sessions WHERE id_hash = ?').run(hashSession(token));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function page(title, body, { extraHead = '' } = {}) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
${extraHead}
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; background: #0b0f14; color: #e6e6e6; }
  a { color: #8ab4f8; }
  .card { border: 1px solid #333; border-radius: 8px; padding: 1rem; margin: 1rem 0; background: #131820; }
  button { font-size: 1rem; padding: .5rem 1rem; border-radius: 6px; border: 0; cursor: pointer; margin-right: .5rem; }
  .approve { background: #2e7d32; color: #fff; }
  .deny { background: #c62828; color: #fff; }
  input { font-size: 1rem; padding: .4rem; border-radius: 4px; border: 1px solid #555; background: #0b0f14; color: #e6e6e6; width: 100%; box-sizing: border-box; }
  table { width: 100%; border-collapse: collapse; }
  td, th { padding: .35rem .5rem; border-bottom: 1px solid #333; text-align: left; font-size: .9rem; vertical-align: top; }
  .muted { color: #999; font-size: .85rem; }
</style>
</head>
<body>${body}</body>
</html>`;
}

export function loginPage({ error } = {}) {
  return page(
    'Secret Broker — sign in',
    `
<h1>Secret Broker</h1>
${error ? `<p style="color:#e57373">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/approve/login" class="card">
  <label>Approver password<br><input type="password" name="password" autofocus required></label><br><br>
  <button class="approve" type="submit">Sign in</button>
</form>`,
  );
}

function requestRow(r) {
  return `<div class="card">
  <strong>${escapeHtml(r.capability)}</strong> &middot; ${escapeHtml(r.level)} &middot; <span class="muted">${escapeHtml(r.status)}</span><br>
  <span class="muted">${escapeHtml(r.device_name || r.device_id)} &middot; ${escapeHtml(r.created_at)}</span>
  ${r.status === 'pending' ? `<br><a href="/approve/${encodeURIComponent(r.id)}">Review &rarr;</a>` : ''}
</div>`;
}

export function listPage({ pending, decided }) {
  return page(
    'Secret Broker — requests',
    `
<h1>Pending requests</h1>
${pending.length ? pending.map(requestRow).join('') : '<p class="muted">None.</p>'}
<h2>Recently decided</h2>
${decided.length ? decided.map(requestRow).join('') : '<p class="muted">None yet.</p>'}
<p><a href="/approve/audit">Audit log</a> &middot;
<form method="post" action="/approve/logout" style="display:inline"><button type="submit">Sign out</button></form></p>`,
  );
}

export function detailPage({ request, title, lastApproval, otherPending }) {
  const expiresInS = Math.max(0, Math.round((new Date(request.expires_at).getTime() - Date.now()) / 1000));
  return page(
    `Secret Broker — ${title}`,
    `
<h1>${escapeHtml(title)}</h1>
<div class="card">
<table>
<tr><td>Capability</td><td>${escapeHtml(request.capability)}</td></tr>
<tr><td>Level / mode</td><td>${escapeHtml(request.level)} / ${escapeHtml(request.mode)}</td></tr>
<tr><td>Device</td><td>${escapeHtml(request.device_name || request.device_id)}</td></tr>
<tr><td>Reason <span class="muted">(as reported by the assistant)</span></td><td>${escapeHtml(request.reason)}</td></tr>
<tr><td>Requested by</td><td>${escapeHtml(request.requested_by)}</td></tr>
<tr><td>Created</td><td>${escapeHtml(request.created_at)}</td></tr>
<tr><td>Expires in</td><td>${expiresInS}s</td></tr>
<tr><td>Last approval of this capability</td><td>${
      lastApproval ? `${escapeHtml(lastApproval.decided_at)} (${escapeHtml(lastApproval.device_name || lastApproval.device_id)})` : 'never'
    }</td></tr>
<tr><td>Other pending requests</td><td>${otherPending}</td></tr>
</table>
</div>
<form method="post" action="/approve/${encodeURIComponent(request.id)}/decision">
${
  request.level === 'highly_sensitive'
    ? '<label>Approver password <span class="muted">(required for this level)</span><br><input type="password" name="password"></label><br><br>'
    : ''
}
<button class="deny" name="decision" value="deny" type="submit">DENY</button>
<button class="approve" name="decision" value="approve" type="submit">APPROVE ONCE</button>
</form>`,
    { extraHead: '<meta http-equiv="refresh" content="15">' },
  );
}

export function auditPage(rows) {
  const row = (r) =>
    `<tr><td>${escapeHtml(r.ts)}</td><td>${escapeHtml(r.event)}</td><td>${escapeHtml(r.request_id || '')}</td><td>${escapeHtml(r.detail)}</td></tr>`;
  return page(
    'Secret Broker — audit log',
    `
<h1>Audit log</h1>
<p><a href="/approve">&larr; back</a></p>
<table><tr><th>Time</th><th>Event</th><th>Request</th><th>Detail</th></tr>${rows.map(row).join('')}</table>`,
  );
}

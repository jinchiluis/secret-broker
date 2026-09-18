import { createServer } from 'node:http';
import { loadConfig } from './config.mjs';
import { openDb } from './db.mjs';
import { loadCapabilities } from './capabilities.mjs';
import { createBaoClient } from './bao.mjs';
import { createAuditLog } from './audit.mjs';
import { hashToken, verifyPassword } from './auth.mjs';
import { sendNotification } from './ntfy.mjs';
import * as requests from './requests.mjs';
import * as approve from './approve.mjs';

const config = loadConfig();
const db = openDb(config.dbPath);
const catalog = loadCapabilities(config.capabilitiesFile);
const bao = createBaoClient({ baoAddr: config.baoAddr, roleId: config.baoRoleId, secretId: config.baoSecretId });
const audit = createAuditLog(db);

// Background sweep for TTL expiry, independent of any single request path.
setInterval(() => {
  try {
    requests.expireStale(db, audit);
  } catch (error) {
    console.error('secret-broker: expiry sweep failed:', error);
  }
}, 30_000).unref();

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(html);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function requireDevice(req) {
  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer (.+)$/);
  if (!match) return null;
  const device = db
    .prepare('SELECT * FROM devices WHERE token_hash = ? AND revoked_at IS NULL')
    .get(hashToken(match[1]));
  return device || null;
}

async function handleApiRequests(req, res, url, device) {
  if (req.method === 'POST' && url.pathname === '/v1/requests') {
    let body;
    try {
      body = JSON.parse((await readBody(req)) || '{}');
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON body' });
    }
    try {
      const created = requests.createRequest(db, {
        deviceId: device.id,
        capability: body.capability,
        reason: body.reason,
        requestedBy: body.requested_by,
        catalog,
        config,
        audit,
        notify: (id, def) => {
          sendNotification({
            ntfyUrl: config.ntfyUrl,
            title: 'Assistant access request',
            body: `${def.title}\nLevel: ${def.level} · Device: ${device.name}\nReason (self-reported): ${body.reason}\nExpires in ${Math.round(config.requestTtlSeconds / 60)} min`,
            clickUrl: `${config.publicUrl}/approve/${id}`,
          }).then((r) => {
            if (!r.ok) audit.append('ntfy_failed', { requestId: id, detail: r });
          });
        },
      });
      return sendJson(res, 201, {
        id: created.id,
        status: created.status,
        level: created.level,
        mode: created.mode,
        expires_at: created.expires_at,
      });
    } catch (error) {
      return sendJson(res, error.status || 500, { error: error.message });
    }
  }

  const idMatch = url.pathname.match(/^\/v1\/requests\/([^/]+)(\/collect)?$/);
  if (idMatch) {
    const [, id, collect] = idMatch;
    if (req.method === 'GET' && !collect) {
      requests.expireStale(db, audit);
      const row = requests.getRequestForDevice(db, id, device.id);
      if (!row) return sendJson(res, 404, { error: 'not found' });
      return sendJson(res, 200, { id: row.id, status: row.status, expires_at: row.expires_at });
    }
    if (req.method === 'POST' && collect) {
      try {
        const fields = await requests.collectRequest(db, id, device.id, { catalog, bao, audit });
        return sendJson(res, 200, { fields });
      } catch (error) {
        return sendJson(res, error.status || 500, { error: error.message });
      }
    }
  }

  return sendJson(res, 404, { error: 'not found' });
}

async function handleApprove(req, res, url) {
  if (url.pathname === '/approve/login') {
    if (req.method === 'GET') return sendHtml(res, 200, approve.loginPage({}));
    if (req.method === 'POST') {
      const body = new URLSearchParams(await readBody(req));
      const ok = verifyPassword(body.get('password') || '', config.approverPasswordHash);
      audit.append(ok ? 'approver_login_ok' : 'approver_login_failed', {
        detail: { ip: req.socket.remoteAddress },
      });
      if (!ok) {
        await new Promise((r) => setTimeout(r, 1000));
        return sendHtml(res, 401, approve.loginPage({ error: 'Wrong password.' }));
      }
      const { token, expiresAt } = approve.createSession(db, {
        clientIp: req.socket.remoteAddress,
        ttlDays: config.sessionTtlDays,
      });
      const maxAge = Math.max(0, Math.round((new Date(expiresAt).getTime() - Date.now()) / 1000));
      return sendHtml(res, 302, '', {
        location: '/approve',
        'set-cookie': `broker_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/approve; Max-Age=${maxAge}`,
      });
    }
  }

  if (url.pathname === '/approve/logout' && req.method === 'POST') {
    approve.deleteSession(db, parseCookies(req).broker_session);
    return sendHtml(res, 302, '', {
      location: '/approve/login',
      'set-cookie': 'broker_session=; Path=/approve; Max-Age=0',
    });
  }

  const sessionToken = parseCookies(req).broker_session;
  if (!approve.verifySession(db, sessionToken)) {
    return sendHtml(res, 302, '', { location: '/approve/login' });
  }

  requests.expireStale(db, audit);

  if (url.pathname === '/approve' && req.method === 'GET') {
    const pending = db
      .prepare(
        "SELECT r.*, d.name AS device_name FROM requests r JOIN devices d ON d.id = r.device_id WHERE r.status = 'pending' ORDER BY r.created_at DESC",
      )
      .all();
    const decided = db
      .prepare(
        "SELECT r.*, d.name AS device_name FROM requests r JOIN devices d ON d.id = r.device_id WHERE r.status != 'pending' ORDER BY r.created_at DESC LIMIT 20",
      )
      .all();
    return sendHtml(res, 200, approve.listPage({ pending, decided }));
  }

  if (url.pathname === '/approve/audit' && req.method === 'GET') {
    return sendHtml(res, 200, approve.auditPage(audit.recent(200)));
  }

  const idMatch = url.pathname.match(/^\/approve\/([^/]+)(\/decision)?$/);
  if (idMatch) {
    const [, id, decisionPath] = idMatch;
    if (req.method === 'GET' && !decisionPath) {
      const request = db
        .prepare(
          'SELECT r.*, d.name AS device_name FROM requests r JOIN devices d ON d.id = r.device_id WHERE r.id = ?',
        )
        .get(id);
      if (!request) return sendHtml(res, 404, 'not found');
      const def = catalog.get(request.capability);
      const lastApproval = db
        .prepare(
          "SELECT r.*, d.name AS device_name FROM requests r JOIN devices d ON d.id = r.device_id WHERE r.capability = ? AND r.status IN ('approved','collected') AND r.id != ? ORDER BY r.decided_at DESC LIMIT 1",
        )
        .get(request.capability, id);
      const otherPending = db
        .prepare("SELECT COUNT(*) AS n FROM requests WHERE status = 'pending' AND id != ?")
        .get(id).n;
      return sendHtml(
        res,
        200,
        approve.detailPage({ request, title: def?.title || request.capability, lastApproval, otherPending }),
      );
    }
    if (req.method === 'POST' && decisionPath) {
      if ((req.headers.origin || '') !== config.publicUrl) {
        audit.append('approve_bad_origin', { requestId: id, detail: { origin: req.headers.origin || '' } });
        return sendHtml(res, 403, 'bad origin');
      }
      const body = new URLSearchParams(await readBody(req));
      const decision = body.get('decision');
      const request = requests.getRequest(db, id);
      if (request?.level === 'highly_sensitive') {
        const ok = verifyPassword(body.get('password') || '', config.approverPasswordHash);
        if (!ok) {
          audit.append('decision_bad_password', { requestId: id });
          return sendHtml(res, 401, 'wrong password for a highly sensitive approval');
        }
      }
      try {
        requests.decideRequest(db, id, decision, { config, audit });
        return sendHtml(res, 302, '', { location: '/approve' });
      } catch (error) {
        return sendHtml(res, error.status || 500, error.message);
      }
    }
  }

  return sendHtml(res, 404, 'not found');
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/health' && req.method === 'GET') {
      const vault = await bao.health();
      const pending = db.prepare("SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'").get().n;
      return sendJson(res, 200, { ok: true, vault, pending });
    }

    if (url.pathname.startsWith('/approve')) {
      return await handleApprove(req, res, url);
    }

    if (url.pathname.startsWith('/v1/')) {
      const device = requireDevice(req);
      if (!device) return sendJson(res, 401, { error: 'unauthorized' });
      return await handleApiRequests(req, res, url, device);
    }

    return sendJson(res, 404, { error: 'not found' });
  } catch (error) {
    console.error('secret-broker: unhandled error:', error);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(config.listenPort, config.listenHost, () => {
  console.error(`secret-broker listening on ${config.listenHost}:${config.listenPort}`);
});

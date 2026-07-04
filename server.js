// ════════════════════════════════════════════════════════════
//  MelloVibes API — accounts, invite codes, Jellyfin brokering
//  Node + Express + Postgres. Deploy on Railway.
// ════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// ── CORS: allow your frontend origin(s). Set FRONTEND_ORIGIN in Railway (comma-separated). ──
const ORIGINS = (process.env.FRONTEND_ORIGIN || '*').split(',').map(s => s.trim());
app.use(cors({ origin: ORIGINS.includes('*') ? true : ORIGINS }));

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-railway';

const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) {
  console.error('\n[FATAL] DATABASE_URL is not set.\n' +
    'In Railway: open the mellovibes-api service → Variables → New Variable →\n' +
    'Add Reference → select the Postgres service\'s DATABASE_URL. Then redeploy.\n');
  process.exit(1);
}
// Railway's INTERNAL url (postgres.railway.internal) doesn't use SSL; the PUBLIC
// proxy url does. Only enable SSL when it's actually a public/remote host.
const needsSsl = /sslmode=require/i.test(DB_URL) ||
  (!DB_URL.includes('railway.internal') && !DB_URL.includes('localhost') && !DB_URL.includes('127.0.0.1'));
const pool = new Pool({
  connectionString: DB_URL,
  ssl: needsSsl ? { rejectUnauthorized: false } : false
});

// ── DB schema ──
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'Member',
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS invite_codes (
      code TEXT PRIMARY KEY,
      reusable BOOLEAN NOT NULL DEFAULT false,
      grants_admin BOOLEAN NOT NULL DEFAULT false,
      used_by TEXT,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  // Seed an admin account from env (so you're never locked out)
  const adminUser = (process.env.ADMIN_USERNAME || 'mello').toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || 'haven';
  const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [adminUser]);
  if (exists.rowCount === 0) {
    const hash = await bcrypt.hash(adminPass, 10);
    await pool.query(
      'INSERT INTO users (username, name, password_hash, role) VALUES ($1,$2,$3,$4)',
      [adminUser, process.env.ADMIN_NAME || 'Mello', hash, 'Admin']
    );
    console.log(`[seed] created admin user "${adminUser}"`);
  }
  // Seed a starter invite code if none exist
  const codes = await pool.query('SELECT 1 FROM invite_codes LIMIT 1');
  if (codes.rowCount === 0) {
    await pool.query('INSERT INTO invite_codes (code, reusable) VALUES ($1, true)', ['MELLOVIBES']);
    console.log('[seed] created reusable invite code "MELLOVIBES"');
  }
}

// ── Helpers ──
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '60d' });
}
function publicUser(u) { return { id: u.id, username: u.username, name: u.name, role: u.role }; }

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'Admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Routes ──
app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/signup', async (req, res) => {
  try {
    let { name, username, password, code } = req.body || {};
    if (!name || !username || !password || !code) return res.status(400).json({ error: 'All fields are required.' });
    username = String(username).trim().toLowerCase();
    code = String(code).trim().toUpperCase();
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });

    const cr = await pool.query('SELECT * FROM invite_codes WHERE UPPER(code)=$1', [code]);
    const invite = cr.rows[0];
    if (!invite) return res.status(400).json({ error: 'That access code isn’t valid.' });
    if (!invite.reusable && invite.used_by) return res.status(400).json({ error: 'That access code has already been used.' });

    const taken = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
    if (taken.rowCount) return res.status(409).json({ error: 'That username is taken.' });

    const hash = await bcrypt.hash(password, 10);
    const role = invite.grants_admin ? 'Admin' : 'Member';
    const ins = await pool.query(
      'INSERT INTO users (username, name, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING *',
      [username, name.trim(), hash, role]
    );
    if (!invite.reusable) {
      await pool.query('UPDATE invite_codes SET used_by=$1, used_at=now() WHERE code=$2', [username, invite.code]);
    }
    const user = ins.rows[0];
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    let { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
    username = String(username).trim().toLowerCase();
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Incorrect username or password.' });
    }
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
  res.json({ user: publicUser(r.rows[0]) });
});

// ── Invite code management (admin) ──
app.get('/api/invite-codes', auth, adminOnly, async (_req, res) => {
  const r = await pool.query('SELECT code, reusable, grants_admin, used_by, used_at, created_at FROM invite_codes ORDER BY created_at DESC');
  res.json({ codes: r.rows });
});

app.post('/api/invite-codes', auth, adminOnly, async (req, res) => {
  const { reusable = false, grantsAdmin = false } = req.body || {};
  const code = (req.body?.code?.trim().toUpperCase()) || ('MV-' + Math.random().toString(36).slice(2, 8).toUpperCase());
  try {
    await pool.query('INSERT INTO invite_codes (code, reusable, grants_admin) VALUES ($1,$2,$3)', [code, !!reusable, !!grantsAdmin]);
    res.json({ code });
  } catch { res.status(409).json({ error: 'Code already exists' }); }
});

app.delete('/api/invite-codes/:code', auth, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM invite_codes WHERE UPPER(code)=$1', [req.params.code.toUpperCase()]);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
// Jellyfin brokering — per-user profiles
//
// Each MelloVibes account gets its OWN Jellyfin user (mv_<username>), created
// on demand via the admin API, so Continue Watching / My List / watched state
// are personal. The MelloVibes admin account maps to the original Jellyfin
// user (JELLYFIN_USERNAME) so existing watch history is preserved.
// ══════════════════════════════════════════════════════════════
const crypto = require('crypto');
const JF_URL = () => process.env.JELLYFIN_URL;

function jfDeviceHeader(name, deviceId) {
  return `MediaBrowser Client="MelloVibes", Device="${String(name||'Browser').replace(/"/g,'')}", DeviceId="${deviceId}", Version="1.0.0"`;
}
// Deterministic per-account Jellyfin password (never shown to anyone)
function jfUserPassword(username) {
  return crypto.createHmac('sha256', JWT_SECRET).update('jf:' + username).digest('hex').slice(0, 24);
}

async function jfAuthenticate(username, password, deviceName, deviceId) {
  const r = await fetch(`${JF_URL()}/Users/AuthenticateByName`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': jfDeviceHeader(deviceName, deviceId) },
    body: JSON.stringify({ Username: username, Pw: password })
  });
  if (!r.ok) return null;
  return r.json();
}

// Cached admin token (the env account must be a Jellyfin administrator)
let _adminCache = null;
async function jfAdminToken(force = false) {
  if (_adminCache && !force && Date.now() - _adminCache.at < 12 * 3600e3) return _adminCache.token;
  const data = await jfAuthenticate(process.env.JELLYFIN_USERNAME, process.env.JELLYFIN_PASSWORD, 'MelloVibes-API', 'mv-api-admin');
  if (!data) throw new Error('Jellyfin admin auth failed');
  _adminCache = { token: data.AccessToken, at: Date.now() };
  return _adminCache.token;
}
async function jfAdminFetch(path, opts = {}, retried = false) {
  const token = await jfAdminToken();
  const r = await fetch(`${JF_URL()}${path}`, {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'X-Emby-Token': token, ...(opts.headers || {}) }
  });
  if (r.status === 401 && !retried) { await jfAdminToken(true); return jfAdminFetch(path, opts, true); }
  return r;
}

// Find-or-create the Jellyfin user for a MelloVibes account
async function ensureJfUser(mvUsername) {
  const jfName = 'mv_' + mvUsername;
  const list = await (await jfAdminFetch('/Users')).json();
  let u = (list || []).find(x => x.Name && x.Name.toLowerCase() === jfName.toLowerCase());
  if (!u) {
    const cr = await jfAdminFetch('/Users/New', {
      method: 'POST',
      body: JSON.stringify({ Name: jfName, Password: jfUserPassword(mvUsername) })
    });
    if (!cr.ok) throw new Error(`Could not create Jellyfin user (${cr.status})`);
    u = await cr.json();
    // Grant access to all libraries; keep them non-admin
    await jfAdminFetch(`/Users/${u.Id}/Policy`, {
      method: 'POST',
      body: JSON.stringify({
        ...u.Policy, IsAdministrator: false, EnableAllFolders: true,
        EnableMediaPlayback: true, EnablePlaybackRemuxing: true,
        EnableVideoPlaybackTranscoding: true, EnableAudioPlaybackTranscoding: true,
        EnableContentDownloading: false, EnableSyncTranscoding: false, AuthenticationProviderId: u.Policy?.AuthenticationProviderId
      })
    }).catch(() => {});
    console.log(`[jellyfin] created profile user "${jfName}"`);
  }
  return jfName;
}

app.get('/api/jellyfin', auth, async (req, res) => {
  if (!JF_URL() || !process.env.JELLYFIN_USERNAME || !process.env.JELLYFIN_PASSWORD) {
    return res.status(501).json({ error: 'Jellyfin not configured on server' });
  }
  const mvUser = (req.user.username || 'user').toLowerCase();
  const deviceId = 'mv-' + mvUser;
  const isOwner = mvUser === (process.env.ADMIN_USERNAME || 'mello').toLowerCase();
  try {
    let data;
    if (isOwner) {
      // The owner keeps the original Jellyfin user (and all existing watch history)
      data = await jfAuthenticate(process.env.JELLYFIN_USERNAME, process.env.JELLYFIN_PASSWORD, req.user.name, deviceId);
      if (!data) return res.status(502).json({ error: 'Jellyfin auth failed' });
    } else {
      const jfName = await ensureJfUser(mvUser);
      data = await jfAuthenticate(jfName, jfUserPassword(mvUser), req.user.name, deviceId);
      if (!data) {
        // Password drift (e.g. JWT_SECRET changed) → reset via admin and retry once
        const list = await (await jfAdminFetch('/Users')).json();
        const u = (list || []).find(x => x.Name && x.Name.toLowerCase() === jfName.toLowerCase());
        if (u) {
          await jfAdminFetch(`/Users/${u.Id}/Password`, { method: 'POST', body: JSON.stringify({ ResetPassword: true }) });
          await jfAdminFetch(`/Users/${u.Id}/Password`, { method: 'POST', body: JSON.stringify({ CurrentPw: '', NewPw: jfUserPassword(mvUser) }) });
          data = await jfAuthenticate(jfName, jfUserPassword(mvUser), req.user.name, deviceId);
        }
        if (!data) return res.status(502).json({ error: 'Jellyfin profile auth failed' });
      }
    }
    res.json({ url: JF_URL(), token: data.AccessToken, userId: data.User.Id, deviceId, profile: data.User.Name });
  } catch (e) { console.error('[jellyfin broker]', e.message); res.status(502).json({ error: 'Could not reach Jellyfin' }); }
});

// Live "Now Watching" presence for everyone — uses the admin token server-side,
// since per-user tokens can only see their own sessions.
app.get('/api/sessions', auth, async (_req, res) => {
  try {
    const r = await jfAdminFetch('/Sessions');
    if (!r.ok) return res.status(502).json({ error: 'Sessions unavailable' });
    const sessions = await r.json();
    const active = (sessions || []).filter(s => s.NowPlayingItem).map(s => ({
      DeviceId: s.DeviceId, DeviceName: s.DeviceName, UserName: s.UserName,
      NowPlayingItem: {
        Id: s.NowPlayingItem.Id, Name: s.NowPlayingItem.Name,
        SeriesName: s.NowPlayingItem.SeriesName || null, RunTimeTicks: s.NowPlayingItem.RunTimeTicks || 0
      },
      PlayState: { PositionTicks: s.PlayState?.PositionTicks || 0, IsPaused: !!s.PlayState?.IsPaused }
    }));
    res.json({ sessions: active });
  } catch (e) { console.error('[sessions]', e.message); res.status(502).json({ error: 'Could not reach Jellyfin' }); }
});

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`MelloVibes API listening on ${PORT}`)))
  .catch(e => { console.error('DB init failed:', e); process.exit(1); });

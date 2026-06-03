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

// ── Jellyfin brokering: hides server creds from the frontend ──
// The frontend calls this (with its JWT) to get a Jellyfin token, instead of
// embedding the Jellyfin username/password in the page source.
app.get('/api/jellyfin', auth, async (req, res) => {
  const url = process.env.JELLYFIN_URL;
  const user = process.env.JELLYFIN_USERNAME;
  const pass = process.env.JELLYFIN_PASSWORD;
  if (!url || !user || !pass) return res.status(501).json({ error: 'Jellyfin not configured on server' });
  try {
    // Per-account device identity so Jellyfin /Sessions can tell people apart
    const deviceId = 'mv-' + (req.user.username || 'user');
    const authHeader = `MediaBrowser Client="MelloVibes", Device="${(req.user.name||'Browser').replace(/"/g,'')}", DeviceId="${deviceId}", Version="1.0.0"`;
    const r = await fetch(`${url}/Users/AuthenticateByName`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
      body: JSON.stringify({ Username: user, Pw: pass })
    });
    if (!r.ok) return res.status(502).json({ error: 'Jellyfin auth failed', status: r.status });
    const data = await r.json();
    res.json({ url, token: data.AccessToken, userId: data.User.Id, deviceId });
  } catch (e) { console.error(e); res.status(502).json({ error: 'Could not reach Jellyfin' }); }
});

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`MelloVibes API listening on ${PORT}`)))
  .catch(e => { console.error('DB init failed:', e); process.exit(1); });

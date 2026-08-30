import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Pool } from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'url';
import { FLAG_HASHES } from './flags.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 8610);
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error('DATABASE_URL is not configured');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '16kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const TEAMS = ['ALFA', 'BRAVO', 'CHARLY', 'DELTA'];
const FLAGS_PER_TEAM = 25;
const PASSWORDS = {
  ALFA: process.env.ALFA_PASSWORD,
  BRAVO: process.env.BRAVO_PASSWORD,
  CHARLY: process.env.CHARLY_PASSWORD,
  DELTA: process.env.DELTA_PASSWORD
};
const ADMIN_USER = process.env.ADMIN_USER || 'WAZOWSKI';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const sessions = new Map();

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY,
      team TEXT NOT NULL,
      type TEXT NOT NULL,
      flag_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_events_unique_flag ON events(team, type, flag_id)');
}

function newSession(user, role) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { user, role, createdAt: Date.now() });
  return token;
}

function auth(req, res, next) {
  const token = req.get('Authorization')?.replace(/^Bearer\s+/i, '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ error: 'No autorizado' });
  req.session = session;
  next();
}

function adminOnly(req, res, next) {
  if (req.session?.role !== 'admin') return res.status(403).json({ error: 'Solo administrador' });
  next();
}

async function teamState(team) {
  const { rows } = await pool.query(
    'SELECT flag_id FROM events WHERE team = $1 AND type = $2 ORDER BY id',
    [team, 'FLAG_ACCEPTED']
  );
  const ids = [...new Set(rows.map(row => row.flag_id).filter(Boolean))];
  const next = (FLAG_HASHES[team] || []).find(flag => !ids.includes(flag.id))?.id || null;
  return { team, flags: ids.length, total: FLAGS_PER_TEAM, percent: Math.round(ids.length / FLAGS_PER_TEAM * 100), captured: ids, next };
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'dicib-ctf', database: 'connected' });
  } catch {
    res.status(503).json({ ok: false, service: 'dicib-ctf', database: 'unavailable' });
  }
});

app.post('/api/login', (req, res) => {
  const user = String(req.body?.user || '').trim().toUpperCase();
  const password = String(req.body?.password || '');
  let role = null;
  if (user === ADMIN_USER && ADMIN_PASSWORD && password === ADMIN_PASSWORD) role = 'admin';
  else if (TEAMS.includes(user) && PASSWORDS[user] && password === PASSWORDS[user]) role = 'team';
  else return res.status(401).json({ error: 'Credenciales incorrectas' });
  res.json({ token: newSession(user, role), user, role });
});

app.post('/api/logout', auth, (req, res) => {
  const token = req.get('Authorization')?.replace(/^Bearer\s+/i, '');
  sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  if (req.session.role === 'admin') return res.json({ user: req.session.user, role: 'admin' });
  res.json({ user: req.session.user, role: 'team', state: await teamState(req.session.user) });
});

app.post('/api/flags/submit', auth, async (req, res) => {
  if (req.session.role !== 'team') return res.status(403).json({ error: 'Solo equipos' });
  const team = req.session.user;
  const flagId = String(req.body?.flagId || '').trim().toUpperCase();
  const answer = String(req.body?.answer || '').trim();
  const flags = FLAG_HASHES[team] || [];
  const index = flags.findIndex(flag => flag.id === flagId);
  if (index < 0) return res.status(400).json({ accepted: false, error: 'FLAG no válida para este equipo' });

  const previous = index > 0 ? flags[index - 1].id : null;
  if (previous) {
    const unlocked = await pool.query(
      'SELECT 1 FROM events WHERE team=$1 AND flag_id=$2 AND type=$3 LIMIT 1',
      [team, previous, 'FLAG_ACCEPTED']
    );
    if (!unlocked.rowCount) return res.status(409).json({ accepted: false, error: 'Primero debes completar la FLAG anterior' });
  }

  const answerHash = crypto.createHash('sha256').update(answer, 'utf8').digest('hex');
  if (answerHash !== flags[index].hash) return res.status(400).json({ accepted: false, error: 'FLAG incorrecta' });

  await pool.query(
    'INSERT INTO events(team, type, flag_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
    [team, 'FLAG_ACCEPTED', flagId]
  );

  const state = await teamState(team);
  res.json({ accepted: true, state, next: flags[index + 1]?.id || null });
});

app.get('/api/standings', auth, adminOnly, async (_req, res) => {
  const states = await Promise.all(TEAMS.map(teamState));
  const currentStandings = states.sort((a, b) => b.flags - a.flags || a.team.localeCompare(b.team));
  const { rows: events } = await pool.query('SELECT team,type,flag_id,created_at FROM events ORDER BY id DESC LIMIT 50');
  res.json({ standings: currentStandings, events });
});

app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/*splat', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

initDatabase()
  .then(() => app.listen(PORT, () => console.log(`CTF backend listening on port ${PORT}`)))
  .catch(error => {
    console.error('Database initialization failed:', error);
    process.exit(1);
  });

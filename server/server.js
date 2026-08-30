import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FLAG_HASHES } from './flags.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, 'ctf.sqlite'));
const PORT = Number(process.env.PORT || 8610);
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) console.warn('SESSION_SECRET is not configured; in-memory sessions still work for this instance.');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '16kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const TEAMS = ['ALFA', 'BRAVO', 'CHARLY', 'DELTA'];
const FLAGS_PER_TEAM = 25;
const PASSWORDS = { ALFA: process.env.ALFA_PASSWORD, BRAVO: process.env.BRAVO_PASSWORD, CHARLY: process.env.CHARLY_PASSWORD, DELTA: process.env.DELTA_PASSWORD };
const ADMIN_USER = process.env.ADMIN_USER || 'WAZOWSKI';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const sessions = new Map();

db.exec(`CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  team TEXT NOT NULL,
  type TEXT NOT NULL,
  flag_id TEXT,
  created_at TEXT NOT NULL
)`);

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
function teamState(team) {
  const rows = db.prepare('SELECT flag_id FROM events WHERE team = ? AND type = ? ORDER BY id').all(team, 'FLAG_ACCEPTED');
  const ids = new Set(rows.map(r => r.flag_id));
  const next = (FLAG_HASHES[team] || []).find(f => !ids.has(f.id))?.id || null;
  return { team, flags: ids.size, total: FLAGS_PER_TEAM, percent: Math.round(ids.size / FLAGS_PER_TEAM * 100), captured: [...ids], next };
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'dicib-ctf' }));

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

app.get('/api/me', auth, (req, res) => {
  if (req.session.role === 'admin') return res.json({ user: req.session.user, role: 'admin' });
  res.json({ user: req.session.user, role: 'team', state: teamState(req.session.user) });
});

app.post('/api/flags/submit', auth, (req, res) => {
  if (req.session.role !== 'team') return res.status(403).json({ error: 'Solo equipos' });
  const team = req.session.user;
  const flagId = String(req.body?.flagId || '').trim().toUpperCase();
  const answer = String(req.body?.answer || '').trim();
  const flags = FLAG_HASHES[team] || [];
  const index = flags.findIndex(f => f.id === flagId);
  if (index < 0) return res.status(400).json({ accepted: false, error: 'FLAG no válida para este equipo' });
  const previous = index > 0 ? flags[index - 1].id : null;
  if (previous) {
    const unlocked = db.prepare('SELECT 1 FROM events WHERE team=? AND flag_id=? AND type=?').get(team, previous, 'FLAG_ACCEPTED');
    if (!unlocked) return res.status(409).json({ accepted: false, error: 'Primero debes completar la FLAG anterior' });
  }
  const answerHash = crypto.createHash('sha256').update(answer, 'utf8').digest('hex');
  if (answerHash !== flags[index].hash) return res.status(400).json({ accepted: false, error: 'FLAG incorrecta' });
  const exists = db.prepare('SELECT 1 FROM events WHERE team=? AND flag_id=? AND type=?').get(team, flagId, 'FLAG_ACCEPTED');
  if (!exists) db.prepare('INSERT INTO events(team,type,flag_id,created_at) VALUES(?,?,?,?)').run(team, 'FLAG_ACCEPTED', flagId, new Date().toISOString());
  res.json({ accepted: true, state: teamState(team), next: flags[index + 1]?.id || null });
});

app.get('/api/standings', auth, adminOnly, (req, res) => {
  const standings = TEAMS.map(teamState).sort((a, b) => b.flags - a.flags);
  const events = db.prepare('SELECT team,type,flag_id,created_at FROM events ORDER BY id DESC LIMIT 30').all();
  res.json({ standings, events });
});

// Serve the team page with a small visual objective overlay that uses the server's next flag ID.
app.get('/', (_req, res) => {
  let html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  const overlay = `<style>#nextObjective{margin-top:18px;padding:18px;border:1px solid #0b5870;background:rgba(0,0,0,.22);box-shadow:inset 0 0 20px rgba(0,229,255,.03)}#nextObjective .next-id{display:inline-block;margin-top:8px;padding:10px 16px;border:1px solid var(--cyan);color:var(--cyan);font-size:22px;letter-spacing:3px;text-shadow:0 0 12px rgba(0,229,255,.55)}</style><script>(function(){const originalFetch=window.fetch;window.fetch=async function(){const response=await originalFetch.apply(this,arguments);try{const url=String(arguments[0]||'');if(url==='/api/me'){const copy=response.clone();const data=await copy.json();if(data.state){let box=document.getElementById('nextObjective');if(!box){const validator=document.getElementById('submitFlag')?.parentElement;if(validator){box=document.createElement('div');box.id='nextObjective';validator.appendChild(box)}}if(box){box.innerHTML=data.state.next?'<div class="muted">// NEXT OBJECTIVE</div><div class="next-id">'+data.state.next+'</div><div class="muted" style="margin-top:8px">Analiza el siguiente evento de red.</div>':'<div class="ok">// OBJECTIVE COMPLETE // ALL FLAGS CAPTURED</div>'}}}}catch(e){}return response};})();</script>`;
  html = html.replace('</body>', overlay + '</body>');
  res.type('html').send(html);
});

app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/*splat', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));
app.listen(PORT, () => console.log(`CTF backend listening on port ${PORT}`));

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

const TEAMS = ['ALFA', 'BRAVO', 'CHARLIE', 'DELTA'];
const FLAGS_PER_TEAM = 25;
const PASSWORDS = {
  ALFA: process.env.ALFA_PASSWORD,
  BRAVO: process.env.BRAVO_PASSWORD,
  CHARLIE: process.env.CHARLIE_PASSWORD,
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

// Admin-only reset controls. These delete progress events only; users and flag definitions remain intact.
app.post('/api/admin/reset-all', auth, adminOnly, async (_req, res) => {
  try {
    const result = await pool.query("DELETE FROM events WHERE type = 'FLAG_ACCEPTED'");
    const states = await Promise.all(TEAMS.map(teamState));
    res.json({ ok: true, scope: 'all', deleted: result.rowCount, standings: states });
  } catch (error) {
    console.error('Reset all failed:', error);
    res.status(500).json({ ok: false, error: 'No se pudo restablecer el reto completo' });
  }
});

app.post('/api/admin/reset-team', auth, adminOnly, async (req, res) => {
  const team = String(req.body?.team || '').trim().toUpperCase();
  if (!TEAMS.includes(team)) return res.status(400).json({ ok: false, error: 'Equipo no válido' });
  try {
    const result = await pool.query("DELETE FROM events WHERE team = $1 AND type = 'FLAG_ACCEPTED'", [team]);
    res.json({ ok: true, scope: 'team', team, deleted: result.rowCount, state: await teamState(team) });
  } catch (error) {
    console.error(`Reset ${team} failed:`, error);
    res.status(500).json({ ok: false, error: `No se pudo restablecer ${team}` });
  }
});

// Generates a valid PCAP directly from the server. This avoids serving a corrupted
// or incorrectly encoded binary file from the static directory.
function ipChecksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) sum += buf.readUInt16BE(i);
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

function ipv4(addr) {
  return Buffer.from(addr.split('.').map(Number));
}

function ethernetIpv4Udp(src, dst, sport, dport, payload) {
  const eth = Buffer.from('aabbccddeeffaabbccddeeff0800', 'hex');
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(sport, 0); udp.writeUInt16BE(dport, 2);
  udp.writeUInt16BE(8 + payload.length, 4); udp.writeUInt16BE(0, 6);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip.writeUInt16BE(20 + udp.length + payload.length, 2);
  ip.writeUInt16BE(0x4000, 6); ip[8] = 64; ip[9] = 17;
  ipv4(src).copy(ip, 12); ipv4(dst).copy(ip, 16); ip.writeUInt16BE(ipChecksum(ip), 10);
  return Buffer.concat([eth, ip, udp, payload]);
}

function ethernetIpv4Tcp(src, dst, sport, dport, seq, ack, flags, payload = Buffer.alloc(0)) {
  const eth = Buffer.from('aabbccddeeffaabbccddeeff0800', 'hex');
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(sport, 0); tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4); tcp.writeUInt32BE(ack >>> 0, 8);
  tcp.writeUInt16BE((5 << 12) | flags, 12); tcp.writeUInt16BE(64240, 14);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip.writeUInt16BE(20 + tcp.length + payload.length, 2);
  ip.writeUInt16BE(0x4000, 6); ip[8] = 64; ip[9] = 6;
  ipv4(src).copy(ip, 12); ipv4(dst).copy(ip, 16); ip.writeUInt16BE(ipChecksum(ip), 10);
  return Buffer.concat([eth, ip, tcp, payload]);
}

function buildTrainingPcap() {
  const chunks = [];
  const global = Buffer.alloc(24);
  global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6);
  global.writeUInt32LE(0, 8); global.writeUInt32LE(0, 12); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20);
  chunks.push(global);
  const start = Math.floor(Date.now() / 1000);
  const add = (ts, packet) => { const h = Buffer.alloc(16); h.writeUInt32LE(Math.floor(ts), 0); h.writeUInt32LE(Math.floor((ts - Math.floor(ts)) * 1e6), 4); h.writeUInt32LE(packet.length, 8); h.writeUInt32LE(packet.length, 12); chunks.push(h, packet); };
  const answers = Object.fromEntries(TEAMS.map(team => [team, [
    `FLAG{INICIO_${team}}`, `FLAG{${team}_BUSCA_EL_EVENTO}`, `FLAG{${team}_MIRA_LA_URI}`, `FLAG{${team}_FILTRA_HTTP}`,
    `FLAG{${team}_IDENTIFICA_EL_METODO}`, `FLAG{${team}_LOCALIZA_EL_HOST}`, `FLAG{${team}_IDENTIFICA_EL_ORIGEN}`, `FLAG{${team}_IDENTIFICA_EL_DESTINO}`,
    `FLAG{${team}_SIGUE_LA_CONEXION}`, `FLAG{${team}_BUSCA_EL_PARAMETRO}`, `FLAG{${team}_RECONSTRUYE_LA_PETICION}`, `FLAG{${team}_ENCUENTRA_EL_VALOR_OCULTO}`,
    `FLAG{${team}_SIGUE_LA_CADENA}`, 'micorreoeswazowski@gmail.com', 'JuniorTuPapa', `FLAG{${team}_REVISA_EL_CORREO}`,
    "Poyvi ha'e Colombia, ryvy Paraguái.", `FLAG{${team}_RECONSTRUYE_EL_MENSAJE}`, `FLAG{${team}_BUSCA_LA_IDENTIDAD}`, `FLAG{${team}_ENCUENTRA_EL_PERFIL}`,
    `FLAG{${team}_SIGUE_LA_PISTA_FINAL}`, `FLAG{${team}_UBICA_EL_USUARIO}`, `FLAG{${team}_BUSCA_INSTAGRAM}`, `FLAG{${team}_CONFIRMA_MIKEVARGAX}`, 'HACK THE WORLD'
  ]]));

  // Constant background traffic for the full two-hour exercise.
  for (let sec = 0; sec <= 7200; sec += 30) {
    for (let i = 0; i < TEAMS.length; i++) {
      const payload = Buffer.from(`heartbeat team=${TEAMS[i]} sequence=${sec / 30} status=OK`);
      add(start + sec + i * 0.001, ethernetIpv4Udp(`10.20.${i + 1}.10`, `172.16.${i + 1}.20`, 40000 + i, 53, payload));
    }
  }

  // Real HTTP evidence appears progressively; false FLAG-like strings are mixed in as decoys.
  for (let i = 0; i < TEAMS.length; i++) {
    const team = TEAMS[i]; const src = `10.20.${i + 1}.10`; const dst = `172.16.${i + 1}.20`;
    answers[team].forEach((answer, n) => {
      const ts = start + 90 + n * 270 + i * 12; const sport = 50000 + i * 100 + n; const cseq = 1000 + n * 100;
      add(ts, ethernetIpv4Tcp(src, dst, sport, 80, cseq, 0, 0x002));
      add(ts + .01, ethernetIpv4Tcp(dst, src, 80, sport, 7000 + n, cseq + 1, 0x012));
      add(ts + .02, ethernetIpv4Tcp(src, dst, sport, 80, cseq + 1, 7001 + n, 0x010));
      const req = Buffer.from(`GET /api/event/${n + 1}?team=${team}&evidence=${n + 1} HTTP/1.1\\r\\nHost: training.dicib.local\\r\\nUser-Agent: DICIB-Analyst/1.0\\r\\nConnection: close\\r\\n\\r\\n`);
      add(ts + .03, ethernetIpv4Tcp(src, dst, sport, 80, cseq + 1, 7001 + n, 0x018, req));
      const decoy = `FLAG{${team}_PISTA_FALSA_${String(n + 1).padStart(2, '0')}}`;
      let body;
      if (n === 13) body = `Correo objetivo: ${answer}\\n${decoy}\\nRevisar el correo para continuar.`;
      else if (n === 14) body = `Clave encontrada: ${answer}\\n${decoy}`;
      else if (n === 16) body = `Mensaje recuperado: ${answer}\\n${decoy}`;
      else if (n === 24) body = `Perfil de Instagram confirmado: ${answer}\\n${decoy}`;
      else body = `Evidencia: ${answer}\\nSeñuelo: ${decoy}\\nNota: continuar con el siguiente evento.`;
      const bodyBuf = Buffer.from(body, 'utf8');
      const resp = Buffer.from(`HTTP/1.1 200 OK\\r\\nContent-Type: text/plain; charset=utf-8\\r\\nContent-Length: ${bodyBuf.length}\\r\\n\\r\\n`);
      add(ts + .04, ethernetIpv4Tcp(dst, src, 80, sport, 7001 + n, cseq + 1 + req.length, 0x018, Buffer.concat([resp, bodyBuf])));
      add(ts + .05, ethernetIpv4Tcp(src, dst, sport, 80, cseq + 1 + req.length, 7001 + n + resp.length + bodyBuf.length, 0x011));
      add(ts + .06, ethernetIpv4Tcp(dst, src, 80, sport, 7002 + n, cseq + 2 + req.length, 0x010));
    });
  }
  return Buffer.concat(chunks);
}

app.get('/pcap/DICIB-CAPTURE.pcap', (_req, res) => {
  const pcap = buildTrainingPcap();
  res.set({ 'Content-Type': 'application/vnd.tcpdump.pcap', 'Content-Disposition': 'attachment; filename="DICIB-CAPTURE.pcap"', 'Content-Length': String(pcap.length) });
  res.send(pcap);
});

app.get('/pcap/DICIB-CAPTURE.pcap.gz', (_req, res) => {
  const pcap = buildTrainingPcap();
  res.set({ 'Content-Type': 'application/vnd.tcpdump.pcap', 'Content-Disposition': 'attachment; filename="DICIB-CAPTURE.pcap"', 'Content-Length': String(pcap.length) });
  res.send(pcap);
});

app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/*splat', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

initDatabase()
  .then(() => app.listen(PORT, () => console.log(`CTF backend listening on port ${PORT}`)))
  .catch(error => {
    console.error('Database initialization failed:', error);
    process.exit(1);
  });
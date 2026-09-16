import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Pool } from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 8610);
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error('DATABASE_URL is not configured');
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5, idleTimeoutMillis: 30000 });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '16kb' }));
app.use(rateLimit({ windowMs: 60000, limit: 180, standardHeaders: true, legacyHeaders: false }));

const PLAYERS = [
 ['DICIB-01','Cap AvC','María Eugenia Ruiz Diaz Samaniego'],['DICIB-02','Cap AvC','Rita Maria Montiel Florenciano'],['DICIB-03','Tte 1° AvC','Hugo Manuel Sosa Ramírez'],['DICIB-04','Tte AvC','Walter Osmar Escurra Ojeda'],['DICIB-05','SO Tec','Gustavo Ariel Vera Lugo'],['DICIB-06','SO Avc','Pablo Cesar Escurra Ferreira'],['DICIB-07','Sgto A Tec','Julio Cesar Franco Jacquet'],['DICIB-08','Sgto A Tec','Miguel Ángel Jara Medina'],['DICIB-09','Sgto A Tec','Melanio Parra Martínez'],['DICIB-10','Sgto A Tec','Héctor Rolando Garcete Pereira'],['DICIB-11','Sgto A Tec','Miguela López Ortega'],['DICIB-12','Sgto A Tec','Lizandra Belen Carreras Román'],['DICIB-13','Sgto 1° Tec','Héctor Raul Amarilla Cardozo'],['DICIB-14','VSgto 1° Avc','Jorge Luis López']
];

// Preguntas de opción múltiple basadas únicamente en Nmap, Shodan, BlackEye y Wireshark.
const QUESTIONS = [
 {id:'Q01',topic:'NMAP',q:'¿Qué opción de Nmap realiza descubrimiento de hosts sin escanear puertos?',options:['-sn','-sV','-O','-A'],answer:0},
 {id:'Q02',topic:'NMAP',q:'¿Qué opción de Nmap intenta identificar las versiones de los servicios?',options:['-Pn','-sV','-sn','-F'],answer:1},
 {id:'Q03',topic:'NMAP',q:'¿Qué mecanismo de Nmap permite ampliar el reconocimiento mediante scripts?',options:['NSE','ARP','DNSSEC','TLS'],answer:0},
 {id:'Q04',topic:'SHODAN',q:'¿Qué consulta de Shodan limita los resultados al país Paraguay?',options:['country:PY','nation:PY','geo:PY','country=PY'],answer:0},
 {id:'Q05',topic:'SHODAN',q:'¿Qué filtro de Shodan busca servicios en el puerto 443?',options:['tcp:443','port:443','https:443','service:443'],answer:1},
 {id:'Q06',topic:'SHODAN',q:'¿Qué filtro de Shodan identifica resultados con captura de pantalla?',options:['screen:true','has_screenshot:true','screenshot:yes','image:true'],answer:1},
 {id:'Q07',topic:'BLACKEYE',q:'Dentro del bloque Linux trabajado en el curso, ¿qué proyecto se utilizó?',options:['BlackEye','Metasploit','Hydra','John'],answer:0},
 {id:'Q08',topic:'BLACKEYE',q:'En el laboratorio de BlackEye, ¿qué se presenta para la práctica controlada?',options:['Una página de acceso simulada','Un firewall real','Un servidor DNS público','Un escáner de puertos'],answer:0},
 {id:'Q09',topic:'WIRESHARK',q:'¿Qué filtro de Wireshark muestra tráfico HTTP?',options:['tcp.http','http','web','proto:http'],answer:1},
 {id:'Q10',topic:'WIRESHARK',q:'¿Qué función de Wireshark permite reconstruir una conversación TCP?',options:['Decode As','Follow TCP Stream','Expert Info','Capture Filters'],answer:1}
];

const ADMIN_USER = (process.env.ADMIN_USER || 'WAZOWSKI').trim().toUpperCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const sessions = new Map();
const playerMap = new Map(PLAYERS.map(([id,rank,name]) => [id,{id,rank,name}]));

async function initDatabase() {
 await pool.query(`CREATE TABLE IF NOT EXISTS blackout_events (id BIGSERIAL PRIMARY KEY, player_id TEXT NOT NULL, type TEXT NOT NULL, question_id TEXT, flag TEXT, answer_index INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS blackout_correct_once ON blackout_events(player_id,question_id) WHERE type='CORRECT'`);
 await pool.query(`CREATE INDEX IF NOT EXISTS blackout_events_time ON blackout_events(created_at DESC)`);
}
function newToken(user,role){const t=crypto.randomBytes(32).toString('hex');sessions.set(t,{user,role,createdAt:Date.now()});return t;}
function auth(req,res,next){const t=req.get('Authorization')?.replace(/^Bearer\s+/i,'');const s=t&&sessions.get(t);if(!s)return res.status(401).json({error:'No autorizado'});req.session=s;next();}
function adminOnly(req,res,next){if(req.session?.role!=='admin')return res.status(403).json({error:'Solo administrador'});next();}
function playerOnly(req,res,next){if(req.session?.role!=='player')return res.status(403).json({error:'Solo operadores'});next();}
function makeFlag(player,q){const sig=crypto.createHmac('sha256',SESSION_SECRET).update(`${player.id}:${q.id}`).digest('hex').slice(0,12).toUpperCase();return `BLACKOUT{${player.id.replace('DICIB-','P')}_${q.id}_${sig}}`;}
async function playerState(playerId){
 const {rows}=await pool.query(`SELECT type,question_id,created_at FROM blackout_events WHERE player_id=$1 ORDER BY id`,[playerId]);
 const solved=new Set(rows.filter(r=>r.type==='CORRECT').map(r=>r.question_id));
 const errors=rows.filter(r=>r.type==='WRONG').length;
 return {solved:solved.size,errors,score:solved.size*100-errors*50,total:QUESTIONS.length,percent:Math.round(solved.size/QUESTIONS.length*100),solvedIds:[...solved],last:rows.at(-1)?.created_at||null};
}
async function dashboardState(){
 const out=[];
 for(const [id,rank,name] of PLAYERS) out.push({id,rank,name,...await playerState(id)});
 out.sort((a,b)=>b.score-a.score||b.solved-a.solved||a.id.localeCompare(b.id));
 return out;
}

app.get('/api/health',async(_req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'dicib-blackout',database:'connected'});}catch{res.status(503).json({ok:false,service:'dicib-blackout',database:'unavailable'});}});

// ÚNICO acceso administrativo. La contraseña debe existir en ADMIN_PASSWORD en Render.
app.post('/api/login',(req,res)=>{
 const user=String(req.body?.user||'').trim().toUpperCase();
 const password=String(req.body?.password||'');
 if(user!==ADMIN_USER||!ADMIN_PASSWORD||password!==ADMIN_PASSWORD)return res.status(401).json({error:'Credenciales de administrador incorrectas'});
 res.json({token:newToken(user,'admin'),user,role:'admin'});
});

app.post('/api/player/start',(req,res)=>{
 const id=String(req.body?.playerId||'').trim().toUpperCase();
 const p=playerMap.get(id); if(!p)return res.status(400).json({error:'Operador no válido'});
 res.json({token:newToken(id,'player'),user:id,role:'player',player:p});
});
app.post('/api/logout',auth,(req,res)=>{const t=req.get('Authorization')?.replace(/^Bearer\s+/i,'');sessions.delete(t);res.json({ok:true});});
app.get('/api/me',auth,async(req,res)=>{if(req.session.role==='admin')return res.json({user:req.session.user,role:'admin'});const p=playerMap.get(req.session.user);res.json({user:p.id,role:'player',player:p,state:await playerState(p.id)});});
app.get('/api/questions',auth,playerOnly,(_req,res)=>res.json({questions:QUESTIONS.map(({id,topic,q,options})=>({id,topic,q,options}))}));

app.post('/api/questions/answer',auth,playerOnly,async(req,res)=>{
 const p=playerMap.get(req.session.user); const q=QUESTIONS.find(x=>x.id===String(req.body?.questionId||'').trim().toUpperCase()); const choice=Number(req.body?.choice);
 if(!q||!Number.isInteger(choice)||choice<0||choice>=q.options.length)return res.status(400).json({error:'Pregunta o respuesta no válida'});
 const already=await pool.query(`SELECT flag FROM blackout_events WHERE player_id=$1 AND question_id=$2 AND type='CORRECT' LIMIT 1`,[p.id,q.id]);
 if(already.rowCount)return res.json({correct:true,already:true,flag:already.rows[0].flag,state:await playerState(p.id)});
 if(choice===q.answer){
  const flag=makeFlag(p,q);
  await pool.query(`INSERT INTO blackout_events(player_id,type,question_id,flag,answer_index) VALUES($1,'CORRECT',$2,$3,$4) ON CONFLICT DO NOTHING`,[p.id,q.id,flag,choice]);
  return res.json({correct:true,flag,points:100,state:await playerState(p.id)});
 }
 await pool.query(`INSERT INTO blackout_events(player_id,type,question_id,answer_index) VALUES($1,'WRONG',$2,$3)`,[p.id,q.id,choice]);
 res.json({correct:false,penalty:50,state:await playerState(p.id)});
});

// Panel exclusivo del administrador: se actualiza cada 2 segundos desde el navegador.
app.get('/api/admin/dashboard',auth,adminOnly,async(_req,res)=>{
 const players=await dashboardState();
 const totals=players.reduce((a,p)=>(a.score+=p.score,a.solved+=p.solved,a.errors+=p.errors,a),{score:0,solved:0,errors:0});
 const {rows:events}=await pool.query(`SELECT player_id,type,question_id,flag,created_at FROM blackout_events ORDER BY id DESC LIMIT 40`);
 res.json({players,totals,events});
});
app.post('/api/admin/reset-all',auth,adminOnly,async(_req,res)=>{await pool.query('TRUNCATE blackout_events RESTART IDENTITY');res.json({ok:true});});

app.use(express.static(path.join(__dirname,'..','ctf-dicib')));
app.use(express.static(path.join(__dirname,'..','public')));
app.listen(PORT,()=>console.log(`DICIB BLACKOUT listening on ${PORT}`));
initDatabase().catch(error=>{console.error('DB init failed',error);process.exit(1);});

// API de Horas para mis metas: cuentas con usuario y contraseña, y guardado de los datos en MongoDB Atlas.
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://nahsev.github.io').split(',').map(s => s.trim()).filter(Boolean);

if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('Falta JWT_SECRET (mínimo 32 caracteres).'); process.exit(1); }

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(cors({ origin: (o, cb) => cb(null, !o || ORIGINS.includes(o)), methods: ['GET', 'POST', 'PUT'], allowedHeaders: ['Content-Type', 'Authorization'], maxAge: 86400 }));
app.use(express.json({ limit: '1mb' }));

let users = null;
async function db() {
  if (users) return users;
  if (!MONGODB_URI) throw Object.assign(new Error('La base de datos no está configurada.'), { status: 503 });
  const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  users = client.db(process.env.DB_NAME || 'horas').collection('users');
  await users.createIndex({ username: 1 }, { unique: true });
  return users;
}

// Límite simple de intentos de login/registro por IP (en memoria)
const hits = new Map();
function limited(ip) {
  const now = Date.now(), w = 15 * 60 * 1000, max = 20;
  const arr = (hits.get(ip) || []).filter(t => now - t < w);
  arr.push(now); hits.set(ip, arr);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < w)) hits.delete(k);
  return arr.length > max;
}

const USER_RE = /^[a-z0-9._-]{3,30}$/;
function cleanUser(u) { return String(u || '').trim().toLowerCase(); }
function token(u) { return jwt.sign({ sub: String(u._id), u: u.username }, JWT_SECRET, { expiresIn: '180d' }); }
function auth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  if (!m) return res.status(401).json({ error: 'Tenés que entrar con tu usuario.' });
  try { req.user = jwt.verify(m[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Tu sesión venció. Entrá de nuevo.' }); }
}
const wrap = fn => (req, res, next) => fn(req, res).catch(next);

app.get('/', (req, res) => res.json({ ok: true, app: 'horas-metas-api' }));
app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/api/register', wrap(async (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Demasiados intentos. Probá en unos minutos.' });
  const username = cleanUser(req.body.username), password = String(req.body.password || '');
  if (!USER_RE.test(username)) return res.status(400).json({ error: 'El usuario tiene que tener entre 3 y 30 letras, números, puntos, guiones o guiones bajos.' });
  if (password.length < 6) return res.status(400).json({ error: 'La contraseña tiene que tener al menos 6 caracteres.' });
  const col = await db();
  const doc = { username, passHash: await bcrypt.hash(password, 10), data: null, saved: 0, createdAt: new Date() };
  try { const r = await col.insertOne(doc); doc._id = r.insertedId; }
  catch (e) { if (e.code === 11000) return res.status(409).json({ error: 'Ese usuario ya existe. Elegí otro o entrá con tu contraseña.' }); throw e; }
  res.status(201).json({ token: token(doc), username, data: null, saved: 0 });
}));

app.post('/api/login', wrap(async (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Demasiados intentos. Probá en unos minutos.' });
  const username = cleanUser(req.body.username), password = String(req.body.password || '');
  const col = await db();
  const u = await col.findOne({ username });
  if (!u || !(await bcrypt.compare(password, u.passHash))) return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  res.json({ token: token(u), username, data: u.data, saved: u.saved || 0 });
}));

app.get('/api/data', auth, wrap(async (req, res) => {
  const col = await db();
  const u = await col.findOne({ username: req.user.u }, { projection: { data: 1, saved: 1 } });
  if (!u) return res.status(401).json({ error: 'La cuenta ya no existe.' });
  res.json({ data: u.data, saved: u.saved || 0 });
}));

// Guarda si lo que llega es más nuevo que lo guardado; si no, devuelve lo guardado (409)
app.put('/api/data', auth, wrap(async (req, res) => {
  const data = req.body.data, saved = Number(req.body.saved) || 0;
  if (!data || typeof data !== 'object' || !Array.isArray(data.goals)) return res.status(400).json({ error: 'Datos inválidos.' });
  const col = await db();
  const r = await col.findOneAndUpdate(
    { username: req.user.u, $or: [{ saved: { $lte: saved } }, { saved: { $exists: false } }] },
    { $set: { data, saved, updatedAt: new Date() } },
    { returnDocument: 'after', projection: { saved: 1 } });
  if (r) return res.json({ ok: true, saved });
  const cur = await col.findOne({ username: req.user.u }, { projection: { data: 1, saved: 1 } });
  if (!cur) return res.status(401).json({ error: 'La cuenta ya no existe.' });
  res.status(409).json({ data: cur.data, saved: cur.saved });
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.status === 503 ? err.message : 'Error del servidor. Probá de nuevo en un rato.' });
});

app.listen(PORT, () => console.log('API escuchando en el puerto ' + PORT));

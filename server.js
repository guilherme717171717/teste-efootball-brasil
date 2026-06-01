const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();
const { WebSocketServer } = require('ws');

const db = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static('.'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Wraps route handlers so thrown errors go to the error middleware
function safeHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = Date.now().toString(36) + Math.random().toString(36).slice(2, 6) + ext;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ===== RATE LIMITER =====
const rateLimitMap = new Map();

function rateLimiter(maxRequests = 5, windowMs = 60000) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    if (!rateLimitMap.has(ip)) {
      rateLimitMap.set(ip, []);
    }
    const timestamps = rateLimitMap.get(ip).filter(t => now - t < windowMs);
    if (timestamps.length >= maxRequests) {
      return res.status(429).json({ error: 'Muitas tentativas. Aguarde 1 minuto.' });
    }
    timestamps.push(now);
    rateLimitMap.set(ip, timestamps);
    next();
  };
}

// Clean rate limit map every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of rateLimitMap.entries()) {
    const valid = timestamps.filter(t => now - t < 60000);
    if (valid.length === 0) rateLimitMap.delete(ip);
    else rateLimitMap.set(ip, valid);
  }
}, 300000);

// ===== JWT HELPERS =====
function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ===== AUTH MIDDLEWARE =====
function requireRole(...roles) {
  return (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    const decoded = verifyToken(token);
    if (!decoded || !roles.includes(decoded.role)) {
      return res.status(401).json({ error: 'Não autorizado' });
    }
    req.user = decoded;
    next();
  };
}

// ===== DATA STORAGE (legacy JSON) =====
const DATA_DIR = path.join(__dirname, 'data');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readStore(name) {
  const file = path.join(DATA_DIR, `${name}.json`);
  if (!fs.existsSync(file)) return [];
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return []; }
}

function writeStore(name, data) {
  ensureDataDir();
  fs.writeFileSync(path.join(DATA_DIR, `${name}.json`), JSON.stringify(data, null, 2));
}

function addEntry(name, entry) {
  const store = readStore(name);
  entry.id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  entry.createdAt = new Date().toISOString();
  entry.status = 'pending';
  store.unshift(entry);
  writeStore(name, store);
  return entry;
}

// ===== DISCORD WEBHOOK =====
const WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

async function sendDiscordNotification(embeds) {
  if (!WEBHOOK_URL) return;
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'eFootball Brasil',
        avatar_url: 'https://cdn.discordapp.com/icons/1077324994373222500/08057e13928a3482a90584a315d662df.png',
        embeds
      })
    });
  } catch (err) {
    console.error('Webhook error:', err.message);
  }
}

function formatDiscordEmbed(type, data) {
  const colors = { ticket: 0x00ff88, report: 0xff4444, purchase: 0xffaa00 };
  const titles = {
    ticket: '\u{1F3AB} Novo Ticket de Suporte',
    report: '\u{1F6A8} Nova Den\u00FAncia',
    purchase: '\u{1F4B0} Nova Compra VIP'
  };
  const fields = Object.entries(data)
    .filter(([k]) => !['id', 'createdAt', 'status'].includes(k))
    .map(([k, v]) => ({ name: k, value: String(v).slice(0, 1024), inline: true }));
  return [{
    title: titles[type] || 'Nova Submiss\u00E3o',
    color: colors[type] || 0x5865f2,
    fields,
    timestamp: new Date().toISOString(),
    footer: { text: `ID: ${data.id}` }
  }];
}

// ===== AUTH ENDPOINTS =====
// API Login (returns JSON)
app.post('/api/auth/login', rateLimiter(5, 60000), (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
    }
    const result = db.authenticateUser(username, password);
    if (!result) {
      return res.status(401).json({ error: 'Usuário ou senha inválidos' });
    }
    if (result.error === 'suspended') {
      return res.status(403).json({ error: 'Conta suspensa. Contate o administrador.' });
    }
    if (result.error === 'banned') {
      return res.status(403).json({ error: 'Conta banida. Contate o administrador.' });
    }
    const token = signToken(result);
    db.addLog(username, 'Login realizado', 'API', req.ip);
    return res.json({ token, role: result.role, username, name: result.name });
  } catch (e) {
    console.error('LOGIN ERROR:', e);
    return res.status(500).json({ error: 'Erro no login' });
  }
});

// Form POST login — redirect to admin.html
app.post('/admin/login', rateLimiter(5, 60000), safeHandler((req, res) => {
  const { username, password } = req.body || {};
  const result = db.authenticateUser(username, password);
  if (result && !result.error) {
    const token = signToken(result);
    db.addLog(username, 'Login realizado', 'Painel Admin', req.ip);
    return res.redirect(`/admin.html?token=${token}`);
  }
  res.redirect('/admin.html?error=1');
}));

// Legacy staff POST redirect
app.post('/staff/login', rateLimiter(5, 60000), safeHandler((req, res) => {
  const { username, password } = req.body || {};
  const result = db.authenticateUser(username, password);
  if (result && !result.error) {
    const token = signToken(result);
    db.addLog(username, 'Login realizado', 'Painel Staff', req.ip);
    return res.redirect(`/admin.html?token=${token}`);
  }
  res.redirect('/admin.html?error=1');
}));

// Verify token / get current user
app.get('/api/auth/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
  const user = db.getUserByUsername(decoded.username);
  if (!user) {
    return res.status(401).json({ error: 'Usuário não encontrado' });
  }
  return res.json({
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
    status: user.status,
    last_login: user.last_login,
    login_count: user.login_count,
    created_at: user.created_at
  });
});

app.get('/api/auth/verify', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ valid: false });
  return res.json({ valid: true, role: decoded.role, username: decoded.username });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.body?.token;
  if (token) {
    const decoded = verifyToken(token);
    if (decoded) db.addLog(decoded.username, 'Logout', 'Sessão encerrada', req.ip);
  }
  res.json({ success: true });
});

// ===== DISCORD OAUTH =====
app.post('/api/auth/discord', async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Código de autorização necessário' });
  }
  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI
      })
    });
    if (!tokenResponse.ok) {
      const err = await tokenResponse.text();
      return res.status(400).json({ error: 'Falha na autenticação', details: err });
    }
    const tokenData = await tokenResponse.json();
    const userResponse = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    if (!userResponse.ok) {
      return res.status(400).json({ error: 'Falha ao buscar dados do usuário' });
    }
    const userData = await userResponse.json();
    if (process.env.DISCORD_GUILD_ID && process.env.DISCORD_BOT_TOKEN) {
      try {
        await fetch(
          `https://discord.com/api/v10/guilds/${process.env.DISCORD_GUILD_ID}/members/${userData.id}`,
          {
            method: 'PUT',
            headers: {
              Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ access_token: tokenData.access_token })
          }
        );
      } catch (guildErr) {
        console.log('Erro ao adicionar ao servidor (pode já ser membro):', guildErr.message);
      }
    }
    res.json({
      user: userData,
      token: tokenData.access_token
    });
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ===== SUBMISSIONS API =====
app.post('/api/tickets', safeHandler(async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Campos obrigatórios: name, email, message' });
  }
  const entry = addEntry('tickets', {
    name, email, subject: subject || 'geral',
    messages: [{ text: message, role: 'user', createdAt: new Date().toISOString() }]
  });
  const tickets = readStore('tickets');
  const maxNum = tickets.reduce((max, t) => Math.max(max, t.ticketNumber || 0), 0);
  entry.ticketNumber = maxNum + 1;
  const idx = tickets.findIndex(t => t.id === entry.id);
  if (idx >= 0) { tickets[idx].ticketNumber = entry.ticketNumber; writeStore('tickets', tickets); }
  sendDiscordNotification(formatDiscordEmbed('ticket', { ...entry, message }));
  res.json({ success: true, id: entry.id, ticketNumber: entry.ticketNumber });
}));

app.get('/api/tickets', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
  const store = readStore('tickets');
  const list = store.filter(t => t.name && t.name.toLowerCase() === name.toLowerCase());
  res.json(list);
});

app.get('/api/tickets/:id', (req, res) => {
  const store = readStore('tickets');
  const ticket = store.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket não encontrado' });
  const { name } = req.query;
  if (name && name.toLowerCase() !== ticket.name.toLowerCase()) {
    return res.status(403).json({ error: 'Nome não corresponde ao ticket' });
  }
  res.json(ticket);
});

app.post('/api/tickets/:id/reply', (req, res) => {
  const { name, text } = req.body || {};
  if (!name || !text) return res.status(400).json({ error: 'Nome e texto obrigatórios' });
  const store = readStore('tickets');
  const idx = store.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Ticket não encontrado' });
  if (name.toLowerCase() !== store[idx].name.toLowerCase()) {
    return res.status(403).json({ error: 'Nome não corresponde ao ticket' });
  }
  if (!store[idx].messages) store[idx].messages = [];
  store[idx].messages.push({ text, role: 'user', createdAt: new Date().toISOString() });
  store[idx].updatedAt = new Date().toISOString();
  if (store[idx].status === 'resolved') store[idx].status = 'pending';
  writeStore('tickets', store);
  sendDiscordNotification(formatDiscordEmbed('ticket', { ...store[idx], message: text }));
  broadcast('ticket', req.params.id, { type: 'newMsg', messages: store[idx].messages });
  res.json({ success: true });
});

app.post('/api/reports', upload.single('evidence'), safeHandler(async (req, res) => {
  const { reporter, player, reason, description } = req.body;
  if (!player || !reason || !description) {
    return res.status(400).json({ error: 'Campos obrigatórios: player, reason, description' });
  }
  const fileUrl = req.file ? `/uploads/${req.file.filename}` : (req.body.evidence || '');
  const entry = addEntry('reports', { reporter, player, reason, description, evidence: fileUrl, messages: [] });
  sendDiscordNotification(formatDiscordEmbed('report', entry));
  res.json({ success: true, id: entry.id, evidence: fileUrl });
}));

// ===== TICKET CHAT =====
app.get('/api/tickets/:id/messages', (req, res) => {
  const store = readStore('tickets');
  const ticket = store.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket não encontrado' });
  const msgs = ticket.messages || [];
  res.json(msgs);
});

app.post('/api/tickets/:id/chat', (req, res) => {
  const { name, text } = req.body || {};
  if (!name || !text) return res.status(400).json({ error: 'name e text obrigatórios' });
  const store = readStore('tickets');
  const idx = store.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Ticket não encontrado' });
  if (store[idx].name.toLowerCase() !== name.toLowerCase())
    return res.status(403).json({ error: 'Nome não corresponde ao ticket' });
  if (!store[idx].messages) store[idx].messages = [];
  store[idx].messages.push({ text, role: 'user', name, createdAt: new Date().toISOString() });
  store[idx].updatedAt = new Date().toISOString();
  writeStore('tickets', store);
  broadcast('ticket', req.params.id, { type: 'newMsg', messages: store[idx].messages });
  res.json({ success: true });
});

// ===== REPORT CHAT =====
app.get('/api/reports', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório' });
  const store = readStore('reports');
  const list = store.filter(r => r.reporter && r.reporter.toLowerCase() === name.toLowerCase());
  res.json(list);
});

app.get('/api/reports/:id', (req, res) => {
  const store = readStore('reports');
  const report = store.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ error: 'Denúncia não encontrada' });
  const { name } = req.query;
  if (name && report.reporter && report.reporter.toLowerCase() !== name.toLowerCase()) {
    return res.status(403).json({ error: 'Nome não corresponde' });
  }
  res.json(report);
});

app.get('/api/reports/:id/messages', (req, res) => {
  const store = readStore('reports');
  const report = store.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ error: 'Denúncia não encontrada' });
  const msgs = report.messages || [];
  res.json(msgs);
});

app.post('/api/reports/:id/chat', (req, res) => {
  const { name, text } = req.body || {};
  if (!name || !text) return res.status(400).json({ error: 'name e text obrigatórios' });
  const store = readStore('reports');
  const idx = store.findIndex(r => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Denúncia não encontrada' });
  if (store[idx].reporter.toLowerCase() !== name.toLowerCase())
    return res.status(403).json({ error: 'Nome não corresponde à denúncia' });
  if (!store[idx].messages) store[idx].messages = [];
  store[idx].messages.push({ text, role: 'user', name, createdAt: new Date().toISOString() });
  store[idx].updatedAt = new Date().toISOString();
  writeStore('reports', store);
  broadcast('report', req.params.id, { type: 'newMsg', messages: store[idx].messages });
  res.json({ success: true });
});

app.post('/api/purchases', safeHandler(async (req, res) => {
  const { usuario, produto, valor, email } = req.body;
  if (!usuario || !produto) {
    return res.status(400).json({ error: 'Campos obrigatórios: usuario, produto' });
  }
  const entry = addEntry('purchases', { usuario, produto, valor: valor || 0, email: email || '' });
  sendDiscordNotification(formatDiscordEmbed('purchase', entry));
  res.json({ success: true, id: entry.id });
}));

// ===== LEGACY ADMIN USER MANAGEMENT (backward compat with admin.html) =====
app.get('/api/admin/users', requireRole('admin', 'dono', 'moderador'), (req, res) => {
  const users = db.listUsers();
  res.json(users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    name: u.name,
    status: u.status,
    last_login: u.last_login,
    created_at: u.created_at
  })));
});

app.post('/api/admin/users', requireRole('admin', 'dono'), (req, res) => {
  const { username, password, role, name, email } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
  const user = db.getUserByUsername(username);
  if (user) {
    if (user.deleted_at) {
      db.restoreUser(user.id, req.user.username);
      db.updateUser(user.id, { password, role: role || 'staff', name, email, _updated_by: req.user.username });
      return res.json({ success: true, username, role: role || 'staff', restored: true });
    }
    return res.status(400).json({ error: 'Usuário já existe' });
  }
  const result = db.createUser({
    username, password, name, email,
    role: role || 'staff',
    created_by: req.user.username
  });
  if (!result) return res.status(400).json({ error: 'Erro ao criar usuário' });
  res.json({ success: true, ...result });
});

app.delete('/api/admin/users/:identifier', requireRole('admin', 'dono'), (req, res) => {
  const ident = req.params.identifier;
  const user = db.getUserByUsername(ident) || db.getUserById(parseInt(ident));
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  if (user.username === req.user.username) return res.status(400).json({ error: 'Não pode excluir a si mesmo' });
  db.softDeleteUser(user.id, req.user.username);
  res.json({ success: true, trashed: true });
});

// ===== NEW DB-BASED ADMIN USER MANAGEMENT =====
app.get('/api/admin/users/list', requireRole('admin', 'dono', 'moderador'), (req, res) => {
  const users = db.listUsers();
  res.json(users.map(u => ({
    id: u.id,
    name: u.name,
    username: u.username,
    email: u.email,
    role: u.role,
    status: u.status,
    created_by: u.created_by,
    last_login: u.last_login,
    login_count: u.login_count,
    created_at: u.created_at,
    updated_at: u.updated_at
  })));
});

app.get('/api/admin/users/trash', requireRole('admin', 'dono'), (req, res) => {
  const trash = db.listTrash();
  res.json(trash);
});

app.get('/api/admin/users/:id', requireRole('admin', 'dono', 'moderador'), (req, res) => {
  const user = db.getUserById(parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  const { password, ...safe } = user;
  res.json(safe);
});

app.patch('/api/admin/users/:id', requireRole('admin', 'dono'), (req, res) => {
  const fields = { ...req.body, _updated_by: req.user.username };
  delete fields.id;
  const result = db.updateUser(parseInt(req.params.id), fields);
  if (!result) return res.status(404).json({ error: 'Usuário não encontrado ou sem alterações' });
  db.addLog(req.user.username, 'Conta atualizada', `ID: ${req.params.id}`, req.ip);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/restore', requireRole('admin', 'dono'), (req, res) => {
  const result = db.restoreUser(parseInt(req.params.id), req.user.username);
  if (!result) return res.status(404).json({ error: 'Usuário não encontrado na lixeira' });
  res.json({ success: true });
});

app.post('/api/admin/users/:id/reset-password', requireRole('admin', 'dono'), (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 3) return res.status(400).json({ error: 'Nova senha obrigatória (mín. 3 caracteres)' });
  db.updateUser(parseInt(req.params.id), { password, _updated_by: req.user.username });
  db.addLog(req.user.username, 'Senha redefinida', `ID: ${req.params.id}`, req.ip);
  res.json({ success: true });
});

// ===== LOGS & BACKUP =====
app.get('/api/admin/logs', requireRole('admin', 'dono'), (req, res) => {
  const limit = parseInt(req.query.limit) || 200;
  const offset = parseInt(req.query.offset) || 0;
  const logs = db.getLogs(limit, offset);
  res.json(logs);
});

app.post('/api/admin/backup', requireRole('admin', 'dono'), (req, res) => {
  try {
    const backupPath = db.runBackup();
    db.addLog(req.user.username, 'Backup manual', `Arquivo: ${path.basename(backupPath)}`, req.ip);
    res.json({ success: true, path: path.basename(backupPath) });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar backup' });
  }
});

app.get('/api/admin/stats', requireRole('admin', 'dono', 'moderador'), (req, res) => {
  const stats = db.getStats();
  const tickets = readStore('tickets');
  const reports = readStore('reports');
  const purchases = readStore('purchases');
  const vips = readStore('vips');
  res.json({
    ...stats,
    tickets: { total: tickets.length, pending: tickets.filter(t => t.status === 'pending').length },
    reports: { total: reports.length, pending: reports.filter(r => r.status === 'pending').length },
    purchases: { total: purchases.length },
    vips: { total: vips.length, active: vips.filter(v => v.status === 'active').length }
  });
});

// ===== ADMIN CONTENT API (legacy) =====
app.get('/api/admin/:type', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  const validTypes = ['tickets', 'reports', 'purchases', 'vips', 'staff'];
  if (!validTypes.includes(req.params.type)) {
    return res.status(400).json({ error: 'Tipo inválido. Use: tickets, reports, purchases, vips, staff' });
  }
  res.json(readStore(req.params.type));
});

app.get('/api/admin/:type/:id', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  const validTypes = ['tickets', 'reports', 'purchases', 'vips', 'staff'];
  if (!validTypes.includes(req.params.type)) return res.status(400).json({ error: 'Tipo inválido' });
  const store = readStore(req.params.type);
  const entry = store.find(e => e.id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'Não encontrado' });
  res.json(entry);
});

app.patch('/api/admin/:type/:id', requireRole('admin', 'dono', 'moderador'), (req, res) => {
  const validTypes = ['tickets', 'reports', 'purchases', 'vips', 'staff'];
  if (!validTypes.includes(req.params.type)) {
    return res.status(400).json({ error: 'Tipo inválido' });
  }
  const store = readStore(req.params.type);
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store[idx] = { ...store[idx], ...req.body, updatedAt: new Date().toISOString() };
  writeStore(req.params.type, store);
  res.json(store[idx]);
});

app.post('/api/admin/tickets/:id/reply', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  const session = verifyToken(token);
  if (!session || !['admin', 'dono', 'moderador', 'suporte', 'staff'].includes(session.role)) {
    return res.status(401).json({ error: 'Não autorizado' });
  }
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'Texto obrigatório' });
  const store = readStore('tickets');
  const idx = store.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Ticket não encontrado' });
  if (!store[idx].messages) store[idx].messages = [{ text: store[idx].message, role: 'user', createdAt: store[idx].createdAt }];
  const name = session.role === 'admin' || session.role === 'dono' ? `Admin (${session.username})` : `Suporte (${session.username})`;
  store[idx].messages.push({ text, role: 'admin', name, createdAt: new Date().toISOString() });
  store[idx].updatedAt = new Date().toISOString();
  writeStore('tickets', store);
  sendDiscordNotification(formatDiscordEmbed('ticket', { ...store[idx], message: text }));
  broadcast('ticket', req.params.id, { type: 'newMsg', messages: store[idx].messages });
  res.json({ success: true });
});

app.post('/api/admin/reports/:id/reply', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  const session = verifyToken(token);
  if (!session || !['admin', 'dono', 'moderador', 'suporte', 'staff'].includes(session.role)) {
    return res.status(401).json({ error: 'Não autorizado' });
  }
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'Texto obrigatório' });
  const store = readStore('reports');
  const idx = store.findIndex(r => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Denúncia não encontrada' });
  if (!store[idx].messages) store[idx].messages = [{ text: store[idx].message, role: 'user', name: store[idx].reporter, createdAt: store[idx].createdAt }];
  const name = session.role === 'admin' || session.role === 'dono' ? `Admin (${session.username})` : `Suporte (${session.username})`;
  store[idx].messages.push({ text, role: 'admin', name, createdAt: new Date().toISOString() });
  store[idx].updatedAt = new Date().toISOString();
  writeStore('reports', store);
  broadcast('report', req.params.id, { type: 'newMsg', messages: store[idx].messages });
  res.json({ success: true });
});

// ===== VIP MANAGEMENT =====
app.get('/api/admin/vips', requireRole('admin', 'dono', 'moderador'), (req, res) => {
  res.json(readStore('vips'));
});

app.post('/api/admin/vips', requireRole('admin', 'dono'), (req, res) => {
  const { discordId, name, plan, expiresAt } = req.body || {};
  if (!name || !expiresAt) return res.status(400).json({ error: 'Nome e data de expiração obrigatórios' });
  const store = readStore('vips');
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    discordId: discordId || '',
    name, plan: plan || 'VIP',
    expiresAt, createdAt: new Date().toISOString(), status: 'active'
  };
  store.unshift(entry);
  writeStore('vips', store);
  res.json({ success: true, id: entry.id });
});

app.patch('/api/admin/vips/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('vips');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store[idx] = { ...store[idx], ...req.body, updatedAt: new Date().toISOString() };
  writeStore('vips', store);
  res.json(store[idx]);
});

app.delete('/api/admin/vips/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('vips');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store.splice(idx, 1);
  writeStore('vips', store);
  res.json({ success: true });
});

app.delete('/api/admin/purchases/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('purchases');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store.splice(idx, 1);
  writeStore('purchases', store);
  res.json({ success: true });
});

app.delete('/api/admin/tickets/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('tickets');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store.splice(idx, 1);
  writeStore('tickets', store);
  res.json({ success: true });
});

app.delete('/api/admin/reports/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('reports');
  const idx = store.findIndex(e => e.id === req.params.id);
  console.log('DELETE REPORT id=' + req.params.id + ' idx=' + idx + ' total=' + store.length);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store.splice(idx, 1);
  writeStore('reports', store);
  res.json({ success: true });
});

app.get('/api/vips/expiring', (req, res) => {
  const store = readStore('vips');
  const now = Date.now();
  const expiring = store.filter(v => {
    if (v.status !== 'active') return false;
    const diff = new Date(v.expiresAt).getTime() - now;
    return diff > 0 && diff <= 7 * 86400000;
  }).map(v => ({ name: v.name, plan: v.plan, expiresAt: v.expiresAt, daysLeft: Math.ceil((new Date(v.expiresAt).getTime() - now) / 86400000) }));
  res.json(expiring);
});

app.get('/api/vips/members', (req, res) => {
  const store = readStore('vips');
  const now = Date.now();
  const active = store.filter(v => v.status === 'active' && new Date(v.expiresAt).getTime() > now)
    .map(v => ({ name: v.name, plan: v.plan, expiresAt: v.expiresAt }));
  res.json(active);
});

// ===== STAFF MANAGEMENT =====
app.get('/api/staff', (req, res) => {
  const store = readStore('staff');
  res.json(store.map(s => ({ id: s.id, name: s.name, role: s.role, status: s.status || 'offline', discordId: s.discordId || '', userId: s.userId || null })));
});

app.post('/api/staff/status', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.body?.token;
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Não autorizado' });
  const { status } = req.body;
  if (!status || !['online', 'offline'].includes(status)) {
    return res.status(400).json({ error: 'Status inválido' });
  }
  const store = readStore('staff');
  const userId = decoded.id;
  const idx = store.findIndex(s => Number(s.userId) === Number(userId));
  if (idx === -1) return res.json({ success: true, note: 'staff_not_found' });
  store[idx].status = status;
  writeStore('staff', store);
  broadcast('staff', 'status', {
    type: 'staff_status',
    staff: [{ id: store[idx].id, name: store[idx].name, role: store[idx].role, status }]
  });
  res.json({ success: true });
});

app.get('/api/admin/staff', requireRole('admin', 'dono'), (req, res) => {
  res.json(readStore('staff'));
});

app.post('/api/admin/staff', requireRole('admin', 'dono'), (req, res) => {
  const { name, role, discordId, userId, username, password } = req.body || {};
  if (!name || !role) return res.status(400).json({ error: 'Nome e cargo obrigatórios' });
  const store = readStore('staff');
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    name, role, discordId: discordId || '',
    userId: userId ? Number(userId) : null,
    status: 'offline',
    createdAt: new Date().toISOString()
  };
  store.unshift(entry);
  writeStore('staff', store);

  if (username && password) {
    const existing = db.getUserByUsername(username);
    if (!existing) {
      db.createUser({ username, password, name, role: 'staff', created_by: req.user.username });
    } else if (existing.deleted_at) {
      db.restoreUser(existing.id, req.user.username);
      db.updateUser(existing.id, { password, role: 'staff', name, _updated_by: req.user.username });
    }
  }

  res.json({ success: true, id: entry.id });
});

app.patch('/api/admin/staff/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('staff');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  const body = { ...req.body };
  if (body.userId !== undefined) body.userId = body.userId ? Number(body.userId) : null;
  store[idx] = { ...store[idx], ...body, updatedAt: new Date().toISOString() };
  writeStore('staff', store);
  res.json(store[idx]);
});

app.delete('/api/admin/staff/:id', requireRole('admin', 'dono'), (req, res) => {
  const store = readStore('staff');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  const removed = store.splice(idx, 1)[0];
  writeStore('staff', store);
  res.json({ success: true });
});

// ===== SUPPORT API =====
app.get('/api/support/tickets', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  res.json(readStore('tickets'));
});

app.patch('/api/support/tickets/:id', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  const store = readStore('tickets');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store[idx] = { ...store[idx], ...req.body, updatedAt: new Date().toISOString() };
  writeStore('tickets', store);
  res.json(store[idx]);
});

app.get('/api/support/reports', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  res.json(readStore('reports'));
});

app.patch('/api/support/reports/:id', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  const store = readStore('reports');
  const idx = store.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Não encontrado' });
  store[idx] = { ...store[idx], ...req.body, updatedAt: new Date().toISOString() };
  writeStore('reports', store);
  res.json(store[idx]);
});

app.get('/api/support/staff', requireRole('admin', 'dono', 'moderador', 'suporte', 'staff'), (req, res) => {
  const store = readStore('staff');
  res.json(store.map(s => ({ id: s.id, name: s.name, role: s.role, status: s.status || 'offline', discordId: s.discordId || '' })));
});

// ===== FILE UPLOAD =====
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Arquivo obrigatório' });
  res.json({ url: `/uploads/${req.file.filename}`, name: req.file.originalname, size: req.file.size });
});

// ===== WEBHOOK PIX =====
app.post('/api/webhook/pix', safeHandler(async (req, res) => {
  const payment = req.body;
  if (payment.status === 'approved') {
    const entry = addEntry('purchases', {
      usuario: payment.usuario || 'desconhecido',
      produto: payment.produto || 'vip',
      valor: payment.valor || 0,
      email: payment.email || '',
      pagamento_id: payment.id
    });
    sendDiscordNotification(formatDiscordEmbed('purchase', entry));
  }
  res.json({ received: true });
}));

// ===== SERVER STATS =====
let statsCache = { data: null, expires: 0 };

app.get('/api/server/stats', async (req, res) => {
  if (Date.now() < statsCache.expires) {
    return res.json(statsCache.data);
  }
  try {
    const resp = await fetch('https://discord.com/api/v10/invites/efootballbrasil?with_counts=true');
    if (!resp.ok) throw new Error('Discord API error');
    const json = await resp.json();
    statsCache.data = {
      name: json.guild?.name || 'eFootball Brasil',
      members: json.approximate_member_count || 0,
      online: json.approximate_presence_count || 0,
      icon: json.guild?.icon || '',
      id: json.guild?.id || ''
    };
    statsCache.expires = Date.now() + 60_000;
    res.json(statsCache.data);
  } catch {
    const fallback = await fetch('https://discord.com/api/guilds/1077324994373222500/widget.json').catch(() => null);
    if (fallback?.ok) {
      const w = await fallback.json();
      statsCache.data = { name: w.name, members: w.members?.length || 0, online: 0, id: w.id };
      statsCache.expires = Date.now() + 60_000;
      return res.json(statsCache.data);
    }
    res.status(503).json({ error: 'Indisponível' });
  }
});

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
  res.json({ status: 'online', server: 'eFootball Brasil' });
});

app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err);
  res.status(500).json({ error: 'Erro interno' });
});

db.startAutoBackup();

const clients = new Map(); // ticketId -> Set<WebSocket>

function broadcast(type, id, data) {
  const key = type + ':' + id;
  const conns = clients.get(key);
  if (!conns) return;
  const msg = JSON.stringify(data);
  for (const ws of conns) {
    if (ws.readyState === 1) ws.send(msg);
  }
}

function addClient(type, id, ws) {
  const key = type + ':' + id;
  if (!clients.has(key)) clients.set(key, new Set());
  clients.get(key).add(ws);
  ws.on('close', () => {
    const s = clients.get(key);
    if (s) { s.delete(ws); if (s.size === 0) clients.delete(key); }
  });
}

const server = require('http').createServer(app);

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const u = new URL(req.url, 'http://x');
  const token = u.searchParams.get('token');
  const session = token ? verifyToken(token) : null;
  ws._session = session;

  ws.on('message', raw => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'join') {
        addClient(msg.channelType || 'ticket', msg.channelId, ws);
      }
    } catch (_) {}
  });
});

process.on('uncaughtException', (err) => console.error('🔥 Uncaught:', err.message));
process.on('unhandledRejection', (err) => console.error('🔥 Unhandled:', err.message));

server.listen(PORT, () => {
  console.log(`\u26BD eFootball Brasil rodando em http://localhost:${PORT}`);
  console.log(`\uD83D\uDD17 JWT Auth ativo`);
  console.log(`\uD83D\uDCCB Banco SQLite: data/database.sqlite`);
  console.log(`\uD83D\uDDC3\uFE0F Backups: backups/ (a cada 1 hora)`);
  console.log(`\uD83D\uDD11 Login API: POST /api/auth/login`);
  console.log(`\uD83D\uDD11 Login Page: http://localhost:${PORT}/public/login.html`);
  console.log(`\uD83D\uDEE0\uFE0F Painel: http://localhost:${PORT}/public/panel.html`);
  console.log(`\uD83D\uDCCB Admin: http://localhost:${PORT}/admin.html`);
  console.log(`\uD83C\uDFAB Staff: http://localhost:${PORT}/admin.html`);
  console.log(`\uD83D\uDD0C WebSocket ativo em ws://localhost:${PORT}`);
});

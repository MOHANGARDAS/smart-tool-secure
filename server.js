// ═══════════════════════════════════════════════════════════
// SMART-TOOL/M — Secure Backend Server (Supabase Version)
// ═══════════════════════════════════════════════════════════
'use strict';

const express       = require('express');
const jwt           = require('jsonwebtoken');
const multer        = require('multer');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const path          = require('path');
const { createClient } = require('@supabase/supabase-js');
const { PDFDocument } = require('pdf-lib');
const XLSX          = require('xlsx');
const JSZip          = require('jszip');

// ── CONFIGURATION ─────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'smarttool-master-secret-786';
const ADMIN_KEY  = process.env.ADMIN_KEY || '1121'; // Admin panel password

// Supabase Connection Configuration (Render Environment Variables se connect hoga)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// In-memory sessions verification map
const activeSessions = new Map();

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

// Security Rate Limiting
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many login attempts' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000, max: 30, message: { error: 'Rate limit exceeded' } });

// Serve frontend assets safely
app.use(express.static(__dirname));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB max payload
});

// ── AUTH MIDDLEWARE ──────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (activeSessions.has(decoded.username) && activeSessions.get(decoded.username) !== token) {
      return res.status(401).json({ error: 'Session terminated or expired' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session tokens' });
  }
}

function requireAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Admin key required' });
  }
  next();
}

// ═══════════════════════════════════════════════════════════
// REAL DATABASE AUTH ROUTES
// ═══════════════════════════════════════════════════════════

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const inputUser = username.toLowerCase().trim();
    const inputPass = password.trim();

    // 🔍 Supabase Database se user check karna
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', inputUser)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid Username or Password' });
    }

    // Checking if account is blocked
    if (user.blocked) {
      return res.status(403).json({ error: 'Your account has been blocked by Admin' });
    }

    // Password validation match (Strict matching)
    if (user.password !== inputPass) {
      return res.status(401).json({ error: 'Invalid Username or Password' });
    }

    // Token Generation on successful auth
    const token = jwt.sign({ username: inputUser }, JWT_SECRET, { expiresIn: '1h' });
    activeSessions.set(inputUser, token);

    // Update last login timestamp in Supabase database
    await supabase
      .from('users')
      .update({ last_login: new Date(), online: true })
      .eq('username', inputUser);

    res.json({ ok: true, token, username: inputUser });
  } catch (e) {
    res.status(500).json({ error: 'Server authentication crash' });
  }
});

app.post('/api/logout', requireAuth, async (req, res) => {
  const user = req.user.username;
  activeSessions.delete(user);
  
  await supabase
    .from('users')
    .update({ online: false })
    .eq('username', user);

  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════
// REAL ADMIN MANAGEMENT ENDPOINTS
// ═══════════════════════════════════════════════════════════

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, username, online, blocked, last_login');

    if (error) throw error;

    // Direct interface formatting data
    const formattedUsers = users.map(u => ({
      id: u.id,
      username: u.username,
      online: activeSessions.has(u.username),
      blocked: u.blocked || false,
      lastLogin: u.last_login
    }));

    res.json(formattedUsers);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch database users' });
  }
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Credentials missing' });

    const { error } = await supabase
      .from('users')
      .insert([{ 
        username: username.toLowerCase().trim(), 
        password: password.trim(),
        blocked: false,
        online: false
      }]);

    if (error) return res.status(400).json({ error: 'User already exists or DB schema conflict' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'User setup initialization failed' });
  }
});

app.get('/api/admin/sessions', requireAdmin, (req, res) => {
  const sessions = Array.from(activeSessions.keys()).map(user => ({
    username: user,
    loginAt: new Date()
  }));
  res.json(sessions);
});

app.post('/api/admin/sessions/:username/kill', requireAdmin, async (req, res) => {
  const user = decodeURIComponent(req.params.username);
  activeSessions.delete(user);
  
  await supabase.from('users').update({ online: false }).eq('username', user);
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/block', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { data: user } = await supabase.from('users').update({ blocked: true }).eq('id', id).select().single();
  if (user) activeSessions.delete(user.username);
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/unblock', requireAdmin, async (req, res) => {
  const { id } = req.params;
  await supabase.from('users').update({ blocked: false }).eq('id', id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  await supabase.from('users').delete().eq('id', id);
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/password', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  await supabase.from('users').update({ password: password.trim() }).eq('id', id);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════
// FILE PROCESSING LOGIC
// ═══════════════════════════════════════════════════════════

app.post('/api/process/:tool', requireAuth, apiLimiter,
  upload.fields([{ name: 'file', maxCount: 1 }, { name: 'files', maxCount: 500 }]),
  async (req, res) => {
    const tool = req.params.tool;
    try {
      let resultBuffer, mimeType, filename;
      if (!req.files?.file?.[0] && !req.files?.files?.length) {
        return res.status(400).json({ error: 'No data file uploaded' });
      }

      if (tool === '3c') {
        const src = await PDFDocument.load(req.files.file[0].buffer);
        const out = await PDFDocument.create();
        const cp = await out.copyPages(src, Array.from({length: src.getPageCount()}, (_,i)=>i));
        cp.forEach(p => out.addPage(p));
        const bytes = await out.save();
        resultBuffer = Buffer.from(bytes);
        mimeType = 'application/pdf';
        filename = '3Copies_output.pdf';
      } else if (tool === 'ew') {
        const out = await PDFDocument.create();
        const bytes = await out.save();
        resultBuffer = Buffer.from(bytes);
        mimeType = 'application/pdf';
        filename = 'EwayBill_output.pdf';
      } else {
        resultBuffer = req.files?.file?.[0]?.buffer || Buffer.from([]);
        mimeType = 'application/octet-stream';
        filename = 'processed_output.file';
      }

      res.set({
        'Content-Type': mimeType,
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': resultBuffer.length
      });
      res.send(resultBuffer);
    } catch (e) {
      res.status(500).json({ error: 'Processing failed securely' });
    }
  }
);

// ── ADMIN AND USER HTML ROUTING ──────────────────────
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'SMART-TOOL-M (1).html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'SMART-TOOL-M (1).html'));
});

app.listen(PORT, () => console.log(`✓ Live Engine running securely on port ${PORT}`));

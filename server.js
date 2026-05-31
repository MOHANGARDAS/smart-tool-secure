// ═══════════════════════════════════════════════════════════
// SMART-TOOL/M — Secure Backend Server (Fixed Version)
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

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'smarttool-master-secret-786';
const ADMIN_KEY  = process.env.ADMIN_KEY || '1121'; // Admin Panel Password

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://pjfmdyirsaventhzeqte.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'dummy';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const activeSessions = new Map();
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many login attempts' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000, max: 30, message: { error: 'Rate limit exceeded' } });

app.use(express.static(__dirname));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }
});

// ── AUTH MIDDLEWARE ──────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (activeSessions.has(decoded.username) && activeSessions.get(decoded.username) !== token) {
      return res.status(401).json({ error: 'Session terminated' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session' });
  }
}

// ═══════════════════════════════════════════════════════════
// FIXED USER & ADMIN LOGIN ROUTES (BINA DB KE INSTANT LOGIN)
// ═══════════════════════════════════════════════════════════

// 1. Normal User Portal Login (`/`)
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const inputUser = username.toLowerCase().trim();
    const inputPass = password.trim();

    // 🔒 FIXED LOGIN LOCK: Username 'mohan' aur Password '1121' par set hai
    if (inputUser === 'mohan' && inputPass === '1121') {
      const token = jwt.sign({ username: inputUser }, JWT_SECRET, { expiresIn: '1h' });
      activeSessions.set(inputUser, token);
      return res.json({ ok: true, token, username: inputUser });
    }

    return res.status(401).json({ error: 'Invalid Username or Password' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. Admin Panel Login (`/admin`)
app.post('/api/admin/login', (req, res) => {
  const { adminKey } = req.body;
  // Agar headers me key nahi hai toh body se check karega (Form submit support)
  const keyToCheck = adminKey || req.headers['x-admin-key'];

  if (keyToCheck === ADMIN_KEY) {
    return res.json({ ok: true, message: "Admin access granted" });
  }
  return res.status(403).json({ error: 'Invalid admin key' });
});

app.post('/api/logout', requireAuth, (req, res) => {
  activeSessions.delete(req.user.username);
  res.json({ ok: true });
});

// Mock endpoints for frontend compatibility
app.get('/api/admin/users', (req, res) => res.json([{ id: '1', username: 'mohan', online: true, blocked: false }]));
app.post('/api/admin/users', (req, res) => res.json({ ok: true }));
app.get('/api/admin/sessions', (req, res) => res.json([]));

// ═══════════════════════════════════════════════════════════
// FILE PROCESSING LOGIC
// ═══════════════════════════════════════════════════════════
app.post('/api/process/:tool', requireAuth, apiLimiter, upload.fields([{ name: 'file', maxCount: 1 }]), async (req, res) => {
  try {
    if (!req.files?.file?.[0]) return res.status(400).json({ error: 'No file uploaded' });
    let resultBuffer = req.files.file[0].buffer;
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="output.pdf"' });
    res.send(resultBuffer);
  } catch (e) {
    res.status(500).json({ error: 'Processing failed' });
  }
});

// Routing paths
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'SMART-TOOL-M (1).html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'SMART-TOOL-M (1).html')));

app.listen(PORT, () => console.log(`✓ Live Engine running securely on port ${PORT}`));

// ═══════════════════════════════════════════════════════════
// SMART-TOOL/M — Backend Server
// Express + MongoDB + Session Auth + PDF/Excel Processing
// ═══════════════════════════════════════════════════════════
'use strict';

const express       = require('express');
const session       = require('express-session');
const MongoStore    = require('connect-mongo');
const mongoose      = require('mongoose');
const bcrypt        = require('bcryptjs');
const multer        = require('multer');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const { v4: uuid }  = require('uuid');
const path          = require('path');
const { PDFDocument } = require('pdf-lib');
const XLSX          = require('xlsx');
const JSZip         = require('jszip');

// ── ENV ─────────────────────────────────────────────────
const PORT      = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/smarttool';
const SESS_SEC  = process.env.SESSION_SECRET || 'smarttool-secret-change-in-prod';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin-master-key-change-me';

// ── MONGOOSE MODELS ──────────────────────────────────────
const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true },
  blocked:   { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});
const User = mongoose.model('User', userSchema);

// In-memory active sessions map: sessionId → { username, loginAt, socketId }
const activeSessions = new Map();

// ── EXPRESS SETUP ────────────────────────────────────────
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

// Rate limiting
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many login attempts' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000, max: 30, message: { error: 'Rate limit exceeded' } });

// Session store
app.use(session({
  secret: SESS_SEC,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI, ttl: 3600 }),
  cookie: { secure: false, httpOnly: true, maxAge: 3600000 } // 60 min
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ── MULTER — memory storage (no disk write) ──────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB max
});

// ── AUTH MIDDLEWARE ──────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Not authenticated' });
  User.findById(req.session.userId)
    .then(user => {
      if (!user || user.blocked) {
        req.session.destroy();
        return res.status(401).json({ error: 'Account blocked or not found' });
      }
      req.user = user;
      next();
    })
    .catch(() => res.status(500).json({ error: 'Auth error' }));
}

function requireAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(403).json({ error: 'Admin key required' });
  next();
}

// ═══════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/login
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = await User.findOne({ username: username.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.blocked) return res.status(403).json({ error: 'Account is blocked' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Kill existing session for this user
    for (const [sid, data] of activeSessions.entries()) {
      if (data.username === user.username) activeSessions.delete(sid);
    }

    req.session.userId   = user._id.toString();
    req.session.username = user.username;

    // Track session
    activeSessions.set(req.sessionID, {
      username: user.username,
      loginAt: new Date(),
      userId: user._id.toString()
    });

    user.lastLogin = new Date();
    await user.save();

    res.json({ ok: true, username: user.username });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  activeSessions.delete(req.sessionID);
  req.session.destroy(() => res.json({ ok: true }));
});

// GET /api/me
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username });
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════

// GET /api/admin/users
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    // Annotate with live session info
    const result = users.map(u => {
      const sess = [...activeSessions.values()].find(s => s.username === u.username);
      return {
        _id: u._id, username: u.username, blocked: u.blocked,
        createdAt: u.createdAt, lastLogin: u.lastLogin,
        online: !!sess, loginAt: sess?.loginAt || null
      };
    });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/admin/users — create user
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username: username.toLowerCase().trim(), password: hash });
    res.json({ ok: true, user: { _id: user._id, username: user.username } });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/admin/users/:id/block
app.patch('/api/admin/users/:id/block', requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { blocked: true }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    // Kill their active session
    for (const [sid, data] of activeSessions.entries()) {
      if (data.username === user.username) activeSessions.delete(sid);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// PATCH /api/admin/users/:id/unblock
app.patch('/api/admin/users/:id/unblock', requireAdmin, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { blocked: false });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    for (const [sid, data] of activeSessions.entries()) {
      if (data.username === user.username) activeSessions.delete(sid);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// GET /api/admin/sessions — live sessions
app.get('/api/admin/sessions', requireAdmin, (req, res) => {
  const list = [...activeSessions.entries()].map(([sid, data]) => ({
    sessionId: sid, username: data.username, loginAt: data.loginAt
  }));
  res.json(list);
});

// POST /api/admin/sessions/:username/kill — force logout
app.post('/api/admin/sessions/:username/kill', requireAdmin, (req, res) => {
  let killed = 0;
  for (const [sid, data] of activeSessions.entries()) {
    if (data.username === req.params.username) {
      activeSessions.delete(sid);
      killed++;
    }
  }
  res.json({ ok: true, killed });
});

// PATCH /api/admin/users/:id/password — reset password
app.patch('/api/admin/users/:id/password', requireAdmin, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
    const hash = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(req.params.id, { password: hash });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ═══════════════════════════════════════════════════════════
// PROCESSING ROUTES (authenticated)
// ═══════════════════════════════════════════════════════════

// POST /api/process/:tool
// tool: 3c | iz | ie | et | em | ew
app.post('/api/process/:tool', requireAuth, apiLimiter,
  upload.fields([{ name: 'file', maxCount: 1 }, { name: 'files', maxCount: 500 }]),
  async (req, res) => {
    const tool = req.params.tool;
    try {
      let resultBuffer, mimeType, filename;

      if (['3c','iz','ie'].includes(tool)) {
        // PDF tools — single file
        if (!req.files?.file?.[0]) return res.status(400).json({ error: 'No PDF uploaded' });
        const buf = req.files.file[0].buffer;

        if (tool === '3c') {
          ({ buffer: resultBuffer, filename } = await proc3Copies(buf));
          mimeType = 'application/pdf';
        } else {
          const isEcom = tool === 'ie';
          ({ buffer: resultBuffer, filename } = await procInvoiceZip(buf, isEcom));
          mimeType = 'application/zip';
        }

      } else if (tool === 'ew') {
        // E-Way Bill — multiple files
        if (!req.files?.files?.length) return res.status(400).json({ error: 'No PDF files uploaded' });
        const bufs = req.files.files.map(f => f.buffer);
        ({ buffer: resultBuffer, filename } = await procEwayMerge(bufs));
        mimeType = 'application/pdf';

      } else if (tool === 'et') {
        // Excel TRPT
        if (!req.files?.file?.[0]) return res.status(400).json({ error: 'No Excel file uploaded' });
        ({ buffer: resultBuffer, filename } = await procExcelTRPT(req.files.file[0].buffer));
        mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

      } else if (tool === 'em') {
        // Excel Merge + NP
        if (!req.files?.file?.[0]) return res.status(400).json({ error: 'No Excel file uploaded' });
        ({ buffer: resultBuffer, filename } = await procExcelMerge(req.files.file[0].buffer));
        mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

      } else {
        return res.status(400).json({ error: 'Unknown tool' });
      }

      res.set({
        'Content-Type': mimeType,
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': resultBuffer.length
      });
      res.send(resultBuffer);

    } catch (e) {
      console.error('Processing error:', e);
      res.status(500).json({ error: e.message || 'Processing failed' });
    }
  }
);

// ═══════════════════════════════════════════════════════════
// PROCESSING FUNCTIONS
// ═══════════════════════════════════════════════════════════

const INVOICE_PATS = [
  /Invoice\s*No\.?\s*[:\-]?\s*([A-Za-z0-9\/\-]+)/i,
  /Invoice\s*Number\s*[:\-]?\s*([A-Za-z0-9\/\-]+)/i,
  /Inv\s*No\.?\s*[:\-]?\s*([A-Za-z0-9\/\-]+)/i,
  /Bill\s*No\.?\s*[:\-]?\s*([A-Za-z0-9\/\-]+)/i
];

// Extract text from PDF using pdf-lib (basic) — or via pdfjs
async function extractPdfPages(buf) {
  // We use a manual approach: load with pdf-lib for structure
  // and pdfjs for text. Since pdfjs-dist in node needs canvas,
  // we do a regex-based approach on raw text streams as fallback.
  // In production, use pdf-parse or pdfjs with node canvas.
  const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
  const doc = await pdfjsLib.getDocument({ data: new Uint8Array(buf) }).promise;
  const pages = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    const tc = await page.getTextContent();
    const text = tc.items.map(t => t.str).join(' ');
    pages.push({ index: i - 1, text });
  }
  return pages;
}

async function groupByInvoice(buf, keepInstruction) {
  const pages = await extractPdfPages(buf);
  const grouped = {}, instrPages = {}, order = [];
  let current = null;

  for (const { index, text } of pages) {
    if (!keepInstruction && text.includes('INSTRUCTION TO CUSTOMER')) continue;
    let found = false;
    for (const pat of INVOICE_PATS) {
      const m = pat.exec(text);
      if (m) {
        current = m[1].trim();
        if (!grouped[current]) { grouped[current] = []; instrPages[current] = []; order.push(current); }
        found = true; break;
      }
    }
    if (current) {
      if (keepInstruction && text.includes('INSTRUCTION TO CUSTOMER')) instrPages[current].push(index);
      else grouped[current].push(index);
    }
  }
  return { grouped, instrPages, order };
}

async function proc3Copies(buf) {
  const { grouped, order } = await groupByInvoice(buf, false);
  if (!order.length) throw new Error('No invoices detected in PDF');

  const src = await PDFDocument.load(buf);
  const out = await PDFDocument.create();
  for (const inv of order) {
    const pages = grouped[inv] || [];
    for (let c = 0; c < 3; c++) {
      const cp = await out.copyPages(src, pages);
      cp.forEach(p => out.addPage(p));
    }
  }
  const bytes = await out.save({ useObjectStreams: true });
  return { buffer: Buffer.from(bytes), filename: '3Copies_output.pdf' };
}

async function procInvoiceZip(buf, isEcom) {
  const { grouped, instrPages, order } = await groupByInvoice(buf, true);
  if (!order.length) throw new Error('No invoices detected in PDF');

  const src = await PDFDocument.load(buf);
  const zip = new JSZip();

  for (const inv of order) {
    const pages = grouped[inv] || [];
    const ip = instrPages[inv] || [];
    const doc = await PDFDocument.create();
    if (pages.length) { const cp = await doc.copyPages(src, pages); cp.forEach(p => doc.addPage(p)); }
    if (ip.length) { const cp = await doc.copyPages(src, [ip[ip.length-1]]); cp.forEach(p => doc.addPage(p)); }
    const b = await doc.save({ useObjectStreams: true });
    zip.file((isEcom ? 'ECOM_' : '') + inv + '.pdf', b);
  }

  const zipBuf = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: { level: 4 } });
  return { buffer: zipBuf, filename: isEcom ? 'Invoices_Ecom.zip' : 'Invoices.zip' };
}

async function procEwayMerge(buffers) {
  const out = await PDFDocument.create();
  for (const buf of buffers) {
    try {
      const src = await PDFDocument.load(buf, { ignoreEncryption: true });
      const count = src.getPageCount();
      const idx = Array.from({ length: count }, (_, k) => k);
      const c1 = await out.copyPages(src, idx); c1.forEach(p => out.addPage(p));
      const c2 = await out.copyPages(src, idx); c2.forEach(p => out.addPage(p));
    } catch (e) { /* skip corrupt */ }
  }
  const bytes = await out.save({ useObjectStreams: true });
  return { buffer: Buffer.from(bytes), filename: `EwayBill_${buffers.length}files.pdf` };
}

function validInv(n) { return n.length === 9 || n.length === 10; }

function expandInvoice(raw) {
  const cl = String(raw).replace(/\.\.\./g,'').replace(/\.\./g,'').trim();
  if (!cl || cl === 'nan') return [];
  const res = [];
  for (let block of cl.split(',')) {
    block = block.trim();
    if (block.includes('/')) {
      const pts = block.split('/');
      const base = pts[0].replace(/\D/g,'');
      if (!validInv(base)) continue;
      res.push(base);
      for (const suf of pts.slice(1)) {
        const s = suf.replace(/\D/g,'');
        if (!s || s.length > base.length) continue;
        const n = base.slice(0, base.length - s.length) + s;
        if (validInv(n)) res.push(n);
      }
    } else {
      const n = block.replace(/\D/g,'');
      if (validInv(n)) res.push(n);
    }
  }
  return [...new Set(res)];
}

function procExcelTRPT(buf) {
  const wb = XLSX.read(buf, { type: 'buffer' });
  const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { defval: '' });
  if (!rows.length) throw new Error('No data found');

  const keys = Object.keys(rows[0] || {});
  const fk = n => keys.find(k => k.trim().toLowerCase() === n.toLowerCase()) || n;
  const dK = fk('Docket No'), iK = fk('Invoice No'), dtK = fk('Delivery Date');

  const out = [];
  for (const row of rows) {
    const expanded = expandInvoice(String(row[iK] || ''));
    for (const inv of expanded) out.push({ 'Docket No': String(row[dK]||''), 'Invoice No': inv, 'Delivery Date': String(row[dtK]||'') });
  }

  const owb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(owb, XLSX.utils.json_to_sheet(out), 'Expanded');
  const ob = XLSX.write(owb, { bookType: 'xlsx', type: 'buffer' });
  return { buffer: ob, filename: 'TRPT_output.xlsx' };
}

const NP_KW  = ['ALASPAN','SARIDON','SUPRADYN','CANESTEN','BECOZYM','BENADON','BEPANTHEN','LUCIARA','MYCOSPOR','POLARAMINE',"BAYER'S TONIC"];
const HDR_KW = ['material','order qty','batch','storage location','plant'];
const PRIO   = ['Material','Order Qty','UNIT','BATCH','Storage location','Plant','Remark','Product','distribution','division','remaks','regd no','PARTY NAME','NP'];

function procExcelMerge(buf) {
  const wb = XLSX.read(buf, { type: 'buffer', cellDates: true });
  const allRows = [], allHdrs = new Set();

  for (const sn of wb.SheetNames) {
    const rr = XLSX.utils.sheet_to_json(wb.Sheets[sn], { header: 1, defval: '' });
    if (!rr.length) continue;

    const partyName = getPartyName(rr);
    const hi = getHeaderRow(rr);
    if (hi === null) continue;

    const hdrs = makeUniqueHdrs(rr[hi].map(String));
    hdrs.forEach(h => allHdrs.add(h));
    allHdrs.add('regd no'); allHdrs.add('PARTY NAME');

    for (let i = hi + 1; i < rr.length; i++) {
      const row = rr[i];
      if (row.every(c => String(c).trim() === '')) continue;
      const obj = {};
      hdrs.forEach((h, j) => { obj[h] = j < row.length ? String(row[j]).trim() : ''; });
      obj['regd no'] = sn; obj['PARTY NAME'] = partyName;
      allRows.push(obj);
    }
  }

  if (!allRows.length) throw new Error('No valid data found');
  allHdrs.add('NP');

  const fc = buildCols([...allHdrs]);
  allRows.forEach(r => { r['NP'] = tagNP(r['Product'] || ''); });

  const oR = allRows.map(r => { const o = {}; fc.forEach(c => { o[c] = r[c] ?? ''; }); return o; });
  const owb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(owb, XLSX.utils.json_to_sheet(oR, { header: fc }), 'Merged_Data');
  const ob = XLSX.write(owb, { bookType: 'xlsx', type: 'buffer' });
  return { buffer: ob, filename: 'Merged_NP_output.xlsx' };
}

function getPartyName(rows) {
  for (const row of rows.slice(0,20))
    for (let i = 0; i < row.length; i++)
      if (String(row[i]).toUpperCase().includes('PARTY NAME'))
        if (i+1 < row.length && String(row[i+1]).trim()) return String(row[i+1]).trim();
  return '';
}
function getHeaderRow(rows) {
  for (let i = 0; i < rows.length; i++) {
    const lo = rows[i].map(c => String(c).toLowerCase());
    if (HDR_KW.filter(kw => lo.some(c => c.includes(kw))).length >= 2) return i;
  }
  return null;
}
function makeUniqueHdrs(raw) {
  const cnt = {};
  return raw.map(h => { const cl = h.trim() || 'EMPTY_COL'; const n = cnt[cl] = (cnt[cl]||0)+1; return n===1?cl:`${cl}_${n-1}`; });
}
function buildCols(hs) {
  const p = PRIO.filter(c => hs.includes(c));
  return [...p, ...hs.filter(c => !p.includes(c)).sort()];
}
function tagNP(p) {
  const u = p.trim().toUpperCase();
  if (!u) return '';
  return NP_KW.some(k => u.includes(k)) ? 'N' : '';
}

// ── SPA fallback ─────────────────────────────────────────
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✓ MongoDB connected');
    app.listen(PORT, () => console.log(`✓ Server running on http://localhost:${PORT}`));
  })
  .catch(e => { console.error('MongoDB error:', e); process.exit(1); });

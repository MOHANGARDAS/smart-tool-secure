// ═══════════════════════════════════════════════════════════════════
// SMART-TOOL/M — Secure PWA Backend
//   • Auth (JWT) + Admin
//   • File processing tools
//   • AI Repo Assistant (voice/text → plan → confirm → push to GitHub)
// ═══════════════════════════════════════════════════════════════════
'use strict';

const express       = require('express');
const jwt           = require('jsonwebtoken');
const multer        = require('multer');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const path          = require('path');
const fs            = require('fs');
const http          = require('http');
const https         = require('https');
const { createClient } = require('@supabase/supabase-js');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const XLSX = require('xlsx');

// ── Portable outbound HTTPS helper ──────────────────────────────
// Uses the system CA bundle so TLS works even where Node's bundled
// CA store is incomplete (also lets GitHub/Gemini calls run anywhere).
let SYSTEM_CA;
try {
  const caPath = process.env.SSL_CERT_FILE || '/etc/ssl/certs/ca-certificates.crt';
  if (fs.existsSync(caPath)) SYSTEM_CA = fs.readFileSync(caPath);
} catch {}

function request(url, options) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, {
      method: (options && options.method) || 'GET',
      headers: (options && options.headers) || {},
      ca: SYSTEM_CA
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (options && options.body) req.write(options.body);
    req.end();
  });
}

async function apiFetch(url, options) {
  const r = await request(url, options);
  return {
    ok: r.status >= 200 && r.status < 300,
    status: r.status,
    headers: r.headers,
    async json() { return JSON.parse(r.text); },
    async text() { return r.text; }
  };
}

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'smarttool-master-secret-786';
const ADMIN_KEY  = process.env.ADMIN_KEY || '1121';

// Persistent data dir (config.json, users.json) — default is app dir;
// set DATA_DIR to a mounted volume in Docker/cloud so data survives restarts.
const DATA_DIR = process.env.DATA_DIR || __dirname;

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://pjfmdyirsaventhzeqte.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'dummy';
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ── Dynamic users (memory + disk persistence) ──────────────────
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const dynamicUsers = new Map();
function loadUsers() {
  try {
    const raw = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
    Object.entries(raw).forEach(([u, p]) => dynamicUsers.set(u, String(p)));
  } catch {}
}
function persistUsers() {
  try {
    fs.writeFileSync(USERS_PATH, JSON.stringify(Object.fromEntries(dynamicUsers), null, 2));
  } catch {}
}
loadUsers();
// Default admin-user (always present)
if (!dynamicUsers.has('mohan')) dynamicUsers.set('mohan', '1121');
const activeSessions = new Map();

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(express.static(__dirname));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many login attempts' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000, max: 60, message: { error: 'Rate limit exceeded' } });

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500*1024*1024 } });

// ── CONFIG (AI + GitHub) — persisted server-side, env fallback ──
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); }
  catch { return {}; }
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

function aiConfig() {
  const a = (loadConfig().ai) || {};
  const provider = a.provider || process.env.AI_PROVIDER || 'gemini';
  const model    = a.model    || process.env.AI_MODEL    || (provider === 'gemini' ? 'gemini-2.5-flash' : 'gpt-4o-mini');
  const apiKey   = a.apiKey   || process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY || '';
  const baseUrl  = a.baseUrl  || process.env.AI_BASE_URL  || '';
  return { provider, model, apiKey, baseUrl };
}
function ghConfig() {
  const g = (loadConfig().github) || {};
  const token  = g.token  || process.env.GITHUB_TOKEN  || '';
  const owner  = g.owner  || process.env.GITHUB_OWNER  || 'MOHANGARDAS';
  const repo   = g.repo   || process.env.GITHUB_REPO   || 'smart-tool-secure';
  const branch = g.branch || process.env.GITHUB_BRANCH || 'main';
  return { token, owner, repo, branch };
}

// ── AUTH MIDDLEWARE (login disabled — all endpoints public) ─────
function requireAuth(req, res, next) {
  // No login required anymore. Keep a dummy user so route code still works.
  const token = (req.headers['authorization'] || '').split(' ')[1];
  try {
    const decoded = token ? jwt.verify(token, JWT_SECRET) : { username: 'guest' };
    req.user = decoded;
  } catch {
    req.user = { username: 'guest' };
  }
  next();
}

// ═══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════
app.post('/api/login', loginLimiter, upload.none(), (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const u = username.toLowerCase().trim();
  const p = String(password).trim();
  if (dynamicUsers.has(u) && dynamicUsers.get(u) === p) {
    const token = jwt.sign({ username: u }, JWT_SECRET, { expiresIn: '12h' });
    activeSessions.set(u, token);
    return res.json({ ok: true, token, username: u });
  }
  return res.status(401).json({ error: 'Invalid Username or Password' });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.user.username }));

app.post('/api/logout', requireAuth, (req, res) => {
  activeSessions.delete(req.user.username);
  res.json({ ok: true });
});

app.post('/api/admin/login', upload.none(), (req, res) => {
  const key = (req.body && req.body.adminKey) || req.headers['x-admin-key'];
  if (key === ADMIN_KEY) return res.json({ ok: true, message: 'Admin access granted' });
  return res.status(403).json({ error: 'Invalid admin key' });
});

app.get('/api/admin/users', (req, res) => {
  const users = Array.from(dynamicUsers.keys()).map((u, i) => ({
    id: `usr_${i}`, username: u, online: activeSessions.has(u), blocked: false, lastLogin: new Date()
  }));
  res.json(users);
});

app.post('/api/admin/users', upload.none(), (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Credentials missing' });
  dynamicUsers.set(username.toLowerCase().trim(), String(password).trim());
  persistUsers();
  res.json({ ok: true, message: `User ${username} created` });
});

app.get('/api/admin/sessions', (req, res) => res.json([]));

// ═══════════════════════════════════════════════════════════════
// FILE PROCESSING
// ═══════════════════════════════════════════════════════════════
app.post('/api/process/:tool', requireAuth, apiLimiter, upload.fields([{ name: 'file', maxCount: 1 }, { name: 'files', maxCount: 100 }]), async (req, res) => {
  try {
    const tool = req.params.tool;
    const single = req.files && req.files.file && req.files.file[0];
    const many = req.files && req.files.files ? req.files.files : [];

    let outBuf, outName, ctype = 'application/pdf';

    if (tool === 'ew') {
      if (!many.length) return res.status(400).json({ error: 'No files uploaded' });
      const merged = await PDFDocument.create();
      for (const f of many) {
        const src = await PDFDocument.load(f.buffer);
        const pages = await merged.copyPages(src, src.getPageIndices());
        pages.forEach(p => merged.addPage(p));
      }
      outBuf = Buffer.from(await merged.save());
      outName = 'EwayBill_merged.pdf';
    } else if (tool === '3c' && single) {
      const src = await PDFDocument.load(single.buffer);
      const out = await PDFDocument.create();
      for (let i = 0; i < 3; i++) {
        const pages = await out.copyPages(src, src.getPageIndices());
        pages.forEach(p => out.addPage(p));
      }
      outBuf = Buffer.from(await out.save());
      outName = '3Copies.pdf';
    } else if (single) {
      outBuf = single.buffer;
      outName = single.originalname;
      if (/\.(xlsx|xls|xlsm|xlsb|csv)$/i.test(outName)) {
        ctype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
      } else if (/\.zip$/i.test(outName)) ctype = 'application/zip';
    } else {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    res.set({ 'Content-Type': ctype, 'Content-Disposition': `attachment; filename="${outName}"` });
    res.send(outBuf);
  } catch (e) {
    res.status(500).json({ error: 'Processing failed: ' + e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// AI REPO ASSISTANT
// ═══════════════════════════════════════════════════════════════

function ghHeaders(gh) {
  return {
    Authorization: `Bearer ${gh.token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
    'User-Agent': 'smart-tool-m'
  };
}

const TEXT_EXT = /\.(js|ts|tsx|jsx|html|css|json|md|txt|yml|yaml|xml|svg|env|sh|py|java|c|h|cpp|cs|go|rs|rb|php|vue|svelte|sql|conf|ini|toml|graphql|mjs|cjs|gitignore|npmrc)$/i;
const SKIP_DIR = /(^|\/)(node_modules|\.git|dist|build|out|coverage|\.next|\.venv|vendor|target)(\/|$)/;

function isTextPath(p) {
  if (!TEXT_EXT.test(p)) return false;
  return !SKIP_DIR.test(p);
}

async function getSnapshot(gh) {
  if (gh.token) {
    const files = [];
    const treeUrl = `https://api.github.com/repos/${gh.owner}/${gh.repo}/git/trees/${encodeURIComponent(gh.branch)}?recursive=1`;
    const tr = await apiFetch(treeUrl, { headers: ghHeaders(gh) });
    if (!tr.ok) throw new Error('GitHub tree fetch failed (' + tr.status + ')');
    const td = await tr.json();
    const blobs = (td.tree || []).filter(e => e.type === 'blob' && e.size < 150000 && isTextPath(e.path));
    const picked = blobs.slice(0, 60);
    let total = 0;
    for (const e of picked) {
      if (total > 400000) break;
      try {
        const cr = await apiFetch(
          `https://api.github.com/repos/${gh.owner}/${gh.repo}/contents/${encodeURIComponent(e.path)}?ref=${encodeURIComponent(gh.branch)}`,
          { headers: ghHeaders(gh) }
        );
        if (!cr.ok) continue;
        const cd = await cr.json();
        if (cd.encoding === 'base64' && cd.content) {
          const buf = Buffer.from(cd.content.replace(/\n/g, ''), 'base64');
          files.push({ path: e.path, content: buf.toString('utf8') });
          total += buf.length;
        }
      } catch {}
    }
    return { source: 'github', files };
  }

  // Local fallback
  const files = [];
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      const rel = path.relative(__dirname, full).split(path.sep).join('/');
      if (ent.isDirectory()) {
        if (SKIP_DIR.test('/' + rel + '/')) continue;
        walk(full);
      } else if (ent.isFile() && isTextPath(ent.name)) {
        if (files.length >= 60) return;
        try {
          const buf = fs.readFileSync(full);
          if (buf.length > 150000) return;
          files.push({ path: rel, content: buf.toString('utf8') });
        } catch {}
      }
    }
  }
  walk(__dirname);
  return { source: 'local', files };
}

async function callLLM(ai, messages) {
  if (!ai.apiKey) throw new Error('AI API key not configured. Open Settings and add a free Gemini key.');
  if (ai.provider === 'gemini') {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(ai.model)}:generateContent?key=${encodeURIComponent(ai.apiKey)}`;
    const parts = messages.map(m => ({ text: `${m.role === 'assistant' ? 'Assistant' : 'User'}: ${m.content}` }));
    const body = { contents: [{ parts }], generationConfig: { temperature: 0.2, responseMimeType: 'application/json' } };
    const r = await apiFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error((d.error && d.error.message) || 'Gemini error ' + r.status);
    return (d.candidates && d.candidates[0] && d.candidates[0].content &&
      d.candidates[0].content.parts.map(p => p.text).join('')) || '';
  }
  // OpenAI-compatible
  const base = (ai.baseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const url = base + '/chat/completions';
  const body = { model: ai.model, messages, temperature: 0.2, response_format: { type: 'json_object' } };
  const r = await apiFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ai.apiKey}` }, body: JSON.stringify(body) });
  const d = await r.json();
  if (!r.ok) throw new Error((d.error && d.error.message) || 'Provider error ' + r.status);
  return (d.choices && d.choices[0] && d.choices[0].message && d.choices[0].message.content) || '';
}

const RULES_FILE = 'SMARTTOOL_RULES.md';

const SYSTEM_PROMPT = `You are an expert coding assistant embedded in a PWA that edits a GitHub repository.
You receive a repository snapshot (file paths + contents) and the user's request (a feature change, a rule, a condition, a bug fix, or a memory/note).

Respond with STRICT JSON ONLY, exactly in this shape:
{
  "summary": "short human-readable summary of what you will change",
  "changes": [
    { "path": "relative/path.js", "action": "create", "content": "full file content" },
    { "path": "relative/path.js", "action": "update", "content": "full NEW file content" },
    { "path": "relative/path.js", "action": "delete" }
  ]
}

CRITICAL — MEMORY & RULES (anti-duplication — prevents mess):
- The file "${RULES_FILE}" is the PERSISTENT MEMORY. It holds every rule/condition the user has ever told you.
- When the user states a rule/condition, do BOTH:
  1) Record it in ${RULES_FILE}, AND
  2) Apply the matching CODE change to the relevant script/button so it is actually enforced.
- UPDATE vs ADD — THIS IS THE MOST IMPORTANT RULE:
  * If the user is CHANGING an EXISTING rule/mapping/value (they say "change X from x to y", "update", "ab x ke jagah y karo", "make it y instead"), then EDIT THE EXISTING entry IN PLACE:
    - In ${RULES_FILE}, REPLACE the old line/value with the new one.
    - In the code, CHANGE the existing value in place.
    - NEVER add a second duplicate entry for the same key/product.
  * Only ADD a NEW entry when the subject is genuinely new (a product/rule not mentioned before).
  * One key/product = exactly ONE entry, always. No duplicates ever.
- When the user asks to CHANGE existing behaviour, first read ${RULES_FILE} to find the current rule, then update that same rule AND its code together (not a new one).
- If a rule cannot be enforced because the referenced tool has no real logic yet, say so in "summary" and still record the rule in memory.

General rules:
- For "update", "content" MUST be the COMPLETE new file content, never a diff.
- For "delete", omit "content".
- Only "update"/"delete" files that exist in the snapshot; "create" new paths as needed.
- Never include secrets, API keys, or tokens in any file content.
- Match the existing code style and conventions.
- If ambiguous, make the most reasonable choice and mention it in "summary".
- If no file change is warranted, return an empty "changes" array and explain in "summary".
- Output ONLY the JSON object. No markdown fences, no extra text.`;

function parsePlan(text) {
  let t = String(text).trim();
  t = t.replace(/^```(json)?/i, '').replace(/```$/i, '').trim();
  const start = t.indexOf('{');
  const end = t.lastIndexOf('}');
  if (start >= 0 && end > start) t = t.slice(start, end + 1);
  const obj = JSON.parse(t);
  return {
    summary: obj.summary || 'No summary',
    changes: Array.isArray(obj.changes) ? obj.changes : []
  };
}

// Settings (masked read)
app.get('/api/ai/settings', requireAuth, (req, res) => {
  const ai = aiConfig(), gh = ghConfig();
  res.json({
    ai: { provider: ai.provider, model: ai.model, baseUrl: ai.baseUrl, hasKey: !!ai.apiKey },
    github: { hasToken: !!gh.token, owner: gh.owner, repo: gh.repo, branch: gh.branch }
  });
});

app.post('/api/ai/settings', requireAuth, (req, res) => {
  const cfg = loadConfig();
  const b = req.body || {};
  if (b.ai) {
    const a = cfg.ai || (cfg.ai = {});
    if (b.ai.provider !== undefined) a.provider = b.ai.provider;
    if (b.ai.model !== undefined) a.model = b.ai.model;
    if (b.ai.baseUrl !== undefined) a.baseUrl = b.ai.baseUrl;
    if (b.ai.apiKey !== undefined && b.ai.apiKey !== '') a.apiKey = b.ai.apiKey;
  }
  if (b.github) {
    const g = cfg.github || (cfg.github = {});
    if (b.github.token !== undefined && b.github.token !== '') g.token = b.github.token;
    if (b.github.owner !== undefined) g.owner = b.github.owner;
    if (b.github.repo !== undefined) g.repo = b.github.repo;
    if (b.github.branch !== undefined) g.branch = b.github.branch;
  }
  saveConfig(cfg);
  res.json({ ok: true });
});

// Read the persistent memory / rules file
app.get('/api/ai/memory', requireAuth, async (req, res) => {
  try {
    const gh = ghConfig();
    let content = null, source = 'none', exists = false;
    if (gh.token) {
      const url = `https://api.github.com/repos/${gh.owner}/${gh.repo}/contents/${encodeURIComponent(RULES_FILE)}?ref=${encodeURIComponent(gh.branch)}`;
      const r = await apiFetch(url, { headers: ghHeaders(gh) });
      if (r.ok) {
        const d = await r.json();
        if (d.encoding === 'base64' && d.content) {
          content = Buffer.from(d.content.replace(/\n/g, ''), 'base64').toString('utf8');
          exists = true; source = 'github';
        }
      } else if (r.status === 404) {
        exists = false; source = 'github';
      } else {
        throw new Error('GitHub fetch failed (' + r.status + ')');
      }
    } else {
      const p = path.join(__dirname, RULES_FILE);
      if (fs.existsSync(p)) { content = fs.readFileSync(p, 'utf8'); exists = true; }
      source = 'local';
    }
    res.json({ ok: true, file: RULES_FILE, exists, source, content: content || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Generate a change plan from a prompt (no push yet)
app.post('/api/ai/assist', requireAuth, apiLimiter, async (req, res) => {
  try {
    const { prompt, history } = req.body || {};
    if (!prompt) return res.status(400).json({ error: 'Empty prompt' });
    const ai = aiConfig(), gh = ghConfig();
    const snapshot = await getSnapshot(gh);

    const rulesEntry = snapshot.files.find(f => f.path === RULES_FILE);
    const memoryBlock = rulesEntry
      ? `CURRENT MEMORY (${RULES_FILE}):\n\`\`\`\n${rulesEntry.content}\n\`\`\`\n\n(These are the rules you must always respect and update when the user states a new rule.)`
      : `CURRENT MEMORY: no ${RULES_FILE} file exists yet. If the user states a rule, create it.`;

    const repoBlock = snapshot.files
      .filter(f => f.path !== RULES_FILE)
      .map(f => `### FILE: ${f.path}\n\`\`\`\n${f.content.length > 8000 ? f.content.slice(0, 8000) + '\n... [truncated]' : f.content}\n\`\`\``)
      .join('\n\n');

    const messages = [{ role: 'system', content: SYSTEM_PROMPT }];
    if (Array.isArray(history)) {
      for (const h of history.slice(-6)) {
        if (h && h.role && h.content) messages.push({ role: h.role, content: h.content });
      }
    }
    messages.push({
      role: 'user',
      content: `${memoryBlock}\n\nRepository snapshot:\n${repoBlock}\n\nUser request:\n${prompt}\n\nReturn the JSON plan now.`
    });

    const raw = await callLLM(ai, messages);
    let plan;
    try { plan = parsePlan(raw); }
    catch { plan = { summary: 'AI did not return a valid change plan.', raw, changes: [] }; }

    // Attach "before" content for update/delete so UI can render a diff
    const byPath = {};
    snapshot.files.forEach(f => { byPath[f.path] = f.content; });
    plan.changes = plan.changes.map(c => {
      if ((c.action === 'update' || c.action === 'delete') && byPath[c.path] !== undefined) {
        c.before = byPath[c.path];
      }
      return c;
    });

    res.json({ ok: true, plan, snapshotSource: snapshot.source });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Apply a confirmed plan → single commit + push
app.post('/api/ai/apply', requireAuth, apiLimiter, async (req, res) => {
  try {
    const { changes, summary } = req.body || {};
    if (!Array.isArray(changes) || !changes.length) return res.status(400).json({ error: 'No changes to apply' });
    const gh = ghConfig();
    if (!gh.token) return res.status(400).json({ error: 'GitHub token not configured' });

    const H = ghHeaders(gh);
    const base = `https://api.github.com/repos/${gh.owner}/${gh.repo}`;

    // 1. current HEAD ref
    let r = await apiFetch(`${base}/git/ref/heads/${encodeURIComponent(gh.branch)}`, { headers: H });
    if (r.status === 404) return res.status(400).json({ error: `Branch '${gh.branch}' not found in ${gh.owner}/${gh.repo}` });
    if (!r.ok) throw new Error('Ref fetch failed ' + r.status);
    const headSha = (await r.json()).object.sha;

    // 2. base tree
    r = await apiFetch(`${base}/git/commits/${headSha}`, { headers: H });
    if (!r.ok) throw new Error('Commit fetch failed ' + r.status);
    const baseTree = (await r.json()).tree.sha;

    // 3. blobs + tree items
    const treeItems = [];
    for (const c of changes) {
      if (c.action === 'delete') {
        treeItems.push({ path: c.path, mode: '100644', type: 'blob', sha: null });
        continue;
      }
      let content = c.content == null ? '' : String(c.content);
      if (content === '') content = '\n';
      const b64 = Buffer.from(content, 'utf8').toString('base64');
      const br = await apiFetch(`${base}/git/blobs`, { method: 'POST', headers: H, body: JSON.stringify({ content: b64, encoding: 'base64' }) });
      if (!br.ok) { const e = await br.json().catch(() => ({})); throw new Error(`Blob create failed for ${c.path}: ` + (e.message || br.status)); }
      const bd = await br.json();
      treeItems.push({ path: c.path, mode: '100644', type: 'blob', sha: bd.sha });
    }

    // 4. new tree
    r = await apiFetch(`${base}/git/trees`, { method: 'POST', headers: H, body: JSON.stringify({ base_tree: baseTree, tree: treeItems }) });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error('Tree create failed: ' + (e.message || r.status)); }
    const newTree = (await r.json()).sha;

    // 5. commit
    const msg = (summary || 'AI change') + '\n\nvia SMART-TOOL/M AI assistant';
    r = await apiFetch(`${base}/git/commits`, { method: 'POST', headers: H, body: JSON.stringify({ message: msg, tree: newTree, parents: [headSha] }) });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error('Commit failed: ' + (e.message || r.status)); }
    const newCommit = (await r.json()).sha;

    // 6. push (update ref)
    r = await apiFetch(`${base}/git/refs/heads/${encodeURIComponent(gh.branch)}`, { method: 'PATCH', headers: H, body: JSON.stringify({ sha: newCommit, force: false }) });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error('Push failed: ' + (e.message || r.status)); }

    res.json({ ok: true, commit: newCommit, url: `https://github.com/${gh.owner}/${gh.repo}/commit/${newCommit}` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// AI FILE ANALYSIS — upload any file, AI reads/analyzes, output any format
// ═══════════════════════════════════════════════════════════════

const IMAGE_MIME = /^image\/(png|jpe?g|webp|gif)$/i;
const TEXT_MIME  = /^text\//i;
const TEXT_EXT2  = /\.(txt|md|csv|json|log|xml|html|css|js|ts|py|java|c|cpp|h|sh|yml|yaml|ini|conf|sql)$/i;
const XLS_EXT    = /\.(xlsx|xls|xlsm|xlsb)$/i;

function xlsxToText(buf) {
  try {
    const wb = XLSX.read(buf, { type: 'buffer' });
    return wb.SheetNames.map(n => `## Sheet: ${n}\n${XLSX.utils.sheet_to_csv(wb.Sheets[n])}`).join('\n\n');
  } catch (e) {
    return '[Excel read failed]';
  }
}

function csvEscape(v) {
  let s = v == null ? '' : String(v);
  if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function wrapLines(text, font, size, maxWidth) {
  const out = [];
  for (const rawLine of String(text).split('\n')) {
    const words = rawLine.split(/\s+/).filter(Boolean);
    if (!words.length) { out.push(''); continue; }
    let line = '';
    for (const w of words) {
      const test = line ? line + ' ' + w : w;
      if (font.widthOfTextAtSize(test, size) > maxWidth && line) { out.push(line); line = w; }
      else line = test;
    }
    if (line) out.push(line);
  }
  return out;
}

async function generateOutput(format, analysis, outputData) {
  if (format === 'csv') {
    const rows = (outputData && outputData.rows) || [];
    const csv = rows.map(r => (Array.isArray(r) ? r : []).map(csvEscape).join(',')).join('\n');
    return { filename: 'output.csv', mime: 'text/csv', buffer: Buffer.from(csv || analysis, 'utf8') };
  }
  if (format === 'xlsx') {
    const rows = (outputData && outputData.rows) || [];
    const ws = XLSX.utils.aoa_to_sheet(rows.length ? rows : [[analysis]]);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
    return {
      filename: 'output.xlsx',
      mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      buffer: XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' })
    };
  }
  if (format === 'pdf') {
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const size = 11, margin = 50, lineH = 16;
    const lines = wrapLines(analysis, font, size, 595 - margin * 2);
    let page = doc.addPage([595, 842]);
    let y = 842 - margin;
    for (const ln of lines) {
      if (y < margin) { page = doc.addPage([595, 842]); y = 842 - margin; }
      page.drawText(ln, { x: margin, y, size, font, color: rgb(0, 0, 0) });
      y -= lineH;
    }
    return { filename: 'output.pdf', mime: 'application/pdf', buffer: Buffer.from(await doc.save()) };
  }
  // text
  return { filename: 'output.txt', mime: 'text/plain', buffer: Buffer.from(analysis, 'utf8') };
}

async function callGeminiRaw(ai, parts, temperature) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(ai.model)}:generateContent?key=${encodeURIComponent(ai.apiKey)}`;
  const body = { contents: [{ parts }], generationConfig: { temperature: temperature || 0.3, responseMimeType: 'application/json' } };
  const r = await apiFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const d = await r.json();
  if (!r.ok) throw new Error((d.error && d.error.message) || 'Gemini error ' + r.status);
  return (d.candidates && d.candidates[0] && d.candidates[0].content &&
    d.candidates[0].content.parts.map(p => p.text).join('')) || '';
}

const ANALYZE_SYSTEM = `You are an expert document & data analyst. Analyze the attached file(s) according to the user's instruction.
Respond with STRICT JSON ONLY, exactly:
{
  "analysis": "your detailed analysis/answer in plain text",
  "output_format": "none|text|pdf|csv|xlsx",
  "output_data": { "rows": [ ["col1","col2"], ["val1","val2"] ] }
}
Rules:
- If the user wants a table / excel / csv / spreadsheet output, set output_format to "xlsx" or "csv" and fill output_data.rows as a 2D array (first row = headers).
- If the user wants a PDF or text document, set output_format to "pdf" or "text" and put the full content in "analysis".
- If no specific output file is requested, set output_format to "none" and answer in "analysis".
- Read and understand EVERY file attached (text, csv, excel, pdf, image).
- Answer in the same language the user used.
- Output ONLY the JSON. No markdown fences, no extra text.`;

app.post('/api/ai/analyze', requireAuth, apiLimiter, upload.array('files', 10), async (req, res) => {
  try {
    const instruction = (req.body && req.body.instruction) || 'Analyze and summarize these files.';
    const files = req.files || [];
    const ai = aiConfig();
    if (!ai.apiKey) return res.status(400).json({ error: 'AI API key not configured. Open Settings and add a free Gemini key.' });
    if (!files.length) return res.status(400).json({ error: 'Upload at least one file' });

    const parts = [{ text: instruction }];
    for (const f of files) {
      const mime = f.mimetype || '';
      const name = f.originalname || 'file';
      if (mime === 'application/pdf' || IMAGE_MIME.test(mime)) {
        if (f.size > 15 * 1024 * 1024) return res.status(400).json({ error: `${name} too big for AI (max 15MB)` });
        parts.push({ inline_data: { mime_type: mime || 'application/pdf', data: f.buffer.toString('base64') } });
      } else if (XLS_EXT.test(name)) {
        parts.push({ text: `### FILE: ${name} (Excel as CSV)\n${xlsxToText(f.buffer)}` });
      } else if (TEXT_MIME.test(mime) || TEXT_EXT2.test(name)) {
        parts.push({ text: `### FILE: ${name}\n${f.buffer.toString('utf8').slice(0, 120000)}` });
      } else {
        // fallback: try as text
        parts.push({ text: `### FILE: ${name}\n${f.buffer.toString('utf8').slice(0, 120000)}` });
      }
    }

    const raw = await callGeminiRaw(ai, parts, 0.3);
    let obj;
    try { obj = JSON.parse(raw.replace(/^```(json)?/i, '').replace(/```$/i, '').trim()); }
    catch { obj = { analysis: raw, output_format: 'none' }; }

    const analysis = obj.analysis || '(no analysis)';
    let fmt = (obj.output_format || 'none').toLowerCase();
    const allowed = ['none', 'text', 'pdf', 'csv', 'xlsx'];
    if (!allowed.includes(fmt)) fmt = 'none';

    const out = fmt === 'none' ? null : await generateOutput(fmt, analysis, obj.output_data);

    res.json({
      ok: true,
      analysis,
      output: out ? { filename: out.filename, mime: out.mime, base64: out.buffer.toString('base64') } : null
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── HTML routes ────────────────────────────────────────────────
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`✓ SMART-TOOL/M engine live on port ${PORT}`));

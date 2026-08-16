# SMART-TOOL/M — PWA + AI Repo Assistant

A secure, installable **PWA** with file tools + a new **AI Repo Assistant**:
speak or type a change → review the plan → confirm → it pushes the changes to your GitHub repo.

---

## Features

- 📱 **Installable PWA** — manifest + service worker, add to home screen.
- 🔐 **JWT login** — admin-created users (default `mohan` / `1121`), admin panel at `/admin`.
- 🛠 **File tools** — 3-copies PDF, E-Way bill merge, invoice-wise PDF/ZIP, Excel tools.
- 🤖 **AI Repo Assistant** —
  - Voice (Web Speech API) **or** typed text.
  - Reads your repo, proposes a **change plan** (rules / conditions / features / memory / fixes).
  - Shows a **diff** for every file.
  - On **Confirm**, pushes a **single atomic commit** to your GitHub branch.
  - **Persistent memory**: rules live in `SMARTTOOL_RULES.md` in the repo. Updates are done
    **in-place** (no duplicates) — changing "X from x to y" edits the existing entry, never adds a second one.

---

## 🚀 Deploy — NO CARD required

### Option 1 (easiest): Render free tier — no card
1. Push this repo to GitHub.
2. Go to **render.com** → sign up with GitHub (no card).
3. **New → Blueprint** (it will read `render.yaml`) **or** use this one-click link:
   `https://render.com/deploy?repo=https://github.com/MOHANGARDAS/smart-tool-secure`
4. It will ask for **GEMINI_API_KEY** and **GITHUB_TOKEN** — paste them.
5. Deploy → live URL in ~1–2 min. ✅

> ⚠️ Render free tier **sleeps after 15 min idle** (wakes up in ~30–60s on next visit).
> Use env vars (not the in-app Settings screen) there, because the free disk resets on redeploy.
> For personal use this is usually fine.

### Option 2 (always-on, no card): Self-host at home
Run on your own PC/laptop (must stay on), expose free via **Cloudflare Tunnel**:
```bash
# on your machine:
npm install
cp .env.example .env && nano .env   # paste keys
node server.js

# in another terminal — free public URL (no card, no static IP):
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && chmod +x cloudflared
./cloudflared tunnel --url http://localhost:3000   # gives a free https URL
```

### Option 3 (always-on, needs card): Oracle Cloud Always Free
Real VPS, 24/7, free forever — but needs a **card only for identity verification** (₹0 billed).
Steps: `cloud.oracle.com` → Always Free ARM VM (Ubuntu) → then:
```bash
sudo apt update && sudo apt install -y docker.io git
git clone https://github.com/MOHANGARDAS/smart-tool-secure.git && cd smart-tool-secure
cp .env.example .env && nano .env
docker compose up -d --build
```

---

## Local run (for development)
```bash
npm install
npm start
# open http://localhost:3000
```
Default login: `mohan` / `1121`. Admin panel: `/admin` (key `1121`).

---

## Configure via UI (alternative to .env)

Open the app → **⚙ Settings** and paste the Gemini key + GitHub token + repo details.
Saved server-side in `config.json` (git-ignored). Env vars (`.env`) also work as fallback.

## Notes

- **Voice input** needs Chrome/Edge + HTTPS (or localhost).
- Users persist in `users.json` (git-ignored) — safe across restarts. In Docker, data is in the
  `smarttool_data` volume.
- `config.json`, `users.json`, `.env`, `node_modules/` are git-ignored — never commit secrets.

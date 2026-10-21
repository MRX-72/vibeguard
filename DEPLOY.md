# Hosting VibeGuard for the hackathon

This gets VibeGuard live at one public URL that works without your laptop, for free and without a credit card:

| Part | Where | What it costs |
|---|---|---|
| Website (React) | Firebase Hosting, project `vibeguard-scan` → **https://vibeguard-scan.web.app** | Free (Spark plan) |
| Scanner API (FastAPI + scanners, Docker) | Render, free web service `vibeguard-api` → `https://vibeguard-api.onrender.com` (Render may add a suffix) | Free |
| AI review | Groq API (`openai/gpt-oss-120b`) | Free tier |
| Code | GitHub, **https://github.com/MRX-72/vibeguard** (public) | Free |

```
phone / laptop ──► vibeguard-scan.web.app (static site, Firebase)
                         │  fetch()  (CORS: only these two origins are allowed)
                         ▼
                   vibeguard-api.onrender.com (Docker on Render)
                         │  gitleaks · osv-scanner · semgrep · ast-grep · bandit · zizmor · …
                         └─► Groq (AI review, secrets masked)
```

Total time the first time: about 30 minutes, most of it waiting for Render's first build.

---

## 0. What you need

- The GitHub repo pushed (done: `MRX-72/vibeguard`, branch `main`).
- A **Groq API key**: https://console.groq.com/keys. It's already in `backend/.env` on your Mac (`GROQ_API_KEY=...`). Never commit it or paste it anywhere public.
- **Node 20+** and the **Firebase CLI**, logged in (`firebase login`). Already set up on your Mac. The `vibeguard-scan` project already exists.
- A **Render account**: https://render.com. Sign up with GitHub; no card needed for the free plan.

---

## 1. Deploy the API on Render (about 10–15 minutes)

1. Go to https://dashboard.render.com → **New** → **Blueprint**.
2. Connect GitHub if asked, and pick **MRX-72/vibeguard**. Render reads `render.yaml` from the repo and shows one service, **vibeguard-api** (Docker, free plan).
3. It asks for the two secret values the blueprint leaves out. Enter:

   | Key | Value |
   |---|---|
   | `GROQ_API_KEY` | your Groq key (copy it from `backend/.env`) |
   | `ALLOWED_ORIGINS` | `https://vibeguard-scan.web.app,https://vibeguard-scan.firebaseapp.com` |

   `GROQ_MODEL=openai/gpt-oss-120b` and `TRIAGE_BACKEND=groq` are already set by the blueprint. Type `ALLOWED_ORIGINS` exactly: comma-separated, no spaces, no trailing slashes.
4. Click **Apply**. The first build takes **5–10 minutes**. It downloads the pinned scanners and bakes the Semgrep rules into the image.
5. When the service shows **Live**, copy its URL from the top of the service page, e.g. `https://vibeguard-api.onrender.com`. You need it in step 2.
6. Check it from your terminal:

   ```sh
   API=https://vibeguard-api.onrender.com     # your URL
   curl -s $API/health                          # → {"ok":true}
   ```

   If it hangs for about a minute the first time, that's the free instance waking up (see "Cold starts" below).

The same Dockerfile is built and tested on every push by the **image** GitHub Action: it runs the demo scan inside the container and fails if a scanner is missing. If Render's build ever fails, check that workflow first: https://github.com/MRX-72/vibeguard/actions

---

## 2. Deploy the website on Firebase (about 3 minutes)

From the repo root on your Mac:

```sh
cd frontend
npm ci
VITE_API_BASE_URL=https://vibeguard-api.onrender.com npm run build    # your Render URL, no trailing slash
cd ..
firebase deploy --only hosting                                         # uses project vibeguard-scan (.firebaserc)
```

Firebase prints **Hosting URL: https://vibeguard-scan.web.app**. That's your submission link.

`VITE_API_BASE_URL` is baked into the JavaScript at build time. If the Render URL ever changes, rebuild and redeploy the website.

---

## 3. Check that it works end to end

Do this **from your phone on mobile data**, not your laptop. It proves nothing depends on your machine.

1. Open https://vibeguard-scan.web.app.
2. If you see the amber bar "Waking the scanner", wait about a minute.
3. Go to **Demo** → **Review the demo app**. You should see the checks tick through, then a report: **Changes requested, grade F, about 35 comments**.
4. Open a comment. It should show the code, the plain-English impact, the suggested change, and the prompt for the AI builder.
5. Go to **Scan** → **GitHub repo**, paste `https://github.com/appsecco/dvna`, and start the review. Expect grade F with SQL injection and command injection near the top.
6. Under the grade, try the **Markdown** and **SARIF** downloads.

From a terminal you can run the same check without a browser:

```sh
API=https://vibeguard-api.onrender.com
id=$(curl -s -X POST $API/scan -F source_type=demo | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')
sleep 60
curl -s $API/scan/$id/status | python3 -m json.tool | head -5      # "status": "done"
```

**Time the demo scan on Render once** and write the number down. The free instance has 0.1 CPU, so Semgrep is the slow step. If the demo takes much longer than a minute, see "Scans are slow" below.

---

## 4. Before judging: keep it awake

Render's free instance **sleeps after 15 minutes without traffic** and takes **about a minute to wake**. The site handles this ("Waking the scanner…"), but you don't want a judge to wait.

- **Right before you present or submit:** open the site and run the demo once. That wakes the API and warms it up.
- **During the judging window:** set up a free uptime ping so it never sleeps.
  1. Create a monitor at https://uptimerobot.com (free) or https://cron-job.org.
  2. Point it at `https://vibeguard-api.onrender.com/health`, type HTTP(s), every **10 minutes**.
  3. Render's free plan includes 750 instance-hours a month, enough to stay awake all month for this one service.

---

## 5. Updating after you change code

| You changed | Do this |
|---|---|
| Backend or scanners (`backend/`, `Dockerfile`) | `git push`. Render rebuilds and redeploys automatically (`autoDeploy: true`), in 5–10 minutes. |
| Frontend (`frontend/`) | Run the step 2 commands again: `VITE_API_BASE_URL=... npm run build`, then `firebase deploy --only hosting`. |
| An env var (Groq key, allowed origins) | Render dashboard → vibeguard-api → **Environment** → edit → **Save changes**. The service restarts. |

Reports are kept in SQLite on the instance's disk, so they **disappear when Render restarts or redeploys**. That's expected: VibeGuard keeps no user data. The site says "Reports are kept only until the server restarts" when a link expires.

---

## 6. Running it locally (backup plan for the demo)

If the venue Wi-Fi or Render misbehaves, run everything on your laptop:

```sh
# terminal 1: API on :8000 (reads backend/.env for the Groq key)
cd backend
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt   # first time only
.venv/bin/uvicorn main:app --port 8000 --env-file .env

# terminal 2: website on :5173 (proxies /scan and /health to :8000)
cd frontend
npm install       # first time only
npm run dev
```

Open http://localhost:5173. The scanners need to be installed on your Mac (they already are). On a new machine:

```sh
brew install gitleaks osv-scanner trufflehog zizmor ast-grep
uv tool install semgrep && uv tool install bandit
npm install -g retire lockfile-lint
```

Any scanner that's missing is skipped and listed under "Checks run on this review". The scan still works.

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Site says **"The scanner isn't answering"** | The API is down or asleep for more than about 2.5 minutes. Check that the Render service is **Live**, and open `…/health` in a browser. |
| Browser console shows a **CORS error** | `ALLOWED_ORIGINS` on Render doesn't exactly match the site's origin. It must be `https://vibeguard-scan.web.app,https://vibeguard-scan.firebaseapp.com`: no spaces, no trailing `/`. Save, and wait for the restart. |
| Site loads but **every request fails** (404s from `web.app`) | The website was built without `VITE_API_BASE_URL`. Rebuild with it (step 2) and redeploy. |
| **"Too many scans are waiting right now"** (429) | One scan runs at a time and up to 8 can wait. Wait a minute and try again. |
| A step shows **"didn't finish (timed out)"** | That scanner hit its own time limit on the slow free CPU. The rest of the report is still valid. |
| **"This scan took longer than 15 minutes"** | The whole-scan safety limit. Usually a very large repo: try a smaller one, or a zip without `node_modules`/`dist`. |
| "AI review" shows **"no API key set"** in "Checks run" | `GROQ_API_KEY` is missing on Render. Add it under Environment. The report still works without it. |
| **Render build fails** | Look at the failing step in the Render log, and compare with the `image` GitHub Action. A pinned scanner download (GitHub releases, PyPI, npm) or the Semgrep rule fetch can fail temporarily: click **Manual Deploy → Deploy latest commit** to retry. |
| **Scans are slow** (well over a minute) | That's the free plan's 0.1 CPU. Warm the service first (section 4). For the live demo, the built-in demo app and small repos are the safest choices. |
| GitHub repo scan fails | Only public repos work, and the 50 MB limit applies after cloning. |

---

## 8. Two-minute demo script

1. **Home:** "AI builders ship apps with leaked keys and open databases. VibeGuard reviews the code like a senior engineer would." Click **Commit suggestion** on the example: the red line turns into its green fix, and once all three are committed the review flips to **Approved**.
2. **Demo** → **Review the demo app:** status checks run, then the report: grade F, "Fix these first", comments grouped by file.
3. Open the **Row-Level Security** comment: it's confirmed reachable, with a read-only `curl` you can run to see the exposure on your own project. Then show **Prompt for your AI builder** and copy it.
4. **Scan** → paste a public repo (e.g. `https://github.com/appsecco/dvna`) to show it on real code.
5. Close on the exports (Markdown, SARIF for GitHub code scanning, PDF), and the privacy line: code is deleted after every scan, and keys are masked everywhere.

---

## Checklist

- [ ] Render service **vibeguard-api** is Live, and `/health` returns `{"ok":true}`
- [ ] `GROQ_API_KEY` and `ALLOWED_ORIGINS` are set on Render (never committed)
- [ ] Website built with `VITE_API_BASE_URL=<Render URL>` and deployed: https://vibeguard-scan.web.app
- [ ] The demo scan works **from a phone on mobile data**, and you've written down how long it takes
- [ ] Uptime ping on `/health` every 10 minutes during judging
- [ ] Service warmed right before presenting
- [ ] Submission link: **https://vibeguard-scan.web.app** (repo: https://github.com/MRX-72/vibeguard)

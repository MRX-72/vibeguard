# VibeGuard — Build Guide & Progress Tracker

> **For Claude Code:** This is the single source of truth for building VibeGuard. Read it fully before starting. Work through the phases in order. **After completing any task, update its checkbox and the Progress Log at the bottom.** Keep this file accurate — it is how progress survives across sessions.

---

## 0. What we're building

**VibeGuard** is a security scanner for AI-generated ("vibe-coded") apps. A developer submits a codebase (pasted code, a `.zip`, or a public GitHub URL) and gets back a prioritized, plain-English security report focused on the mistakes that apps built quickly with AI tools commonly ship with — each finding with a concrete fix.

**The differentiator** is not "another SAST tool." Snyk, CodeQL, and Semgrep already exist. VibeGuard targets the *specific* mistakes AI code generators make (exposed frontend keys, disabled Supabase RLS, client-only auth, wildcard CORS, etc.) and uses an LLM to filter false positives, explain each issue in plain English, and generate a patch.

**Primary user:** indie devs / small teams who shipped something fast with AI tools and have had no security review.

**Product scope — do one thing flawlessly.** VibeGuard is the best tool in the world at *detecting* vulnerabilities in a vibe-coded app's **code and its live product/config**, and at turning them into a **flawless, plain-English report**. It does **not** modify, patch, or open fix-PRs against the user's code. Suggested fixes and secure re-prompts appear *in the report* as guidance the user chooses to act on — VibeGuard never writes to their codebase. Everything that turns this from a demo into a real product lives in §14–§21; the MVP (§9) is the foundation those build on.

---

## 1. Operating rules for Claude Code

- **Follow the phases in order.** Each phase builds on the last. Do not jump ahead.
- **Keep each phase shippable.** The app should run and demo *something* at the end of every phase.
- **Update this file as you go** — check boxes, and append a dated line to the Progress Log (§10) describing what changed and any deviation from the plan.
- **If you deviate from the spec, write down why** in the Decisions log (§11). Don't silently diverge.
- **Verify, don't assume.** After wiring a scanner, run it against the sample repo and confirm real findings appear before moving on.
- **Secrets never get hardcoded.** `LLM_API_KEY` comes from the environment only.
- **Commit at the end of each phase** with a clear message (e.g. `feat: phase 3 — real gitleaks + semgrep integration`).

---

## 2. Tech stack (build exactly this)

| Layer | Choice | Reason |
|---|---|---|
| Backend | Python 3.11+ + FastAPI | Security tooling is Python/CLI-centric |
| Frontend | React (Vite) + Tailwind CSS | Single dashboard page |
| Database | SQLite | Zero-config, one file |
| Jobs | FastAPI `BackgroundTasks` + frontend polling | No external queue needed for MVP |
| Scanners | `semgrep`, `njsscan`, `gitleaks`, `retire.js`, `osv-scanner`, `trivy` (all CLI) | See §2.1 — chosen for the vibe-coded stack |
| LLM triage | One `triage()` function on **Groq** (OpenAI-compatible API), swappable to local | Groq for fast/cheap inference; abstraction keeps a local-model escape hatch |

### 2.1 Target stack & the scanners we wrap

VibeGuard is tuned for the stack that AI app-builders actually generate. Output from Lovable, Bolt.new, v0, Replit, and Cursor converges on one pattern: **JavaScript/TypeScript, React (often Next.js — Bolt also emits Astro/SvelteKit/Vue), a Supabase or Firebase backend, Tailwind/shadcn-ui on the frontend, and Node for any server code.** The scanners below are chosen to cover that stack end to end. We don't reinvent analysis — we orchestrate best-in-class open-source CLIs and layer AI triage on top.

| Tool | Role | What it catches on this stack | Invocation |
|---|---|---|---|
| **Semgrep** | Multi-language SAST | XSS sinks, injection, insecure patterns in JS/TS/React/Python; also hosts our custom vibe rules | `semgrep --config p/default --config p/owasp-top-ten --config rules/vibe-coded.yml --json` |
| **njsscan** | Node.js SAST | Server-side Node/Express issues: deserialization RCE, path traversal, missing security controls | `njsscan --json -o out.json <dir>` |
| **gitleaks** | Secret scanner | Hardcoded API keys, tokens, DB creds in source + git history | `gitleaks detect --no-git --report-format json` |
| **retire.js** | Vulnerable JS libraries | Outdated frontend/Node libraries with known CVEs (OWASP "known vulnerable components") | `retire --outputformat json --path <dir>` |
| **osv-scanner** | Dependency CVEs | Known vulns in npm/yarn/pnpm (and pip) deps via Google's OSV.dev database | `osv-scanner scan source -r --format json <dir>` |
| **Trivy** | Deps + secrets + misconfig | All-in-one: dependency CVEs, secrets, and IaC/config misconfigurations | `trivy fs --scanners vuln,secret,misconfig --format json <dir>` |

**Overlap is deliberate but must be de-duplicated.** Secrets are covered by both gitleaks and Trivy; dependency CVEs by osv-scanner, retire.js, and Trivy. Run them, then have `normalize.py` dedupe by `(file, line, rule-or-cve)` so the user never sees the same issue twice. For a leaner MVP, run **semgrep + gitleaks + osv-scanner + njsscan** as the core set and treat retire.js and Trivy as additive — document whatever you choose in §11.

> The **custom vibe-coded rules (§7) remain the real differentiator.** These generic scanners are the baseline every security tool has; the Supabase-RLS / client-only-auth / exposed-frontend-key detections are what make VibeGuard specific to vibe-coded apps. Don't let scanner integration crowd out §7.

### 2.2 LLM triage backend (Groq)

Triage runs on **Groq** for fast, cheap inference. Groq exposes an **OpenAI-compatible API** at `https://api.groq.com/openai/v1`, so use the official `openai` Python SDK pointed at that base URL with `GROQ_API_KEY` — no separate client library needed:

```python
from openai import OpenAI
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=os.environ["GROQ_API_KEY"])
```

**Model choice — verify before building.** Groq's catalog shifts and models get retired (the Llama 3.x models were pulled from free/dev tiers in Aug 2026). The safe production text models are **`openai/gpt-oss-20b`** (faster/cheaper — good default for triage) and **`openai/gpt-oss-120b`** (more capable). Read the model id from `GROQ_MODEL` (default `openai/gpt-oss-20b`) and check <https://console.groq.com/docs/models> for the current list before locking it in. Use JSON mode (`response_format={"type": "json_object"}`) so triage output parses reliably.

**Keep the local escape hatch.** Put the Groq call behind the single `triage()` interface with a provider abstraction, so a `LocalTriageProvider` (local Ollama/Gemma at `OLLAMA_URL`) can be swapped in later with no other code change. Select via `TRIAGE_BACKEND=groq|local` (default `groq`). Everything else in the app must be identical regardless of backend.

---

## 3. Architecture

```
┌─────────────┐     POST /scan      ┌──────────────────────┐
│  React SPA  │ ──────────────────► │   FastAPI backend    │
│ (dashboard) │ ◄── poll status ─── │                      │
└─────────────┘                     │  ┌────────────────┐  │
                                    │  │  Scan pipeline │  │
                                    │  │ 1 secrets      │  │
                                    │  │ 2 deps (CVEs)  │  │
                                    │  │ 3 SAST         │  │
                                    │  │ 4 vibe rules   │  │
                                    │  │ 5 normalize    │  │
                                    │  │ 6 triage(Groq) │  │
                                    │  └────────────────┘  │
                                    │         │            │
                                    │      SQLite          │
                                    └──────────────────────┘
```

**Pipeline runs per job, in order:** ingest → secret scan (gitleaks) → dependency scan (osv-scanner / trivy / retire.js) → SAST (semgrep + njsscan) → custom vibe rules → normalize + dedupe → AI triage (Groq) → risk score → store.

---

## 4. Repository layout (target)

```
vibeguard/
├── VibeGuard.md              # this file
├── README.md
├── backend/
│   ├── main.py               # FastAPI app + routes
│   ├── db.py                 # SQLite setup + queries
│   ├── models.py             # Pydantic schemas
│   ├── ingest.py             # paste/zip/github → temp sandbox dir
│   ├── pipeline.py           # orchestrates the scan steps
│   ├── scanners/
│   │   ├── base.py           # Scanner interface: run(dir) -> [Finding]
│   │   ├── gitleaks.py       # secrets
│   │   ├── semgrep.py        # SAST + custom rules
│   │   ├── njsscan.py        # Node.js SAST
│   │   ├── osv_scanner.py    # dependency CVEs
│   │   ├── retirejs.py       # vulnerable JS libs (optional)
│   │   ├── trivy.py          # deps + secrets + misconfig (optional)
│   │   └── custom_rules.py   # vibe-coded pattern checks
│   ├── normalize.py          # merge all findings → common schema
│   ├── triage.py             # triage() + provider abstraction
│   ├── scoring.py            # risk score calculation
│   ├── rules/
│   │   └── vibe-coded.yml    # custom semgrep rules
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── src/
│   │   ├── App.jsx           # single dashboard page
│   │   ├── components/
│   │   │   ├── InputCard.jsx
│   │   │   ├── ScanProgress.jsx
│   │   │   ├── Report.jsx
│   │   │   └── FindingRow.jsx
│   │   └── api.js            # fetch wrappers
│   └── package.json
├── sample-repo/              # deliberately insecure demo app
└── replit.nix / nix config   # system deps if run on Replit
```

---

## 5. Data model (SQLite)

**`scans`**
| column | type | notes |
|---|---|---|
| id | TEXT (uuid) | primary key |
| created_at | TEXT (ISO) | |
| source_type | TEXT | `paste` \| `zip` \| `github` |
| status | TEXT | `queued` \| `running` \| `done` \| `failed` |
| stage | TEXT | human-readable current stage for polling |
| risk_score | INTEGER | 0–100, null until done |
| error | TEXT | populated on failure |

**`findings`**
| column | type | notes |
|---|---|---|
| id | TEXT (uuid) | primary key |
| scan_id | TEXT | FK → scans.id |
| source | TEXT | `gitleaks` \| `semgrep` \| `custom` |
| severity | TEXT | `Critical` \| `High` \| `Medium` \| `Low` |
| title | TEXT | |
| file | TEXT | |
| line | INTEGER | |
| code_snippet | TEXT | |
| raw_rule_id | TEXT | original scanner rule id |
| explanation | TEXT | from triage |
| fix_diff | TEXT | before/after, from triage |
| is_false_positive | INTEGER | 0/1, from triage |

---

## 6. API contract

| Method | Path | Body / Params | Returns |
|---|---|---|---|
| POST | `/scan` | `{ source_type, payload }` where payload is code string, uploaded file, or repo URL | `{ scan_id }` |
| GET | `/scan/{id}/status` | — | `{ status, stage, risk_score? }` |
| GET | `/scan/{id}` | — | full report: scan meta + findings[] sorted by severity |

**Finding JSON shape (normalized):**
```json
{
  "id": "…",
  "source": "custom",
  "severity": "Critical",
  "title": "Supabase Row-Level Security disabled",
  "file": "src/db.js",
  "line": 12,
  "code_snippet": "…",
  "raw_rule_id": "vibe.supabase-rls-off",
  "explanation": "…",
  "fix_diff": "…",
  "is_false_positive": false
}
```

---

## 7. Custom "vibe-coded" rules (the core value — implement all)

Implement each as a Semgrep rule in `rules/vibe-coded.yml` where feasible, and as a regex/AST check in `custom_rules.py` where Semgrep is awkward. Each rule needs: a stable `raw_rule_id`, a clear `title`, a default `severity`, and a canned remediation template that triage later tailors.

- [ ] `vibe.frontend-secret` — API keys/secrets exposed to the frontend (`NEXT_PUBLIC_*` holding a real key, keys in client-side JS) — **Critical**
- [ ] `vibe.supabase-rls-off` — Supabase client used with RLS disabled / no policies — **Critical**
- [ ] `vibe.firebase-open-rules` — Firebase rules `allow read, write: if true` — **Critical**
- [ ] `vibe.client-only-auth` — sensitive action gated only by client-side check, no server guard — **High**
- [ ] `vibe.cors-wildcard` — CORS `*` on authenticated endpoints — **High**
- [ ] `vibe.xss-sink` — `dangerouslySetInnerHTML` / `innerHTML` / `v-html` fed from user input — **High**
- [ ] `vibe.sql-string-concat` — SQL built via concatenation/template literals, not parameterized — **Critical**
- [ ] `vibe.no-rate-limit` — auth or public write endpoints with no rate limiting — **Medium**
- [ ] `vibe.debug-in-prod` — debug mode / verbose errors / stack traces enabled in prod config — **Medium**
- [ ] `vibe.eval-user-input` — `eval()` or dynamic code execution on user input — **Critical**
- [ ] `vibe.unrestricted-upload` — file upload with no type/size validation — **Medium**

Target 10–15 shipped rules. These three (XSS sink, SQL concat, frontend secret) **must** fire on the sample repo for the demo.

---

## 8. AI triage behavior

`triage(findings: list) -> list` takes normalized findings (batched to control token use) and returns, **per finding, as strict parseable JSON**:
- `is_false_positive` — true for obvious noise (placeholder secrets like `your-api-key-here`, test fixtures, commented-out code)
- `severity` — Critical/High/Medium/Low **with a one-line justification**
- `explanation` — 2–3 sentences, no jargon: what the risk is and what an attacker could do
- `fix_diff` — a concrete before/after code change for that file

**Prompt constraints:** stay grounded only in the supplied code snippet; never invent files, lines, or issues not present; if unsure, prefer marking lower severity over fabricating detail. Validate/parse the JSON defensively — if a finding's triage output is malformed, keep the raw finding with a "triage unavailable" note rather than dropping it.

**Backend:** runs on Groq via the `triage()` abstraction (see §2.2). Request JSON mode where supported, and batch ~10–20 findings per call to stay within context and rate limits.

---

## 9. Build phases (work top to bottom)

### Phase 0 — Scaffold
- [x] Create repo layout from §4 *(dirs created; module files land in the phase that needs them)*
- [x] `backend/` FastAPI app boots, `/health` returns ok
- [x] `frontend/` Vite+React+Tailwind boots, blank dashboard renders
- [x] SQLite initializes with both tables on startup
- [x] README with run instructions for both services
- [x] **Commit**

### Phase 1 — End-to-end skeleton with fake data
- [ ] `POST /scan`, `GET /scan/{id}/status`, `GET /scan/{id}` implemented
- [ ] Scanner is stubbed: returns 3–4 hardcoded fake findings after a short delay
- [ ] `BackgroundTasks` drives job status `queued → running → done`
- [ ] Frontend: input card (3 tabs), submit, poll status, render report with fake findings
- [ ] Severity badges, expandable rows, risk score all render from fake data
- [ ] **Commit** — *demoable: full UX works end to end*

### Phase 2 — Ingestion
- [ ] Paste → write to temp sandbox dir
- [ ] Zip upload → extract to temp dir (reject path-traversal entries)
- [ ] GitHub URL → shallow clone (`--depth 1`), **public only**, reject private/auth
- [ ] Enforce 50 MB size cap; clean up temp dir after every scan (even on failure)
- [ ] **Commit**

### Phase 3 — Real scanners
- [ ] `gitleaks detect` wired + output parsed into normalized findings
- [ ] `semgrep` wired with `p/default` + `p/owasp-top-ten` + parsed
- [ ] `njsscan` wired + parsed (Node.js SAST)
- [ ] `osv-scanner` wired + parsed (dependency CVEs)
- [ ] `retire.js` wired + parsed (vulnerable JS libs) — *optional / additive*
- [ ] `trivy fs` wired + parsed (deps + secrets + misconfig) — *optional / additive*
- [ ] Each scanner lives in its own module under `scanners/`, implements the `base.py` interface, and **fails soft** if its binary is absent (skip + note in report, don't crash the scan)
- [ ] `normalize.py` merges all sources into the common schema, dedupes by (file, line, rule-or-cve)
- [ ] Verify real findings appear against the sample repo
- [ ] **Commit**

### Phase 4 — Custom vibe-coded rules
- [ ] `rules/vibe-coded.yml` + `custom_rules.py` implementing all rules in §7
- [ ] Wired into the pipeline as step 3
- [ ] Each rule verified to fire on a crafted positive and not on a crafted negative
- [ ] **Commit**

### Phase 5 — AI triage
- [ ] `triage.py` with provider abstraction (`hosted` + `local` backends)
- [ ] `TRIAGE_BACKEND` env switch; `LLM_API_KEY` / `OLLAMA_URL` from env
- [ ] Batched calls, strict-JSON parsing with defensive fallback
- [ ] Findings enriched with severity/explanation/fix_diff; false positives filtered
- [ ] **Commit**

### Phase 6 — Scoring, polish, demo
- [ ] `scoring.py` → 0–100 risk score (weight by severity + count), shown with grade
- [ ] Per-severity counts in report header
- [ ] Scan progress shows real stage names ("Scanning for secrets…", "Static analysis…", "AI triage…")
- [ ] "No major issues found" empty state
- [ ] Beautiful, polished UI per the design direction in §23 — top priority alongside the report
- [ ] "Dynamic/DOM-XSS fuzzing — coming soon" note in UI
- [ ] **Report excellence (the product's whole point — see §15):**
  - [ ] Executive summary at top: letter grade + risk score + top 3 "this could hurt you" items in plain English
  - [ ] Each finding carries a one-line **business/plain-English impact** (not CVE-speak) and a `$`-risk flag where relevant (exposed key, no rate limit)
  - [ ] Each finding shows a **suggested fix** and a **secure re-prompt** snippet — guidance shown in the report, never auto-applied
  - [ ] Confidence / reachability badge per finding (see §16)
  - [ ] Export: Markdown + SARIF (shareable report)
- [ ] Built-in **"Try a demo repo"** button scans the bundled sample (§12)
- [ ] **Deploy (see §22) — the submission is one working public URL:**
  - [ ] One Docker image: FastAPI serves the API + the built React app; all six scanners baked in with DBs pre-cached
  - [ ] Backend on Cloud Run (`--memory 2Gi`, binds `0.0.0.0:$PORT`)
  - [ ] Clean link via Firebase Hosting rewrite to the Cloud Run service (`*.web.app`), or a custom domain
  - [ ] Public URL verified from a device that is **not** the dev's machine
  - [ ] Service warmed right before submitting (cold-start guard)
- [ ] **Commit + tag `v1.0-demo`**

### Phase 7 — Toward a real product (post-hackathon; see §14–§21)
> Not for the demo. This is the roadmap that turns the scanner into a product — all detection & reporting, **no code-fixing**.
- [ ] Reachability / taint analysis to cut false positives (§16)
- [ ] Secret validation: live vs placeholder (§16)
- [ ] Live Supabase / Firebase posture checks (§17)
- [ ] Continuous dependency monitoring + new-CVE alerts (§18)
- [ ] GitHub App: scan every PR, comment inline, block merge on Critical (§19)
- [ ] CLI + pre-commit hook + GitHub Actions template with SARIF upload (§19)
- [ ] Optional dynamic probe: spin up submitted app, fuzz one user-supplied endpoint

---

## 10. Progress Log

> Append a dated entry after each work session. Most recent at top.

- 2026-10-21 — Phase 0 done. FastAPI `/health`, SQLite (`scans` + `findings`, plus report columns used later: `severity_reason`, `impact`, `money_risk`, `confidence`, `reprompt`, `refs`, `evidence`, `triage_note`, and `scans.scanners`/`source_label`), Vite 8 + React 19 + Tailwind 4 shell with dark design tokens, README. All six scanners installed locally (semgrep 1.181, njsscan 1.0.1, gitleaks 8.30.1, retire 6.1.0, osv-scanner 2.7.0, trivy 0.76.0).
- _2026-10-21 — (Claude Code) initialized project from spec. Starting Phase 0._

---

## 11. Decisions & deviations

> Record any choice that differs from this spec, with the reason.

- **2026-10-21 — Scanner selection.** Core set is semgrep + njsscan + gitleaks + osv-scanner, with retire.js + trivy as additive, chosen to cover the JS/TS + React/Next + Supabase/Firebase + Node stack that vibe-coding tools generate. retire.js/trivy overlap the core set on deps/secrets and are optional for the MVP.
- **2026-10-21 — LLM = Groq.** OpenAI-compatible endpoint; default model `openai/gpt-oss-20b` (Groq retired the Llama models from free/dev tiers in Aug 2026). Kept behind the `triage()` abstraction so local Ollama/Gemma can replace it.
- **2026-10-21 — Hosting = Cloud Run, single container.** The deliverable is one public URL, so a local tunnel won't do. One Docker image (FastAPI serving the React build + the scan API, all six scanners baked in) deploys to Cloud Run with `--memory 2Gi`. Clean `*.web.app` link via Firebase Hosting rewrite to the Cloud Run service. Scanner DBs pre-baked into the image. (See §22.)

---

## 12. Acceptance criteria & demo script

**The sample repo** (`sample-repo/`) is a deliberately insecure app containing at minimum:
- a hardcoded API key
- `dangerouslySetInnerHTML` on user-controlled input
- SQL built by string concatenation
- `CORS: *`

**Demo must pass:**
- [ ] Clicking "Try a demo repo" runs a full scan in **under ~60 seconds**
- [ ] The report surfaces **at least** the exposed key, the XSS sink, and the SQL injection
- [ ] Each of those three has a plain-English explanation and a working fix diff
- [ ] Risk score and severity counts render correctly
- [ ] No secrets appear in the codebase or logs

**General acceptance:**
- [ ] All three input methods work (paste / zip / GitHub URL)
- [ ] App degrades gracefully when a scanner binary or the LLM is unavailable
- [ ] Temp directories are always cleaned up
- [ ] Switching `TRIAGE_BACKEND` between `groq` and `local` requires no code changes
- [ ] The report leads with a plain-English executive summary a non-security founder can act on
- [ ] No finding is shown in raw CVE/CWE-speak without a plain-English impact line
- [ ] The submission is a single public URL that works without the developer's machine running
- [ ] The UI is genuinely polished (not a default/unstyled look) — see §23

---

## 13. Environment & setup

**Required env vars:**
```
TRIAGE_BACKEND=groq               # or: local
GROQ_API_KEY=...                  # required if groq
GROQ_MODEL=openai/gpt-oss-20b     # groq model id; verify at console.groq.com/docs/models
OLLAMA_URL=http://localhost:11434 # required if local
PORT=8080                         # Cloud Run injects this; the app MUST bind 0.0.0.0:$PORT
```
On Cloud Run, set `GROQ_API_KEY`, `GROQ_MODEL`, and `TRIAGE_BACKEND` as service env vars / secrets — never baked into the image. Full deploy details in §22.

**System dependencies** (install and verify on PATH at startup; if any is missing, skip that scanner gracefully and note it in the report rather than crashing):
- `semgrep` — `pip install semgrep`
- `njsscan` — `pip install njsscan`
- `gitleaks` — binary release / `brew install gitleaks`
- `retire` (retire.js) — `npm install -g retire`
- `osv-scanner` — Go binary / `brew install osv-scanner`
- `trivy` — binary release / `brew install trivy`

**Run locally:**
```
# backend
cd backend && pip install -r requirements.txt && uvicorn main:app --reload

# frontend
cd frontend && npm install && npm run dev
```

---

## 14. Product scope & positioning

**The one sentence:** *VibeGuard finds the security holes in apps built with AI, explains them in plain English, and tells you exactly what to change — without ever touching your code.*

**In scope (do these flawlessly):**
- Detect vulnerabilities in **code** (SAST, deps, secrets, custom vibe rules).
- Detect vulnerabilities in the **product/config** (live Supabase/Firebase posture, exposed buckets, open rules — §17).
- Produce a **flawless report**: accurate, low-noise, plain-English, with exact remediation guidance (§15).

**Out of scope (deliberately — this is a feature, not a gap):**
- Never edits, patches, or commits to the user's code.
- Never opens fix-PRs or applies changes.
- Suggested fixes and secure re-prompts are **report content** the user chooses to act on.

Why this boundary makes it *better*: a read-only detector is safe to point at any codebase, can't break a build, needs far fewer permissions, and earns trust faster. "We never modify or store your code" is a selling point an auto-fixer can't make.

---

## 15. The report (the crown jewel)

The report is the product. It must be accurate, scannable in 30 seconds by a non-expert, and deep enough for an engineer. Structure:

**A. Executive summary (top of page)**
- **Security grade** (A–F) + numeric risk score (0–100), with a one-line verdict.
- **Top 3 "this could hurt you"** items in plain English, worst first.
- Counts per severity, and a count of what was *checked* (so "clean" means something).

**B. Per-finding card** — every finding carries:
- Severity + a one-line justification for that severity.
- **Plain-English impact** — what an attacker can actually do ("anyone on the internet can read every user's email"). Never raw CVE/CWE-speak alone.
- **$-risk flag** where relevant — exposed key / missing rate limit framed as "this could run up a bill or drain an API quota."
- **Evidence** — the code snippet, `file:line`, and for reachability-analyzed findings the **source→sink path** (see §16).
- **Confidence / reachability badge** — `Confirmed reachable` / `Likely` / `Needs review`.
- **Suggested fix** — the corrected code shown inline (display only, copy button) — *not applied*.
- **Secure re-prompt** — a ready-to-paste prompt the user can give back to their AI builder (Lovable/Cursor/etc.) to regenerate that piece correctly. This is VibeGuard's unique move: it closes the loop with the tool that made the bug.
- **References** — links to the CWE/OWASP/CVE for the curious.

**C. Product/config section** (§17) — Supabase/Firebase posture: RLS state, public buckets, open rules, exposed anon vs service keys.

**D. Dependency section** — vulnerable packages, the CVE, fixed version, and whether the vulnerable code path is actually reachable.

**E. Export & share**
- Markdown and PDF (a founder can hand this to a customer or investor as proof they take security seriously).
- **SARIF** (so it drops straight into GitHub code scanning / CI).
- Shareable link with a trendable grade that improves as issues are resolved — retention + a light viral loop.

**Report quality bar:** every finding is either backed by evidence or clearly labelled lower-confidence. A report that cries wolf once loses the user forever — bias toward fewer, truer findings.

---

## 16. Detection-quality upgrades (the real moat)

Noise is what kills security tools. These separate a trustworthy detector from a `grep` with a UI:

- **Reachability / taint analysis.** Use Semgrep's taint mode to confirm user input actually flows into a dangerous sink, and osv-scanner's call analysis to confirm a vulnerable dependency function is actually invoked. Report the **source→sink path** as proof. Do this well for a few high-value classes (XSS, injection) rather than badly for all.
- **Secret validation.** Don't just match a key pattern — classify it. Format-validate, and for a few providers do a single harmless read call to tell **live key (Critical)** from **placeholder/test value (noise)**. Massive false-positive reduction. *(Handle found credentials carefully — see §20.)*
- **Confidence scoring + dedupe.** Every finding gets a confidence level; overlapping findings from multiple scanners collapse into one (dedupe by file/line/rule-or-cve). The UI can default to hiding low-confidence noise.
- **Framework-aware context.** Know the stack (§2.1): a `NEXT_PUBLIC_` key is Critical *because* Next.js ships it to the browser; a server-only env var is not. Context changes severity.

---

## 17. Product-level detection (live config — the vibe-coder wedge)

The worst vibe-coded vulnerabilities aren't in the code — they're in the dashboard. With the user's **read-only** consent, connect to their backend and check the live posture mainstream scanners miss:

- **Supabase:** Row-Level Security on/off per table, tables readable by the `anon` role, public storage buckets, `service_role` key exposure.
- **Firebase:** security rules evaluating to `allow read, write: if true`, open Firestore/Storage, unauthenticated functions.
- Report findings as "your database is currently exposing X to the public internet" — present-tense, product-level, concrete.

This is the single hardest thing for Snyk/Semgrep to copy, because it requires understanding *this specific stack's* failure modes. It is also the most dangerous to build — read-only, least-privilege, and never store their credentials (§20).

---

## 18. Continuous monitoring

One-shot scanners are forgettable; a watchdog is a subscription.
- Re-scan a saved project's dependencies on a schedule and alert when a **new** CVE drops for something they already ship.
- Re-check live config posture periodically (RLS didn't get turned off in last week's "quick fix").
- Weekly digest email with the grade trend. This is the natural paid tier.

---

## 19. Distribution — live where developers already work

A web app visited once is dead; a tool in the workflow is a habit. All detection/reporting, no code-fixing:
- **GitHub App** — scan every PR, post findings as inline review comments, and optionally **block merge on Critical**. This is the growth engine.
- **CLI** — `vibeguard scan .`, same engine, for local/CI use.
- **Pre-commit hook** — catch secrets and obvious holes before they're ever committed.
- **GitHub Actions template** — drop-in workflow that runs the scan and **uploads SARIF** to GitHub code scanning.

---

## 20. Trust & privacy (a real moat, not boilerplate)

Developers will not upload proprietary code to a tool they don't trust — so trust *is* the product surface.
- **Local-first / ephemeral.** Default to scanning without persisting the user's code; delete sandboxes after each scan. Say it loudly in the UI.
- **Local model option.** The `triage()` abstraction already allows a local Ollama/Gemma backend (§2.2) — "your code never leaves your machine" is then literally true.
- **Least privilege for live checks.** §17's config access is read-only, scoped, and credentials are never stored — used in-memory for the scan and discarded.
- **Handle discovered secrets as hazmat.** Never log them, never echo full values in the report (mask them), never send them anywhere. A secret-validation call must be the one harmless read it claims to be.

---

## 21. Prioritized roadmap (impact × effort)

| Priority | Item | Impact | Effort | When |
|---|---|---|---|---|
| 1 | Report excellence — exec summary, plain-English impact, grade (§15) | High | Low | **Hackathon** |
| 2 | Secure re-prompt per finding (§15) | High | Low | **Hackathon** |
| 3 | $-risk / bill-protection framing (§15) | High | Low | **Hackathon** |
| 4 | SARIF export (§15/§19) | Med | Low | **Hackathon** |
| 5 | Reachability/taint to cut false positives (§16) | Very high | High | Post-MVP |
| 6 | Live Supabase/Firebase posture checks (§17) | Very high | Med | Post-MVP |
| 7 | Secret validation — live vs placeholder (§16) | High | Med | Post-MVP |
| 8 | GitHub App — PR scan + inline comments + block (§19) | Very high | High | Post-MVP |
| 9 | CLI + pre-commit + Actions (§19) | High | Med | Post-MVP |
| 10 | Continuous monitoring + alerts (§18) | High | Med | Product |
| 11 | Shareable trendable report + grade history (§15) | Med | Med | Product |

**Rule of thumb:** priorities 1–4 are nearly free and are exactly what makes a judge (or an early user) remember *this* tool — do them for the hackathon. 5–9 are the post-hackathon story that makes it look like a company. 10–11 are the subscription.

---

## 22. Hosting & deployment (the submission is one public URL)

**The constraint that drives everything here:** the deliverable is a single link that must work when a judge clicks it, with none of the developer's machines running. A local tunnel (ngrok/cloudflared) therefore does **not** qualify — the backend must live on an always-reachable host. **Target: Google Cloud Run** — serverless containers, an always-free allowance, it runs the scanner binaries, and it scales to zero.

### Topology

Ship **one Docker image**: FastAPI serves both the built React app (at `/`) and the scan API (at `/scan`). That single image is the whole product, and it deploys to Cloud Run as one service.

- **Backend → Cloud Run** → gives a working HTTPS URL (`https://vibeguard-xxxx-xx.a.run.app`).
- **Clean link (the "like Firebase" ask) → use Firebase Hosting in front:**
  - Host the React build on **Firebase Hosting** (free, gives `https://vibeguard.web.app`).
  - Add a rewrite in `firebase.json` that proxies API paths to the Cloud Run service, so the browser only ever talks to `vibeguard.web.app` — **same-origin, no CORS**, clean link.

  ```json
  // firebase.json
  { "hosting": {
      "public": "frontend/dist",
      "rewrites": [
        { "source": "/scan/**", "run": { "serviceId": "vibeguard", "region": "<region>" } },
        { "source": "**", "destination": "/index.html" }
      ]
  }}
  ```
  With Firebase Hosting in front, the Cloud Run container only needs to serve the API; Firebase serves the UI and owns the clean link. *(Alternative: map a custom domain directly to Cloud Run. Simpler fallback: just use the plain `…run.app` URL — it works, it's only less pretty.)*

### Dockerfile (what Claude Code should build)

Multi-stage: build the React app with Node, then a Python base that installs all six scanners and **pre-caches their databases at build time** so a cold container never downloads hundreds of MB on a judge's first click.

```dockerfile
# 1) build frontend
FROM node:20 AS web
WORKDIR /web
COPY frontend/ .
RUN npm ci && npm run build                 # -> /web/dist

# 2) runtime with scanners
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl git nodejs npm \
 && pip install --no-cache-dir semgrep njsscan \
 && npm i -g retire \
 && curl -sSfL <gitleaks release url>    -o /usr/local/bin/gitleaks    && chmod +x /usr/local/bin/gitleaks \
 && curl -sSfL <osv-scanner release url> -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner \
 && curl -sSfL <trivy install script>    | sh -s -- -b /usr/local/bin
# pre-cache vuln DBs / rules at BUILD time, not runtime
RUN trivy image --download-db-only
WORKDIR /app
COPY backend/ .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=web /web/dist ./static          # FastAPI serves these at /
ENV PORT=8080
CMD ["sh","-c","uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
```
*(Pin exact release versions/URLs for gitleaks, osv-scanner, and trivy.)*

### Deploy

```
gcloud run deploy vibeguard \
  --source . --region <region> \
  --allow-unauthenticated \
  --memory 2Gi --cpu 1 --timeout 300
```

### Cloud Run gotchas (each has bitten someone)

- **Bind `0.0.0.0:$PORT`.** Cloud Run injects `PORT` (8080). If the app hardcodes a port or binds `localhost`, the deploy "succeeds" but every request fails.
- **Memory.** Cloud Run's filesystem is in-memory — the cloned repo *and* Trivy's DB count against RAM. 512 MB will OOM; use **2 GiB**, and keep the 50 MB repo cap.
- **Cold starts.** It scales to zero, so the first click after idle waits a few seconds. For judging: warm it right before submitting, show a "waking the scanner…" state in the UI, and optionally `--min-instances 1` during the judging window (a warm instance can exceed the always-free allowance, so set it back to 0 afterward).
- **Timeout.** 300s request timeout is the budget a scan must finish within — run scanners in parallel and cap repo size.
- **DBs must be pre-baked** (above), or the first scan is slow or fails.

### Env on Cloud Run
Set `GROQ_API_KEY`, `GROQ_MODEL`, and `TRIAGE_BACKEND=groq` as service env vars / secrets — never baked into the image.

---

## 23. UI & design direction (the UI is half the product)

A **beautiful UI** is a stated top priority — the interface and the report are what judges and users actually see, so this gets real design effort, not a default theme. Aim for the polish of **Linear / Vercel / Raycast**, never a stock Bootstrap look. When building the frontend, Claude Code should load the **`frontend-design` skill** and treat the following as the brief.

**Feel:** calm, precise, confident — a professional security tool, not a toy. Dark-first.

**Specifics**
- **Type:** one clean modern sans (Inter / Geist) for UI, a mono (JetBrains Mono / Geist Mono) for code snippets and findings. Clear size hierarchy; don't cram.
- **Color:** a near-black base (not pure `#000`), one restrained accent, and a disciplined severity palette — Critical red / High orange / Medium amber / Low blue. Severity color carries meaning; it's never decorative.
- **Space:** generous whitespace, a comfortable max-width, a consistent 4/8px spacing rhythm. Breathing room is what reads as "expensive."
- **Motion:** subtle only — a smooth reveal through the scan stages, findings fading in, the risk score counting up. Nothing bouncy.
- **The hero moment is the report.** Design it like a product, not a table dump: a large grade/score at the top, the "this could hurt you" items as bold cards, each finding a clean expandable card with a colored severity rail, the code in a proper mono block, and the plain-English impact as the most prominent text in the card. This screen wins the hackathon — give it the most attention.
- **States:** design the empty, scanning, clean ("no major issues found"), and error states deliberately — a tool is judged by its in-between moments.
- **Responsive:** must look right when the link is opened on a phone (judges will).

Restraint is the whole trick: one component style, one spacing scale, one accent. Consistency is what makes it look designed.

---

*End of build guide. Keep §9 checkboxes, §10 log, and §11 decisions current — that is what makes this file worth following.*

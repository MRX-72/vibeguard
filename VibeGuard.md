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
| Hosting | Render free (API container) + Firebase Hosting Spark (UI) | Card-free; see §22 |
| Scanners | `semgrep`, `njsscan`, `gitleaks`, `retire.js`, `osv-scanner`, `trivy` (all CLI) | See §2.1 — chosen for the vibe-coded stack |
| LLM triage | One `triage()` function on **Groq** (OpenAI-compatible API), swappable to local | Groq for fast/cheap inference; abstraction keeps a local-model escape hatch |

### 2.1 Target stack & the scanners we wrap

VibeGuard is tuned for the stack that AI app-builders actually generate. Output from Lovable, Bolt.new, v0, Replit, and Cursor converges on one pattern: **JavaScript/TypeScript, React (often Next.js — Bolt also emits Astro/SvelteKit/Vue), a Supabase or Firebase backend, Tailwind/shadcn-ui on the frontend, and Node for any server code.** The scanners below are chosen to cover that stack end to end. We don't reinvent analysis — we orchestrate best-in-class open-source CLIs and layer AI triage on top.

| Tool | Role | What it catches on this stack | Invocation |
|---|---|---|---|
| **Semgrep** | Multi-language SAST | XSS sinks, injection, insecure patterns in JS/TS/React/Python; also hosts our custom vibe rules | `semgrep --config p/default --config p/owasp-top-ten --config rules/vibe-coded.yml --json` |
| **njsscan** | Node.js SAST | Server-side Node/Express issues: deserialization RCE, path traversal, missing security controls | `njsscan --json -o out.json <dir>` |
| **gitleaks** | Secret scanner | Hardcoded API keys, tokens, DB creds; extended with Supabase's 2025 key formats | `gitleaks dir --config rules/gitleaks.toml --report-format json` |
| **trufflehog** | Live-key check (opt-in) | Which found keys still work: one read-only request per key to its provider | `trufflehog filesystem --json --results=verified <dir>` |
| **ast-grep** | Structural rules | The structural half of our own rules (§7): browser-side secrets and role checks, unsanitized `dangerouslySetInnerHTML`, SQL concatenation, CORS, uploads, stack traces, plus Supabase Edge Function / `getSession()` / Stripe webhook checks | `ast-grep scan -c rules/ast-grep/sgconfig.yml --json` |
| **bandit** | Python SAST | Python backends: shell injection, unsafe YAML/pickle, Flask debug, SQL strings | `bandit -r -f json -s <noisy tests> <dir>` |
| **zizmor** | GitHub Actions | Injection from issue/PR text, `pull_request_target`, token persistence, unpinned actions | `zizmor --offline --format json-v1 <dir>` |
| **lockfile-lint** | Lockfile tampering | Packages from unexpected hosts, over HTTP, under another package's name | `lockfile-lint --path <lock> --validate-https --validate-package-names` |
| **retire.js** | Vulnerable JS libraries | Outdated frontend/Node libraries with known CVEs (OWASP "known vulnerable components") | `retire --outputformat json --path <dir>` |
| **osv-scanner** | Dependency CVEs | Known vulns in npm/yarn/pnpm (and pip) deps via Google's OSV.dev database | `osv-scanner scan source -r --format json <dir>` |
| ~~**Trivy**~~ | ~~Deps + secrets + misconfig~~ | *Dropped: doesn't fit Render free's 512 MB (§11, §22).* | |

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

- [x] `vibe.frontend-secret` — API keys/secrets exposed to the frontend (`NEXT_PUBLIC_*` holding a real key, keys in client-side JS) — **Critical** *(Python: public-prefixed env vars holding a key; keys hardcoded in browser code. ast-grep: browser code reading `VITE_`/`NEXT_PUBLIC_`/… secrets, `dangerouslyAllowBrowser: true`)*
- [x] `vibe.supabase-rls-off` — Supabase client used with RLS disabled / no policies — **Critical** *(Python reads `supabase/migrations` in order: RLS off → Critical; always-true write policies → Critical; signed-in-only writes, open reads/inserts on personal-looking tables → High/Medium "Needs review"; views without `security_invoker` → High)*
- [x] `vibe.firebase-open-rules` — Firebase rules `allow read, write: if true` — **Critical** *(Python: Firestore/Storage rules and Realtime Database JSON; also unexpired test-mode dates, signed-in-only rules on the whole database, and `{userId}` paths that never compare it with `request.auth.uid`)*
- [x] `vibe.client-only-auth` — sensitive action gated only by client-side check, no server guard — **High** *(ast-grep: role flags read from localStorage/sessionStorage; Supabase writes inside a browser-side role check, confirmed or dropped against the table's RLS in the migrations)*
- [x] `vibe.cors-wildcard` — CORS `*` on authenticated endpoints — **High** *(ast-grep: High for any-origin + credentials; a plain `*` is Low, see §11)*
- [x] `vibe.xss-sink` — `dangerouslySetInnerHTML` / `innerHTML` / `v-html` fed from user input — **High** *(semgrep taint from URL/request → "Confirmed reachable"; ast-grep/Python for unsanitized `dangerouslySetInnerHTML`, `v-html`, `{@html}` → "Needs review")*
- [x] `vibe.sql-string-concat` — SQL built via concatenation/template literals, not parameterized — **Critical** *(semgrep taint → "Confirmed reachable", incl. PostgREST `.or()` filter strings; ast-grep pattern → "Needs review"; fix diff rewrites the call to `$1` parameters)*
- [x] `vibe.no-rate-limit` — auth or public write endpoints with no rate limiting — **Medium** *(Python, cross-file: Express routes with their mount paths, Next.js route handlers, API routes and Edge Functions; login/sign-up/reset paths, and anything calling a paid AI API ($ risk))*
- [x] `vibe.debug-in-prod` — debug mode / verbose errors / stack traces enabled in prod config — **Medium** *(Python: debug flags in `.env.production`; ast-grep: `err.stack` in responses)*
- [x] `vibe.eval-user-input` — `eval()` or dynamic code execution on user input — **Critical** *(semgrep taint: eval, Function, vm, string timers; shell commands as a variant)*
- [x] `vibe.unrestricted-upload` — file upload with no type/size validation — **Medium** *(ast-grep: multer without `fileFilter`/`limits`; High when saved into `public/`)*

Target 10–15 shipped rules. These three (XSS sink, SQL concat, frontend secret) **must** fire on the sample repo for the demo.

*Shipped: the 11 above plus 12 more = 23 rules (59 variants): `vibe.supabase-edge-service-role-no-auth`, `vibe.supabase-getsession-on-server`, `vibe.stripe-webhook-unsigned`, `vibe.supabase-privilege-escalation` (roles from sign-up metadata, `user_metadata` in policies or code, self-editable role/plan columns, self-granted roles), `vibe.supabase-rpc-exposed` (SECURITY DEFINER functions anyone can call over `/rest/v1/rpc`), `vibe.supabase-storage-open`, `vibe.plaintext-password`, `vibe.jwt-no-expiry`, `vibe.mass-assignment`, `vibe.ai-open-proxy`, `vibe.webhook-unsigned` (Lemon Squeezy, Paddle, Razorpay, PayPal, Clerk, Polar) and `vibe.missing-auth` (login tokens nobody verifies; server functions that write with the service-role key and check no one). All three demo must-fires are confirmed by taint or by the file itself.*

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
- [x] `POST /scan`, `GET /scan/{id}/status`, `GET /scan/{id}` implemented
- [x] Scanner is stubbed: returns 3–4 hardcoded fake findings after a short delay
- [x] `BackgroundTasks` drives job status `queued → running → done`
- [x] Frontend: input card (3 tabs), submit, poll status, render report with fake findings
- [x] Severity badges, expandable rows, risk score all render from fake data
- [x] **Commit** — *demoable: full UX works end to end*

### Phase 2 — Ingestion
- [x] Paste → write to temp sandbox dir
- [x] Zip upload → extract to temp dir (reject path-traversal entries)
- [x] GitHub URL → shallow clone (`--depth 1`), **public only**, reject private/auth
- [x] Enforce 50 MB size cap; clean up temp dir after every scan (even on failure)
- [x] **Commit**

### Phase 3 — Real scanners
- [x] `gitleaks detect` wired + output parsed into normalized findings *(uses `gitleaks dir`, the 8.30 replacement for `detect --no-git`)*
- [x] `semgrep` wired with `p/default` + `p/owasp-top-ten` + parsed
- [x] `njsscan` wired + parsed (Node.js SAST)
- [x] `osv-scanner` wired + parsed (dependency CVEs)
- [x] `retire.js` wired + parsed (vulnerable JS libs) — *optional / additive*
- [ ] ~~`trivy fs` wired + parsed (deps + secrets + misconfig) — *optional / additive*~~ *Dropped: doesn't fit Render free's 512 MB (§11, §22).*
- [x] `trufflehog` live-key check, opt-in per scan ("Test any keys we find")
- [x] `zizmor` wired + parsed (GitHub Actions); takes over from semgrep's Actions rules
- [x] `ast-grep` wired with our own structural rules in `rules/ast-grep/` (Supabase + Stripe starter set)
- [x] `bandit` wired + parsed (Python), with the noisy tests skipped
- [x] `lockfile-lint` wired + parsed (npm and yarn v1 lockfiles)
- [ ] ~~`hadolint`~~ *Not added (decided 2026-10-21).*
- [x] Each scanner lives in its own module under `scanners/`, implements the `base.py` interface, and **fails soft** if its binary is absent (skip + note in report, don't crash the scan)
- [x] `normalize.py` merges all sources into the common schema, dedupes by (file, line, rule-or-cve)
- [x] Verify real findings appear against the sample repo
- [x] **Commit**

### Phase 4 — Custom vibe-coded rules
- [x] `rules/vibe-coded.yml` + `custom_rules.py` implementing all rules in §7 *(plus ast-grep rules in `rules/ast-grep/rules/` and the migration reader `scanners/supabase_sql.py`)*
- [x] Wired into the pipeline as step 3 *(the "VibeGuard rules" step after SAST, per §3; the taint rules ride in the semgrep run)*
- [x] Each rule verified to fire on a crafted positive and not on a crafted negative *(`test_vibe_rules`)*
- [x] **Commit**

### Phase 5 — AI triage
- [x] `triage.py` with provider abstraction (`hosted` + `local` backends) — one OpenAI-compatible `Provider`: Groq or Ollama
- [x] `TRIAGE_BACKEND` env switch (`groq` | `local` | `off`); `GROQ_API_KEY`/`LLM_API_KEY` / `OLLAMA_URL` from env
- [x] Batched calls, strict-JSON parsing with defensive fallback (one retry; a batch that still fails leaves its findings untouched)
- [x] Findings enriched with severity/explanation/fix_diff; false positives filtered (within guardrails, see §11)
- [x] **Commit**

### Phase 6 — Scoring, polish, demo
- [x] `scoring.py` → 0–100 risk score (weight by severity + count), shown with grade
- [x] Per-severity counts in report header
- [x] Scan progress shows real stage names ("Scanning for secrets…", "Static analysis…", "AI triage…")
- [x] "No major issues found" empty state
- [x] Beautiful, polished UI per the design direction in §23 — top priority alongside the report
- [x] "Dynamic/DOM-XSS fuzzing — coming soon" note in UI
- [x] **Report excellence (the product's whole point — see §15):**
  - [x] Executive summary at top: letter grade + risk score + top 3 "this could hurt you" items in plain English
  - [x] Each finding carries a one-line **business/plain-English impact** (not CVE-speak) and a `$`-risk flag where relevant (exposed key, no rate limit)
  - [x] Each finding shows a **suggested fix** and a **secure re-prompt** snippet — guidance shown in the report, never auto-applied
  - [x] Confidence / reachability badge per finding (see §16)
  - [x] Export: Markdown + SARIF (shareable report), plus Save as PDF (print theme)
- [x] Built-in **"Try a demo repo"** button scans the bundled sample (§12)
- [ ] **Deploy (see §22) — the submission is one working public URL, card-free:**
  - [x] API-only Docker image on Render free: pinned gitleaks, trufflehog, osv-scanner, lockfile-lint, retire.js, semgrep, bandit, zizmor, ast-grep + baked semgrep rules; binds `0.0.0.0:$PORT`; `render.yaml` blueprint; CI builds it and runs the demo inside
  - [ ] Scanners run sequentially, one scan at a time (512 MB RAM); demo scan timed on the 0.1 CPU instance
  - [ ] CORS restricted to the Firebase origins via `ALLOWED_ORIGINS`
  - [ ] React build with `VITE_API_BASE_URL` → Firebase Hosting (Spark) at `*.web.app`
  - [x] "Waking the scanner…" state while the Render service cold-starts
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

- 2026-10-21 — Pages and identity. New logo: a "V" drawn as a heat trace (cool to hot) crossed by a white-hot scan line, also the favicon; "Beta" and the top-bar scanner status removed (Home still says when the scanner is waking or offline). Four pages: **Home** (hero, thermal specimen, the three steps), **Scan** (the form and your scans), **Demo** (what the demo app is, what's planted in it worst first, what to expect, run it or open your last demo report) and **History**; reports live at `#/scan/<id>` under History in the breadcrumb. Phone: the four pages as tabs under the top bar. Click-through verified (Home → Demo → run → report → Scan); no horizontal scroll at 390 px on any page.
- 2026-10-21 — Design pass (frontend-design). The reference look (near-black, one mint accent, uppercase mono labels, three identical stat cards) is the commonest generated-UI pattern, so the identity was rebuilt around the subject: **thermal imaging**, a scan that shows heat the eye can't see. Colour now means risk and nothing else: severity is a cool-to-hot ramp (Low blue #6f8cff, Medium amber, High orange, Critical magenta-red #ff3e6c) on a violet-black base; safe/passed is a cool teal; primary actions are white-hot (near-white with dark text), so action colour never competes with risk colour. Type: Bricolage Grotesque for display and UI, IBM Plex Mono only for code and paths; labels in sentence case. One bold element per screen: the home hero is a *thermal specimen*, a typical AI-built component where a scan line passes once on load and the three risky lines heat up with their plain-English risk (wraps on phones, static under reduced motion); the report gets a *heat strip*, one clickable segment per finding, hottest first. Removed: uppercase eyebrows, middle-dot meta strings, fake macOS window dots, the amber "$ risk" chip (amber means Medium here). Stats became one summary row in "Your scans". Checked at 1440 and 390 px: no horizontal scroll, every screen reviewed from screenshots.
- 2026-10-21 — UI rebuilt to the owner's reference: an app shell (sidebar with Overview and Scan history, a sticky top bar with breadcrumbs, live scanner status and refresh), deep green-black surfaces with one mint accent, mono tracked eyebrows. Overview: two-tone hero, three stat cards (scans, completed, average risk coloured by the grade it maps to), a New scan panel with a code editor (title bar with the file name, line-number gutter that scrolls with the text), ZIP and GitHub tabs, the live-key option, and Recent scans (grade + score chip, findings, polling while one runs). Scan history page; the progress page gets a progress bar and per-step states; the report gets a grade tile, verdict headline, export actions, numbered top-3 cards, sections with icons and an "Already right" card. History is per-browser: ids in localStorage, and `GET /scans?ids=` returns rows only for ids the caller holds (no global list). Phone: top bar + tabs instead of the sidebar, three compact stats, no horizontal scroll at 390 px. lucide-react 1.49.0 for icons.
- 2026-10-21 — Phase 6, build half. **Report:** grade + one-line verdict ("Attackers could do real damage today. Fix the 10 critical issues first.") + three "this could hurt you" cards that jump to and open their finding; findings grouped into keys and secrets / database, auth and setup / your code / dependencies; each card adds the re-prompt for the AI builder and copy buttons (the fix copies only the new lines); a "What we checked" list with counts; a "coming soon" line for live-app testing; "No major issues found" with what wasn't guaranteed. **Exports:** `report.md` and `report.sarif` (2.1.0, `security-severity` for GitHub's ranking, filtered findings as suppressed with the reason) from one shared `export.summary()`, and Save as PDF through a light print theme with every card opened (page breaks only inside cards, never a blank half page). **Cold start:** the home page pings `/health` and says "Waking the scanner" after 1.5 s, retrying for 2.5 minutes. **Uploads:** a request without Content-Length gets 411, closing the chunked-upload gap from the review. **Deploy files:** `Dockerfile` (pinned release binaries, Python scanners in their own venv, node only for retire.js and lockfile-lint, semgrep rules baked at build, unprivileged user, one worker), `render.yaml`, `firebase.json` (immutable asset caching, nosniff/DENY/referrer headers), and an `image` workflow that builds the image on linux/amd64 and runs the demo scan inside it (zizmor: no findings). Tests: 29 checks, ruff and oxlint clean, no overflow at 390 px.
- 2026-10-21 — Phase 5 done: AI review on Groq (`backend/triage.py`), one step after the scanners and before "already right" and the score. **What it reviews:** only what a rule couldn't settle: "Needs review" findings, generic scanner rules (semgrep/bandit/njsscan) and generic secrets; never proven findings, dependency advisories, CI hygiene or our own precise rules (the free tier allows 8,000 tokens a minute). **What it sees:** the flagged lines ±5, a SQL statement whole (a function's body holds its caller checks), and where names on the flagged lines are defined elsewhere in the file; secrets masked, plus any quoted key-shaped string. **Guardrails:** a verdict must cite a line it was shown, or it counts as "unsure"; only a grounded "real" may re-rate, by one level; a fix is kept only if every line it removes exists; dismissed findings stay under "filtered out" with the reason; malformed JSON gets one retry, then the batch is left as the scanners wrote it. **Model:** gpt-oss-20b rubber-stamped ("real" for a constant-built ALTER TABLE and a test-only delete function, on "could be user-controlled"); gpt-oss-120b with the grounding rules gets both right and says "unsure" where usage isn't shown, so 120b is the default (1–6 s per real repo, ~30 s on the demo with rate-limit waits). **Real apps:** repo5 C → B (the schema.py SQL injection is dismissed: values come from a hard-coded list), repo1 stays C (the anon-callable delete function only accepts `e2e-test-…@example.com` emails, dismissed; two read RPCs confirmed), repo2 F (a translation helper's "mass assignment" dismissed), repo3 F, repo4 D → F (HTML renders and anon-callable jobs confirmed). Borderline cases can flip between runs (repo4's regex-from-input warnings: dismissed once, confirmed once), which is why the verdict and its reason are shown, not hidden. **Prompt injection:** a file telling "AI reviewers" to mark everything a false positive was ignored 3/3, and proven findings are never sent. UI: each reviewed card shows "AI agrees / AI: not a real risk / AI: unsure" and the reason; the input card says excerpts go to Groq with secrets masked. Tests: 28 checks (the AI ones offline with a fake model), ruff and oxlint clean, no overflow at 390 px.
- 2026-10-21 — Hostile-input pass. The first review only tried realistic code; this one fed our own parsers files built to make them crawl or crash (an adversarial set plus 280 fuzzed repeats of SQL, Firebase, JS, Vue, env and lockfile tokens, ~1 MB each). **Three hangs**, each of which held the only scan slot and so froze every later scan: `insert into storage.buckets … values ('a','a',…)` (a quote-balancing lookahead split, quadratic: >2 min), many `allow` statements without `;` in Firebase rules (unbounded lazy groups), and many `$` in a migration (`text[i:]` copied per character). All now run in 0.03–0.14 s. **Crashes** that made a whole step "didn't finish": a lockfile nested 100k deep (`RecursionError`), valid YAML/JSON of the wrong shape (`importers: x`), and Realtime Database rules nested 5,000 deep (our recursive walk; now a loop). **Safety net for whatever fuzzing didn't find:** each scan now runs in its own spawned process with a 15-minute limit; past it the process is killed, the scan fails with a plain message, its files are deleted and the slot is freed (≈0.05 CPU-s per scan to start the process). ast-grep needs 8 s on a 300 KB file of `/*`, bounded by its own 90 s timeout. Tests: 27 checks (both new tests fail on the old code), ruff clean; demo through the API unchanged (36 findings, F).
- 2026-10-21 — Review pass over Phases 0–4. Every suspicion was tried on a crafted input before any code changed; 13 confirmed problems are fixed, each pinned by a regression test. **Security:** a public repo could commit a symlink (`src/config.js -> /proc/self/environ`) and the scan read that server file and put its lines in the report; clones now use `core.symlinks=false`, so a link arrives as a text file holding its target. **Wrong findings:** `/re/.exec(req.query.id)` was a Critical SQL injection *and* a shell injection, and `cp.exec(…)` was also a SQL injection (`.exec` sinks now need a database-like or `child_process` receiver, and an options object like GraphQL's `client.query({ query, variables })` isn't SQL text); `crypto.createHmac(…).update(req.body)`, the *correct* webhook check, was mass assignment; a sign-up trigger choosing between fixed values (`case when … = 'seller' then 'seller' else 'buyer' end`) was "Anyone can sign up as an admin", Confirmed; `credits`/`plan` keys were also titled "as an admin"; storage findings named `'jpg'` from `storage.extension(name) = 'jpg'` as a bucket; in a Node API with no frontend, `src/` counted as browser code (a key in `src/config.js` read as shipped to browsers, and `jwt.verify` in `src/middleware/auth.js` was invisible). **Missed findings:** a column-level `GRANT UPDATE (name)` was taken as protection although Supabase grants every column to `authenticated` until the table-level UPDATE is revoked; `revoke update, delete … from anon, authenticated` hid a table from every RLS check; revoking from PUBLIC counted although anon keeps its direct grant; a `to` inside a USING expression (`'up to date'`) was read as the policy's role; Python-only projects never ran the FastAPI/flask CORS rule. **Report:** "Already right" could say "SQL queries keep values separate from the query text" beside a Critical SQL injection proven by taint analysis, because it only saw VibeRules' own findings; checks are now settled against the final merged report, including Critical/High secrets other scanners find in browser files. Firebase findings get one card per path. **Robustness:** scans a restart interrupted now fail with a message instead of polling forever; the UI retries a dropped status poll (up to 4 times, 2 s apart) instead of calling the scan failed; at most 8 scans wait (more get a 429), so a burst can't fill the disk; the input card no longer claims "Nothing is stored" (the report is kept, the code isn't). **Unchanged where it should be:** identical findings and grades on all five real apps (C, F, F, D, C) and the demo (36 cards, F). Tests: 25 checks, ruff and oxlint clean, frontend builds.
- 2026-10-21 — Phase 4 deepened: from 14 rules to 23, from single findings to connected ones. **Whole-app reasoning instead of single lines.** The migration reader now replays functions, triggers, column grants, storage policies and buckets to their final state, which unlocked the Supabase mistakes that matter most: *anyone can sign up as an admin* (a trigger on `auth.users` copying `is_admin`/`role` from `raw_user_meta_data`, which the person signing up chooses), policies or code trusting `user_metadata` (users edit it with `updateUser()`), *users can make themselves admins / give themselves a paid plan* (own-row update policy on a table with a role/plan/credits column and nothing limiting that column: no column grant, no check, no guard trigger), roles tables users can insert into, SECURITY DEFINER functions anyone can call over `/rest/v1/rpc` (High when the caller picks the rows via arguments, Medium for no-argument jobs and read-only functions, with the Supabase gotcha spelled out: revoking EXECUTE from PUBLIC doesn't remove anon's direct grant), and storage policies that check the bucket but not the owner. On the server side: login tokens issued but never verified (with the list of endpoints that answer anyone), server functions (TanStack `createServerFn`, Next server actions and route handlers) that *write* with the service-role client and check no one, plaintext password comparison/storage, tokens without expiry, the whole request body written to the database, AI endpoints that take the conversation or the model from the caller, unsigned webhooks from six more payment/auth providers, and FastAPI/flask-cors wildcard-with-credentials (which echoes the caller's origin). **Findings are connected:** an env var and the browser code that reads it point at each other; an open table lists the browser code that already queries it; an Edge Function lists where the site invokes it; when the app ships the Supabase URL and anon key, an RLS-off table is **Confirmed reachable** and comes with a read-only `curl` check the owner can run. **Fixes are rewritten from the actual line** (`user.password !== password` → `!(await bcrypt.compare(password, user.password_hash))`, `jwt.sign(p, s)` → `jwt.sign(p, s, { expiresIn: "1h" })`, rate limits written for Express, Next or an Edge Function as appropriate). **What passed is shown:** the VibeGuard step reports what it checked and found right ("Row-Level Security is on for all 78 tables…", "Storage policies check who owns each file"), shown in the report as "Already right", with an empty state when nothing is wrong. **Hardening found on the way:** a SAST-found secret (`jwt.sign(p, "supersecret123")`) leaked through *another* finding's snippet on the same line; such literals are now masked in every finding. **Calibration on the five real apps:** app 1's sign-up trigger once read the role from metadata, so the check reads only each function's final definition (later fixed there, correctly not reported); the server-function rule first flagged 4 public read endpoints in app 2 (wanted-persons lists) and now only fires on writes; app 2's `requireStaff()` helpers count as guards. New true positives: app 1 grants anon EXECUTE on a SECURITY DEFINER function that deletes (test) users; app 4 lets anyone create notifications for any user and trigger log retention via RPC; app 2 lets anyone upload to two buckets (Needs review: it's an anonymous reporting app). Grades: C (was B), F, F, D, C. **Demo:** 34 findings (10 Critical, 14 High, 9 Medium, 1 Low; 7 confirmed reachable), ~8 s via the API. Tests: 22 checks; the fixture now holds a positive and a negative for all 59 variants. The VibeGuard step still costs ≤ 0.4 CPU-s on the largest repo.
- 2026-10-21 — Phase 4 done: 14 VibeGuard rules (the 11 in §7 + Edge Function service role without a caller check, server-side `getSession()`, unsigned Stripe webhooks), split across three engines by what each does best. **semgrep taint** (`rules/vibe-coded.yml`: SQL, XSS, eval, shell) proves request/URL data reaches the sink → "Confirmed reachable"; it rides in the main semgrep run, because a separate run cost 2.6–5 CPU-s per real repo (≈26–50 s on Render) against +1–2 s merged. **ast-grep** (13 structural rules) for patterns that need no data flow. **Python** for what isn't JS/TS or spans files: env files, Supabase migrations (new `scanners/supabase_sql.py` replays them in order, including `DO $$ … EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY')` loops, REVOKE/GRANT, renames and drops), Firebase rules, rate limits (Express mounts resolved across files), Vue/Svelte templates. All report text lives in one catalog (`CATALOG`/`VARIANTS` in `scanners/custom_rules.py`): title, severity and why, impact, explanation, fix diff, re-prompt, references. Fix diffs are real: SQL calls are rewritten to `$1` parameters (`db.query("... WHERE email = $1", [email])`), URL-fed `dangerouslySetInnerHTML` templates become plain JSX children, Supabase fixes use the table's actual owner column. Cross-checks: a browser-side admin check around a Supabase write is **confirmed** when the migrations show that table without RLS (or with an always-true policy) and **dropped** when RLS has no policy opening that command. **Demo:** 30 findings (9 Critical, 11 High, 7 Medium, 1 Low, 2 filtered as noise), risk 100 / F, 8 s through the API; the three §12 must-fires are all there, SQL and XSS confirmed by taint, each with a working fix. **Real repos (precision):** 7 hits across 5 apps, all checked by hand: 2 "any signed-in user can change these tables" (Needs review: depends on whether sign-ups are open), 2 HTML-from-data renders (a document generator that really injects HTML), 1 paid-AI Edge Function with no rate limit; no RLS false positives across 133 tables (an early version flagged 16 tables enabled through a `DO $$` loop; fixed and tested). Grades: B, F, F (was D), D (was C), C; the two moves come from those "Needs review" findings, which Phase 5's AI triage will judge. **Cost:** the VibeGuard step takes 0.1–0.4 CPU-s; the taint rules add 1–2 CPU-s to semgrep. Tests: 21 checks (a crafted positive and negative for every rule in one fixture project; the demo's full expected report), ruff and oxlint clean, no horizontal overflow at 390 px.
- 2026-10-21 — Phase 3 extended with five more scanners and the gaps found in the last review. **New tools:** trufflehog (opt-in live-key check), zizmor (GitHub Actions), ast-grep (our own structural rules), bandit (Python), lockfile-lint (npm/yarn v1 lockfiles); hadolint left out by decision. **Gaps closed:** (1) Supabase's 2025 key formats: an `sb_secret_` key in a `.ts` file was missed by both gitleaks and semgrep, and `sb_publishable_` was a High false alarm; `rules/gitleaks.toml` extends gitleaks' defaults with `sb_secret_`, `sb_publishable_` and `sbp_` (access token) rules, and the classifier treats them like `service_role` / `anon` / Critical; (2) pnpm (v6, v9) and yarn (v1, berry) lockfiles now feed the runtime-vs-build dependency graph, including npm aliases; the same project locked four ways gives identical tiers (180 packages), and lockfile lines are located for the report; (3) "Hardcoded credential" on a JWT secret now reads "JWT signing secret in code" with what that means; (4) a golden test pins the demo's whole report. **ast-grep starter rules** (none of them in §7, all missed by the registry): Edge Function using the service-role key with no caller check (High), `getSession()` trusted in server code (Medium, two rules: server paths, and TanStack server functions / `'use server'`), Stripe webhook without signature verification (High, $ risk). Each fires on a crafted positive and stays quiet on its negative; zero hits on the five real repos. The demo app gained an unsigned Stripe webhook and a service-role Edge Function so both show up. **Real repos:** grades unchanged (B, F, D, C, C); zizmor replaced semgrep's GitHub Actions findings with better-judged ones (e.g. a `${{ }}` with no outsider-controlled input is Low, not an injection); bandit, ast-grep and lockfile-lint added no noise (bandit's 13 raw hits on the Python repo were all in its skip list; lockfile-lint's 4 alias hits are recognised as npm aliases). **Cost:** the five new tools together add < 1 CPU-second per real repo (≈10 s on Render); trufflehog only runs when the user ticks the box. Steps that have nothing to check ("no Python files", "no GitHub workflows") show as not needed instead of "not checked". Demo: 15 findings, risk 96 / F, ~7 s through the API. Tests: 18 checks pass, ruff and oxlint clean, no horizontal overflow at 390 px.
- 2026-10-21 — Phase 3 refinement, driven by real repos. Ran the pipeline against 5 public Lovable/Bolt-built repos (kept anonymous here: one has a live-looking Supabase `service_role` key committed). First pass: **every repo got an F at risk 89–100**, buried under 21–36 findings each, mostly CVEs in build tooling (brace-expansion via eslint, nanoid via postcss…) plus CI hygiene and `console.log` noise. That's the "cries wolf" failure §15 warns about. After the changes below, findings shown dropped from 115 to 34 (−70%) and grades now separate the repos: A **F** (committed service_role key + critical framework CVE), B **B**, C **D** (critical TanStack Start CVE), D **C**, E **C**; demo app still F. Changes: (1) dependency findings split into runtime vs. build/test via the lockfile graph (`scanners/npm_deps.py`: package-lock v2/v3 + bun.lock, build tools recognised even when listed under `dependencies`, peers not followed, walk stops at bundlers), one roll-up Low finding for all build/test tooling CVEs, one finding per package across versions and lockfiles, "pulled in by X" for indirect deps, a level lower when the code never imports a direct dep, and package.json-without-lockfile checked at the declared minimums; (2) semgrep skips tests/docs/build output (secrets are still scanned there), −40% CPU on real repos with identical results; (3) curated rule verdicts: `console.log` format-string rule → noise, CI action pinning / package-manager release-age → Low hygiene grouped repo-wide, CSRF → noise when the app uses no cookies, GitHub Actions `run:` injection → Low unless the `${{ }}` reads issue/PR/comment text; (4) same rule repeating in a file → one finding listing every line; findings in test code a level lower; (5) evidence snippets now carry ±2 lines of context with line numbers and the flagged lines highlighted (secrets get no context: neighbouring `.env` lines are often secrets too); (6) secrets get provider-specific rotation links, an env-var fix diff (`apiKey: "sk-…"` → `apiKey: process.env.OPENAI_API_KEY`, or a `.gitignore`/`git rm --cached` fix for committed `.env` files), and a re-prompt; more placeholder shapes filtered (`pk_this_is_…`, `fake`, `for_testing`); (7) risk score weights "Needs review" findings at half; (8) every scanner report parse failure becomes a soft "didn't finish", never a crash; per-scan scanner instances; each step records what it checked ("412 source files", "1,043 packages"). Evaluated and rejected: adding `p/nodejsscan` to semgrep (same 3 demo findings as njsscan, but +150% CPU on a real repo); njsscan found 0 issues on all 5 real repos (it only analyses `.js`, and these are TypeScript). Tests: 13 checks pass, ruff and oxlint clean, demo scan 5.8 s through the UI.
- 2026-10-21 — Phase 3 done. Five real scanners under `scanners/` (gitleaks, osv-scanner, retire.js, semgrep, njsscan) behind `base.Scanner` (`available()`, `run(root, work)`, process-group-safe `exec()` with timeout). `normalize.py` merges, dedupes, masks secrets and adds plain-English titles/impact from a CWE table. Demo app result: 18 raw findings → 13 (1 Critical, 8 High, 2 Medium, 1 Low, 1 filtered as noise), risk 96 / F, in **5.8 s** wall time end to end through the UI. Verified on the demo: service_role JWT → Critical; anon JWT → filtered with an explanation; eval found by semgrep (2 rules) + njsscan → one finding at the precise line; jwt.sign secret found by semgrep + njsscan (block range 2–12) → one finding at line 10; 5 vulnerable packages, each one finding with the advisory list, the minimal fixing version and a `package.json` diff (e.g. axios `^0.21.1` → `^0.33.0`, 24 advisories). retire.js verified separately on a vendored `jquery-3.4.1.min.js` (2 CVEs, fix 3.5.0). Fail-soft verified: no binaries → every step "not installed" and the scan **fails with an honest message** instead of reporting an empty A; a scanner that exits non-zero, raises, or hangs past its timeout → that step marked "didn't finish" and the scan still completes; no orphan child processes after a timeout. `test_vibeguard.py` now also covers version-range math, secret classification, masking of truncated secrets, dedupe rules and an integration run on `sample-repo/` that asserts no secret value appears anywhere in the output. Gaps that Phase 4 fills: no scanner caught the SQL concatenation, `dangerouslySetInnerHTML`, Supabase RLS, Firebase rules, client-only admin check, missing rate limit, debug config, or unrestricted upload in the demo app.
- 2026-10-21 — Phase 2 done. `ingest.py`: `validate()` runs before queueing (instant 400 with a plain-English message) and `sandbox()` builds a `TemporaryDirectory` that is always deleted. Paste → file named from the optional filename (path-sanitized) or guessed from content (`.py`/`.rules`/`.sql`/`.env`/`.tsx`/`.js`). Zip → spooled to a temp file (not RAM), rejected on absolute/`..`/drive-letter entries, > 20k entries, or > 50 MB declared uncompressed size; `node_modules/`, `.git/`, `__MACOSX/` skipped. GitHub → URL validated and rebuilt as `https://github.com/<owner>/<repo>.git`, `git clone --depth 1` with credential helpers disabled and prompts off, so private repos fail fast (0.6 s) instead of hanging; `.git` removed after clone. 50 MB cap on request size, zip contents and final tree. One scan runs at a time (semaphore) for the 512 MB Render box. Added `sample-repo/` ("PromptPal": React + Supabase + Express + Firebase, 20 files) and the `demo` source. Verified: `test_vibeguard.py` (traversal, zip bomb, cleanup on error, URL forms, paste names) passes; every source exercised through the API; no sandbox dirs or temp zips left behind.
- 2026-10-21 — Phase 1 done. `POST /scan` (multipart form), `GET /scan/{id}/status`, `GET /scan/{id}`; stubbed pipeline walks the stage list with a delay and stores 4 fake findings; `scoring.py` (final formula: risk 0–100 + A–F grade) is already in. Frontend: 3-tab input card (paste with optional filename / zip dropzone / GitHub URL), "Try the demo app" button, polling progress list, report with grade, risk score count-up, severity counts, expandable finding cards with severity rail. Report URL is `#/scan/<id>`, so it survives refresh and can be shared. Verified in headless Chromium at 1280px and 390px. Fixed: stub reused finding ids, so a second scan failed on the UNIQUE constraint — the failed state rendered correctly, which doubled as an error-state test.
- 2026-10-21 — Hosting switched to Render free + Firebase Hosting (card-free); §22 rewritten, Trivy dropped from the deployed set. Groq key verified against the live API (`openai/gpt-oss-20b` and `gpt-oss-120b` both listed); stored only in gitignored `backend/.env`.
- 2026-10-21 — Phase 0 done. FastAPI `/health`, SQLite (`scans` + `findings`, plus report columns used later: `severity_reason`, `impact`, `money_risk`, `confidence`, `reprompt`, `refs`, `evidence`, `triage_note`, and `scans.scanners`/`source_label`), Vite 8 + React 19 + Tailwind 4 shell with dark design tokens, README. All six scanners installed locally (semgrep 1.181, njsscan 1.0.1, gitleaks 8.30.1, retire 6.1.0, osv-scanner 2.7.0, trivy 0.76.0).
- _2026-10-21 — (Claude Code) initialized project from spec. Starting Phase 0._

---

## 11. Decisions & deviations

> Record any choice that differs from this spec, with the reason.

- **2026-10-21 — Scanner selection.** Core set is semgrep + njsscan + gitleaks + osv-scanner, with retire.js + trivy as additive, chosen to cover the JS/TS + React/Next + Supabase/Firebase + Node stack that vibe-coding tools generate. retire.js/trivy overlap the core set on deps/secrets and are optional for the MVP.
- **2026-10-21 — LLM = Groq.** OpenAI-compatible endpoint; default model `openai/gpt-oss-20b`, later `gpt-oss-120b` (see Phase 5 decisions) (Groq retired the Llama models from free/dev tiers in Aug 2026). Kept behind the `triage()` abstraction so local Ollama/Gemma can replace it.
- ~~**2026-10-21 — Hosting = Cloud Run, single container.**~~ *Superseded the same day — see next entry.* The deliverable is one public URL, so a local tunnel won't do. One Docker image (FastAPI serving the React build + the scan API, all six scanners baked in) deploys to Cloud Run with `--memory 2Gi`. Clean `*.web.app` link via Firebase Hosting rewrite to the Cloud Run service. Scanner DBs pre-baked into the image. (See §22.)
- **2026-10-21 — Hosting = Render free (API) + Firebase Hosting Spark (UI), card-free.** No payment method is available, and we still want a clean link. Cloud Run (+ Firebase rewrite) needs a card; Hugging Face free Docker Spaces became PRO-only in July 2026. Render's free tier runs a Docker container with no card; Firebase Spark gives `*.web.app` with no card. Consequences: (1) the container is API-only and the React app calls it cross-origin via build-time `VITE_API_BASE_URL`, with CORS limited to the Firebase origins (`ALLOWED_ORIGINS`), never `*`; (2) Render free is 512 MB RAM / 0.1 CPU, so **Trivy is dropped**, the image ships semgrep + gitleaks + osv-scanner + njsscan, scanners run sequentially, one scan at a time, with pre-downloaded trimmed semgrep rules; (3) the service sleeps after 15 min idle, so the UI shows a wake-up state. Any spec text that still implies Cloud Run or a single image serving the UI is overridden by §22.
- **2026-10-21 — `POST /scan` takes `multipart/form-data`** (`source_type`, `payload`, optional `filename`), so one format covers code strings, zip uploads and URLs. `source_type` also accepts `demo` (scans the bundled `sample-repo/`).
- **2026-10-21 — Progress is a step list, not just a stage string.** `scans.steps` (JSON) holds `{key, label, state, note}` per pipeline step/scanner; the UI renders it live, and the report reuses it for "what was checked" and skipped-scanner notes. `stage` stays as the human-readable current step.
- **2026-10-21 — Dedupe is smarter than `(file, line, rule-or-cve)`.** Different scanners use different rule ids for the same bug, and njsscan reports whole blocks (e.g. lines 2–12) where semgrep reports the exact line. So: **code** findings merge when they're in the same file, their line ranges overlap, and they share a CWE (or the same non-empty rule id); **secrets** merge on same file + overlapping lines; **dependencies** merge on `package@version` across osv-scanner and retire.js. The kept copy comes from the most specific source (`custom > gitleaks > semgrep > njsscan > osv-scanner > retire.js`), takes the worst severity (unless it was classified as noise), unions CWEs/refs, records `detected_by`, and is bumped from "Needs review" to "Likely" when two scanners agree.
- **2026-10-21 — One dependency finding per package, not per CVE.** axios 0.21.1 alone has 24 advisories; 24 cards would bury everything else. Each package gets one finding with the worst advisory as the severity reason, the full advisory list as evidence, and the **lowest version that fixes all of them on the installed release line**, computed from OSV ranges (`scanners/versions.py`), plus a manifest diff when the dependency is direct. Transitive deps get "Needs review" and override guidance.
- **2026-10-21 — Secrets are classified, not just matched (start of §16 secret validation, offline only).** JWTs are decoded: Supabase `service_role` → Critical; `anon` → filtered as public-by-design (with the RLS caveat). Placeholders (`your-api-key-here`, `<KEY>`, `${KEY}`, `changeme`…) → filtered. Known prefixes (OpenAI, Anthropic, Groq, Stripe live/test, AWS, GitHub, Slack, SendGrid, Google) set the title, severity, impact and `$`-risk flag; test/example paths drop one severity level. No live validation calls yet (Phase 7).
- **2026-10-21 — Secret hazmat (§20).** The raw value lives only in a private, never-serialized field; every snippet, diff, explanation and evidence line is masked, including copies cut short by snippet truncation (matched on their first 16 chars; a real leak of the service_role signature was caught and fixed this way). Hardcoded credentials found by SAST rules (e.g. `jwt.sign(p, "supersecret123")`) are masked too. gitleaks' report file (which holds raw secrets) is written inside the sandbox and deleted with it. Scanner processes get an environment **without** `GROQ_API_KEY`/`LLM_API_KEY`, and semgrep metrics/version checks are off.
- **2026-10-21 — Semgrep rules cached and trimmed.** `rules/fetch_registry.py` downloads `p/default` + `p/owasp-top-ten` (1,144 unique rules; 490 overlap) and keeps the 597 for JS/TS/Python/generic/config languages in `rules/registry.json` (gitignored, fetched at Docker build). On the demo: identical results to the live packs with 35% less CPU and 27% less peak memory; `--jobs 1` keeps semgrep from forking a worker per host CPU inside a container. **License caveat:** registry rules are under the Semgrep Rules License v1.0, which restricts offering them as a hosted/SaaS product. Fine for a non-commercial hackathon demo; a commercial VibeGuard must replace them with its own rules (our `vibe.*` rules) or license Semgrep.
- **2026-10-21 — No source→sink traces from Semgrep OSS.** Semgrep 1.181 OSS omits `dataflow_trace` from JSON and `codeFlows` from SARIF even with `--dataflow-traces` (it only appears in text output). So reachability evidence can't come from registry rules for now; Phase 4's own taint rules will mark findings "Confirmed reachable", and the full path display stays in Phase 7.
- **2026-10-21 — Render CPU budget risk: njsscan.** Measured CPU time on the demo: njsscan 8.8 s, semgrep 1.2 s, osv-scanner 0.15 s (network-bound), gitleaks < 0.1 s. At Render's 0.1 CPU that's roughly 90 s for njsscan alone. All 3 of its demo findings are also found by semgrep. If the Phase 6 timing on Render misses the 60 s target, njsscan is the first thing to leave the image (no code change: a missing binary is skipped).
- **2026-10-21 — A scan where no scanner ran fails loudly.** An empty report would read as grade A; instead the scan fails with "None of the scanners could run on this server, so nothing was checked."
- **2026-10-21 — Dependency severity follows what ships (§16 reachability, offline).** A CVE's CVSS is about the package, not your app. Policy: direct runtime dependency your code imports → advisory severity, "Likely"; direct runtime dependency never imported → one level lower, "Needs review" ("removing it is the simplest fix"); indirect runtime dependency → one level lower, "Needs review", with the direct dependency that pulls it in; build/test-only → rolled into one Low finding per project. "Build-only" comes from the lockfile graph walked from the app's runtime dependencies, stopping at known bundlers/linters/CSS tooling (Lovable lists vite and tailwind under `dependencies`, and frameworks like TanStack Start depend on their own bundler). yarn.lock/pnpm-lock graphs aren't read yet: those fall back to osv-scanner's `dependency_groups` and are marked "Needs review".
- **2026-10-21 — Curated verdicts for a handful of registry rules** (`scanners/semgrep.py: POLICY`): decided once, with the reason shown to the user, instead of re-litigated in every report. Kept deliberately short; anything broader is Phase 5 triage's job.
- **2026-10-21 — Risk score is confidence-weighted.** "Needs review" findings count half (one unconfirmed Critical = 28, not 55), so a guess can't fail a repo on its own.
- **2026-10-21 — Five more scanners, each with a narrow job.** trufflehog only verifies keys (unverified, it added nothing on the five real repos but three dummy credentials in test files, so it doesn't run unless asked); zizmor owns GitHub Actions and semgrep skips `.github` when zizmor is installed; ast-grep runs our own rules (fast, structural, one YAML file per rule with its report text in `metadata`); bandit covers Python with B101/B104/B105–B108/B110/B112/B113/B311/B404/B603/B607 skipped (all 13 hits on a real Python app were these) and two CWEs corrected (B201 → CWE-489, B506 → CWE-502) so its findings merge with semgrep's; lockfile-lint reads npm and yarn v1 lockfiles, with npm aliases passed as allowed (otherwise `string-width-cjs` → `string-width` is flagged as injection), and yarn berry lockfiles skipped (no URLs to check). hadolint was left out by the user. nuclei (scan the live deployed URL) is a different input — an arbitrary URL is someone else's server — so it belongs with §17, not here.
- **2026-10-21 — Live-key testing is opt-in per scan (§16, §20).** Verification sends the user's keys to third parties, and a public GitHub URL may not be the user's code, so it runs only when they tick "Test any keys we find" (default off; `verify_secrets` form field). A key its provider accepts becomes Critical / "Confirmed live", overriding any placeholder guess; raw keys come back on trufflehog's stdout only and are masked everywhere, including the other parts of multi-part keys (AWS id + secret). Verified against a real key (the project's own Groq key): live → verified, a random `gsk_` → not. **SSRF guard:** only an allowlist of detectors runs (`DETECTORS` in `scanners/trufflehog.py`: OpenAI, Anthropic, Groq, Stripe, AWS, GitHub, Slack, SendGrid, Supabase token…), all of which call the provider's own fixed API host. Detectors like URI, Postgres, JDBC, MongoDB or Redis verify by connecting to the host written in the scanned code, so a submitted repo could aim our server at `169.254.169.254` or internal addresses; a test plants such a URI and checks it's never picked up (without the allowlist, the Postgres detector does pick it up).
- **2026-10-21 — ast-grep rules don't duplicate §7.** The starter set covers Supabase/Stripe mistakes no registry rule knows (verified: no `getSession`, Stripe-webhook or Edge Function rule in the 597 cached rules). Phase 4's §7 rules can be written for either engine: ast-grep for structural patterns (much cheaper at 0.1 CPU), semgrep where taint tracking is needed.
- **2026-10-21 — "Not needed" is not "not checked".** A scanner with nothing to look at (no Python files, no workflows, no npm/yarn v1 lockfile, no JS/TS) gets step state `na` and stays out of the report's "Not checked" line; "skipped" now only means not installed or turned off.
- **2026-10-21 — The demo report is pinned by a golden test.** `DEMO`, `DEMO_NOISE` and `DEMO_DEPS` in `test_vibeguard.py` list every expected finding, filtered decoy and vulnerable package; any change that adds, drops or re-rates one fails until the list is updated on purpose.
- **2026-10-21 — Phase 4 rules: three engines, one catalog.** §7 says semgrep where feasible, Python where awkward; we added ast-grep (Phase 3) as the cheap structural engine. Taint (needs data flow) → semgrep, in the same run as the registry rules. Structure → ast-grep. Non-JS files and cross-file facts → Python. One `CATALOG` keeps every rule's words in one place, and each rule id is stable (`vibe.<rule>[:variant][@table]`).
- **2026-10-21 — Severities calibrated against real risk, not the §7 defaults.** `vibe.cors-wildcard` is High only for any-origin **with credentials** (the actual exploit); a plain `*` can't carry cookies, so it's Low (and Supabase's own Edge Function template is ignored). `vibe.unrestricted-upload` is Medium, High when files land in `public/` (an uploaded `.html` runs on your domain). `vibe.no-rate-limit` covers login/sign-up/reset routes and anything that calls a paid AI API ($ risk); other POST routes would be noise. Pattern-only XSS and SQL hits are "Needs review" (we can't see where the value comes from); taint hits are "Confirmed reachable". Open `select`/`insert` policies are only reported on tables whose names suggest personal data (`profiles`, `orders`, `messages`…): `recipes` or `police_stations` readable by anyone is the point.
- **2026-10-21 — A VibeGuard rule's rating wins a merge.** When our rule and a generic one report the same line, the card keeps our severity, words and references (they know the framework), while "found by" lists both. Before, a generic Medium could override our calibrated Low.
- **2026-10-21 — One card per table for RLS, every place's fix in grouped cards.** RLS findings carry the table in their id so two open tables are two Critical cards, not one; grouped cards (same rule, same file) now show each place's own fix (both SQL rewrites, both `.env.production` flags).
- **2026-10-21 — Rules reason about the whole app, not one line.** The best Supabase findings need several files: a trigger *and* the metadata it reads; a policy *and* the columns it doesn't protect; a function *and* its grants. So the migration reader keeps the final state of everything, and `_connect` links findings that are one story. The rule is precision first: every new check was run on the five real apps and narrowed until each hit was defensible (writes only for server functions, guard helpers recognised, read-only/no-argument functions rated lower).
- **2026-10-21 — Read-only proof, never an exploit.** Findings may carry a `curl` the owner can run to see the exposure for themselves (a `select … limit=1` against their own project, with `<your anon key>` as a placeholder). Write-path issues are described, never scripted.
- **2026-10-21 — "Already right" is part of the report.** A clean result only means something if it says what was checked (§15), so each scanner can report `passed` items; the VibeGuard step reports per-area passes (RLS, roles, functions, storage, Edge Functions, browser secrets, Firebase rules, SQL, webhooks).
- **2026-10-21 — Cloned repos never contain symlinks.** git clones with `core.symlinks=false` (zip extraction never created links). A committed link is how a submitted repo would make our in-process checks, any scanner, or a report snippet read a file on the server.
- **2026-10-21 — "Already right" is decided against the final report.** Each check names the VibeGuard rules, and the CWEs in which files, that would contradict it (`custom_rules._passed`); the pipeline drops contradicted checks after normalize (`settle()`), because taint findings and other scanners' findings never pass through VibeRules. Low findings don't contradict (a Firebase web key is public by design).
- **2026-10-21 — Table privileges follow Postgres.** A column-level `GRANT UPDATE (cols)` narrows nothing until table-level UPDATE is revoked (Postgres also drops column grants when the table-level privilege is revoked, so order matters); a table counts as unexposed only when anon and authenticated both lose every privilege; `REVOKE … FROM PUBLIC` doesn't touch Supabase's direct grants to anon and authenticated.
- **2026-10-21 — A Node API without a frontend has no browser code** except `public/` and `static/`: the root `package.json` lists express/fastify/koa/hono/nest/hapi and none of react/vue/svelte/vite/next/nuxt/astro/angular/expo.
- **2026-10-21 — At most 8 scans wait.** One scan runs at a time and every waiting upload sits on disk; the 9th waiting scan gets a 429 with a plain message. A per-IP limit can come with real traffic.
- **2026-10-21 — Each scan runs in a child process with a 15-minute limit.** Every tool already has a timeout, but our own Python (rules, lockfile readers, normalize) runs in-process, and Python can't stop a thread. A spawned process can be killed, so no file can freeze the one-at-a-time queue. Spawn rather than fork: forking a threaded server can deadlock. A tool still running at the moment of the kill finishes on its own, bounded by its own timeout.
- **2026-10-21 — AI review judges, rules decide.** §8 has the model return severity, explanation and fix for every finding. Instead it reviews only what rules couldn't settle, keeps our catalog's hand-written explanations and fixes (it writes them only for generic scanner findings without one), must ground each verdict in a cited line, re-rates by at most one level, and never sees proven findings. A model that is wrong, or manipulated by the scanned code, can therefore only make a finding "unsure" or move it to the visible "filtered out" list with its reason. `TRIAGE_BACKEND=off` turns it off; Ollama (`local`) uses the same OpenAI-compatible client.
- **2026-10-21 — Default model gpt-oss-120b, not 20b.** Same 8k tokens/minute free limit, a few seconds per repo; 20b called constant-built SQL and a guarded test function "real" on speculation.
- **2026-10-21 — The image is tested in CI, not on Render.** There's no Docker on the dev machine, and Render's build logs need the owner's dashboard; a GitHub Actions job builds the same Dockerfile and runs the demo scan in the container, so a broken pin or missing tool fails there first.
- **2026-10-21 — PDF is the browser's print, not a server renderer.** A headless Chrome on a 512 MB instance is a non-starter; a print stylesheet (light tokens, every card open) gives a clean PDF from any browser.
- **2026-10-21 — Real-repo validation stays out of the repo.** The 5 public repos used for calibration aren't named in this file or committed fixtures: one exposes a third party's live-looking credential, and pointing at it would do harm.

---

## 12. Acceptance criteria & demo script

**The sample repo** (`sample-repo/`) is a deliberately insecure app containing at minimum:
- a hardcoded API key
- `dangerouslySetInnerHTML` on user-controlled input
- SQL built by string concatenation
- `CORS: *`

**Demo must pass:**
- [ ] Clicking "Try a demo repo" runs a full scan in **under ~60 seconds**
- [x] The report surfaces **at least** the exposed key, the XSS sink, and the SQL injection
- [x] Each of those three has a plain-English explanation and a working fix diff
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
GROQ_MODEL=openai/gpt-oss-120b    # groq model id; verify at console.groq.com/docs/models
OLLAMA_URL=http://localhost:11434 # required if local
PORT=10000                        # Render injects this; the app MUST bind 0.0.0.0:$PORT
ALLOWED_ORIGINS=http://localhost:5173   # prod: https://vibeguard.web.app,https://vibeguard.firebaseapp.com
VITE_API_BASE_URL=                # frontend build-time; the Render URL in prod, empty in dev (Vite proxy)
```
On Render, set `GROQ_API_KEY`, `GROQ_MODEL`, `TRIAGE_BACKEND`, and `ALLOWED_ORIGINS` as service env vars — never baked into the image. Locally they live in the gitignored `backend/.env`. Full deploy details in §22.

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

**The constraints that drive everything here:** the deliverable is a single link that must work when a judge clicks it, with none of the developer's machines running, **and no payment method is available**. A local tunnel (ngrok/cloudflared) does not qualify. Cloud Run (+ Firebase rewrite) needs a card, and Hugging Face free Docker Spaces became PRO-only in July 2026, so both are out. **Target: Render free (backend) + Firebase Hosting Spark (frontend)** — both card-free.

### Topology

```
 browser ──► https://vibeguard.web.app        Firebase Hosting (Spark, free)   React build only
    │
    └─── fetch(VITE_API_BASE_URL + "/scan…") ──► https://<svc>.onrender.com   Render free web service
                                                  (Docker: FastAPI + scanners, API only)
```

- **Backend → Render free web service**, one Docker container: FastAPI + scanners. **API only** — it does not serve the React build.
- **Frontend → Firebase Hosting (Spark)**: the React build, giving the clean `https://vibeguard.web.app` link we submit. `firebase.json` has only the SPA fallback rewrite — Spark can't proxy to Render.
- **Cross-origin API calls.** The React app calls the Render backend over HTTPS using the build-time env var `VITE_API_BASE_URL` (the `…onrender.com` URL). The backend enables CORS for the Firebase origins only, via `ALLOWED_ORIGINS` (default dev value `http://localhost:5173`). Never `*` — VibeGuard would flag itself.

```json
// firebase.json
{ "hosting": {
    "public": "frontend/dist",
    "rewrites": [ { "source": "**", "destination": "/index.html" } ]
}}
```

### Building around Render free limits (512 MB RAM, 0.1 CPU)

- **Trivy is dropped.** It's the memory hog and needs a large DB. **njsscan stays out of the image too**: ~10 CPU-seconds per scan (≈100 s at 0.1 CPU) for zero findings on five real TypeScript apps; its one unique demo finding (wildcard CORS) is Phase 4's `vibe.cors-wildcard`. The container ships **gitleaks + trufflehog + osv-scanner + lockfile-lint + retire.js + semgrep + ast-grep + bandit + zizmor**; measured peak memory per scanner is 43–228 MB. Scanner modules stay fail-soft, so anything not installed is skipped and noted in the report.
- **Scanners run one at a time**, never in parallel, and only **one scan runs at a time** (up to 8 more wait; beyond that, a 429). Peak memory ≈ the single biggest scanner, not the sum.
- **Semgrep rules are pre-downloaded into the image** (no registry fetch per scan) and trimmed to the languages the target stack uses, because rule loading dominates semgrep's time at 0.1 CPU. Measure the demo scan on the deployed service; the < 60 s target is the budget.
- **Keep the 50 MB repo cap** — the filesystem is ephemeral and shares the 512 MB.
- **Spin-down after 15 min idle, ~1 min to wake.** Firebase serves the UI instantly; on load it pings `/health` and shows a "Waking the scanner…" state until the API answers. Warm it right before judging. 750 free instance-hours/month covers one service running all month, so an external uptime ping during the judging window is an option.
- **Ephemeral filesystem.** SQLite lives on local disk and reports vanish on spin-down/redeploy. Acceptable: we never persist user code anyway.
- **`PORT`.** Render injects `PORT` (default `10000`); the app must bind `0.0.0.0:$PORT`.

### Dockerfile (API only)

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates
# pip: semgrep, bandit, zizmor (binary wheel), ast-grep-cli (binary wheel)
# pinned release binaries: gitleaks, trufflehog, osv-scanner
# node (already needed for retire.js): npm i -g retire lockfile-lint
# njsscan is left out (CPU, see above)
# semgrep rule packs downloaded at BUILD time into rules/
WORKDIR /app
COPY backend/ .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["sh","-c","uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}"]
```
*(Pin exact versions/URLs for every scanner.)*

### Deploy

1. Push the repo to GitHub.
2. **Render:** New → Blueprint (`render.yaml`, plan `free`, runtime `docker`). Set `GROQ_API_KEY` (secret), `GROQ_MODEL`, `TRIAGE_BACKEND=groq`, `ALLOWED_ORIGINS=https://vibeguard.web.app,https://vibeguard.firebaseapp.com`.
3. **Firebase:** `cd frontend && VITE_API_BASE_URL=https://<svc>.onrender.com npm run build`, then `firebase deploy --only hosting`.
4. Open `https://vibeguard.web.app` from a phone (not the dev machine) and run the demo scan.

### Env on Render
Set `GROQ_API_KEY`, `GROQ_MODEL`, `TRIAGE_BACKEND`, and `ALLOWED_ORIGINS` as service env vars — never baked into the image. `VITE_API_BASE_URL` is a frontend **build-time** var (it's a public URL, not a secret).

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

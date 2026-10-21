# VibeGuard

Security scanner for apps built with AI tools (Lovable, Bolt, v0, Replit, Cursor). Submit pasted code, a `.zip`, or a public GitHub URL and get a plain-English report of what's exposed and how to fix it. VibeGuard only reads your code; it never modifies it.

The build plan and progress log live in [VibeGuard.md](VibeGuard.md).

## Run locally

Backend (Python 3.11+; [uv](https://docs.astral.sh/uv/) recommended):

```sh
cd backend
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/uvicorn main:app --reload --env-file .env   # http://127.0.0.1:8000
```

Frontend (Node 20+), in a second terminal:

```sh
cd frontend
npm install
npm run dev                                 # http://localhost:5173, proxies the API to :8000
```

## Scanners

Each scanner is optional. A missing binary is skipped and noted in the report.

```sh
uv tool install --python 3.12 semgrep
uv tool install --python 3.12 bandit
uv tool install --python 3.12 njsscan       # separate tool env: njsscan pins its own semgrep (local only, not deployed)
brew install gitleaks osv-scanner trufflehog zizmor ast-grep
npm install -g retire lockfile-lint
```

Scanners with nothing to check are marked "not needed" (bandit without Python files, zizmor without GitHub workflows, lockfile-lint without an npm or yarn v1 lockfile). trufflehog only runs when the user ticks "Test any keys we find": it sends each key it recognises to its provider once to see if it's live.

`uv tool` puts binaries in `~/.local/bin`; make sure it's on the `PATH` the backend runs with.

Optional but faster: cache the Semgrep rule packs (`p/default` + `p/owasp-top-ten`, filtered to JS/TS/Python/config languages) so scans don't download them every time:

```sh
cd backend && .venv/bin/python rules/fetch_registry.py   # writes rules/registry.json (gitignored)
```

## VibeGuard rules

Our own checks for mistakes AI app builders make (VibeGuard.md §7), in `backend/rules/` and `backend/scanners/custom_rules.py`:
semgrep taint rules (`rules/vibe-coded.yml`), ast-grep structural rules (`rules/ast-grep/rules/`), and Python checks for env files,
Supabase migrations (RLS, roles, RPC functions, storage), Firebase rules, rate limits and app-wide auth. 23 rules, 59 variants;
every rule's report text (title, severity, fix, re-prompt) is in `CATALOG`.

## Checks

```sh
cd backend && PATH="$HOME/.local/bin:$PATH" .venv/bin/python test_vibeguard.py
```

Covers ingestion safety (zip traversal, size caps, cleanup), dedupe, secret classification and masking, dependency tiers across npm/pnpm/yarn lockfiles, every VibeGuard rule against a crafted positive and negative, the Supabase migration reader, and runs every installed scanner against `sample-repo/`, whose full expected report is pinned in the test.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `TRIAGE_BACKEND` | `groq` | `groq`, `local` (Ollama) or `off` |
| `GROQ_API_KEY` | — | required for `groq` (`LLM_API_KEY` also accepted) |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | see console.groq.com/docs/models |
| `OLLAMA_URL` | `http://localhost:11434` | for `local` |
| `OLLAMA_MODEL` | `gemma3:4b` | for `local` |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | comma-separated origins allowed to call the API (CORS) |
| `PORT` | `10000` | container only (Render injects it) |

Without an LLM key the scan still runs; findings use the built-in explanations and fixes, and the report lists the AI review as not checked.

The AI review only sees findings a rule couldn't settle ("Needs review", generic scanner rules, generic secrets), never proven ones. It gets the code around each one with secrets masked, must cite the line that decides its verdict (otherwise it counts as "unsure"), can move severity one level, and its fixes are kept only if the lines they remove exist. What it dismisses stays visible under "filtered out", with its reason.

## Reports

The report opens with the grade, a one-line verdict and the three findings that could hurt most, then groups findings by area (keys and secrets, database and auth setup, your code, dependencies). Each card has the impact in plain English, the evidence, a suggested fix and a prompt to paste back into your AI builder, both with copy buttons. Export with the buttons under the grade, or directly:

- `GET /scan/{id}/report.md`: Markdown, for people
- `GET /scan/{id}/report.sarif`: SARIF 2.1.0, for GitHub code scanning (`gh api` upload or `github/codeql-action/upload-sarif`); filtered findings are included as suppressed, with the reason
- "Save as PDF" prints the page with a light theme and every card expanded

## Deploy (card-free)

Full step-by-step guide, with checks, troubleshooting and a demo script: [DEPLOY.md](DEPLOY.md).

The API runs on Render's free plan from the `Dockerfile` (pinned scanners, semgrep rules baked in, unprivileged user); the UI is static on Firebase Hosting. The `image` workflow builds the same image on every push and runs the demo scan inside it.

1. Push to GitHub. On Render: **New → Blueprint**, pick the repo (`render.yaml`), then set `GROQ_API_KEY` and `ALLOWED_ORIGINS` (`https://vibeguard-scan.web.app,https://vibeguard-scan.firebaseapp.com`).
2. Build and deploy the UI against the Render URL:
   ```bash
   cd frontend && VITE_API_BASE_URL=https://<service>.onrender.com npm run build && cd ..
   firebase deploy --only hosting
   ```
3. Open the site from a phone and run the demo. The free API sleeps after 15 idle minutes; the page says "Waking the scanner" while it starts (about a minute), so open it once before you show it.

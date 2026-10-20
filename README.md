# VibeGuard

Security scanner for apps built with AI tools (Lovable, Bolt, v0, Replit, Cursor). Submit pasted code, a `.zip`, or a public GitHub URL and get a plain-English report of what's exposed and how to fix it. VibeGuard only reads your code; it never modifies it.

The build plan and progress log live in [VibeGuard.md](VibeGuard.md).

## Run locally

Backend (Python 3.11+; [uv](https://docs.astral.sh/uv/) recommended):

```sh
cd backend
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/uvicorn main:app --reload        # http://127.0.0.1:8000
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
uv tool install --python 3.12 njsscan       # separate tool env: njsscan pins its own semgrep
brew install gitleaks osv-scanner trivy
npm install -g retire
```

`uv tool` puts binaries in `~/.local/bin`; make sure it's on the `PATH` the backend runs with.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `TRIAGE_BACKEND` | `groq` | `groq` or `local` |
| `GROQ_API_KEY` | — | required for `groq` (`LLM_API_KEY` also accepted) |
| `GROQ_MODEL` | `openai/gpt-oss-20b` | see console.groq.com/docs/models |
| `OLLAMA_URL` | `http://localhost:11434` | for `local` |
| `PORT` | `8080` | container only |

Without an LLM key the scan still runs; findings use the built-in explanations and fixes.

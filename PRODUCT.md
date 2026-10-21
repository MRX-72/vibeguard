# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Non-security builders: founders and makers who built an app with AI tools (Lovable, Bolt, Cursor, Replit) and want to know what's exposed before they launch or share it. They can read code a little, don't know security vocabulary, and act by pasting instructions back into their AI builder.

## Product Purpose
Scan an AI-built app's code (pasted file, zip, or public GitHub repo) and return a plain-English report: what a stranger could do, on which exact line, how bad it is, and the fix plus a prompt to paste back into the builder. Success: the builder fixes the real problems before launch, and trusts the report because it doesn't cry wolf.

## Positioning
Knows vibe-coded stacks the way generic scanners don't: Supabase Row-Level Security and policies, SECURITY DEFINER functions, storage buckets, Firebase rules, keys in public env vars (VITE_, NEXT_PUBLIC_), service-role keys in browser code, unsigned payment webhooks. Every finding is explained in plain English with a paste-back prompt for the AI builder.

## Operating Context
A builder opens the site with their project in another tab, pastes a file, drops a zip or links a public repo, waits about a minute, then works through the report top-down: grade and verdict, the three worst items, then each finding with its fix. Reports export as Markdown, SARIF and PDF. The hosted API runs on a free server that sleeps when idle (about a minute to wake).

## Capabilities and Constraints
- Inputs: paste (with optional file name), zip up to 50 MB, public GitHub repo; a bundled demo app (`sample-repo/`).
- Scanners: gitleaks, trufflehog (opt-in live key test), osv-scanner, lockfile-lint, retire.js, semgrep, bandit, zizmor, ast-grep, plus VibeGuard's own rules; an AI review (Groq) double-checks uncertain findings with secrets masked.
- Output: grade A–F, risk score 0–100, findings by severity (Critical, High, Medium, Low) with confidence (Confirmed reachable, Likely, Needs review), "Already right" checks.
- Code is deleted when the scan ends; reports stay until the server restarts; scan history is per browser (no accounts).
- Frontend: React 19, Vite, Tailwind 4 (static on Firebase Hosting); API: FastAPI on Render free.

## Brand Commitments
- Name: VibeGuard (no "Beta").
- Voice: plain English, direct, specific to the line of code; no security jargon without an explanation.

## Evidence on Hand
- The demo app's real report (grade F, ~35 findings) and five anonymized real-app calibration runs (never named publicly).
- No customers, testimonials, logos, metrics or press exist: do not fabricate any.

## Product Principles
1. Fewer, truer findings: a report that cries wolf once loses the user.
2. Point at the line: every claim is tied to code the user can see.
3. Plain English first, detail on demand.
4. Close the loop with the AI builder: every fix comes with a prompt to paste back.
5. Never keep the user's code, never show their secrets.

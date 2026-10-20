import re
from pathlib import Path

from models import Finding

from .base import Scanner, ScannerError, cwe_ids, humanize, lower, read_json, rel, snippet

RULES = Path(__file__).resolve().parent.parent / "rules"
REGISTRY = ["p/default", "p/owasp-top-ten"]  # fetched live unless rules/registry.json was downloaded
SEV = {"CRITICAL": "Critical", "ERROR": "High", "HIGH": "High", "WARNING": "Medium", "MEDIUM": "Medium", "INFO": "Low", "LOW": "Low"}
# Code that never ships to users. Secrets are still scanned there (gitleaks); static analysis isn't, which also
# cuts semgrep's time on real repos by ~40%.
EXCLUDE = ["*.test.*", "*.spec.*", "__tests__", "__mocks__", "test", "tests", "e2e", "cypress", "playwright", "docs",
           "*.md", "*.lock", "package-lock.json", "*.min.js", "*.map", "dist", "build", ".next", "out", "coverage",
           "storybook-static", "node_modules"]

# Registry rules that are noise or hygiene for this audience, decided once here instead of on every report.
HYGIENE = "Supply-chain hygiene for your build pipeline, not a vulnerability in your app."
POLICY = {
    "unsafe-formatstring": ("noise", "JavaScript has no format-string exploits like C does: a variable in console.log only changes how the log line looks."),
    "github-actions-mutable-action-tag": ("hygiene", HYGIENE + " Pinning actions to a commit SHA protects CI from a hijacked action release."),
    "bun-missing-minimum-release-age": ("hygiene", HYGIENE + " A minimum release age protects you from freshly published malicious versions."),
    "npm-missing-minimum-release-age": ("hygiene", HYGIENE + " A minimum release age protects you from freshly published malicious versions."),
    "pnpm-minimum-release-age": ("hygiene", HYGIENE + " A minimum release age protects you from freshly published malicious versions."),
    "renovate-missing-minimum-release-age": ("hygiene", HYGIENE + " A minimum release age protects you from freshly published malicious versions."),
    "express-check-csurf-middleware-usage": ("cookies", "This app never sets or reads cookies, so cross-site request forgery doesn't apply: "
                                             "browsers attach cookies to cross-site requests automatically, but never an Authorization header."),
}
# GitHub Actions contexts outsiders control (issue titles, PR branches, comments…). Workflow inputs aren't among
# them: only people with write access can dispatch a workflow.
UNTRUSTED_CONTEXT = re.compile(r"github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|pages|commits|head_commit|workflow_run)|head_ref)")
COOKIES = re.compile(r"express-session|cookie-session|cookie-parser|\bres\.cookie\(|[Ss]et-[Cc]ookie|\bcookies\(\)")


class Semgrep(Scanner):
    name = binary = "semgrep"
    label = "Static analysis"
    timeout = 240

    def configs(self):
        cached = RULES / "registry.json"
        return [str(cached)] if cached.exists() else REGISTRY

    def run(self, root, work):
        out = work / "semgrep.json"
        # --jobs 1: in a container semgrep sees the host's CPU count and would fork a worker per core (OOM on 512 MB)
        args = [self.binary, "scan", "--json", "--output", str(out), "--metrics=off", "--quiet", "--disable-version-check",
                "--jobs", "1", "--max-target-bytes", "1000000", "--timeout", "10"]
        for pattern in EXCLUDE:
            args += ["--exclude", pattern]
        for config in self.configs():
            args += ["--config", config]
        r = self.exec(args + [str(root)], ok=(0, 1, 2))
        data = read_json(out, {})
        if r.returncode == 2 and not data.get("results"):
            first = next((e.get("message", "") for e in data.get("errors", [])), "")
            raise ScannerError(f"could not run: {first[:120]}" if first else "could not run")
        files = len(data.get("paths", {}).get("scanned", []))
        self.checked = f"{files:,} source file{'s' * (files != 1)}"
        uses_cookies = _uses_cookies(root)
        return [self._finding(root, r, uses_cookies) for r in data.get("results", [])]

    def _finding(self, root, r, uses_cookies):
        rule, extra = r["check_id"], r["extra"]
        meta = extra.get("metadata", {})
        file, line, end = rel(root, r["path"]), r["start"]["line"], r["end"]["line"]
        code, start = snippet(root, file, line, end)

        rated = SEV.get(extra.get("severity", "").upper(), "Medium")
        likelihood, impact, conf = (str(meta.get(k, "")).upper() for k in ("likelihood", "impact", "confidence"))
        audit = "audit" in (meta.get("subcategory") or [])
        sev, reason = rated, f"The Semgrep rule rates this {rated.lower()}"
        if (likelihood, impact) != ("", ""):
            reason += f" (likelihood {likelihood.lower() or 'unrated'}, impact {impact.lower() or 'unrated'})"
        if sev == "High" and likelihood == impact == "HIGH" and conf != "LOW":
            sev, reason = "Critical", reason + "; high likelihood and high impact make it critical"
        if audit and conf == "LOW" and sev != "Low":
            sev, reason = lower(sev), reason + "; it's a broad, low-confidence audit rule, so we rate it a level lower"

        f = Finding(
            source=self.name, severity=sev, title=humanize(rule),
            kind="secret" if rule.startswith("generic.secrets.") or "secrets" in (meta.get("technology") or []) else "code",
            file=file, line=line, end_line=end, code_snippet=code, snippet_start=start,
            raw_rule_id=rule, cwe=cwe_ids(meta.get("cwe")), explanation=re.sub(r"\s+", " ", extra.get("message", "")).strip(),
            severity_reason=reason + ".",
            confidence="Needs review" if conf == "LOW" or audit else "Likely",
            refs=[u for u in (meta.get("references") or []) + [meta.get("source")] if isinstance(u, str) and u.startswith("http")][:4],
        )
        verdict, why = POLICY.get(rule.split(".")[-1], (None, ""))
        if verdict == "noise" or (verdict == "cookies" and not uses_cookies):
            f.is_false_positive, f.triage_note = True, why
        elif verdict == "hygiene":
            f.severity, f.kind, f.triage_note, f.severity_reason = "Low", "config", why, why
        elif rule.endswith("run-shell-injection"):
            flagged = "\n".join(code.splitlines()[line - start : end - start + 1])
            if not UNTRUSTED_CONTEXT.search(flagged):
                f.severity, f.confidence, f.kind = "Low", "Needs review", "config"
                f.triage_note = ("The ${{ }} expression only uses values that people with write access control (like workflow inputs), "
                                 "not text from issues or pull requests, so outsiders can't inject commands. Passing it through an env: variable is still tidier.")
        return f


def _uses_cookies(root):
    for path in root.rglob("*"):
        if path.suffix in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"} and "node_modules" not in path.parts and path.is_file():
            try:
                if COOKIES.search(path.read_text(errors="replace")):
                    return True
            except OSError:
                continue
    return False

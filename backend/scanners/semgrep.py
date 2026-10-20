import json
import re
from pathlib import Path

from models import Finding

from .base import Scanner, ScannerError, cwe_ids, humanize, lower, rel, snippet

RULES = Path(__file__).resolve().parent.parent / "rules"
REGISTRY = ["p/default", "p/owasp-top-ten"]  # fetched live unless rules/registry.json was downloaded
SEV = {"CRITICAL": "Critical", "ERROR": "High", "HIGH": "High", "WARNING": "Medium", "MEDIUM": "Medium", "INFO": "Low", "LOW": "Low"}


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
        for config in self.configs():
            args += ["--config", config]
        r = self.exec(args + [str(root)], ok=(0, 1, 2))
        data = json.loads(out.read_text()) if out.exists() and out.stat().st_size else {}
        if r.returncode == 2 and not data.get("results"):
            first = next((e.get("message", "") for e in data.get("errors", [])), "")
            raise ScannerError(f"could not run: {first[:120]}" if first else "could not run")
        return [self._finding(root, r) for r in data.get("results", [])]

    def _finding(self, root, r):
        rule, extra = r["check_id"], r["extra"]
        meta = extra.get("metadata", {})
        file, line, end = rel(root, r["path"]), r["start"]["line"], r["end"]["line"]
        cwe = cwe_ids(meta.get("cwe"))

        sev = SEV.get(extra.get("severity", "").upper(), "Medium")
        likelihood, impact, conf = (str(meta.get(k, "")).upper() for k in ("likelihood", "impact", "confidence"))
        if sev == "High" and likelihood == impact == "HIGH" and conf != "LOW":
            sev = "Critical"
        audit = "audit" in (meta.get("subcategory") or [])
        if audit and conf == "LOW" and sev != "Low":
            sev = lower(sev)

        reason = f"Semgrep rates impact {impact.lower() or 'unrated'} and likelihood {likelihood.lower() or 'unrated'}"
        return Finding(
            source=self.name, severity=sev, title=humanize(rule),
            kind="secret" if rule.startswith("generic.secrets.") or "secrets" in (meta.get("technology") or []) else "code",
            file=file, line=line, end_line=end, code_snippet=snippet(root, file, line, end),
            raw_rule_id=rule, cwe=cwe, explanation=re.sub(r"\s+", " ", extra.get("message", "")).strip(),
            severity_reason=reason + (", and this is a broad audit rule." if audit else "."),
            confidence="Needs review" if conf == "LOW" or audit else "Likely",
            refs=[u for u in (meta.get("references") or []) + [meta.get("source")] if isinstance(u, str) and u.startswith("http")][:4],
        )


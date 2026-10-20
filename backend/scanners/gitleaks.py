import json

from models import Finding

from .base import Scanner, classify_secret, mask_in, rel, snippet


class Gitleaks(Scanner):
    name = binary = "gitleaks"
    label = "Leaked secrets"

    def run(self, root, work):
        out = work / "gitleaks.json"
        # report goes to the sandbox, never stdout/logs: it contains the raw secrets
        self.exec([self.binary, "dir", str(root), "--report-format", "json", "--report-path", str(out),
                   "--exit-code", "0", "--no-banner", "--log-level", "error", "--max-target-megabytes", "5"])
        return [self._finding(root, r) for r in json.loads(out.read_text() or "[]")]

    def _finding(self, root, r):
        file, secret = rel(root, r["File"]), r.get("Secret") or ""
        info = classify_secret(secret, file, r["RuleID"])
        code = snippet(root, file, r["StartLine"], r["EndLine"])
        f = Finding(
            source=self.name, kind="secret", severity=info["severity"], title=info["title"],
            file=file, line=r["StartLine"], end_line=r["EndLine"],
            code_snippet=mask_in(code, secret),
            raw_rule_id=r["RuleID"], cwe=["CWE-798"], money_risk=info["money_risk"],
            is_false_positive=info["false_positive"], triage_note=info["note"], impact=info["impact"],
            explanation=r.get("Description", ""),
            severity_reason=info["reason"] or "A working credential in source code can be copied by anyone who sees the code.",
        )
        f._secret = secret or None
        return f

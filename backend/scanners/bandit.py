"""Python security checks via bandit, for apps with a Python backend (FastAPI, Flask, Django, scripts)."""

from models import Finding

from .base import Scanner, has_files, read_json, rel, snippet

SEV = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
# Tests that are mostly noise for web apps, measured on a real 118-file Python app (all 13 of its hits were these):
# assert (B101), binding 0.0.0.0 (B104, normal in containers), "password"-named variables holding URLs or 'db' (B105-107;
# gitleaks finds real secrets), temp paths (B108), try/except/pass (B110, B112), requests without timeout (B113),
# random in simulations (B311), and importing or calling subprocess without a shell (B404, B603, B607).
SKIP = "B101,B104,B105,B106,B107,B108,B110,B112,B113,B311,B404,B603,B607"
# Bandit CWEs that don't match what the test finds (B201 flask debug=True is filed as code injection), so the
# report titles them right and they merge with semgrep's findings for the same line.
CWE = {"B201": "CWE-489", "B506": "CWE-502"}
EXCLUDE = "*/tests/*,*/test/*,*/test_*.py,*_test.py,*/.venv/*,*/venv/*,*/site-packages/*,*/node_modules/*"


class Bandit(Scanner):
    name = binary = "bandit"
    label = "Python code checks"

    def skip(self, root):
        return super().skip(root) if has_files(root, "*.py") else ("na", "no Python files")

    def run(self, root, work):
        out = work / "bandit.json"
        # exit 1 = issues found
        self.exec([self.binary, "-r", str(root), "-f", "json", "-q", "-o", str(out), "-s", SKIP, "-x", EXCLUDE], ok=(0, 1))
        data = read_json(out, {})
        n = len([k for k in data.get("metrics", {}) if k != "_totals"])
        self.checked = f"{n:,} Python file{'s' * (n != 1)}"
        return [self._finding(root, r) for r in data.get("results", [])]

    def _finding(self, root, r):
        file, lines = rel(root, r["filename"]), r.get("line_range") or [r["line_number"]]
        sev, conf = SEV.get(r["issue_severity"], "Medium"), r["issue_confidence"].lower()
        code, start = snippet(root, file, lines[0], lines[-1])
        filed = (r.get("issue_cwe") or {}).get("id")
        cwe = [CWE[r["test_id"]]] if r["test_id"] in CWE else [f"CWE-{filed}"] if filed else []
        return Finding(
            source=self.name, severity=sev, title=r["test_name"].replace("_", " ").capitalize(),
            file=file, line=lines[0], end_line=lines[-1], code_snippet=code, snippet_start=start,
            raw_rule_id=f"bandit.{r['test_id']}", cwe=cwe, explanation=r["issue_text"],
            severity_reason=f"Bandit rates this {sev.lower()} with {conf} confidence.",
            confidence="Needs review" if conf == "low" else "Likely",
            refs=[r["more_info"]] if r.get("more_info") else [],
        )

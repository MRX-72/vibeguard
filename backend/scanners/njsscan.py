import json

from models import Finding

from .base import Scanner, cwe_ids, humanize, rel, snippet

SEV = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}


class Njsscan(Scanner):
    name = binary = "njsscan"
    label = "Node.js analysis"

    def run(self, root, work):
        out = work / "njsscan.json"
        self.exec([self.binary, "--json", "-o", str(out), str(root)], ok=(0, 1))
        data = json.loads(out.read_text() or "{}")
        return [
            self._finding(root, rule, spec["metadata"], hit)
            for section in ("nodejs", "templates")
            for rule, spec in (data.get(section) or {}).items()
            for hit in spec.get("files", [])
        ]

    def _finding(self, root, rule, meta, hit):
        file = rel(root, hit["file_path"])
        line, end = (hit.get("match_lines") or [0, 0])[:2]
        sev = SEV.get(meta.get("severity", "").upper(), "Medium")
        return Finding(
            source=self.name, severity=sev, title=humanize(rule), file=file, line=line, end_line=end,
            code_snippet=snippet(root, file, line, end), raw_rule_id=rule, cwe=cwe_ids(meta.get("cwe")),
            explanation=meta.get("description", ""),
            severity_reason=f"njsscan rates this {meta.get('severity', 'WARNING').lower()}.",
            confidence="Likely" if sev == "High" else "Needs review",
        )

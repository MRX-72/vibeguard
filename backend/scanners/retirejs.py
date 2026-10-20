import json

from models import Finding

from .base import Scanner, rel, worst
from .versions import newest

SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


class RetireJs(Scanner):
    """Old versions of front-end libraries that were copied into the repo (vendored), e.g. jquery-3.4.1.min.js."""

    name = "retire.js"
    binary = "retire"
    label = "Vendored JS libraries"

    def run(self, root, work):
        out = work / "retire.json"
        self.exec([self.binary, "--outputformat", "json", "--outputpath", str(out), "--path", str(root), "--exitwith", "0"])
        data = json.loads(out.read_text() or "{}")
        return [self._finding(root, item["file"], res) for item in data.get("data", []) for res in item.get("results", []) if res.get("vulnerabilities")]

    def _finding(self, root, path, res):
        name, version, vulns = res["component"], res["version"], res["vulnerabilities"]
        ids = [(v["identifiers"].get("CVE") or [v["identifiers"].get("githubID") or v["identifiers"].get("issue") or "advisory"])[0] for v in vulns]
        fix = newest(v.get("below") for v in vulns)
        sev = worst(*(SEV.get(v.get("severity"), "Medium") for v in vulns))
        n = len(vulns)
        return Finding(
            source=self.name, kind="dependency", severity=sev, package=f"{name}@{version}",
            title=f"{name} {version} has {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            file=rel(root, path), line=0, raw_rule_id=ids[0],
            cwe=sorted({c for v in vulns for c in v.get("cwe", [])}),
            evidence=[f"{i} ({SEV.get(v.get('severity'), 'Medium')}): {v['identifiers'].get('summary', '').strip()}"[:240] for i, v in zip(ids, vulns)],
            refs=[u for v in vulns for u in v.get("info", [])][:4],
            explanation=f"This file is a copy of {name} {version}. Published advisories affect this version"
                        + (f"; {fix} fixes {'it' if n == 1 else 'them'}." if fix else "."),
            fix_diff=f"Replace {name} {version} with {fix} or later (download the new file, or install {name} from npm)." if fix else "",
            reprompt=f"Replace the vendored {name} {version} file with {name} {fix or 'latest'} and check that pages using it still work.",
            severity_reason=f"Highest advisory severity for this version is {sev.lower()}.",
            confidence="Likely",
        )

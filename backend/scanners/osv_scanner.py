import json
import re
from pathlib import Path

from models import SEVERITIES, Finding

from .base import Scanner, cwe_ids, from_cvss, rel, worst
from .versions import fixed_in, newest

# GitHub advisory severity words, used when there's no CVSS score
GHSA_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
# where a dependency is declared, per lockfile type, so the fix can point at the line to change
MANIFESTS = ["package.json", "requirements.txt", "pyproject.toml", "Pipfile"]


class OsvScanner(Scanner):
    name = binary = "osv-scanner"
    label = "Vulnerable dependencies"

    def run(self, root, work):
        # exit 1 = vulnerabilities found, 128 = no lockfiles to scan
        r = self.exec([self.binary, "scan", "source", "-r", "--format", "json", str(root)], ok=(0, 1, 128))
        if r.returncode == 128 or not r.stdout.strip():
            return []
        findings = []
        for result in json.loads(r.stdout).get("results", []):
            lockfile = Path(result["source"]["path"])
            for pkg in result.get("packages", []):
                if pkg.get("vulnerabilities"):
                    findings.append(self._finding(root, lockfile, pkg))
        return findings

    def _finding(self, root, lockfile, pkg):
        name, version = pkg["package"]["name"], pkg["package"]["version"]
        vulns = {v["id"]: v for v in pkg["vulnerabilities"]}
        issues = []  # one per distinct vulnerability (OSV groups aliases like GHSA + CVE)
        for group in pkg.get("groups") or [{"ids": [i]} for i in vulns]:
            v = next((vulns[i] for i in group["ids"] if i in vulns), None)
            if not v:
                continue
            ids = group.get("aliases") or group["ids"]
            score = group.get("max_severity") or ""
            sev = from_cvss(score) or GHSA_SEV.get(v.get("database_specific", {}).get("severity", "").upper(), "Medium")
            ranges = [rg for a in v.get("affected", []) if a.get("package", {}).get("name") == name for rg in a.get("ranges", [])]
            issues.append({
                "id": next((i for i in ids if i.startswith("CVE-")), group["ids"][0]),
                "osv_id": v["id"], "severity": sev, "score": score,
                "summary": (v.get("summary") or v.get("details", "").split("\n")[0]).strip(),
                "cwe": cwe_ids(v.get("database_specific", {}).get("cwe_ids", [])),
                "fixed": fixed_in(version, ranges),
            })
        issues.sort(key=lambda i: (SEVERITIES.index(i["severity"]), -(float(i["score"]) if i["score"] else 0)))
        top, n = issues[0], len(issues)
        fix = newest(i["fixed"] for i in issues)
        unfixed = sum(1 for i in issues if i["fixed"] == "")
        sev = worst(*(i["severity"] for i in issues))

        file, line, code = self._declaration(root, lockfile, name)
        direct = Path(file).name in MANIFESTS
        fix_diff = ""
        if fix and code:
            old = code.strip()
            key, sep, spec = old.partition(":") if direct and file.endswith(".json") else ("", "", old)
            new = old.replace(version, fix, 1) if version in old else (key + sep + re.sub(r"\d[\w.+-]*", fix, spec, count=1) if sep else "")
            if new and new != old:
                fix_diff = f"- {old}\n+ {new}"
        how = (f"Upgrade to {fix} or later." if fix else "No fixed version is published yet.") + (
            f" {unfixed} of these {'has' if unfixed == 1 else 'have'} no fix yet." if fix and unfixed else "")
        if not direct:
            how += f" {name} isn't listed in your manifest, so it comes in through another package: upgrade that package, or pin {name} with an npm \"overrides\" entry."

        return Finding(
            source=self.name, kind="dependency", severity=sev, package=f"{name}@{version}",
            title=f"{name} {version} has {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            file=file, line=line, code_snippet=code, raw_rule_id=top["id"], cwe=top["cwe"],
            severity_reason=(f"Worst issue: {top['id']}" + (f" (CVSS {top['score']})" if top["score"] else f" ({top['severity'].lower()})")
                             + f": {top['summary']}")[:220],
            explanation=f"Your project installs {name} {version}. {n} published security advisor{'y' if n == 1 else 'ies'} affect{'s' if n == 1 else ''} this version. {how}",
            evidence=[f"{i['id']} ({i['severity']}{', CVSS ' + i['score'] if i['score'] else ''}): {i['summary']}"[:240] for i in issues[:8]]
                     + ([f"…and {n - 8} more"] if n > 8 else []),
            refs=[f"https://osv.dev/vulnerability/{i['osv_id']}" for i in issues[:4]],
            fix_diff=fix_diff,
            reprompt=f"Upgrade {name} from {version} to {fix or 'the latest version'} in {Path(file).name if direct else 'package.json (add an override if it is a transitive dependency)'}, "
                     f"regenerate the lockfile, and fix any breaking changes in code that uses {name}.",
            confidence="Likely" if direct else "Needs review",
        )

    @staticmethod
    def _declaration(root, lockfile, name):
        """(file, line, text) where the dependency is declared: the manifest beside the lockfile, else the lockfile."""
        quoted = re.compile(rf'^\s*"{re.escape(name)}"\s*:')
        bare = re.compile(rf"^\s*{re.escape(name)}\s*([=<>~!\[;]|$)", re.I)
        for candidate in [lockfile.parent / m for m in MANIFESTS] + [lockfile]:
            try:
                lines = candidate.read_text(errors="replace").splitlines()
            except OSError:
                continue
            for n, text in enumerate(lines, 1):
                if quoted.match(text) or (candidate.suffix != ".json" and bare.match(text)) or f'"node_modules/{name}"' in text:
                    return rel(root, candidate), n, text.strip()[:240]
        return rel(root, lockfile), 0, ""

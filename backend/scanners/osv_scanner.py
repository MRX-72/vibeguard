import json
import re
from pathlib import Path

from models import SEVERITIES, Finding

from . import npm_deps
from .base import Scanner, ScannerError, cwe_ids, from_cvss, lower, rel, worst
from .versions import fixed_in, newest, vkey

# GitHub advisory severity words, used when there's no CVSS score
GHSA_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
MANIFESTS = ["package.json", "requirements.txt", "pyproject.toml", "Pipfile"]
NPM_LOCKS = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"]
SYNTH = "osv-synth"


class OsvScanner(Scanner):
    """Known vulnerabilities in dependencies, via OSV.dev, sorted into what ships vs. what only builds the app."""

    name = binary = "osv-scanner"
    label = "Vulnerable dependencies"

    def run(self, root, work):
        root = root.resolve()  # tools report resolved paths (/private/var/… on macOS)
        hits = [(lock, pkg, False) for lock, pkg in self._scan(root)]
        synth = (work / SYNTH).resolve()
        if self._synthesize(root, synth):  # package.json with no lockfile: check the declared minimums
            hits += [(root / lock.relative_to(synth), pkg, True) for lock, pkg in self._scan(synth)]
        imports = npm_deps.imported_packages(root)
        projects, grouped = {}, {}
        for lock, pkg, synthetic in hits:
            p = pkg["package"]
            grouped.setdefault((lock.parent, p.get("ecosystem", ""), p["name"]), []).append((lock, pkg, synthetic))

        findings, tooling = [], {}
        for (folder, eco, name), entries in grouped.items():
            issues = _issues(entries)
            if not issues:
                continue
            if eco == "npm":
                if folder not in projects:
                    projects[folder] = npm_deps.Project(folder)
                tier, via = projects[folder].classify(name)
            else:  # PyPI etc.: no dev/runtime split in the manifest formats we read
                tier, via = ("runtime-direct" if Path(_declaration(root, folder, name, entries[0][0])[0]).name in MANIFESTS else "unknown"), None
            if tier == "dev":
                tooling.setdefault(folder, []).append((name, entries, issues))
            else:
                findings.append(self._finding(root, folder, name, entries, issues, tier, via, eco, imports))
        findings += [self._tooling(root, folder, projects.get(folder), items) for folder, items in tooling.items()]
        return findings

    def _scan(self, target):
        # exit 1 = vulnerabilities found, 128 = no lockfiles to scan
        r = self.exec([self.binary, "scan", "source", "-r", "--format", "json", str(target)], ok=(0, 1, 128))
        self.packages = getattr(self, "packages", 0) + sum(int(n) for n in re.findall(r"found (\d+) packages?", r.stderr))
        self.checked = f"{self.packages:,} package{'s' * (self.packages != 1)}" if self.packages else ""
        if r.returncode == 128 or not r.stdout.strip():
            return []
        try:
            data = json.loads(r.stdout)
        except ValueError:
            raise ScannerError("returned unreadable output (is OSV.dev reachable?)") from None
        return [(Path(res["source"]["path"]).resolve(), pkg) for res in data.get("results") or [] for pkg in res.get("packages") or []
                if pkg.get("vulnerabilities")]

    @staticmethod
    def _synthesize(root, out):
        """Write a minimal lockfile, pinned to each declared minimum, for every package.json that has none."""
        made = False
        for manifest in root.rglob("package.json"):
            if "node_modules" in manifest.parts or any((manifest.parent / lock).exists() for lock in NPM_LOCKS):
                continue
            project = npm_deps.Project(manifest.parent)
            pinned = {n: v for n, s in project.direct.items() if (v := npm_deps.min_version(s))}
            if not pinned:
                continue
            target = out / manifest.parent.relative_to(root) / "package-lock.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}} | {
                f"node_modules/{n}": {"version": v} for n, v in pinned.items()}}))
            made = True
        return made

    def _finding(self, root, folder, name, entries, issues, tier, via, eco, imports):
        versions = sorted({pkg["package"]["version"] for _, pkg, _ in entries}, key=vkey)
        synthetic = all(s for _, _, s in entries)
        top, n = issues[0], len(issues)
        sev = worst(*(i["severity"] for i in issues))
        fixes = {v: newest(i["fixed"].get(v) for i in issues) for v in versions}
        unfixed = sum(1 for i in issues if any(i["fixed"].get(v) == "" for v in versions))
        manifest_file, line, code = _declaration(root, folder, name, entries[0][0])
        is_declared = Path(manifest_file).name in MANIFESTS

        notes, confidence, demoted = [], "Likely", ""
        if tier == "runtime-direct" and eco == "npm" and name not in imports:
            sev, confidence, demoted = lower(sev), "Needs review", "your code never imports it"
            notes.append(f"Your code never imports {name}, so these bugs are only reachable if something else loads it. "
                         "If nothing needs it, removing it is the simplest fix.")
        elif tier == "runtime":
            sev, confidence, demoted = lower(sev), "Needs review", f"it's an indirect dependency (through {via})"
            notes.append(f"{name} isn't in your package.json; {via} pulls it in. Whether the vulnerable code runs depends on how {via} uses it.")
        elif tier == "unknown":
            sev, confidence, demoted = lower(sev), "Needs review", "it's an indirect dependency"
            notes.append(f"{name} isn't in your package.json, and we couldn't tell which of your dependencies pulls it in.")
        if synthetic:
            confidence = "Needs review"
            notes.append(f"There's no lockfile, so we checked the oldest version your package.json allows ({versions[0]}). "
                         "Your installed version may be newer: commit a lockfile so scans see exactly what you ship.")

        if all(fixes.values()):
            targets = sorted(set(fixes.values()), key=vkey)
            how = "Upgrade to " + (targets[0] if len(targets) == 1 else ", ".join(f"{fixes[v]} (from {v})" for v in versions)) + " or later."
        elif any(fixes.values()):
            how = "Upgrading fixes some of these; " + f"{unfixed} {'has' if unfixed == 1 else 'have'} no fixed release yet."
        else:
            how = "No fixed release is published yet: watch the advisory, or replace the package."
        fix = fixes[versions[-1]]

        fix_diff = _bump(code, versions[0], fix) if fix and len(versions) == 1 and is_declared else ""

        if tier == "runtime" and via:
            reprompt = (f"Upgrade {via} to its latest version so it pulls in a fixed {name}" + (f" ({fix} or later)" if fix else "")
                        + f". If it still resolves an old {name}, add an npm \"overrides\" entry for {name}. Regenerate the lockfile.")
        else:
            reprompt = (f"Upgrade {name} from {versions[-1]} to {fix or 'the latest version'} in {Path(manifest_file).name}, regenerate the lockfile, "
                        f"and fix any breaking changes in code that uses {name}.")

        return Finding(
            source=self.name, kind="dependency", severity=sev, package=f"{name}@{', '.join(versions)}",
            title=f"{name} {', '.join(versions)} {'have' if len(versions) > 1 else 'has'} {n} known vulnerabilit{'y' if n == 1 else 'ies'}",
            file=manifest_file, line=line, code_snippet=code, snippet_start=line, raw_rule_id=top["id"], cwe=top["cwe"],
            severity_reason=(f"Worst issue: {top['id']}" + (f" (CVSS {top['score']})" if top["score"] else f" ({top['severity'].lower()})")
                             + f": {top['summary']}")[:200].rstrip(".") + "." + (f" Rated a level lower because {demoted}." if demoted else ""),
            explanation=" ".join([f"Your project installs {name} {', '.join(versions)}. {n} published security advisor{'y affects' if n == 1 else 'ies affect'} "
                                  f"{'it' if len(versions) == 1 else 'these versions'}. {how}"] + notes),
            evidence=[_line(i) for i in issues[:8]] + ([f"…and {n - 8} more"] if n > 8 else []),
            refs=[f"https://osv.dev/vulnerability/{i['osv_id']}" for i in issues[:4]],
            fix_diff=fix_diff, reprompt=reprompt, confidence=confidence,
        )

    def _tooling(self, root, folder, project, items):
        """One roll-up for vulnerable packages that only build or test the app: real, but not shipped to users."""
        items.sort(key=lambda it: (SEVERITIES.index(it[2][0]["severity"]), it[0]))
        count = len(items)
        via = (project.dev_via if project else {})
        file, line, code = rel(root, folder / "package.json"), 0, ""
        try:
            for n, text in enumerate((folder / "package.json").read_text(errors="replace").splitlines(), 1):
                if '"devDependencies"' in text:
                    line, code = n, text.strip()
                    break
        except OSError:
            file = rel(root, items[0][1][0][0])
        evidence, tools = [], []
        for name, entries, issues in items:
            versions = ", ".join(sorted({pkg["package"]["version"] for _, pkg, _ in entries}, key=vkey))
            through = via.get(name)
            if through and through not in tools:
                tools.append(through)
            evidence.append(f"{name} {versions}" + (f" (via {through})" if through and through != name else "")
                            + f": {len(issues)} advisor{'y' if len(issues) == 1 else 'ies'}, worst {issues[0]['id']} ({issues[0]['severity'].lower()})")
        named = ", ".join(tools[:5])
        return Finding(
            source=self.name, kind="dependency", severity="Low", confidence="Needs review",
            title=f"{count} build and test tool{'s' if count != 1 else ''} {'have' if count != 1 else 'has'} known vulnerabilities",
            file=file, line=line, code_snippet=code, snippet_start=line, raw_rule_id="dev-dependencies",
            severity_reason="These packages only build or test the app; they don't ship to users.",
            impact="These run on your laptop and in CI while you build, not in the app your users load. Worth updating, not an emergency.",
            explanation=(f"{count} package{'s' if count != 1 else ''} used only for building or testing {'have' if count != 1 else 'has'} published advisories"
                         + (f", pulled in by {named}" if named else "") + ". Updating those tools usually clears them."),
            evidence=evidence[:12] + ([f"…and {count - 12} more"] if count > 12 else []),
            refs=[f"https://osv.dev/vulnerability/{items[0][2][0]['osv_id']}"],
            reprompt=f"Update the project's build and test tooling ({named or 'vite, eslint, vitest'}) to current versions, "
                     "regenerate the lockfile, and make sure the build and tests still pass. Don't change app behaviour.",
        )


def _issues(entries):
    """Distinct vulnerabilities across every installed version, worst first. fixed = {version: fixed version}."""
    issues = {}
    for _, pkg, _ in entries:
        version = pkg["package"]["version"]
        name = pkg["package"]["name"]
        vulns = {v["id"]: v for v in pkg["vulnerabilities"]}
        for group in pkg.get("groups") or [{"ids": [i]} for i in vulns]:
            v = next((vulns[i] for i in group["ids"] if i in vulns), None)
            if not v:
                continue
            ids = group.get("aliases") or group["ids"]
            key = next((i for i in ids if i.startswith("CVE-")), group["ids"][0])
            score = group.get("max_severity") or ""
            ranges = [rg for a in v.get("affected", []) if a.get("package", {}).get("name") == name for rg in a.get("ranges", [])]
            issue = issues.setdefault(key, {
                "id": key, "osv_id": v["id"], "score": score, "fixed": {},
                "severity": from_cvss(score) or GHSA_SEV.get(str(v.get("database_specific", {}).get("severity", "")).upper(), "Medium"),
                "summary": (v.get("summary") or v.get("details", "").split("\n")[0]).strip(),
                "cwe": cwe_ids(v.get("database_specific", {}).get("cwe_ids", [])),
            })
            issue["fixed"][version] = fixed_in(version, ranges)
    return sorted(issues.values(), key=lambda i: (SEVERITIES.index(i["severity"]), -(float(i["score"]) if i["score"] else 0), i["id"]))


def _bump(line, old, new):
    """'"axios": "^0.21.1",' -> a two-line diff to the fixed version (keeps the range operator)."""
    old_line = (line or "").strip()
    if old in old_line:
        new_line = old_line.replace(old, new, 1)
    elif ":" in old_line:  # declared range differs from the installed version, e.g. "^0.21.0" with 0.21.1 installed
        key, spec = old_line.split(":", 1)
        new_line = key + ":" + re.sub(r"\d[\w.+-]*", new, spec, count=1)
    else:
        return ""
    return f"- {old_line}\n+ {new_line}" if new_line != old_line else ""


def _line(i):
    return f"{i['id']} ({i['severity']}{', CVSS ' + i['score'] if i['score'] else ''}): {i['summary']}"[:240]


def _declaration(root, folder, name, lockfile):
    """(file, line, text) where the dependency is declared: the manifest beside the lockfile, else the lockfile."""
    quoted = re.compile(rf'^\s*"{re.escape(name)}"\s*:')
    bare = re.compile(rf"^\s*{re.escape(name)}\s*([=<>~!\[;]|$)", re.I)
    toml = re.compile(rf'^\s*name\s*=\s*"{re.escape(name)}"', re.I)  # uv.lock, poetry.lock
    listed = re.compile(rf'^\s*["\']{re.escape(name)}\s*([<>=!~\[;,]|["\'])', re.I)  # pyproject.toml dependency arrays
    entry = re.compile(rf'^\s*["\']?/?{re.escape(name)}@')  # yarn.lock and pnpm-lock.yaml entries: axios@0.21.1:, "axios@npm:0.21.1":
    for candidate in [folder / m for m in MANIFESTS] + [lockfile]:
        try:
            lines = candidate.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for n, text in enumerate(lines, 1):
            if quoted.match(text) or (candidate.suffix != ".json" and (bare.match(text) or toml.match(text) or listed.match(text) or entry.match(text))) or f'"node_modules/{name}"' in text:
                return rel(root, candidate), n, text.strip()[:240]
    return rel(root, lockfile), 0, ""

"""Lockfile tampering via lockfile-lint: packages fetched from unexpected hosts, over plain HTTP, under another
package's name (lockfile injection), or with weak integrity hashes. Reads npm and yarn lockfiles (pnpm/bun: not supported)."""

import json
import re

from models import Finding

from . import npm_deps
from .base import Scanner, ScannerError, rel

LOCKS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn"}
ISSUE = re.compile(r"detected (?P<what>.+?): (?P<pkg>\S+)\s*\n\s*expected: (?P<expected>.*)\n\s*actual: (?P<actual>.*)")
YARN_ALIAS = re.compile(r'^"?((?:@[^@/\s"]+/)?[^@\s"]+)@npm:((?:@[^@/\s"]+/)?[^@\s"]+)@', re.M)
KIND = {"different name": "name", "host": "host", "protocol": "protocol", "scheme": "protocol", "integrity": "integrity"}
REGEN = "Delete the lockfile and node_modules, run a clean install to regenerate the lockfile from package.json, and review the diff before committing."
# kind -> (severity, confidence, title, impact, fix)
PLAIN = {
    "name": ("High", "Likely", "Lockfile installs a different package than it names",
             "This is how lockfile injection works: the lockfile names one package but downloads another, possibly malicious, one, and every install runs it.",
             REGEN),
    "host": ("Medium", "Needs review", "Packages installed from outside the npm registry",
             "These downloads skip the registry's malware checks, and what's at the URL can change without a new version number.",
             "If you didn't add these on purpose, " + REGEN[0].lower() + REGEN[1:]),
    "protocol": ("Medium", "Likely", "Packages downloaded over plain HTTP",
                 "Anyone on the network between the server and your machine or CI can swap the package for malicious code during install.",
                 "Change http:// to https:// in these resolved URLs, or " + REGEN[0].lower() + REGEN[1:]),
    "integrity": ("Low", "Likely", "Packages checked with a weak hash",
                  "SHA-1 hashes are weak, so a swapped package could still pass the install-time integrity check.",
                  "Regenerate the lockfile with a current npm or yarn, which records sha512 hashes."),
}


class LockfileLint(Scanner):
    name = binary = "lockfile-lint"
    label = "Lockfile integrity"
    timeout = 60

    def skip(self, root):
        return super().skip(root) if self._locks(root) else ("na", "no npm or yarn v1 lockfile")

    def _locks(self, root):
        # yarn 2+ lockfiles (with __metadata) record no download URLs, so there's nothing for lockfile-lint to check
        return sorted(p for name in LOCKS for p in root.rglob(name)
                      if "node_modules" not in p.parts and p.is_file() and "__metadata:" not in p.read_text(errors="replace")[:4096])

    def run(self, root, work):
        findings, locks = [], self._locks(root)
        for lock in locks:
            args = [self.binary, "--path", str(lock), "--type", LOCKS[lock.name], "--validate-https", "--allowed-hosts", "npm", "yarn",
                    "--validate-package-names", "--validate-integrity", "--format", "plain"]
            # npm aliases ("string-width-cjs": "npm:string-width@4") are intended, not lockfile injection
            text = lock.read_text(errors="replace")
            aliases = npm_deps.npm_aliases(_json(lock)) if LOCKS[lock.name] == "npm" else sorted(
                {f"{npm_deps.spec_name(a)}:{npm_deps.spec_name(r)}" for a, r in YARN_ALIAS.findall(text)})
            args += ["--allowed-package-name-aliases", *aliases] if aliases else []
            r = self.exec(args, ok=(0, 1))
            issues = list(ISSUE.finditer(r.stderr + r.stdout))
            if r.returncode == 1 and not issues:
                raise ScannerError(f"couldn't read {rel(root, lock)}")
            grouped = {}
            for m in issues:
                kind = next((k for word, k in KIND.items() if word in m["what"]), "host")
                grouped.setdefault(kind, []).append(m)
            findings += [self._finding(root, lock, text, kind, ms) for kind, ms in grouped.items()]
        self.checked = f"{len(locks)} lockfile{'s' * (len(locks) != 1)}"
        return findings

    def _finding(self, root, lock, text, kind, matches):
        sev, conf, title, impact, fix = PLAIN[kind]
        # lockfile-lint names packages "left-pad@1.3.0-<sha1 of the entry>"
        file, pkgs = rel(root, lock), list(dict.fromkeys(re.sub(r"-[0-9a-f]{40}$", "", m["pkg"]) for m in matches))
        line = _line(text, npm_deps.spec_name(pkgs[0]), LOCKS[lock.name] == "yarn")
        shown = ", ".join(pkgs[:5]) + (f" and {len(pkgs) - 5} more" if len(pkgs) > 5 else "")
        return Finding(
            source=self.name, kind="config", severity=sev, confidence=conf, title=title, impact=impact, fix_diff=fix,
            file=file, line=line, raw_rule_id=f"lockfile-lint.{kind}",
            code_snippet=text.splitlines()[line - 1].strip() if line else "", snippet_start=line,
            explanation=f"{len(pkgs)} package{'s' * (len(pkgs) != 1)} in {file}: {shown}.",
            evidence=[f"{re.sub(r'-[0-9a-f]{40}$', '', m['pkg'])}: expected {m['expected'].strip()}, found {m['actual'].strip()}" for m in matches[:8]],
            severity_reason=f"Checked by lockfile-lint; {sev.lower()} because of what a tampered download can do at install time.",
            reprompt=f"Regenerate {file} from package.json with a clean install, then confirm every resolved URL is https and on the npm registry.",
        )


def _json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _line(text, pkg, yarn):
    pattern = rf'^"?{re.escape(pkg)}@' if yarn else rf'node_modules/{re.escape(pkg)}"'
    m = re.search(pattern, text, re.M)
    return text.count("\n", 0, m.start()) + 1 if m else 0

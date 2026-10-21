"""GitHub Actions security, via zizmor: injection from issue/PR text, dangerous triggers, leaked tokens, unpinned actions.
It knows which ${{ }} contexts outsiders control, so it replaces semgrep's GitHub Actions rules when installed."""

import re

from models import Finding

from .base import HYGIENE, Scanner, ScannerError, has_files, read_json, rel, snippet

SEV = {"High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Low", "Unknown": "Low"}
# Hardening worth doing, but not something an outsider can exploit in a typical app repo: one Low "config" finding each.
HYGIENE_AUDITS = {
    "unpinned-uses", "artipacked", "excessive-permissions", "undocumented-permissions", "anonymous-definition",
    "concurrency-limits", "dependabot-cooldown", "dependabot-execution", "superfluous-actions", "misfeature",
    "obfuscation", "use-trusted-publishing", "stale-action-refs", "ref-version-mismatch", "unpinned-images", "forbidden-uses",
}
# audit -> (plain title, impact, fix)
PLAIN = {
    "template-injection": (
        "Untrusted text can run as a command in CI",
        "Someone who opens an issue or pull request can run commands in your GitHub Actions, steal repository secrets or push code.",
        '- run: echo "${{ github.event.issue.title }}"\n+ env:\n+   TITLE: ${{ github.event.issue.title }}\n+ run: echo "$TITLE"'),
    "dangerous-triggers": (
        "Workflow runs pull request code with your secrets",
        "A pull request from a stranger can run code with your repository's secrets and write access.",
        "- on: pull_request_target\n+ on: pull_request"),
    "unpinned-uses": (
        "GitHub Actions not pinned to a commit",
        "If one of these actions is hijacked, your CI runs the attacker's version with your repository's secrets.",
        "- uses: actions/checkout@v4\n+ uses: actions/checkout@<full commit SHA>  # v4"),
    "artipacked": (
        "Checkout leaves the GitHub token on disk",
        "A later step that uploads the workspace (as an artifact or cache) can leak a token that pushes to your repository.",
        "  - uses: actions/checkout@v4\n+   with:\n+     persist-credentials: false"),
    "excessive-permissions": (
        "CI token has more permissions than it needs",
        "If any step is compromised, the token can do more damage than the job needs it to, like pushing code.",
        "+ permissions:\n+   contents: read"),
    "cache-poisoning": (
        "Release build can use a poisoned cache",
        "Untrusted runs can plant files in the build cache that your release build then picks up.",
        ""),
    "hardcoded-container-credentials": (
        "Container registry password written in the workflow",
        "Anyone who can read the repository can use this registry account.",
        "- password: hunter2\n+ password: ${{ secrets.REGISTRY_PASSWORD }}"),
}


class Zizmor(Scanner):
    name = binary = "zizmor"
    label = "CI workflow checks"
    timeout = 60

    def skip(self, root):
        return super().skip(root) if has_files(root, ".github/workflows/*.y*ml", "action.y*ml") else ("na", "no GitHub workflows")

    def run(self, root, work):
        out = work / "zizmor.json"
        # --offline: no GitHub API calls (and no token needed); online-only audits are skipped
        r = self.exec([self.binary, "--offline", "--format", "json-v1", "--no-progress", "--no-exit-codes", str(root)], ok=(0, 3))
        if r.returncode == 3:  # every workflow file failed to parse
            raise ScannerError("couldn't parse the workflow files")
        out.write_text(r.stdout)
        n = len(list(root.glob(".github/workflows/*.y*ml")))
        self.checked = f"{n} workflow{'s' * (n != 1)}" if n else ""
        return [f for f in (self._finding(root, z) for z in read_json(out, [])) if f]

    def _finding(self, root, z):
        loc = next((loc for loc in z.get("locations", []) if loc["symbolic"].get("kind") == "Primary"), None)
        path = loc and loc["symbolic"]["key"].get("Local", {}).get("verbatim_path")
        if not path or z.get("ignored"):
            return None
        span = loc["concrete"]["location"]
        line, end = span["start_point"]["row"] + 1, span["end_point"]["row"] + 1
        audit, det = z["ident"], z["determinations"]
        sev = SEV.get(det["severity"], "Low")
        title, impact, fix = PLAIN.get(audit, (_sentence(z["desc"]), "", ""))
        if audit == "template-injection" and det["severity"] in ("Informational", "Unknown"):
            # zizmor found no outsider-controlled text in the expression: tidiness, not an injection
            title = "Workflow pastes a ${{ }} expression straight into a shell command"
            impact = "Nothing outsiders control reaches it today. If that changes, the value runs as a command; passing it through env: prevents that."
        file = rel(root, path)
        code, start = snippet(root, file, line, end)
        f = Finding(
            source=self.name, kind="config", severity=sev, title=title, impact=impact, fix_diff=fix,
            file=file, line=line, end_line=end, code_snippet=code, snippet_start=start, raw_rule_id=f"zizmor.{audit}",
            explanation=_sentence(z["desc"]) + (f": {loc['symbolic'].get('annotation')}." if loc["symbolic"].get("annotation") else "."),
            severity_reason=f"zizmor rates this {det['severity'].lower()} with {det['confidence'].lower()} confidence.",
            confidence="Needs review" if det["confidence"] in ("Low", "Unknown") else "Likely",
            refs=[z["url"]] if z.get("url") else [],
        )
        if audit in HYGIENE_AUDITS:
            f.severity, f.severity_reason, f.triage_note = "Low", HYGIENE, HYGIENE
        return f


def _sentence(text):
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:1].upper() + text[1:]

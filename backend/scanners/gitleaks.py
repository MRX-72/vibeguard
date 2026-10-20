import re
from pathlib import Path

from models import Finding

from .base import Scanner, classify_secret, mask_in, read_json, rel, snippet

ENV_READ = {".py": 'os.environ["{var}"]', ".rb": 'ENV["{var}"]', ".go": 'os.Getenv("{var}")'}


class Gitleaks(Scanner):
    name = binary = "gitleaks"
    label = "Leaked secrets"

    def run(self, root, work):
        out = work / "gitleaks.json"
        # report goes to the sandbox, never stdout/logs: it contains the raw secrets
        self.exec([self.binary, "dir", str(root), "--report-format", "json", "--report-path", str(out),
                   "--exit-code", "0", "--no-banner", "--log-level", "error", "--max-target-megabytes", "5"])
        return [self._finding(root, r) for r in read_json(out, [])]

    def _finding(self, root, r):
        file, secret = rel(root, r["File"]), r.get("Secret") or ""
        info = classify_secret(secret, file, r["RuleID"])
        code, start = snippet(root, file, r["StartLine"], r["EndLine"], context=0)
        f = Finding(
            source=self.name, kind="secret", severity=info["severity"], title=info["title"],
            file=file, line=r["StartLine"], end_line=r["EndLine"], code_snippet=mask_in(code, secret), snippet_start=start,
            raw_rule_id=r["RuleID"], cwe=["CWE-798"], money_risk=info["money_risk"],
            is_false_positive=info["false_positive"], triage_note=info["note"], impact=info["impact"],
            severity_reason=info["reason"] or "A working credential in source code can be copied by anyone who sees the code.",
            refs=[info["rotate"]] if info["rotate"] else [],
        )
        f._secret = secret or None
        if not info["false_positive"]:
            dotenv = Path(file).name.startswith(".env")
            what = info["what"]
            f.explanation = (
                f"{what[:1].upper()}{what[1:]} is written in plain text in {file}"
                + (", an environment file that was committed with your code" if dotenv else "")
                + ". Anyone who can read this code can copy it. Deleting the line doesn't make it safe again: the key is already in your "
                "git history and maybe in deployed builds. Rotate it first"
                + (f" at {info['rotate']}" if info["rotate"] else "")
                + ", then load the new one from an environment variable."
            )
            f.fix_diff = _fix(code, secret, file, info["env_var"], dotenv, _ignored(root, file))
            f.reprompt = (f"Remove the hardcoded {what.removeprefix('your ')} from {file}. Read it from a server-side environment variable "
                          f"named {info['env_var']}, and make every call that needs it from backend code (an API route or a Supabase "
                          "Edge Function), never from code that runs in the browser.")
        return f


def _ignored(root, file):
    """Is this file already in .gitignore (i.e. it was committed before the rule was added)?"""
    try:
        rules = (root / ".gitignore").read_text(errors="replace").splitlines()
    except OSError:
        return False
    name = Path(file).name
    return any(r.strip() in (name, "/" + file, file, ".env*", ".env.*" if name != ".env" else ".env", "*.env") for r in rules)


def _fix(code, secret, file, var, dotenv, ignored=False):
    if dotenv and ignored:  # .gitignore already lists it, so the file was committed before that rule existed
        return f"# stop tracking the file (it stays on your machine), then commit\n$ git rm --cached {file}"
    if dotenv:  # the fix is to stop committing the file; the value moves to the host's env settings
        return "# .gitignore\n+ .env\n+ .env.*\n+ !.env.example"
    line = code.splitlines()[0] if code else ""
    quoted = re.search(r"""(["'`])""" + re.escape(secret) + r"\1", line) if secret else None
    if not quoted:
        return ""
    read = ENV_READ.get(Path(file).suffix, "process.env.{var}").format(var=var)
    return f"- {mask_in(line.strip(), secret)}\n+ {line.strip().replace(quoted[0], read)}"

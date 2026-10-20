"""Scanner interface plus the helpers every scanner shares."""

import base64
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import textwrap
from pathlib import Path

from models import SEVERITIES, Finding

log = logging.getLogger("vibeguard")

# Scanners read untrusted code: they never get our API keys, and semgrep never phones home.
ENV = {k: v for k, v in os.environ.items() if k not in {"GROQ_API_KEY", "LLM_API_KEY"}} | {
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
}


class ScannerError(Exception):
    """The scanner ran but failed. The message is shown (briefly) in the report."""


class Scanner:
    name = ""  # shown in the report, e.g. "gitleaks"
    binary = ""
    label = ""  # the user-facing step name
    timeout = 180

    def available(self):
        return shutil.which(self.binary) is not None

    def run(self, root: Path, work: Path) -> list[Finding]:
        """Scan `root`; `work` is a scratch dir for report files (deleted with the sandbox)."""
        raise NotImplementedError

    def exec(self, args, ok=(0,)):
        # own process group, so a timeout also kills the tool's children (semgrep-core, njsscan workers)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV, start_new_session=True)
        try:
            out, err = p.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            raise ScannerError(f"timed out after {self.timeout}s")
        r = subprocess.CompletedProcess(args, p.returncode, out, err)
        if r.returncode not in ok:
            log.warning("%s exited %s: %s", self.name, r.returncode, r.stderr[-800:])
            raise ScannerError(f"exited with code {r.returncode}")
        return r


def rel(root, path):
    p = Path(path)
    try:
        return (p if p.is_absolute() else root / p).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def snippet(root, file, line, end=None, max_lines=8, max_cols=240):
    """The flagged lines, read from disk (semgrep OSS no longer returns them)."""
    if not line:
        return ""
    try:
        lines = (root / file).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    end = min(max(end or line, line), line + max_lines - 1)
    picked = [ln if len(ln) <= max_cols else ln[:max_cols] + "…" for ln in lines[line - 1 : end]]
    return textwrap.dedent("\n".join(picked)).strip("\n")


def humanize(rule_id):
    words = re.split(r"[-_.]+", rule_id.split(".")[-1])
    text = " ".join(words).strip()
    for acronym in ("jwt", "sql", "xss", "csrf", "cors", "api", "url", "html", "xml", "ssrf", "rce", "ssl", "tls", "aws", "gcp", "md5", "sha1"):
        text = re.sub(rf"\b{acronym}\b", acronym.upper(), text, flags=re.I)
    return text[:1].upper() + text[1:]


def cwe_ids(value):
    """'CWE-79: Improper…' or a list of them -> ['CWE-79']."""
    items = value if isinstance(value, list) else [value or ""]
    return sorted({m.upper() for v in items for m in re.findall(r"CWE-\d+", str(v), re.I)}, key=lambda c: int(c[4:]))


def worst(*severities):
    return min(severities, key=SEVERITIES.index)


def lower(severity):
    return SEVERITIES[min(SEVERITIES.index(severity) + 1, len(SEVERITIES) - 1)]


def from_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"


# --- secrets -----------------------------------------------------------------

PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|\$\{.*\}|\{\{.*\}\}|x{4,}|\*{4,}|0{6,}|(your|my|insert|enter|replace)[-_ ].*|.*(example|placeholder|changeme|change[-_]me|dummy|redacted|sample).*)$"
)
TEST_PATH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|mocks?|examples?|samples?)(/|$)|\.(test|spec|example|sample)\.|\.example$|\.sample$")

BILL = "Anyone who finds this key can use your {what} account on your bill, or drain its quota."
# (prefix, what it is, severity, costs money if abused)
KEY_PREFIXES = [
    ("sk-ant-", "Anthropic API key", "High", True),
    ("sk-proj-", "OpenAI API key", "High", True),
    ("sk-svcacct-", "OpenAI API key", "High", True),
    ("sk-or-", "OpenRouter API key", "High", True),
    ("gsk_", "Groq API key", "High", True),
    ("sk_live_", "Stripe live secret key", "Critical", True),
    ("rk_live_", "Stripe live restricted key", "Critical", True),
    ("sk_test_", "Stripe test key", "Low", False),
    ("AKIA", "AWS access key", "Critical", True),
    ("ASIA", "AWS temporary access key", "High", True),
    ("ghp_", "GitHub personal access token", "High", False),
    ("github_pat_", "GitHub personal access token", "High", False),
    ("xoxb-", "Slack bot token", "High", False),
    ("xoxp-", "Slack user token", "High", False),
    ("SG.", "SendGrid API key", "High", True),
    ("AIza", "Google API key", "Low", True),
    ("sk-", "OpenAI API key", "High", True),
]


IMPACT = {
    "sk_live_": "Anyone with this key can issue refunds, read customer and payment data, and move money in your Stripe account.",
    "rk_live_": "Anyone with this key can use your Stripe account with whatever permissions the key has.",
    "AKIA": "Anyone with this key can use your AWS account: read your data, run servers on your bill, or delete resources.",
    "ghp_": "Anyone with this token can read and change your GitHub repositories.",
    "github_pat_": "Anyone with this token can read and change your GitHub repositories.",
    "xoxb-": "Anyone with this token can read and post messages in your Slack workspace.",
    "xoxp-": "Anyone with this token can act as you in your Slack workspace.",
    "AIza": "If this key isn't restricted, anyone can use Google APIs (like Maps or Gemini) and bill them to your project.",
}


def mask(secret):
    keep = 6 if len(secret) >= 24 else 2
    return secret[:keep] + "•" * 8


def mask_in(text, secret):
    """Mask `secret` in text, including copies cut short by snippet truncation (matched on their first 16 chars)."""
    if not secret or not text:
        return text
    head = secret[:16] if len(secret) >= 16 else secret
    return re.sub(re.escape(head) + r"[^\s\"'`,;]*", lambda _: mask(secret), text)


def jwt_claims(token):
    parts = token.split(".")
    if len(parts) != 3 or not parts[0].startswith("eyJ"):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None


def classify_secret(value, file="", rule=""):
    """What kind of secret this is. Returns dict(title, severity, money_risk, false_positive, note)."""
    value = value.strip().strip("'\"")
    out = {"title": f"Exposed {humanize(rule)}" if rule else "Exposed secret", "severity": "High",
           "money_risk": False, "false_positive": False, "note": "", "impact": "", "reason": ""}
    if rule in ("generic-api-key", ""):
        out["title"] = "Hardcoded API key"
    if len(value) < 8 or PLACEHOLDER.match(value):
        return out | {"false_positive": True, "note": "This looks like a placeholder, not a real secret."}

    claims = jwt_claims(value)
    if claims is not None:
        role = claims.get("role")
        if role == "service_role":
            return out | {"title": "Supabase service_role key exposed", "severity": "Critical",
                          "reason": "service_role keys bypass Row-Level Security entirely.",
                          "impact": "Anyone who finds this key can read, change or delete every row in your Supabase database. Row-Level Security doesn't apply to it."}
        if role == "anon":
            return out | {"title": "Supabase anon key", "severity": "Low", "false_positive": True,
                          "note": "Supabase's anon key is public by design and safe to ship to browsers, as long as Row-Level Security is on for every table."}
        out["title"] = "Hardcoded JWT"
    else:
        for prefix, what, severity, money in KEY_PREFIXES:
            if value.startswith(prefix):
                out |= {"title": f"Exposed {what}", "severity": severity, "money_risk": money,
                        "impact": IMPACT.get(prefix) or (BILL.format(what=what.split(" API")[0]) if money else ""),
                        "reason": "Keys for paid APIs are billed to whoever owns them." if money else ""}
                if prefix == "AIza":
                    out["note"] = "Firebase web config keys look like this and are public by design. Any other Google key should be restricted in Google Cloud Console, or anyone can bill usage to you."
                break

    if TEST_PATH.search(file):
        out |= {"severity": lower(out["severity"]), "note": (out["note"] + " It's in a test or example file, so it may be a dummy value.").strip()}
    return out

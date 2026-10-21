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
    checked = ""  # what this run looked at, for the report ("412 source files"); one instance per scan

    def __init__(self, verify_secrets=False):
        self.verify_secrets = verify_secrets  # the user opted in to testing found keys with their providers (trufflehog)

    def available(self):
        return shutil.which(self.binary) is not None

    def skip(self, root):
        """(state, note) when this scanner shouldn't run on this code: "na" = nothing here for it, "skipped" = not checked."""
        return None if self.available() else ("skipped", "not installed on this server")

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
            raise ScannerError(f"timed out after {self.timeout}s") from None
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


def snippet(root, file, line, end=None, context=2, max_lines=12, max_cols=240):
    """(text, first line number): the flagged lines plus `context` lines around them, read from disk
    (semgrep OSS no longer returns them). Pass context=0 for secrets: neighbouring .env lines are often secrets too."""
    if not line:
        return "", 0
    try:
        lines = (root / file).read_text(errors="replace").splitlines()
    except OSError:
        return "", 0
    end = min(max(end or line, line), line + max_lines - 1)
    start = max(1, line - context)
    stop = min(len(lines), end + context, start + max_lines - 1)
    picked = [ln if len(ln) <= max_cols else ln[:max_cols] + "…" for ln in lines[start - 1 : stop]]
    return textwrap.dedent("\n".join(picked)).rstrip(), start


def has_files(root, *globs):
    return any(p.is_file() and "node_modules" not in p.parts for g in globs for p in root.rglob(g))


def read_json(path, default):
    """A scanner's JSON report; a half-written or garbled one is a scanner failure, not a crash."""
    try:
        text = path.read_text()
    except OSError:
        return default
    try:
        return json.loads(text) if text.strip() else default
    except ValueError:
        raise ScannerError("wrote an unreadable report") from None


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


# Code that never ships to users. Secrets are still scanned there (gitleaks); static analysis (semgrep, our rules) isn't,
# which also cuts semgrep's time on real repos by ~40%.
EXCLUDE = ["*.test.*", "*.spec.*", "__tests__", "__mocks__", "test", "tests", "e2e", "cypress", "playwright", "docs",
           "*.md", "*.lock", "package-lock.json", "*.min.js", "*.map", "dist", "build", ".next", "out", "coverage",
           "storybook-static", "node_modules"]

HYGIENE = "Supply-chain hygiene for your build pipeline, not a vulnerability in your app."

# --- secrets -----------------------------------------------------------------

PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|\$\{.*\}|\{\{.*\}\}|x{4,}|\*{4,}|0{6,}|(your|my|insert|enter|replace)[-_ ].*|.*(example|placeholder|changeme|change[-_]me|dummy|redacted|sample|fake|this[-_ ]?is[-_ ]?(a|not)|not[-_ ]?(a[-_ ]?)?real|for[-_ ]?testing).*)$"
)
TEST_PATH = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|mocks?|examples?|samples?)(/|$)|\.(test|spec|example|sample)\.|\.example$|\.sample$")

SUPABASE_KEYS = "https://supabase.com/dashboard/project/_/settings/api-keys"

# prefix -> (what it is, severity, billed to you if abused, env var to move it to, where to rotate it, impact)
PROVIDERS = {
    "sk-ant-": ("Anthropic API key", "High", True, "ANTHROPIC_API_KEY", "https://console.anthropic.com/settings/keys", None),
    "sk-proj-": ("OpenAI API key", "High", True, "OPENAI_API_KEY", "https://platform.openai.com/api-keys", None),
    "sk-svcacct-": ("OpenAI API key", "High", True, "OPENAI_API_KEY", "https://platform.openai.com/api-keys", None),
    "sk-or-": ("OpenRouter API key", "High", True, "OPENROUTER_API_KEY", "https://openrouter.ai/settings/keys", None),
    "gsk_": ("Groq API key", "High", True, "GROQ_API_KEY", "https://console.groq.com/keys", None),
    "sk_live_": ("Stripe live secret key", "Critical", True, "STRIPE_SECRET_KEY", "https://dashboard.stripe.com/apikeys",
                 "Anyone with this key can issue refunds, read customer and payment data, and move money in your Stripe account."),
    "rk_live_": ("Stripe live restricted key", "Critical", True, "STRIPE_SECRET_KEY", "https://dashboard.stripe.com/apikeys",
                 "Anyone with this key can use your Stripe account with whatever permissions the key has."),
    "sk_test_": ("Stripe test key", "Low", False, "STRIPE_SECRET_KEY", "https://dashboard.stripe.com/test/apikeys",
                 "Test keys can't move real money, but they expose your test data and settings."),
    "AKIA": ("AWS access key", "Critical", True, "AWS_ACCESS_KEY_ID", "https://console.aws.amazon.com/iam/home#/security_credentials",
             "Anyone with this key can use your AWS account: read your data, run servers on your bill, or delete resources."),
    "ASIA": ("AWS temporary access key", "High", True, "AWS_ACCESS_KEY_ID", "https://console.aws.amazon.com/iam/home#/security_credentials", None),
    "ghp_": ("GitHub personal access token", "High", False, "GITHUB_TOKEN", "https://github.com/settings/tokens",
             "Anyone with this token can read and change your GitHub repositories."),
    "github_pat_": ("GitHub personal access token", "High", False, "GITHUB_TOKEN", "https://github.com/settings/tokens",
                    "Anyone with this token can read and change your GitHub repositories."),
    "xoxb-": ("Slack bot token", "High", False, "SLACK_BOT_TOKEN", "https://api.slack.com/apps",
              "Anyone with this token can read and post messages in your Slack workspace."),
    "xoxp-": ("Slack user token", "High", False, "SLACK_USER_TOKEN", "https://api.slack.com/apps",
              "Anyone with this token can act as you in your Slack workspace."),
    "SG.": ("SendGrid API key", "High", True, "SENDGRID_API_KEY", "https://app.sendgrid.com/settings/api_keys",
            "Anyone with this key can send email as you, which gets your domain flagged as spam and burns your quota."),
    "AIza": ("Google API key", "Low", True, "GOOGLE_API_KEY", "https://console.cloud.google.com/apis/credentials",
             "If this key isn't restricted, anyone can use Google APIs (like Maps or Gemini) and bill them to your project."),
    "sbp_": ("Supabase access token", "Critical", False, "SUPABASE_ACCESS_TOKEN", "https://supabase.com/dashboard/account/tokens",
             "Anyone with this token can manage every Supabase project in your account: read and change databases, change settings or delete projects."),
    "sk-": ("OpenAI API key", "High", True, "OPENAI_API_KEY", "https://platform.openai.com/api-keys", None),
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
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None
    return claims if isinstance(claims, dict) else None


def classify_secret(value, file="", rule=""):
    """What kind of secret this is and what to do about it.
    Returns dict(title, what, severity, money_risk, false_positive, note, impact, reason, env_var, rotate)."""
    value = value.strip().strip("'\"")
    out = {"title": f"Exposed {humanize(rule)}" if rule and rule != "generic-api-key" else "Hardcoded API key",
           "what": "this secret", "severity": "High", "money_risk": False, "false_positive": False, "note": "",
           "impact": "", "reason": "", "env_var": "API_KEY", "rotate": ""}
    if len(value) < 8 or PLACEHOLDER.match(value):
        return out | {"false_positive": True, "note": "This looks like a placeholder, not a real secret."}

    # Supabase keys come in two generations: JWTs with a role claim, and since 2025 sb_secret_/sb_publishable_ keys
    claims = jwt_claims(value) or {}
    role = claims.get("role")
    if role == "service_role" or value.startswith("sb_secret_"):
        kind = "service_role" if role else "secret"
        return _in_tests(file, out | {
            "title": f"Supabase {kind} key exposed", "what": f"the Supabase {kind} key", "severity": "Critical",
            "reason": f"Supabase {kind} keys bypass Row-Level Security entirely.",
            "env_var": "SUPABASE_SERVICE_ROLE_KEY" if role else "SUPABASE_SECRET_KEY", "rotate": SUPABASE_KEYS,
            "impact": "Anyone who finds this key can read, change or delete every row in your Supabase database. Row-Level Security doesn't apply to it."})
    if role == "anon" or value.startswith("sb_publishable_"):
        kind = "anon" if role else "publishable"
        return out | {"title": f"Supabase {kind} key", "severity": "Low", "false_positive": True,
                      "note": f"Supabase's {kind} key is public by design and safe to ship to browsers, as long as Row-Level Security is on for every table."}
    if claims:
        out |= {"title": "Hardcoded JWT", "what": "this token", "env_var": "AUTH_TOKEN"}
    else:
        for prefix, (what, severity, money, env_var, rotate, impact) in PROVIDERS.items():
            if value.startswith(prefix):
                out |= {"title": f"Exposed {what}", "what": f"your {what}", "severity": severity, "money_risk": money,
                        "env_var": env_var, "rotate": rotate,
                        "impact": impact or (f"Anyone who finds this key can use your {what.split(' API')[0]} account on your bill, or drain its quota." if money else ""),
                        "reason": "Keys for paid APIs are billed to whoever owns them." if money else ""}
                if prefix == "AIza":
                    out["note"] = "Firebase web config keys look like this and are public by design. Any other Google key should be restricted in Google Cloud Console."
                break
    return _in_tests(file, out)


def _in_tests(file, out):
    if TEST_PATH.search(file):
        out |= {"severity": lower(out["severity"]), "note": (out["note"] + " It's in a test or example file, so it may be a dummy value.").strip()}
    return out

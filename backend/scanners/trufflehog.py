"""Tests each found key with its provider (one read-only request) to tell a live key from a dead or fake one (§16).
Opt-in per scan: it sends the user's keys to third parties, so it only runs when they tick the box (§20)."""

import json
import re

from .base import Scanner, mask_in, rel
from .gitleaks import secret_finding


# Only detectors whose check calls the provider's own fixed API host. Many others (URI, Postgres, JDBC, MongoDB, Redis,
# LDAP, FTP, self-hosted services…) verify by connecting to whatever host the scanned code names, which would let a
# submitted repo point our server at 169.254.169.254 or internal addresses (SSRF). Unknown names abort trufflehog,
# so every name here is checked by the test suite.
DETECTORS = ["OpenAI", "Anthropic", "Groq", "OpenRouter", "Replicate", "HuggingFace", "Stripe", "AWS", "Github", "Slack",
             "SendGrid", "Resend", "Postmark", "Mailgun", "Twilio", "SupabaseToken", "Vercel", "Netlify", "Notion"]


class TruffleHog(Scanner):
    name = binary = "trufflehog"
    label = "Live key check"
    timeout = 120

    def skip(self, root):
        return super().skip(root) if self.verify_secrets else ("skipped", "off")

    def run(self, root, work):
        exclude = work / "trufflehog-exclude.txt"
        exclude.write_text("(^|/)node_modules/\n(^|/)\\.git/\n")
        # only live keys come back, on stdout: raw keys stay in this process's memory, never on disk or in logs
        r = self.exec([self.binary, "filesystem", str(root), "--json", "--no-update", "--no-color", "--results=verified",
                       "--exclude-paths", str(exclude), "--include-detectors", ",".join(DETECTORS)])
        live = [d for d in (json.loads(line) for line in r.stdout.splitlines() if line.startswith("{")) if d.get("Verified")]
        m = re.search(r'"verified_secrets":(\d+),"unverified_secrets":(\d+)', r.stderr)
        n = int(m[1]) + int(m[2]) if m else len(live)
        self.checked = f"{n} key{'s' * (n != 1)}" if n else ""
        return [self._finding(root, d) for d in live]

    def _finding(self, root, d):
        meta = d["SourceMetadata"]["Data"]["Filesystem"]
        det = d.get("DetectorName") or "its provider"
        file, line = rel(root, meta["file"]), meta.get("line") or 0
        f = secret_finding(self.name, root, file, line, line, d.get("Raw") or "", f"{det} credential")
        for part in [d.get("RawV2"), *(d.get("SecretParts") or {}).values()]:  # multi-part keys (AWS key id + secret…)
            if isinstance(part, str) and len(part) >= 8:
                f.code_snippet, f.fix_diff = mask_in(f.code_snippet, part), mask_in(f.fix_diff, part)
        # a provider accepting the key outranks any guess about it being a placeholder or test value
        f.severity, f.confidence, f.is_false_positive, f.triage_note = "Critical", "Confirmed reachable", False, ""
        f.severity_reason = f"{det} accepted this key when we tested it, so it works right now."
        f.explanation = f"{det} accepted this key when we tested it, so it works right now. " + f.explanation
        f.evidence = [f"Tested with {det}: the key is live. VibeGuard made one read-only request with it and kept nothing."]
        return f

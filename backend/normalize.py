"""Merge every scanner's findings into one deduplicated, plain-English, secret-masked list (§15, §16, §20)."""

import re

from models import SEVERITIES, Finding
from scanners.base import TEST_PATH, lower, mask, mask_in, worst

# Which scanner's version of a duplicate we keep (first wins): the most specific source, with the most precise line.
PRIORITY = ["vibeguard", "gitleaks", "trufflehog", "semgrep", "bandit", "njsscan", "zizmor", "osv-scanner", "lockfile-lint", "retire.js"]
CONFIDENCE = ["Confirmed reachable", "Likely", "Needs review"]

# Plain-English title + impact per weakness, used when a scanner only gives rule-speak.
PLAIN = {
    "CWE-20": ("Input not validated", "Unexpected input can crash this code or make it behave in ways you didn't plan for."),
    "CWE-22": ("Path traversal", "An attacker can read or overwrite files outside the folder you intended, like config files and keys."),
    "CWE-78": ("Command injection", "An attacker can run commands on your server and take it over."),
    "CWE-79": ("Cross-site scripting (XSS)", "An attacker can run their own JavaScript in your users' browsers, stealing sessions or acting as them."),
    "CWE-89": ("SQL injection", "An attacker can read, change or delete anything in your database by sending crafted input."),
    "CWE-94": ("Code injection", "An attacker can make your server run their code and take it over."),
    "CWE-95": ("Code injection via eval()", "An attacker can make your server run their code and take it over."),
    "CWE-200": ("Sensitive data exposed", "Information that should stay private can be read by people who shouldn't see it."),
    "CWE-209": ("Error details leaked", "Error messages reveal how your app works inside, which helps attackers plan their next step."),
    "CWE-259": ("Hardcoded password", "Anyone who can see this code can log in with this password."),
    "CWE-284": ("Missing access control", "People can reach data or actions they shouldn't be allowed to."),
    "CWE-285": ("Missing authorization check", "A logged-in user could act on other users' data."),
    "CWE-287": ("Broken authentication", "Attackers may be able to log in as someone else."),
    "CWE-306": ("Missing authentication", "Anyone can use this feature without logging in."),
    "CWE-312": ("Secret stored in clear text", "Anyone who gets hold of this file or database can read the secret directly."),
    "CWE-295": ("Certificate checks turned off", "Anyone on the network can intercept or change this traffic, including passwords and tokens."),
    "CWE-319": ("Data sent unencrypted", "People on the same network can read or change this traffic."),
    "CWE-321": ("Hardcoded secret key", "Anyone with this key can forge tokens or decrypt data your app protects with it."),
    "CWE-326": ("Weak encryption", "Data protected this way can be decrypted with modest effort."),
    "CWE-327": ("Weak cryptography", "Data protected this way can be decrypted or forged."),
    "CWE-328": ("Weak hash", "Hashed values can be reversed or forged."),
    "CWE-338": ("Predictable random values", "Tokens or IDs made this way can be guessed."),
    "CWE-345": ("Data not verified", "Attackers can send forged data that your app trusts."),
    "CWE-346": ("Overly permissive CORS", "Any website can call your API from a visitor's browser."),
    "CWE-347": ("Token signature not verified", "Attackers can forge login tokens and act as any user."),
    "CWE-352": ("Missing CSRF protection", "Another website could make a logged-in user's browser perform actions on your site."),
    "CWE-400": ("Denial of service", "Crafted requests can slow down or crash your app."),
    "CWE-434": ("Unrestricted file upload", "Attackers can upload files that run as code or fill up your storage."),
    "CWE-489": ("Debug mode left on", "Debug features expose internals and sometimes let attackers run code."),
    "CWE-502": ("Unsafe deserialization", "Crafted data sent to your server can make it run attacker code."),
    "CWE-522": ("Credentials poorly protected", "Passwords or tokens can be stolen and reused."),
    "CWE-532": ("Secrets written to logs", "Anyone with log access can read sensitive values."),
    "CWE-601": ("Open redirect", "Attackers can use your domain to send people to phishing sites."),
    "CWE-611": ("XML external entities", "Crafted XML can read files from your server."),
    "CWE-614": ("Cookie sent without Secure flag", "Session cookies can leak over plain HTTP."),
    "CWE-639": ("Insecure direct object reference", "Changing an ID in a request shows or edits someone else's data."),
    "CWE-674": ("Unbounded recursion", "A crafted request can crash your server."),
    "CWE-693": ("Missing security protection", "A standard defence is turned off, making other attacks easier."),
    "CWE-732": ("Overly broad permissions", "More people or processes than intended can read or change this."),
    "CWE-770": ("No limit on resource use", "Attackers can exhaust your server or your API budget with many requests."),
    "CWE-798": ("Hardcoded credential", "Anyone who can see this code can use this credential to get into your accounts or data."),
    "CWE-862": ("Missing authorization check", "Users can perform actions without being allowed to."),
    "CWE-863": ("Incorrect authorization check", "Users can perform actions without being allowed to."),
    "CWE-915": ("Mass assignment", "Users can set fields they shouldn't, like making themselves an admin."),
    "CWE-918": ("Server-side request forgery", "Attackers can make your server fetch internal URLs, exposing internal services or cloud credentials."),
    "CWE-942": ("Overly permissive CORS", "Any website can call your API from a visitor's browser."),
    "CWE-943": ("NoSQL injection", "Attackers can read or change database records by sending crafted input."),
    "CWE-1004": ("Cookie readable by scripts", "If any XSS exists, it can steal session cookies."),
    "CWE-1321": ("Prototype pollution", "Crafted input can change how your app's objects behave, leading to crashes, bypassed checks or code execution."),
    "CWE-1333": ("Regex denial of service", "A crafted string can freeze your server's CPU."),
}
DEFAULT_IMPACT = "This is a pattern that often leads to security bugs. Check the code below and confirm it handles untrusted input safely."
DEP_IMPACT = "Attackers look for apps running versions with published security bugs, because the exploit details are public."
SECRET_IMPACT = "Anyone who can see this code (or your site's JavaScript) can use this credential."


def normalize(findings: list[Finding]) -> list[Finding]:
    secrets = {f._secret for f in findings if f._secret and len(f._secret) >= 8}
    # credentials only a SAST rule spotted (jwt.sign(p, "supersecret123")) are masked in *every* finding that shows that line
    secrets |= {lit for f in findings if f.kind != "dependency" and SECRET_CWES & set(f.cwe) for lit in _flagged_literals(f)}
    merged: list[Finding] = []
    for f in sorted(findings, key=_rank):
        f.detected_by = f.detected_by or [f.source]
        dup = next((m for m in merged if _same(m, f)), None)
        if dup:
            _absorb(dup, f)
        else:
            merged.append(f)
    merged = _group_repeats(merged)
    for f in merged:
        if f.kind in ("code", "config") and TEST_PATH.search(f.file) and not f.is_false_positive:
            f.severity, f.confidence = lower(f.severity), "Needs review"
            f.triage_note = (f.triage_note + " This is test code, which doesn't ship to users.").strip()
        _mask(f, secrets)
        _plain(f)
    merged.sort(key=lambda f: (f.is_false_positive, SEVERITIES.index(f.severity), CONFIDENCE.index(f.confidence), f.file, f.line))
    return merged


def _rank(f):
    return (PRIORITY.index(f.source) if f.source in PRIORITY else len(PRIORITY), SEVERITIES.index(f.severity))


def _group_repeats(findings):
    """One rule firing on many lines of one file becomes one finding that lists every place."""
    groups = {}
    for f in findings:
        repeatable = f.kind in ("code", "config") and f.raw_rule_id and not f.is_false_positive
        # code repeats group per file; config hygiene (CI, package managers) groups across the repo
        key = ((f.raw_rule_id,) if f.kind == "config" else (f.file, f.raw_rule_id)) if repeatable else id(f)
        groups.setdefault(key, []).append(f)
    out = []
    for group in groups.values():
        group.sort(key=lambda f: (f.file, f.line))
        keep = group[0]
        if len(group) > 1:
            files = {f.file for f in group}
            keep.severity = worst(*(f.severity for f in group))
            keep.detected_by = list(dict.fromkeys(s for f in group for s in f.detected_by))
            keep.fix_diff = "\n\n".join(dict.fromkeys(f.fix_diff for f in group if f.fix_diff))  # each place's own fix
            keep.confidence = min((f.confidence for f in group), key=CONFIDENCE.index)
            keep.evidence = [(f"{f.file}:{f.line}" if len(files) > 1 else f"Line {f.line}") + f": {_flagged(f)}" for f in group] + keep.evidence
            keep.explanation = (f"This shows up in {len(group)} places" + (f" across {len(files)} files. " if len(files) > 1 else f" in {keep.file}. ")
                                + keep.explanation)
        out.append(keep)
    return out


def _flagged(f):
    lines = f.code_snippet.splitlines()
    i = f.line - (f.snippet_start or f.line)
    return " ".join(lines[i].split())[:160] if 0 <= i < len(lines) else ""


def _overlap(a, b):
    return a.line <= (b.end_line or b.line) and b.line <= (a.end_line or a.line)


def _same(a, b):
    if a.kind == "dependency" or b.kind == "dependency":
        return a.kind == b.kind and a.package.lower() == b.package.lower()
    if a.file != b.file or not _overlap(a, b):
        return False
    if a.kind == b.kind == "secret":
        return True
    # same weakness on the same lines: two scanners (or two rules) describing one bug
    return bool(set(a.cwe) & set(b.cwe)) or bool(a.raw_rule_id) and a.raw_rule_id == b.raw_rule_id


def _absorb(keep: Finding, other: Finding):
    if other.kind == "secret" and other.confidence == "Confirmed reachable":  # its provider accepted it: never a placeholder
        keep.is_false_positive, keep.triage_note, keep.evidence = False, "", other.evidence + keep.evidence
    # a VibeGuard rule's rating is deliberate (it knows the framework context), so a generic rule doesn't override it
    if not keep.is_false_positive and keep.source != "vibeguard" and SEVERITIES.index(other.severity) < SEVERITIES.index(keep.severity):
        # a "public by design" verdict on the value outranks a generic rule's severity; otherwise the worst rating wins, with its reason
        keep.severity, keep.severity_reason = other.severity, other.severity_reason or keep.severity_reason
    keep.detected_by = list(dict.fromkeys(keep.detected_by + [other.source]))
    keep.cwe = sorted(set(keep.cwe) | set(other.cwe), key=lambda c: int(c[4:]))
    if keep.source != "vibeguard":  # our rules carry hand-picked references
        keep.refs = list(dict.fromkeys(keep.refs + other.refs))
    keep.money_risk = keep.money_risk or other.money_risk
    keep.evidence = keep.evidence or other.evidence
    keep.explanation = keep.explanation or other.explanation
    keep.confidence = min(keep.confidence, other.confidence, key=CONFIDENCE.index)
    if len(set(keep.detected_by)) > 1 and keep.confidence == "Needs review":
        keep.confidence = "Likely"  # independent scanners agreeing is evidence too
    if keep._secret is None:
        keep._secret = other._secret


SECRET_CWES = {"CWE-259", "CWE-321", "CWE-798"}


def _flagged_literals(f):
    lines = f.code_snippet.splitlines()
    start = f.snippet_start or f.line
    flagged = lines[max(f.line - start, 0) : (f.end_line or f.line) - start + 1]
    return {m[2] for line in flagged for m in re.finditer(r"""(["'`])([^"'`\s./]{8,})\1""", line) if _secretish(m[2])}


def _mask(f, secrets):
    def clean(text):
        for s in secrets:
            text = mask_in(text, s)
        if f.kind != "dependency" and SECRET_CWES & set(f.cwe):
            # hardcoded credentials that no secret scanner caught (e.g. jwt.sign(p, "supersecret123"))
            text = re.sub(r"""(["'`])([^"'`\s./]{8,})\1""", lambda m: m[1] + (mask(m[2]) if _secretish(m[2]) else m[2]) + m[1], text)
        return text

    f.code_snippet = clean(f.code_snippet)
    f.fix_diff = clean(f.fix_diff)
    f.explanation = clean(f.explanation)
    f.evidence = [clean(e) for e in f.evidence]


def _secretish(s):
    """Quoted literal that looks like a key/password rather than a word like "jsonwebtoken"."""
    if "•" in s:  # already masked
        return False
    return bool(re.search(r"\d|[_+=-]", s) or (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)))


def _plain(f):
    known = next((PLAIN[c] for c in f.cwe if c in PLAIN), None)
    if known and f.source in ("semgrep", "njsscan", "bandit") and not f.impact:
        f.title = known[0]  # "Code injection via eval()" beats "Code string concat"; a scanner that wrote its own impact chose its title too
    if not f.impact:
        f.impact = known[1] if known and f.kind != "dependency" else SECRET_IMPACT if f.kind == "secret" else DEP_IMPACT if f.kind == "dependency" else DEFAULT_IMPACT
        if f.kind == "dependency" and known:
            f.impact = f"{DEP_IMPACT} The worst one here: {known[1][0].lower()}{known[1][1:]}"
    f.refs = list(dict.fromkeys(f.refs + [f"https://cwe.mitre.org/data/definitions/{c[4:]}.html" for c in f.cwe]))[:5]

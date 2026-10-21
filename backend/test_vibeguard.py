"""Self-checks. Run: .venv/bin/python test_vibeguard.py  (pytest also works)."""

import json
import re
import tempfile
import zipfile
from pathlib import Path

import ingest
import normalize
import scoring
from models import Finding
from scanners import ALL as SCANNERS
from scanners.base import classify_secret, mask_in
from scanners.versions import fixed_in, vkey


def _zip(entries):
    fd, path = tempfile.mkstemp(suffix=".zip")
    with open(fd, "wb") as f, zipfile.ZipFile(f, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return Path(path)


def _rejects(fn, *args):
    try:
        r = fn(*args)
        if hasattr(r, "__enter__"):  # sandbox() only does its work when entered
            with r:
                pass
    except ingest.IngestError:
        return True
    return False


def test_github_urls():
    ok = {
        "https://github.com/vercel/next.js": "https://github.com/vercel/next.js.git",
        "github.com/a-b/c_d.git": "https://github.com/a-b/c_d.git",
        "https://github.com/o/r/tree/main/src": "https://github.com/o/r.git",
    }
    for url, want in ok.items():
        assert ingest.validate("github", url)[0] == want, url
    for bad in ["https://gitlab.com/o/r", "https://github.com/o", "https://github.com.evil.com/o/r",
                "https://github.com/o/r --upload-pack=touch", "file:///etc", "https://github.com/../.."]:
        assert _rejects(ingest.validate, "github", bad), bad


def test_zip_rejects_traversal_and_bombs():
    for name in ["../evil.js", "a/../../evil.js", "/etc/passwd", "C:/win.js", "..\\evil.js"]:
        z = _zip({"ok.js": "1", name: "x"})
        assert _rejects(ingest.validate, "zip", z), name
        assert _rejects(ingest.sandbox, "zip", z), name
        assert not z.exists(), "uploaded zip must be deleted even when rejected"
    z = _zip({"big.txt": "0" * (ingest.MAX_BYTES + 1)})
    assert _rejects(ingest.sandbox, "zip", z)


def test_zip_extracts_and_cleans_up():
    z = _zip({"app/src/index.js": "eval(x)", "app/node_modules/lib/index.js": "x", "__MACOSX/._x": "x"})
    with ingest.sandbox("zip", z) as root:
        files = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
        assert files == ["app/src/index.js"], files
        sandbox_dir = root.parent
    assert not sandbox_dir.exists() and not z.exists()


def test_cleanup_on_error():
    try:
        with ingest.sandbox("paste", "x = 1", "a.py") as root:
            sandbox_dir = root.parent
            raise RuntimeError("scanner blew up")
    except RuntimeError:
        pass
    assert not sandbox_dir.exists()


def test_clone_never_follows_symlinks():
    """A repo can commit a symlink to a server file (/proc/self/environ); the clone must hold the link's text, not the file."""
    import subprocess
    outside = Path(tempfile.mkdtemp()) / "server-secret.txt"
    outside.write_text("GROQ_API_KEY=gsk_not_for_the_report\n")
    repo = Path(tempfile.mkdtemp())
    (repo / "src").mkdir()
    (repo / "src/config.js").symlink_to(outside)
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-qm", "x"], check=True)
    root = Path(tempfile.mkdtemp()) / "src"
    ingest._clone(f"file://{repo}", root)
    link = root / "src/config.js"
    assert not link.is_symlink() and "gsk_" not in link.read_text() and link.read_text() == str(outside)


def test_restart_fails_unfinished_scans():
    import db
    old, db.DB_PATH = db.DB_PATH, str(Path(tempfile.mkdtemp()) / "t.db")
    try:
        db.init()
        db.create_scan("s1", "demo", "Demo app", [])
        db.update_scan("s1", status="running")
        db.init()  # what a restart runs
        assert db.get_scan("s1")["status"] == "failed" and "restarted" in db.get_scan("s1")["error"]
    finally:
        db.DB_PATH = old


def test_paste_names():
    assert ingest.validate("paste", "x", "../../etc/passwd")[1] == "etc/passwd"
    assert ingest.validate("paste", "def f():\n  pass")[1] == "pasted.py"
    assert ingest.validate("paste", "service cloud.firestore {")[1] == "firestore.rules"
    assert ingest.validate("paste", "OPENAI_API_KEY=sk-123\nDEBUG=true")[1] == ".env"
    assert ingest.validate("paste", "export default function App() { return <div/> }")[1] == "pasted.js"
    assert _rejects(ingest.validate, "paste", "   ")
    with ingest.sandbox("paste", "x", "etc/passwd") as root:
        assert (root / "etc/passwd").read_text() == "x"


def test_versions():
    assert vkey("2.0.0-rc.1") < vkey("2.0.0") < vkey("2.0.1") < vkey("10.0.0")
    two_branches = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.30.0"}, {"introduced": "1.0.0"}, {"fixed": "1.15.2"}]}]
    assert fixed_in("0.21.1", two_branches) == "0.30.0"
    assert fixed_in("1.2.0", two_branches) == "1.15.2"
    assert fixed_in("1.15.2", two_branches) is None
    assert fixed_in("3.1.0", [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}]}]) == ""  # never fixed
    assert fixed_in("3.1.0", [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"last_affected": "3.2.0"}]}]) == ""
    assert fixed_in("1.0.0", [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]) is None


def _jwt(role):
    import base64
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'HS256'})}.{b({'iss': 'supabase', 'role': role})}.c2lnbmF0dXJlLXNpZ25hdHVyZQ"


def test_classify_secret():
    assert classify_secret(_jwt("service_role"))["severity"] == "Critical"
    anon = classify_secret(_jwt("anon"))
    assert anon["false_positive"] and "Row-Level Security" in anon["note"]
    for placeholder in ["your-api-key-here", "<OPENAI_KEY>", "${API_KEY}", "xxxxxxxxxxxx", "sk-changeme-1234"]:
        assert classify_secret(placeholder)["false_positive"], placeholder
    live = classify_secret("sk_live_" + "a1B2" * 6)
    assert live["severity"] == "Critical" and live["money_risk"]
    assert classify_secret("AIzaSyA" + "b" * 32)["severity"] == "Low"
    assert classify_secret("sk-proj-" + "Ab3" * 16, "tests/fixtures/keys.js")["severity"] == "Medium"
    # Supabase's 2025 key formats: secret = the new service_role, publishable = the new anon key
    secret = classify_secret("sb_secret_" + "N7UND0Ugj" * 3)
    assert secret["severity"] == "Critical" and secret["env_var"] == "SUPABASE_SECRET_KEY" and "Row-Level" in secret["reason"]
    assert classify_secret("sb_publishable_" + "ACJWlzQH" * 4)["false_positive"]
    assert classify_secret("sbp_" + "a1" * 20)["severity"] == "Critical"


def test_mask_in_catches_truncated_copies():
    secret = _jwt("service_role")
    text = f"KEY={secret[:40]}…"  # what snippet() leaves after cutting a long line
    out = mask_in(text, secret)
    assert secret[16:40] not in out and "•" in out


def _f(**kw):
    return Finding(**{"source": "semgrep", "severity": "Medium", "title": "t", "file": "a.js", "line": 5, **kw})


def test_normalize_dedupes_and_masks():
    key = "sk-proj-" + "Zq9" * 16
    leak = _f(source="gitleaks", kind="secret", severity="High", line=3, cwe=["CWE-798"], code_snippet=f'k = "{key}"')
    leak._secret = key
    out = normalize.normalize([
        _f(cwe=["CWE-95"], raw_rule_id="eval-detected", confidence="Needs review"),
        _f(source="njsscan", severity="High", cwe=["CWE-95"], line=2, end_line=9, raw_rule_id="eval_nodejs", confidence="Needs review"),
        _f(cwe=["CWE-79"], raw_rule_id="xss"),  # same line, different weakness: kept separate
        _f(source="gitleaks", kind="secret", severity="Low", line=7, is_false_positive=True, cwe=["CWE-798"]),
        _f(kind="secret", severity="High", line=7, cwe=["CWE-321"]),  # semgrep echo of a public-by-design key
        leak,
        _f(cwe=["CWE-89"], line=3, code_snippet=f'db.query("{key}" + id)'),  # another finding showing the same secret
        _f(source="osv-scanner", kind="dependency", package="lodash@4.17.15", severity="High", file="package.json"),
        _f(source="retire.js", kind="dependency", package="Lodash@4.17.15", file="vendor/lodash.js"),
    ])
    assert len(out) == 6, [(f.title, f.source, f.line) for f in out]
    ev = next(f for f in out if "CWE-95" in f.cwe)
    assert ev.source == "semgrep" and ev.line == 5 and ev.severity == "High" and ev.detected_by == ["semgrep", "njsscan"]
    assert ev.confidence == "Likely"  # two scanners agreeing
    fp = next(f for f in out if f.is_false_positive)
    assert fp.severity == "Low" and fp.detected_by == ["gitleaks", "semgrep"] and out[-1] is fp  # noise sorts last
    assert next(f for f in out if f.kind == "dependency").detected_by == ["osv-scanner", "retire.js"]
    dumped = json.dumps([f.model_dump() for f in out])
    assert key not in dumped and key[:16] not in dumped
    assert all(f.impact for f in out)  # never rule-speak without a plain-English line


def test_scoring():
    crit = _f(severity="Critical", confidence="Likely")
    assert scoring.risk_score([crit]) == 55 and scoring.grade(55) == "D"
    assert scoring.risk_score([crit, _f(severity="Critical")]) == 80 and scoring.grade(80) == "F"
    assert scoring.risk_score([_f(severity="Critical", confidence="Needs review")]) == 28  # unconfirmed counts half
    assert scoring.risk_score([_f(severity="High", is_false_positive=True)]) == 0 and scoring.grade(0) == "A"
    assert scoring.grade(25) == "B" and scoring.grade(26) == "C"


def test_verified_key_beats_placeholder_guess():
    """A key its provider accepted is live, whatever its text looks like: never noise, always Critical."""
    guess = _f(source="gitleaks", kind="secret", severity="Low", line=3, is_false_positive=True, triage_note="placeholder")
    live = _f(source="trufflehog", kind="secret", severity="Critical", line=3, confidence="Confirmed reachable", evidence=["Tested with Groq: live"])
    (out,) = normalize.normalize([guess, live])
    assert not out.is_false_positive and out.severity == "Critical" and out.confidence == "Confirmed reachable"
    assert out.detected_by == ["gitleaks", "trufflehog"] and out.evidence[0].startswith("Tested with")


def test_trufflehog_masks_every_part_and_is_opt_in():
    from scanners.trufflehog import TruffleHog
    root = Path(tempfile.mkdtemp())
    key_id, secret = "AKIA" + "Q7Z2" * 4, "wJalrXUtnFEMI" + "K7MDENGbPxRfiCY" * 2
    (root / "aws.js").write_text(f'const s3 = new S3({{ accessKeyId: "{key_id}", secretAccessKey: "{secret}" }})\n')
    assert TruffleHog().skip(root) == ("skipped", "off")
    record = {"SourceMetadata": {"Data": {"Filesystem": {"file": str(root / "aws.js"), "line": 1}}}, "DetectorName": "AWS",
              "Verified": True, "Raw": key_id, "RawV2": key_id + ":" + secret, "SecretParts": {"key": key_id, "secret": secret}}
    f = TruffleHog(verify_secrets=True)._finding(root, record)
    assert f.severity == "Critical" and f.confidence == "Confirmed reachable" and f.title == "Exposed AWS access key"
    out = json.dumps(normalize.normalize([f])[0].model_dump())
    assert key_id[:16] not in out and secret[:16] not in out


def test_trufflehog_never_verifies_against_hosts_from_the_code():
    """SSRF guard: only fixed-API detectors run, so a planted internal URL is never contacted."""
    import subprocess
    from scanners.trufflehog import DETECTORS, TruffleHog
    if not TruffleHog().available():
        return print("   (trufflehog not installed, skipped)")
    root = Path(tempfile.mkdtemp())
    (root / "config.js").write_text('const db = "postgres://admin:hunter2pass@169.254.169.254:80/db"\n'
                                    'const groq = "gsk_' + "Vq3TzR8wLm2Kx9Pa" * 3 + 'Zt7Q"\n')
    r = subprocess.run(["trufflehog", "filesystem", str(root), "--json", "--no-update", "--no-verification",
                        "--include-detectors", ",".join(DETECTORS)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-300:]  # every allowlisted name is a real detector
    found = {json.loads(line)["DetectorName"] for line in r.stdout.splitlines() if line.startswith("{")}
    assert found == {"Groq"}, found


def test_lockfile_graphs_agree():
    """pnpm (v6, v9) and yarn (v1, berry) lockfiles give the same runtime/build split as package-lock, aliases included."""
    from scanners import npm_deps
    manifest = json.dumps({"dependencies": {"express": "4", "sw-cjs": "npm:string-width@4"}, "devDependencies": {"vite": "5"}})
    locks = {
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/express": {"dependencies": {"qs": "6"}}, "node_modules/qs": {},
            "node_modules/sw-cjs": {"name": "string-width", "dependencies": {"ansi-regex": "5"}}, "node_modules/ansi-regex": {},
            "node_modules/vite": {"dev": True, "dependencies": {"esbuild": "0.21"}}, "node_modules/esbuild": {"dev": True}}}),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express: {specifier: '4', version: 4.21.0}\n"
                          "      sw-cjs: {specifier: npm:string-width@4, version: string-width@4.2.3}\n"
                          "snapshots:\n  express@4.21.0:\n    dependencies:\n      qs: 6.13.0\n  qs@6.13.0: {}\n"
                          "  string-width@4.2.3:\n    dependencies:\n      ansi-regex: 5.0.1\n  ansi-regex@5.0.1: {}\n"
                          "  vite@5.4.0(@types/node@20.0.0):\n    dependencies:\n      esbuild: 0.21.5\n  esbuild@0.21.5: {}\n",
        "pnpm-lock-v6.yaml": "lockfileVersion: '6.0'\npackages:\n  /express@4.21.0:\n    dependencies:\n      qs: 6.13.0\n    dev: false\n"
                             "  /qs@6.13.0:\n    dev: false\n  /vite@5.4.0:\n    dependencies:\n      esbuild: 0.21.5\n    dev: true\n  /esbuild@0.21.5:\n    dev: true\n",
        "yarn.lock": 'express@4:\n  version "4.21.0"\n  dependencies:\n    qs "^6"\n\nqs@^6:\n  version "6.13.0"\n\n'
                     '"sw-cjs@npm:string-width@4":\n  version "4.2.3"\n  dependencies:\n    ansi-regex "^5"\n\n'
                     'vite@5:\n  version "5.4.0"\n  dependencies:\n    esbuild "^0.21"\n\n'
                     'esbuild@^0.21:\n  version "0.21.5"\n\nansi-regex@^5:\n  version "5.0.1"\n',
        "yarn-berry.lock": '__metadata:\n  version: 8\n\n"express@npm:4":\n  version: 4.21.0\n  dependencies:\n    qs: "npm:^6"\n\n'
                           '"vite@npm:5":\n  version: 5.4.0\n  dependencies:\n    esbuild: "npm:^0.21"\n\n'
                           '"qs@npm:^6":\n  version: 6.13.0\n\n"esbuild@npm:^0.21":\n  version: 0.21.5\n',
    }
    for lock, text in locks.items():
        root = Path(tempfile.mkdtemp())
        (root / "package.json").write_text(manifest)
        (root / lock.replace("-v6", "").replace("-berry", "")).write_text(text)
        p = npm_deps.Project(root)
        assert p.has_graph and p.classify("qs") == ("runtime", "express"), lock
        assert p.classify("esbuild")[0] == "dev" and p.classify("vite")[0] == "dev", lock
        if "ansi-regex" in text:
            assert p.classify("string-width") == ("runtime", "sw-cjs") and p.classify("ansi-regex")[0] == "runtime", lock
    assert npm_deps.npm_aliases(json.loads(locks["package-lock.json"])) == ["sw-cjs:string-width"]


def test_semgrep_policy():
    """Curated rule verdicts: noise is filtered, hygiene is Low, Actions injection is judged by its inputs."""
    from scanners.semgrep import Semgrep
    root = Path(tempfile.mkdtemp())
    (root / "wf.yml").write_text("run: ./x ${{ inputs.mode && '--now' || '' }}\nrun: echo ${{ github.event.issue.title }}\n")
    (root / "a.js").write_text("console.log(`user ${id}`)\n")
    res = lambda rule, file, line, sev="ERROR", meta=None: {
        "check_id": rule, "path": str(root / file), "start": {"line": line}, "end": {"line": line},
        "extra": {"severity": sev, "message": "m", "metadata": meta or {"likelihood": "HIGH", "impact": "HIGH", "confidence": "HIGH"}}}
    s = Semgrep()
    safe = s._finding(root, res("yaml.github-actions.security.run-shell-injection.run-shell-injection", "wf.yml", 1), False)
    bad = s._finding(root, res("yaml.github-actions.security.run-shell-injection.run-shell-injection", "wf.yml", 2), False)
    assert safe.severity == "Low" and bad.severity == "Critical"
    assert s._finding(root, res("javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring", "a.js", 1), False).is_false_positive
    csrf = "javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage"
    assert s._finding(root, res(csrf, "a.js", 1), uses_cookies=False).is_false_positive
    assert not s._finding(root, res(csrf, "a.js", 1), uses_cookies=True).is_false_positive


def test_npm_dependency_tiers():
    """Runtime vs. build-only, through the lockfile graph, even when build tools sit in "dependencies"."""
    from scanners import npm_deps
    root = Path(tempfile.mkdtemp())
    (root / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.0.0", "vite": "^5.0.0", "tailwindcss-animate": "1.0.0"},
                                                   "devDependencies": {"eslint": "^9.0.0"}}))
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/express": {"dependencies": {"qs": "1"}}, "node_modules/qs": {},
        "node_modules/vite": {"dependencies": {"nanoid": "3"}}, "node_modules/nanoid": {},
        "node_modules/tailwindcss-animate": {"peerDependencies": {"tailwindcss": "3"}}, "node_modules/tailwindcss": {"dependencies": {"braces": "3"}},
        "node_modules/braces": {}, "node_modules/eslint": {"dependencies": {"js-yaml": "4"}}, "node_modules/js-yaml": {"dev": True}}}))
    p = npm_deps.Project(root)
    assert p.classify("express") == ("runtime-direct", None)
    assert p.classify("qs") == ("runtime", "express")
    for build_only in ["vite", "nanoid", "tailwindcss", "braces", "eslint", "js-yaml"]:
        assert p.classify(build_only)[0] == "dev", build_only
    (root / "src").mkdir()
    (root / "src/app.ts").write_text('import express from "express"\nconst x = require("@scope/pkg/sub")\nimport "./local"\n')
    assert npm_deps.imported_packages(root) == {"express", "@scope/pkg"}
    assert npm_deps.min_version("^0.21.1") == "0.21.1" and npm_deps.min_version("latest") is None


# The demo app's full expected report: every planted issue at its severity, every decoy filtered, nothing else.
# Phase 4/5 changes that add, drop or re-rate anything must update this on purpose.
DEMO = sorted([
    (".env", 3, "Critical"), (".env", 4, "Critical"),  # service_role + OpenAI keys in NEXT_PUBLIC_ vars
    ("src/lib/ai.js", 5, "Critical"), ("src/lib/supabase.js", 6, "Critical"),  # key + SDK in the browser; service_role read in the browser
    ("server/routes/calc.js", 5, "Critical"), ("server/routes/users.js", 6, "Critical"),  # eval and SQL on request data (taint)
    ("firestore.rules", 5, "Critical"),
    ("supabase/migrations/20260101000000_init.sql", 1, "Critical"), ("supabase/migrations/20260101000000_init.sql", 26, "Critical"),  # RLS off
    ("supabase/migrations/20260101000000_init.sql", 33, "Critical"),  # is_admin taken from sign-up metadata
    ("supabase/migrations/20260101000000_init.sql", 23, "High"),  # anyone can read entries
    ("supabase/migrations/20260101000000_init.sql", 42, "High"),  # clear_entries(uuid) callable by anyone
    ("src/pages/Search.jsx", 9, "High"), ("src/components/CommentList.jsx", 17, "High"),  # XSS (taint, pattern)
    ("src/pages/Admin.jsx", 6, "High"), ("src/pages/Admin.jsx", 14, "High"),  # client-only admin checks
    ("server/routes/auth.js", 9, "High"),  # plaintext passwords
    ("server/routes/auth.js", 10, "High"), ("server/routes/auth.js", 10, "High"),  # JWT signing secret; tokens never verified
    ("server/routes/auth.js", 10, "Medium"),  # tokens never expire
    ("server/routes/billing.js", 8, "High"), ("supabase/functions/delete-account/index.ts", 12, "High"),
    ("server/routes/upload.js", 4, "High"),  # any file type into public/
    (".env.production", 2, "Medium"), ("server/index.js", 21, "Medium"),  # debug flags, stack traces in responses
    ("server/routes/auth.js", 5, "Medium"), ("server/routes/chat.js", 6, "Medium"),  # no rate limit (login, paid AI)
    ("server/routes/chat.js", 9, "Medium"),  # the caller writes the whole AI conversation
    ("server/index.js", 5, "Low"),  # CORS *
])
DEMO_NOISE = {(".env", 2), ("server/index.js", 4)}  # anon key (public by design), CSRF in an app without cookies
DEMO_DEPS = {"axios@0.21.1", "express@4.17.1", "jsonwebtoken@8.5.1", "lodash@4.17.15", "multer@1.4.2"}


def test_scanners_on_sample_repo():
    """Integration: the demo app's report is exactly what we expect, and never leaks a secret."""
    import shutil
    installed = [s for s in (cls() for cls in SCANNERS) if s.available()]
    if not installed:
        print("   (no scanners installed, skipped)")
        return
    with ingest.sandbox("demo", None) as root:
        work = root.parent / "work"
        work.mkdir()
        raw = [f for s in installed if not s.skip(root) for f in s.run(root, work)]
        env_secrets = [line.split("=", 1)[1] for line in (root / ".env").read_text().splitlines() if "KEY=" in line]
        out = normalize.normalize(raw)
    names = {s.name for s in installed}
    by = {(f.file, f.line): f for f in out}
    if {"gitleaks", "semgrep", "osv-scanner"} <= names and shutil.which("ast-grep"):
        code = sorted((f.file, f.line, f.severity) for f in out if f.kind != "dependency" and not f.is_false_positive)
        assert code == DEMO, f"missing {sorted(set(DEMO) - set(code))}, unexpected {sorted(set(code) - set(DEMO))}, all {code}"
        # the three the demo script promises (§12), each confirmed and with a fix
        for key in [("src/lib/ai.js", 5), ("src/pages/Search.jsx", 9), ("server/routes/users.js", 6)]:
            assert by[key].fix_diff and by[key].explanation, key
        assert by[("src/pages/Search.jsx", 9)].confidence == by[("server/routes/users.js", 6)].confidence == "Confirmed reachable"
        assert {(f.file, f.line) for f in out if f.is_false_positive} == DEMO_NOISE
        assert {f.package for f in out if f.kind == "dependency"} == DEMO_DEPS
    if "gitleaks" in names:
        assert "service_role" in by[(".env", 3)].title and by[(".env", 2)].is_false_positive
    if "semgrep" in names:
        assert by[("server/routes/calc.js", 5)].cwe == ["CWE-95"]
        assert "JWT signing secret in code" in {f.title for f in out if (f.file, f.line) == ("server/routes/auth.js", 10)}
    if "osv-scanner" in names:
        axios = next(f for f in out if f.package == "axios@0.21.1")
        assert axios.file == "package.json" and axios.fix_diff.startswith('- "axios": "^0.21.1"')
    if shutil.which("ast-grep"):
        hook = by[("server/routes/billing.js", 8)]
        assert hook.money_risk and "constructEvent" in hook.fix_diff and "server/routes/billing.js" in hook.reprompt
    dumped = json.dumps([f.model_dump() for f in out])
    for secret in env_secrets:
        assert secret[:20] not in dumped, "a secret value leaked into the report"


def _run(scanner, files):
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    work = root.parent / (root.name + "-work")
    work.mkdir()
    return scanner.skip(root), (None if scanner.skip(root) else normalize.normalize(scanner.run(root, work)))


KEY = "sk-proj-" + "Tq7Wv2Lm9Xc4" * 4

# One project holding a crafted positive and negative for every VibeGuard rule (§7, Phase 4).
VIBE_FIXTURE = {
    # frontend-secret
    ".env": f"VITE_OPENAI_API_KEY={KEY}\nVITE_SUPABASE_URL=https://abcdefghijklmnop.supabase.co\nVITE_SUPABASE_ANON_KEY=ANON\nOPENAI_API_KEY={KEY}\n",
    "src/lib/ai.ts": "const key = import.meta.env.VITE_OPENAI_API_KEY\n",
    "src/lib/supabase.ts": "export const s = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY)\n",
    "src/lib/openai.ts": "export const ai = new OpenAI({\n  apiKey: key,\n  dangerouslyAllowBrowser: true,\n})\n",
    "server/openai.ts": f'export const ai = new OpenAI({{ apiKey: process.env.OPENAI_API_KEY }})\nconst backup = "{KEY}"\n',
    "src/config.ts": f'export const live = "{KEY}"\nexport const demo = "sk-placeholder-00000000000000000000"\n',
    # supabase-rls-off
    "supabase/migrations/001_init.sql": (
        "create table public.orders (id uuid primary key, user_id uuid, total int);\n"
        "create table public.notes (id uuid primary key, user_id uuid, body text);\n"
        "alter table public.notes enable row level security;\n"
        "create policy \"own notes\" on public.notes for all to authenticated using ((select auth.uid()) = user_id);\n"
        "create table public.recipes (id uuid primary key, name text);\n"
        "alter table public.recipes enable row level security;\n"
        "create policy \"recipes are public\" on public.recipes for select using (true);\n"
        "create table public.profiles (id uuid primary key references auth.users, email text);\n"
        "alter table public.profiles enable row level security;\n"
        "create policy \"profiles readable\" on public.profiles for select using (true);\n"
        "create table public.posts (id uuid primary key, author_id uuid, body text);\n"
        "do $$ declare t text; begin foreach t in array array['posts'] loop\n"
        "  execute format('alter table public.%I enable row level security', t); end loop; end $$;\n"
        "create policy \"admins delete posts\" on public.posts for delete to authenticated using (public.is_admin());\n"
        "create view public.order_totals as select user_id, sum(total) from public.orders group by user_id;\n"
        "create view public.safe_totals with (security_invoker = true) as select 1;\n"),
    # firebase-open-rules
    "firestore.rules": ("rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n"
                        "    match /users/{userId} {\n      allow read, write: if request.auth != null;\n    }\n"
                        "    match /notes/{noteId} {\n      allow read, write: if request.auth.uid == resource.data.owner;\n    }\n"
                        "    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(2099, 1, 1);\n    }\n  }\n}\n"),
    "storage.rules": ("service firebase.storage {\n  match /b/{bucket}/o {\n    match /avatars/{userId}/{file=**} {\n"
                      "      allow write: if request.auth.uid == userId;\n      allow read: if request.time < timestamp.date(2020, 1, 1);\n    }\n  }\n}\n"),
    "database.rules.json": '{\n  "rules": {\n    ".read": true,\n    ".write": "auth != null"\n  }\n}\n',
    # client-only-auth
    "src/pages/Admin.tsx": ('const isAdmin = localStorage.getItem("isAdmin") === "true"\nconst theme = localStorage.getItem("theme")\n'
                            'async function drop(id) {\n  if (user.role === "admin") {\n    await supabase.from("orders").delete().eq("id", id)\n  }\n'
                            '  if (user.role === "admin") {\n    await supabase.from("posts").delete().eq("id", id)\n  }\n}\n'),
    # cors-wildcard
    "server/app.js": ('const app = express()\napp.use(cors({ origin: true, credentials: true }))\n'
                      'app.use("/api/auth", require("./routes/auth"))\napp.use((err, req, res, next) => res.status(500).json({ stack: err.stack }))\n'),
    "server/public.js": "api.use(cors())\n",
    "server/strict.js": 'api.use(cors({ origin: ["https://a.com"], credentials: true }))\nconsole.error(err.stack)\n',
    "supabase/functions/hello/index.ts": 'const headers = { "Access-Control-Allow-Origin": "*" }\nDeno.serve(() => new Response("hi", { headers }))\n',
    # xss-sink
    "src/pages/Search.tsx": ('export default function Search() {\n  const [params] = useSearchParams()\n  const q = params.get("q")\n'
                             '  return <h1 dangerouslySetInnerHTML={{ __html: `Results for ${q}` }} />\n}\n'),
    "src/components/Post.tsx": ('export const Post = ({ post, css }) => (<>\n  <div dangerouslySetInnerHTML={{ __html: post.body }} />\n'
                                '  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />\n'
                                '  <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />\n  <style dangerouslySetInnerHTML={{ __html: css }} />\n</>)\n'),
    "src/components/ui/chart.tsx": "export const C = ({ x }) => <div dangerouslySetInnerHTML={{ __html: x }} />\n",
    "src/components/Bio.vue": '<template>\n  <div v-html="user.bio"></div>\n  <div v-html="\'<b>hi</b>\'"></div>\n</template>\n',
    # sql-string-concat + eval-user-input + no-rate-limit + unrestricted-upload (Express routes)
    "server/routes/auth.js": ('router.post("/login", async (req, res) => {\n'
                              '  const r = await db.query("SELECT * FROM users WHERE email = \'" + req.body.email + "\'")\n'
                              '  const ok = await db.query("SELECT * FROM users WHERE email = $1", [req.body.email])\n})\n'),
    "server/routes/tools.js": ('router.post("/calc", (req, res) => {\n  res.json({ r: eval(req.body.expr) })\n})\n'
                               'router.post("/safe", (req, res) => {\n  const n = parseInt(req.query.n)\n  res.json({ r: eval(n) })\n})\n'
                               'router.post("/ls", (req, res) => {\n  exec(`ls ${req.query.dir}`)\n  execFile("ls", [req.query.dir])\n})\n'
                               'const report = (table) => db.query(`SELECT * FROM ${table}`)\n'),
    "server/routes/upload.js": ('const a = multer({ dest: "uploads/" })\nconst b = multer({ dest: "public/files" })\n'
                                'const c = multer({ dest: "uploads/", limits: { fileSize: 1000000 } })\n'),
    "supabase/functions/summarize/index.ts": ('Deno.serve(async (req) => {\n  const r = await fetch("https://api.openai.com/v1/chat/completions", {})\n'
                                              '  return new Response(await r.text())\n})\n'),
    "supabase/functions/limited/index.ts": ('import { rateLimit } from "../_shared/rate-limit.ts"\nDeno.serve(async (req) => {\n'
                                            '  await rateLimit(req)\n  return fetch("https://api.openai.com/v1/responses")\n})\n'),
    # debug-in-prod
    ".env.production": "NODE_ENV=production\nDEBUG=true\n",
    ".env.development": "DEBUG=true\n",
    # supabase-privilege-escalation, supabase-rpc-exposed, supabase-storage-open
    "supabase/migrations/002_more.sql": (
        "create function public.handle_new_user() returns trigger language plpgsql security definer as $$\nbegin\n"
        "  insert into public.accounts (id, plan) values (new.id, new.raw_user_meta_data->>'plan');\n  return new;\nend;\n$$;\n"
        "create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();\n"
        "create function public.name_from_meta() returns trigger language plpgsql security definer as $$\nbegin\n"
        "  new.display_name := new.raw_user_meta_data->>'full_name';\n  return new;\nend;\n$$;\n"
        "create table public.accounts (id uuid primary key, plan text, display_name text);\n"
        "alter table public.accounts enable row level security;\n"
        "create policy \"own account\" on public.accounts for update to authenticated using ((select auth.uid()) = id);\n"
        "create table public.settings (id uuid primary key, role text, theme text);\n"
        "alter table public.settings enable row level security;\n"
        "create policy \"own settings\" on public.settings for update to authenticated using (auth.uid() = id) "
        "with check (auth.uid() = id and role = (select role from public.settings where id = auth.uid()));\n"
        "create table public.teams (id uuid primary key, tier text, name text);\n"
        "alter table public.teams enable row level security;\n"
        "create policy \"own team\" on public.teams for update to authenticated using (auth.uid() = id);\n"
        "revoke update on public.teams from authenticated;\ngrant update (name) on public.teams to authenticated;\n"
        "create table public.user_roles (id uuid primary key, user_id uuid, role text);\n"
        "alter table public.user_roles enable row level security;\n"
        "create policy \"add own role\" on public.user_roles for insert to authenticated with check (auth.uid() = user_id);\n"
        "create table public.docs (id uuid primary key, owner uuid);\n"
        "alter table public.docs enable row level security;\n"
        "create policy \"meta admins\" on public.docs for delete to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');\n"
        "create function public.wipe_user(target uuid) returns void language plpgsql security definer as $$\n"
        "begin delete from public.docs where owner = target; end; $$;\n"
        "create function public.wipe_mine() returns void language plpgsql security definer as $$\n"
        "begin delete from public.docs where owner = auth.uid(); end; $$;\n"
        "create function public.purge_old() returns void language plpgsql security definer as $$\n"
        "begin delete from public.docs where owner is null; end; $$;\n"
        "create function public.all_docs() returns setof public.docs language sql security definer as $$ select * from public.docs $$;\n"
        "create function public.internal_job(x int) returns void language plpgsql security definer as $$\n"
        "begin delete from public.docs; end; $$;\n"
        "revoke execute on function public.internal_job(int) from public, anon, authenticated;\n"
        "create function public.is_owner(d uuid) returns boolean language sql security definer as $$ select true $$;\n"
        "create policy \"anyone deletes uploads\" on storage.objects for delete to authenticated using (bucket_id = 'uploads');\n"
        "create policy \"own avatars\" on storage.objects for update to authenticated "
        "using (bucket_id = 'avatars' and (select auth.uid())::text = (storage.foldername(name))[1]);\n"
        "create policy \"anon drops\" on storage.objects for insert to anon with check (bucket_id = 'inbox');\n"),
    # plaintext-password, jwt-no-expiry, mass-assignment
    "server/routes/members.js": ('const user = rows[0]\nif (!user || user.password !== req.body.password) return res.sendStatus(401)\n'
                                 'await db.insert({ email, password: req.body.password })\n'
                                 'const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET)\n'
                                 'const ok = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" })\n'
                                 'const ok2 = jwt.sign({ id: user.id, exp: soon }, process.env.JWT_SECRET)\n'
                                 'const me = jwt.verify(req.headers.authorization, process.env.JWT_SECRET)\n'
                                 'await supabase.from("profiles").update(req.body).eq("id", me.id)\n'
                                 'await supabase.from("profiles").update({ name: req.body.name }).eq("id", me.id)\n'),
    "server/routes/hashed.js": ('await db.insert({ email, password: hashed })\nconst hashed = await bcrypt.hash(req.body.password, 12)\n'
                                'if (!(await bcrypt.compare(req.body.password, user.password_hash))) fail()\n'),
    "src/pages/Signup.tsx": "if (form.password !== form.confirmPassword) setError(\"no match\")\n",
    # ai-open-proxy
    "server/ai.js": ('export async function ask(req) {\n  return openai.chat.completions.create({\n    model: req.body.model,\n'
                     '    messages: req.body.messages,\n  })\n}\n'),
    "server/ai-safe.js": ('export async function ask(req) {\n  return openai.chat.completions.create({\n    model: "gpt-4o-mini",\n'
                          '    messages: [{ role: "system", content: "Only summarise." }, { role: "user", content: req.body.text }],\n  })\n}\n'),
    # webhook-unsigned
    "server/webhooks/lemon.js": '// Lemon Squeezy webhook\nexport function handle(event) {\n  if (event.meta.event_name === "order_created") grantAccess(event)\n}\n',
    "server/webhooks/paddle.js": ('// Paddle webhook\nexport async function handle(raw, sig) {\n  const event = await paddle.webhooks.unmarshal(raw, secret, sig)\n'
                                  '  if (event.eventType === "transaction.completed") grantAccess(event)\n}\n'),
    # role read from user_metadata
    "src/pages/Staff.tsx": ('export const Staff = ({ user }) => {\n  const name = user.user_metadata.full_name\n'
                            '  if (user.user_metadata.role === "admin") return <Panel />\n  return <p>{name}</p>\n}\n'),
    # Python CORS
    "api/main.py": ("app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], allow_credentials=True)\n"
                    "app.add_middleware(CORSMiddleware, allow_origins=[\"https://a.com\"], allow_credentials=True)\n"),
    "api/flask_app.py": "CORS(app, supports_credentials=True)\nCORS(app, origins=[\"https://a.com\"], supports_credentials=True)\n",
}
VIBE_EXPECTED = {
    (".env", "frontend-secret:env-file"), ("src/lib/ai.ts", "frontend-secret:code-env"),
    ("src/lib/openai.ts", "frontend-secret:browser-sdk"), ("src/config.ts", "frontend-secret:literal"),
    ("supabase/migrations/001_init.sql", "supabase-rls-off"), ("supabase/migrations/001_init.sql", "supabase-rls-off:open-read"),
    ("supabase/migrations/001_init.sql", "supabase-rls-off:view"),
    ("firestore.rules", "firebase-open-rules:signed-in-other"), ("firestore.rules", "firebase-open-rules:test-mode"),
    ("database.rules.json", "firebase-open-rules"), ("database.rules.json", "firebase-open-rules:signed-in-all"),
    ("src/pages/Admin.tsx", "client-only-auth:storage-flag"), ("src/pages/Admin.tsx", "client-only-auth:guarded-mutation"),
    ("server/app.js", "cors-wildcard:reflect-credentials"), ("server/public.js", "cors-wildcard:wildcard"),
    ("server/app.js", "debug-in-prod:stack"), (".env.production", "debug-in-prod:env"),
    ("src/pages/Search.tsx", "xss-sink"), ("src/pages/Search.tsx", "xss-sink:pattern"),
    ("src/components/Post.tsx", "xss-sink:pattern"), ("src/components/Bio.vue", "xss-sink:pattern"),
    ("server/routes/auth.js", "sql-string-concat"), ("server/routes/auth.js", "sql-string-concat:pattern"),
    ("server/routes/tools.js", "sql-string-concat:pattern"),
    ("server/routes/tools.js", "eval-user-input"), ("server/routes/tools.js", "eval-user-input:command"),
    ("server/routes/auth.js", "no-rate-limit:auth"), ("supabase/functions/summarize/index.ts", "no-rate-limit:ai"),
    ("server/routes/upload.js", "unrestricted-upload:any"), ("server/routes/upload.js", "unrestricted-upload:public"),
    ("supabase/migrations/002_more.sql", "supabase-privilege-escalation"),
    ("supabase/migrations/002_more.sql", "supabase-privilege-escalation:self-update"),
    ("supabase/migrations/002_more.sql", "supabase-privilege-escalation:role-self-grant"),
    ("supabase/migrations/002_more.sql", "supabase-privilege-escalation:metadata-policy"),
    ("supabase/migrations/002_more.sql", "supabase-rpc-exposed"), ("supabase/migrations/002_more.sql", "supabase-rpc-exposed:job"),
    ("supabase/migrations/002_more.sql", "supabase-rpc-exposed:reads"),
    ("supabase/migrations/002_more.sql", "supabase-storage-open"), ("supabase/migrations/002_more.sql", "supabase-storage-open:upload"),
    ("server/routes/members.js", "plaintext-password:compare"), ("server/routes/members.js", "plaintext-password:store"),
    ("server/routes/members.js", "jwt-no-expiry"), ("server/routes/members.js", "mass-assignment"),
    ("server/ai.js", "ai-open-proxy:messages"), ("server/ai.js", "ai-open-proxy:model"),
    ("server/webhooks/lemon.js", "webhook-unsigned"),
    ("src/pages/Staff.tsx", "supabase-privilege-escalation:metadata-code"),
    ("api/main.py", "cors-wildcard:python-credentials"), ("api/flask_app.py", "cors-wildcard:python-credentials"),
}


def _vibe(files):
    """Every VibeGuard rule on a fixture project: Python checks + ast-grep (VibeRules) and the semgrep taint rules."""
    import subprocess
    from scanners import custom_rules
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text.replace("ANON", _jwt("anon")))
    work = Path(tempfile.mkdtemp())
    found = custom_rules.VibeRules().run(root, work)
    r = subprocess.run(["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--config", "rules/vibe-coded.yml", str(root)],
                       capture_output=True, text=True)
    found += [custom_rules.from_semgrep(root, x) for x in json.loads(r.stdout)["results"]]
    return root, found


def test_vibe_rules():
    """Each §7 rule fires on its crafted positive and stays quiet on its negative, with complete report text."""
    import shutil
    if not (shutil.which("ast-grep") and shutil.which("semgrep")):
        return print("   (ast-grep or semgrep not installed, skipped)")
    root, found = _vibe(VIBE_FIXTURE)
    hits = {(f.file, f.raw_rule_id.removeprefix("vibe.").split("@")[0]) for f in found}
    assert hits == VIBE_EXPECTED, f"missing {VIBE_EXPECTED - hits}, unexpected {hits - VIBE_EXPECTED}"
    by = {(f.file, f.raw_rule_id.removeprefix("vibe.").split("@")[0], f.line): f for f in found}
    # the right lines, and nothing from the negatives
    assert {f.line for f in found if f.file == "src/config.ts"} == {1}  # the placeholder on line 2 is ignored
    assert {f.line for f in found if f.file == "src/components/Post.tsx"} == {2}  # sanitized, static and <style> are fine
    assert {f.line for f in found if f.raw_rule_id == "vibe.eval-user-input"} == {2}  # parseInt() sanitizes line 6
    assert {f.line for f in found if f.raw_rule_id == "vibe.eval-user-input:command"} == {9}  # execFile with an array is safe
    assert {f.line for f in found if f.raw_rule_id.startswith("vibe.unrestricted-upload")} == {1, 2}
    assert {f.raw_rule_id.split("@")[1] for f in found if f.raw_rule_id.startswith("vibe.supabase-rls-off")} == {
        "public.orders", "public.profiles", "public.order_totals"}  # notes (own rows), recipes (public data), posts (DO-block RLS) are fine
    # confidence: taint proves reachability; the browser-gated delete on orders is confirmed by the migration (RLS off)
    assert by[("src/pages/Search.tsx", "xss-sink", 4)].confidence == "Confirmed reachable"
    mutation = next(f for f in found if f.raw_rule_id == "vibe.client-only-auth:guarded-mutation")
    assert mutation.line == 5 and mutation.confidence == "Confirmed reachable" and "public.orders" in mutation.explanation
    # the new rules: the right objects and lines, and the negatives stay quiet
    ids = {f.raw_rule_id for f in found}
    assert "vibe.supabase-privilege-escalation@public.handle_new_user" in ids  # 'plan' from sign-up metadata; 'full_name' is fine
    signup = next(f for f in found if f.raw_rule_id == "vibe.supabase-privilege-escalation@public.handle_new_user")
    assert signup.confidence == "Confirmed reachable" and signup.line == 3  # the trigger on auth.users runs it
    assert {i.split("@")[1] for i in ids if i.startswith("vibe.supabase-privilege-escalation:self-update")} == {"public.accounts.plan"}
    assert {i.split("@")[1] for i in ids if i.startswith("vibe.supabase-rpc-exposed")} == {"public.wipe_user", "public.purge_old", "public.all_docs"}
    assert "fn=" not in str(ids) and any("public.wipe_user(uuid)" in f.fix_diff for f in found)  # REVOKE needs the argument types
    assert {f.title for f in found if f.raw_rule_id.startswith("vibe.supabase-storage-open")} == {
        "Any signed-in user can overwrite or delete files in the uploads bucket", "Anyone can upload files to the inbox bucket"}
    assert {f.line for f in found if f.file == "server/routes/members.js" and "plaintext" in f.raw_rule_id} == {2, 3}
    assert {f.line for f in found if f.raw_rule_id == "vibe.jwt-no-expiry"} == {4}
    assert {f.line for f in found if f.raw_rule_id == "vibe.mass-assignment"} == {8}
    assert {f.line for f in found if f.raw_rule_id == "vibe.supabase-privilege-escalation:metadata-code"} == {3}
    assert {f.line for f in found if f.file == "api/main.py"} == {1} and {f.line for f in found if f.file == "api/flask_app.py"} == {1}
    lemon = next(f for f in found if f.raw_rule_id == "vibe.webhook-unsigned")
    assert lemon.title.startswith("Lemon Squeezy") and lemon.money_risk and "X-Signature" in lemon.fix_diff
    pw = next(f for f in found if f.raw_rule_id == "vibe.plaintext-password:compare")
    assert "await bcrypt.compare(req.body.password, user.password_hash)" in pw.fix_diff
    assert "{ expiresIn: \"1h\" })" in next(f for f in found if f.raw_rule_id == "vibe.jwt-no-expiry").fix_diff
    # connections: the open table is confirmed (the app ships the URL and anon key), with a read-only check and the browser query
    orders = next(f for f in found if f.raw_rule_id == "vibe.supabase-rls-off@public.orders")
    assert orders.confidence == "Confirmed reachable"
    assert any("curl 'https://abcdefghijklmnop.supabase.co/rest/v1/orders?select=*&limit=1'" in e for e in orders.evidence)
    assert any("src/pages/Admin.tsx:5" in e for e in orders.evidence)
    env_key = next(f for f in found if f.raw_rule_id == "vibe.frontend-secret:env-file")
    assert "Read by browser code at src/lib/ai.ts:1" in env_key.evidence
    sql = next(f for f in found if f.raw_rule_id == "vibe.sql-string-concat")
    assert sql.fix_diff.endswith('db.query("SELECT * FROM users WHERE email = $1", [req.body.email])')
    xss = by[("src/pages/Search.tsx", "xss-sink", 4)]
    assert "+ return <h1>Results for {q}</h1>" in xss.fix_diff
    # every finding is complete, with every catalog {placeholder} filled in
    from scanners.custom_rules import CATALOG, VARIANTS, POLICY_REPROMPT
    templates = [str(x) for spec in [*CATALOG.values(), *VARIANTS.values()] for x in spec.values()] + [POLICY_REPROMPT]
    unfilled = re.compile(r"(?<!\$)\{(" + "|".join({m for t in templates for m in re.findall(r"(?<!\$)\{(\w+)\}", t)}) + r")\}")
    for f in found:
        for field in ("title", "impact", "severity_reason", "explanation", "fix_diff", "reprompt"):
            text = getattr(f, field)
            assert text and not unfilled.search(text), (f.raw_rule_id, field, text)
    dumped = json.dumps([f.model_dump() for f in normalize.normalize(found)])
    assert KEY[:16] not in dumped, "a key leaked into the report"


def test_rate_limit_and_client_code_negatives():
    """A project with a rate limiter has no rate-limit findings; Next.js server components aren't browser code."""
    import shutil
    from scanners.custom_rules import is_browser_code
    if not shutil.which("ast-grep"):
        return print("   (ast-grep not installed, skipped)")
    _, found = _vibe({"package.json": '{"dependencies": {"express-rate-limit": "7"}}',
                      "server/routes/auth.js": 'router.post("/login", (req, res) => res.json({}))\n'})
    assert not [f for f in found if "rate-limit" in f.raw_rule_id]
    assert is_browser_code("src/App.tsx", "", "") and not is_browser_code("src/routes/api.server.ts", "", "")
    assert not is_browser_code("app/page.tsx", "export default function P() {}", "next")
    assert is_browser_code("app/page.tsx", '"use client"\nexport default function P() {}', "next")
    assert not is_browser_code("src/lib/fns.ts", "export const f = createServerFn().handler(() => 1)", "")
    # a Node API with no frontend framework: its src/ is server code, only public/ reaches browsers
    assert not is_browser_code("src/middleware/auth.js", "", "backend") and is_browser_code("public/app.js", "", "backend")


def test_missing_auth_and_passed_checks():
    """App-level reasoning: tokens issued but never verified; server functions writing with the admin client; what passed."""
    import shutil
    if not shutil.which("ast-grep"):
        return print("   (ast-grep not installed, skipped)")
    api = {"server/index.js": 'app.use("/api/auth", require("./routes/auth"))\napp.use("/api/items", require("./routes/items"))\n',
           "server/routes/auth.js": 'router.post("/login", (req, res) => res.json({ token: jwt.sign({ id: 1 }, process.env.S, { expiresIn: "1h" }) }))\n',
           "server/routes/items.js": 'router.get("/", (req, res) => res.json(items))\nrouter.delete("/:id", (req, res) => drop(req.params.id))\n',
           "src/lib/fns.ts": ('export const purge = createServerFn({ method: "POST" }).handler(async () => {\n'
                              '  await supabaseAdmin.from("items").delete().neq("id", 0)\n})\n'
                              'export const guarded = createServerFn({ method: "POST" }).handler(async () => {\n'
                              '  const { userId } = await requireUser()\n  await supabaseAdmin.from("items").delete().eq("owner", userId)\n})\n'
                              'export const list = createServerFn({ method: "GET" }).handler(async () => supabaseAdmin.from("items").select("*"))\n')}
    _, found = _vibe(api)
    unchecked = [f for f in found if f.raw_rule_id == "vibe.missing-auth"]
    assert len(unchecked) == 1 and "GET /api/items" in unchecked[0].evidence[0] and "DELETE /api/items/:id" in unchecked[0].evidence[0]
    assert "/login" not in unchecked[0].evidence[0]
    assert [f.line for f in found if f.raw_rule_id == "vibe.missing-auth:admin-server-fn"] == [1]  # guarded and read-only ones pass
    _, found = _vibe(api | {"server/middleware.js": "module.exports = (req, res, next) => { req.user = jwt.verify(req.headers.authorization, process.env.S); next() }\n"})
    assert not [f for f in found if f.raw_rule_id == "vibe.missing-auth"]
    # a clean Supabase project says what it checked
    from scanners.custom_rules import VibeRules, settle
    root = Path(tempfile.mkdtemp())
    (root / "supabase/migrations").mkdir(parents=True)
    (root / "supabase/migrations/001.sql").write_text(
        "create table public.notes (id uuid primary key, user_id uuid, body text);\nalter table public.notes enable row level security;\n"
        "create policy \"own\" on public.notes for all to authenticated using ((select auth.uid()) = user_id);\n")
    (root / "src").mkdir()
    (root / "src/App.tsx").write_text("export const App = () => <p>hi</p>\n")
    v = VibeRules()
    assert v.run(root, Path(tempfile.mkdtemp())) == []
    passed = settle(v.passed, [])
    assert "Row-Level Security is on for your one table, with no wide-open policies" in passed
    assert "No secret keys in browser code or public env vars" in passed
    # findings from other steps take a check back: a secret gitleaks found in browser code, a SQL injection from taint analysis
    leak = Finding(source="gitleaks", severity="High", title="k", file="src/App.tsx", line=1, kind="secret", cwe=["CWE-798"])
    firebase = Finding(source="gitleaks", severity="Low", title="k", file="src/App.tsx", line=1, kind="secret", cwe=["CWE-798"])
    assert "No secret keys in browser code or public env vars" not in settle(v.passed, [leak])
    assert "No secret keys in browser code or public env vars" in settle(v.passed, [firebase])  # Low: public by design
    (root / "server.js").write_text('db.query("select 1")\n')
    v.run(root, Path(tempfile.mkdtemp()))
    sqli = Finding(source="vibeguard", severity="Critical", title="s", raw_rule_id="vibe.sql-string-concat", file="server.js", line=1)
    assert "SQL queries keep values separate from the query text" in settle(v.passed, [])
    assert "SQL queries keep values separate from the query text" not in settle(v.passed, [sqli])


def test_false_positive_guards():
    """Lookalikes of real bugs stay quiet, and findings describe what the code really does."""
    import shutil
    if not (shutil.which("ast-grep") and shutil.which("semgrep")):
        return print("   (ast-grep or semgrep not installed, skipped)")
    _, found = _vibe({
        "server/a.js": ('const cp = require("child_process")\napp.get("/a", (req, res) => {\n  const m = /^(\\d+)$/.exec(req.query.id)\n'
                        '  cp.exec("ls " + req.query.dir)\n  res.json(m)\n})\n'),
        "server/b.js": ('app.get("/b", (req, res) => {\n  this.db.exec("DELETE FROM t WHERE id = " + req.query.id)\n'
                        '  require("child_process").exec("ls " + req.query.dir)\n})\n'),
        "server/hook.js": ('app.post("/webhook", (req, res) => {\n'
                           '  const sig = crypto.createHmac("sha256", process.env.SECRET).update(req.body).digest("hex")\n})\n'),
        "supabase/migrations/1.sql": (
            "create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin\n"
            "  insert into public.profiles (id, role) values (new.id,\n"
            "    case when new.raw_user_meta_data->>'role' = 'seller' then 'seller' else 'buyer' end);\n  return new; end $$;\n"
            "create trigger t after insert on auth.users for each row execute function public.handle_new_user();\n"
            "create function public.seed_wallet() returns trigger language plpgsql security definer as $$ begin\n"
            "  insert into public.wallets (id, credits) values (new.id, (new.raw_user_meta_data->>'credits')::int);\n  return new; end $$;\n"
            "create policy up on storage.objects for update to anon using (bucket_id = 'avatars' and storage.extension(name) = 'jpg');\n")})
    got = sorted((f.file, f.line, f.raw_rule_id.split("@")[0]) for f in found)
    assert got == [("server/a.js", 4, "vibe.eval-user-input:command"),  # RegExp.exec is neither SQL nor a shell; cp.exec isn't SQL
                   ("server/b.js", 2, "vibe.sql-string-concat"), ("server/b.js", 2, "vibe.sql-string-concat:pattern"),
                   ("server/b.js", 3, "vibe.eval-user-input:command"),
                   ("supabase/migrations/1.sql", 7, "vibe.supabase-privilege-escalation"),  # buyer/seller choice is fine; credits aren't
                   ("supabase/migrations/1.sql", 9, "vibe.supabase-storage-open")], got  # the HMAC of the body isn't mass assignment
    titles = {f.title for f in found}
    assert {"Anyone can sign up with any number of credits", "Anyone can overwrite or delete files in the avatars bucket"} <= titles
    # a Python-only project still gets its structural rules (ast-grep used to run only when there was JS/TS)
    from scanners.custom_rules import VibeRules
    root = Path(tempfile.mkdtemp())
    (root / "main.py").write_text('app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n')
    assert [f.raw_rule_id for f in VibeRules().run(root, Path(tempfile.mkdtemp()))] == ["vibe.cors-wildcard:python-credentials"]
    # two open collections are two cards, each titled with its own collection
    (root / "firestore.rules").write_text("service cloud.firestore {\n  match /databases/{database}/documents {\n"
                                          "    match /users/{id} { allow read: if true; }\n    match /messages/{id} { allow read: if true; }\n  }\n}\n")
    cards = normalize.normalize(VibeRules().run(root, Path(tempfile.mkdtemp())))
    assert {f.title for f in cards if f.file == "firestore.rules"} == {"Anyone can read users in Firebase", "Anyone can read messages in Firebase"}


def test_hostile_files_finish_fast():
    """Files built to make our own parsers crawl (each one used to hang a scan for minutes) or crash them."""
    import time
    from scanners import npm_deps
    from scanners.custom_rules import VibeRules
    root = Path(tempfile.mkdtemp())
    hostile = {"supabase/migrations/1.sql": "insert into storage.buckets (id) values (" + "'a'," * 200_000 + ")\n"
                                            "create policy p on t using (" + "$" * 300_000,
               "firestore.rules": "service cloud.firestore {\n" + "allow read, " * 50_000,
               "database.rules.json": '{"rules": ' + '{"a": ' * 5000 + '{".read": true}' + "}" * 5000 + "}"}
    for name, text in hostile.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    started = time.time()
    found = VibeRules().run(root, Path(tempfile.mkdtemp()))
    assert time.time() - started < 10 and [f.raw_rule_id.split("@")[0] for f in found] == ["vibe.firebase-open-rules"]
    for lock, text in {"package-lock.json": "[" * 100_000, "pnpm-lock.yaml": "importers: x\npackages: [1]\n"}.items():
        (root / lock).write_text(text)
        (root / "package.json").write_text('{"dependencies": {"a": "1"}}')
        assert npm_deps.Project(root).classify("a")[0] in ("runtime-direct", "unknown")  # unreadable, not a crash
        (root / lock).unlink()


def test_scans_run_in_a_child_with_a_time_limit():
    """A scan runs in its own process: a normal one finishes; one past the limit is stopped, fails with a message,
    leaves nothing on disk and frees the slot for the next scan."""
    import os
    import db
    import pipeline
    old_db, old_env, old_ai = db.DB_PATH, os.environ.get("VIBEGUARD_DB"), os.environ.get("TRIAGE_BACKEND")
    db.DB_PATH = os.environ["VIBEGUARD_DB"] = str(Path(tempfile.mkdtemp()) / "t.db")  # the child reads the env var
    os.environ["TRIAGE_BACKEND"] = "off"  # no network in tests
    leftovers = lambda: set(Path(tempfile.gettempdir()).glob("vibeguard-*"))  # noqa: E731
    before = leftovers()
    try:
        db.init()
        db.create_scan("ok", "paste", "a.js", pipeline.initial_steps())
        pipeline.run_scan("ok", "paste", "const k = 1\n", "a.js")
        assert db.get_scan("ok")["status"] == "done", db.get_scan("ok")
        old_limit, pipeline.TIME_LIMIT = pipeline.TIME_LIMIT, 1
        try:
            db.create_scan("slow", "demo", "Demo app", pipeline.initial_steps())
            pipeline.run_scan("slow", "demo", None)
        finally:
            pipeline.TIME_LIMIT = old_limit
        scan = db.get_scan("slow")
        assert scan["status"] == "failed" and "took longer" in scan["error"], scan
        assert not any(s["state"] == "running" for s in scan["steps"]) and leftovers() == before
        assert pipeline._slot.acquire(blocking=False)
        pipeline._slot.release()
    finally:
        db.DB_PATH = old_db
        os.environ.pop("TRIAGE_BACKEND") if old_ai is None else os.environ.__setitem__("TRIAGE_BACKEND", old_ai)
        if old_env is None:
            os.environ.pop("VIBEGUARD_DB")
        else:
            os.environ["VIBEGUARD_DB"] = old_env


def test_ai_review_guardrails():
    """The AI reviewer (offline: a fake model) can only change what its guardrails allow, sees no secrets, and a broken
    answer leaves the report as the scanners wrote it."""
    import os
    import triage
    root = Path(tempfile.mkdtemp())
    (root / "api").mkdir()
    key = "sk-proj-" + "Zx8Qw2Er4Ty6" * 4
    (root / "api/app.js").write_text("".join(f"// line {n}\n" for n in range(1, 10)) +
                                     f'const OPENAI = "{key}"\nconst token = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9"\n'
                                     'app.get("/q", (req, res) => db.query("SELECT * FROM t WHERE id = " + req.query.id))\n')
    mk = lambda **kw: Finding(**{"source": "semgrep", "severity": "High", "title": "t", "file": "api/app.js", "line": 12, **kw})  # noqa: E731
    noise = mk(confidence="Needs review", raw_rule_id="a")
    sqli = mk(raw_rule_id="b", explanation="rule-speak")
    vague = mk(confidence="Needs review", raw_rule_id="c", fix_diff="kept")
    proven = mk(confidence="Confirmed reachable", raw_rule_id="d")
    dep = mk(kind="dependency", raw_rule_id="e", package="x@1")
    invented = mk(source="bandit", raw_rule_id="f")
    sent = []

    class Fake:
        model = "fake"

        def __init__(self, answer):
            self.answer = answer

        def complete(self, system, user, max_tokens):
            sent.append(user)
            ids = [i["id"] for i in json.loads(user)["findings"]]
            return self.answer(ids) if callable(self.answer) else self.answer

    line = 'app.get("/q", (req, res) => db.query("SELECT * FROM t WHERE id = " + req.query.id))'
    answers = lambda ids: json.dumps({"results": [  # noqa: E731
        {"id": ids[1], "verdict": "false_positive", "line": 12, "severity": "Low", "reason": "Only a constant reaches it."},
        {"id": ids[0], "verdict": "real", "line": 12, "severity": "Low", "reason": "The id comes straight from the URL.",
         "explanation": "The query text includes whatever the visitor puts in ?id=, so they can add their own SQL to it.",
         "fix": f'- {line}\n+ app.get("/q", (req, res) => db.query("SELECT * FROM t WHERE id = $1", [req.query.id]))'},
        {"id": ids[2], "verdict": "real", "line": 99, "severity": "Critical", "reason": "Probably exploitable."},
        {"id": ids[3], "verdict": "real", "line": 12, "severity": "High", "reason": "Real.", "fix": "- db.run(evil)\n+ db.run(good)"},
    ]})
    findings = [sqli, noise, vague, invented, proven, dep]
    assert triage.triage(findings, root, {key}, Fake(answers)) == ("done", "4 findings reviewed")
    assert noise.is_false_positive and noise.ai_verdict == "false_positive" and noise.ai_note == "Only a constant reaches it."
    assert sqli.severity == "Medium" and "Rated medium" in sqli.ai_note  # asked for Low: one level at most
    assert sqli.explanation.startswith("The query text") and sqli.fix_diff.startswith("- app.get")  # its removed line exists
    assert vague.ai_verdict == "unsure" and vague.confidence == "Needs review" and vague.severity == "High"  # cited a line it wasn't shown
    assert invented.ai_verdict == "real" and invented.fix_diff == ""  # removes a line that isn't in the code
    assert not proven.ai_verdict and not dep.ai_verdict and len(json.loads(sent[0])["findings"]) == 4  # never sent
    assert key[:12] not in "".join(sent) and "aB3dE5fG7hJ9" not in "".join(sent)  # known secret and key-shaped strings masked
    # a model that keeps answering garbage changes nothing, and says so
    fresh = mk(confidence="Needs review", raw_rule_id="g")
    assert triage.triage([fresh], root, set(), Fake("not json")) == ("failed", "the AI reviewer didn't answer")
    assert not fresh.ai_verdict and fresh.severity == "High" and not fresh.is_false_positive
    old = {k: os.environ.get(k) for k in ("TRIAGE_BACKEND", "GROQ_API_KEY", "LLM_API_KEY")}
    try:
        os.environ["TRIAGE_BACKEND"] = "off"
        assert triage.triage([fresh], root, set()) == ("skipped", "turned off")
        os.environ["TRIAGE_BACKEND"] = "groq"
        os.environ.pop("GROQ_API_KEY", None), os.environ.pop("LLM_API_KEY", None)
        assert triage.triage([fresh], root, set()) == ("skipped", "no API key set")
    finally:
        for k, v in old.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_report_exports():
    """The summary leads with the worst, Markdown reads as a report, SARIF is what GitHub code scanning expects,
    and an upload without a length is refused before anything is written to disk."""
    import export
    crit = _f(severity="Critical", title="Key exposed", impact="Anyone can use it.", confidence="Likely", fix_diff="- a\n+ b",
              reprompt="Move the key.", raw_rule_id="vibe.x", cwe=["CWE-798"])
    low = _f(severity="Low", title="Hygiene", raw_rule_id="y", file="ci.yml", line=0)
    noise = _f(severity="High", title="Placeholder", is_false_positive=True, ai_note="It's an example value.", raw_rule_id="z")
    s = export.summary([low, noise, crit])
    assert s["top"] == [crit.id, low.id] and "1 critical issue first" in s["verdict"]
    assert export.summary([])["verdict"] == "No issues found in what we checked."
    scan = {"source_label": "demo", "source_type": "demo", "risk_score": 60, "created_at": "now",
            "steps": [{"label": "VibeGuard rules", "state": "done", "note": "1 finding", "passed": ["RLS is on"]},
                      {"label": "AI review", "state": "skipped", "tool": "groq", "note": "turned off"}]}
    md = export.markdown(scan, "D", [crit, low, noise])
    for part in ("**Grade D**", "## This could hurt you", "1. **Key exposed** (Critical). Anyone can use it.", "```diff\n- a\n+ b",
                 "> Move the key.", "## Already right", "- RLS is on", "Placeholder (", "It's an example value.", "- AI review (groq): turned off"):
        assert part in md, part
    run = export.sarif([crit, low, noise])["runs"][0]
    results = {r["ruleId"]: r for r in run["results"]}
    assert results["vibe.x"]["level"] == "error" and results["vibe.x"]["locations"][0]["physicalLocation"]["region"]["startLine"] == crit.line
    assert "region" not in results["y"]["locations"][0]["physicalLocation"] and results["z"]["suppressions"][0]["justification"]
    assert next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "vibe.x")["properties"]["security-severity"] == "9.5"
    from fastapi.testclient import TestClient
    import main
    r = TestClient(main.app).post("/scan", content=b"x", headers={"content-type": "multipart/form-data; boundary=b", "transfer-encoding": "chunked"})
    assert r.status_code == 411, r.status_code


def test_supabase_sql_reader():
    from scanners import supabase_sql as q
    sql = ("-- comment ; with a semicolon\ncreate table if not exists \"public\".\"Items\" (id int);\n"
           "create function f() returns void as $$ begin perform 1; end $$ language plpgsql;\n"
           "ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;\n"
           "CREATE POLICY \"x\" ON public.items AS RESTRICTIVE FOR UPDATE TO anon USING (true);\n"
           "create policy y on items for insert to authenticated with check (auth.uid() is not null);\n"
           "create table public.secret (id int);\nrevoke all on public.secret from anon, authenticated;\n")
    t = q.read([("m.sql", sql)]).tables
    items = t["public.items"]
    assert items.rls and items.line == 2 and set(items.policies) == {"x", "y"}
    assert q.who(items.policies["x"]) is None  # restrictive policies only narrow access
    assert q.who(items.policies["y"]) == "signed-in"
    assert not q.exposed(t["public.secret"])  # revoked from the API roles
    fns = q.read([("f.sql", "create or replace function public.f(target uuid, note text default null) returns void language plpgsql "
                            "security definer as $$ begin delete from x where id = target; end $$;\n"
                            "revoke execute on function public.f(uuid, text) from public, anon;\n")]).functions
    assert fns["public.f"].args == "uuid, text" and fns["public.f"].definer and fns["public.f"].revoked == {"public", "anon"}
    t = q.read([("g.sql", "create table a (id int, name text, role text);\ngrant update (name) on a to authenticated;\n"
                          "create table b (id int, name text, role text);\nrevoke update on b from authenticated;\n"
                          "grant update (name) on b to authenticated;\n"
                          "create table c (id int);\nrevoke update, delete on c from anon, authenticated;\n"
                          "create table d (id int);\nrevoke all on d from public, authenticated;\n"
                          "create table e (id int, status text);\nalter table e enable row level security;\n"
                          "create policy p on e for update using (status = 'up to date' or true);\n")]).tables
    assert t["public.a"].update_cols == {}  # a column grant alone narrows nothing: authenticated can still update every column
    assert t["public.b"].update_cols == {"authenticated": {"name"}}
    assert q.exposed(t["public.c"]) and q.exposed(t["public.d"])  # still readable; anon keeps its direct grant
    assert t["public.e"].policies["p"].roles == {"public"}  # "to" inside the USING expression isn't a TO clause


def test_zizmor_bandit_lockfile_lint():
    from scanners.bandit import Bandit
    from scanners.lockfile_lint import LockfileLint
    from scanners.zizmor import Zizmor
    if Zizmor().available():
        wf = ("on:\n  pull_request_target:\n  issues:\njobs:\n  greet:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - uses: actions/checkout@v4\n      - run: echo \"${{ github.event.issue.title }}\"\n")
        _, out = _run(Zizmor(), {".github/workflows/triage.yml": wf})
        sev = {f.raw_rule_id: f.severity for f in out}
        assert sev["zizmor.template-injection"] == "High" and sev["zizmor.dangerous-triggers"] == "High"
        assert sev["zizmor.unpinned-uses"] == "Low"  # hygiene
        assert Zizmor().skip(Path(tempfile.mkdtemp())) == ("na", "no GitHub workflows")
    if Bandit().available():
        app = ('import subprocess, yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n'
               '@app.route("/r")\ndef r():\n    return subprocess.check_output("ls " + request.args["d"], shell=True)\n'
               'def load(data):\n    return yaml.load(data, Loader=yaml.Loader)\n')
        noise = "import random\nassert random.random() < 2\ntry:\n    pass\nexcept Exception:\n    pass\n"
        _, out = _run(Bandit(), {"api/app.py": app, "api/util.py": noise, "tests/test_app.py": app})
        assert {(f.file, f.cwe[0]) for f in out} == {("api/app.py", "CWE-78"), ("api/app.py", "CWE-502")}, [(f.file, f.cwe) for f in out]
    if LockfileLint().available():
        lock = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"sw-cjs": "npm:string-width@4"}},
            "node_modules/left-pad": {"version": "1.3.0", "resolved": "http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                                      "integrity": "sha512-" + "A" * 86 + "=="},
            "node_modules/sw-cjs": {"version": "4.2.3", "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
                                    "integrity": "sha512-" + "B" * 86 + "=="}}}
        _, out = _run(LockfileLint(), {"package-lock.json": json.dumps(lock, indent=2)})
        assert [(f.raw_rule_id, f.severity) for f in out] == [("lockfile-lint.protocol", "Medium")], [f.raw_rule_id for f in out]
        assert out[0].line > 0 and "left-pad" in out[0].explanation


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)

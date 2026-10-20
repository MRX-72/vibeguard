"""Self-checks. Run: .venv/bin/python test_vibeguard.py  (pytest also works)."""

import json
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


def test_scanners_on_sample_repo():
    """Integration: whatever scanners are installed must find the planted issues, and never leak a secret."""
    installed = [s for s in (cls() for cls in SCANNERS) if s.available()]
    if not installed:
        print("   (no scanners installed, skipped)")
        return
    with ingest.sandbox("demo", None) as root:
        work = root.parent / "work"
        work.mkdir()
        raw = [f for s in installed for f in s.run(root, work)]
        env_secrets = [line.split("=", 1)[1] for line in (root / ".env").read_text().splitlines() if "KEY=" in line]
        out = normalize.normalize(raw)
    names = {s.name for s in installed}
    by = {(f.file, f.line): f for f in out}
    if "gitleaks" in names:
        assert by[(".env", 3)].severity == "Critical" and "service_role" in by[(".env", 3)].title
        assert by[(".env", 2)].is_false_positive  # anon key
        assert ("src/lib/ai.js", 5) in by
    if "semgrep" in names:
        assert by[("server/routes/calc.js", 5)].cwe == ["CWE-95"]
    if "osv-scanner" in names:
        axios = next(f for f in out if f.package == "axios@0.21.1")
        assert axios.file == "package.json" and axios.fix_diff.startswith('- "axios": "^0.21.1"')
    dumped = json.dumps([f.model_dump() for f in out])
    for secret in env_secrets:
        assert secret[:20] not in dumped, "a secret value leaked into the report"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)

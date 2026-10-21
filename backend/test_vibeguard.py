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
DEMO = {
    (".env", 3, "Critical"), (".env", 4, "High"), ("src/lib/ai.js", 5, "High"),  # service_role + OpenAI keys
    ("server/routes/auth.js", 10, "High"),  # JWT signing secret
    ("server/routes/calc.js", 5, "High"),  # eval
    ("server/routes/billing.js", 8, "High"),  # unsigned Stripe webhook (ast-grep)
    ("supabase/functions/delete-account/index.ts", 12, "High"),  # service-role Edge Function with no caller check (ast-grep)
}
DEMO_NOISE = {(".env", 2), ("server/index.js", 4)}  # anon key (public by design), CSRF in an app without cookies
DEMO_DEPS = {"axios@0.21.1", "express@4.17.1", "jsonwebtoken@8.5.1", "lodash@4.17.15", "multer@1.4.2"}


def test_scanners_on_sample_repo():
    """Integration: the demo app's report is exactly what we expect, and never leaks a secret."""
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
    if {"gitleaks", "semgrep", "osv-scanner", "ast-grep"} <= names:
        code = {(f.file, f.line, f.severity) for f in out if f.kind != "dependency" and not f.is_false_positive}
        expected = DEMO | ({("server/index.js", 9, "Medium")} if "njsscan" in names else set())  # wildcard CORS (njsscan only, until Phase 4)
        assert code == expected, f"missing {expected - code}, unexpected {code - expected}"
        assert {(f.file, f.line) for f in out if f.is_false_positive} == DEMO_NOISE
        assert {f.package for f in out if f.kind == "dependency"} == DEMO_DEPS
    if "gitleaks" in names:
        assert "service_role" in by[(".env", 3)].title and by[(".env", 2)].is_false_positive
    if "semgrep" in names:
        assert by[("server/routes/calc.js", 5)].cwe == ["CWE-95"]
        assert by[("server/routes/auth.js", 10)].title == "JWT signing secret in code"
    if "osv-scanner" in names:
        axios = next(f for f in out if f.package == "axios@0.21.1")
        assert axios.file == "package.json" and axios.fix_diff.startswith('- "axios": "^0.21.1"')
    if "ast-grep" in names:
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


def test_ast_grep_rules():
    """Each structural rule fires on its crafted positive and stays quiet on its negative."""
    from scanners.astgrep import AstGrep
    if not AstGrep().available():
        return print("   (ast-grep not installed, skipped)")
    edge = 'Deno.serve(async (req) => {{\n  {check}\n  const db = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!)\n}})\n'
    hook = 'app.post("/hook", async (req, res) => {{\n  {check}\n  if (event.type === "checkout.session.completed") grant(event)\n}})\n'
    _, out = _run(AstGrep(), {
        "supabase/functions/open/index.ts": edge.format(check=""),
        "supabase/functions/checked/index.ts": edge.format(check="const { data: { user } } = await anon.auth.getUser()"),
        "supabase/functions/internal/index.ts": edge.format(check='if (req.headers.get("Authorization") !== expected) return'),
        "app/api/me/route.ts": "export async function GET() {\n  const { data } = await supabase.auth.getSession()\n}\n",
        "src/lib/session.ts": "export const token = () => supabase.auth.getSession()\n",  # browser code: fine
        "src/routes/fn.tsx": "export const f = createServerFn().handler(async () => {\n  await supabase.auth.getSession()\n})\n",
        "src/actions.ts": "'use server'\nexport async function save() {\n  await supabase.auth.getSession()\n}\n",
        "server/hook.js": hook.format(check="const event = req.body"),
        "server/hook-ok.js": hook.format(check='const event = stripe.webhooks.constructEvent(raw, req.headers["stripe-signature"], secret)'),
    })
    hits = {(f.file, f.raw_rule_id.split(".")[-1]) for f in out}
    assert hits == {
        ("supabase/functions/open/index.ts", "supabase-edge-service-role-no-auth"),
        ("app/api/me/route.ts", "supabase-getsession-on-server"),
        ("src/routes/fn.tsx", "supabase-getsession-in-server-fn"),
        ("src/actions.ts", "supabase-getsession-in-server-fn"),
        ("server/hook.js", "stripe-webhook-unsigned"),
    }, hits
    assert all(f.explanation and f.impact and f.fix_diff and f.reprompt and f.cwe for f in out)


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

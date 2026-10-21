import logging
import multiprocessing
import shutil
import tempfile
import threading
from pathlib import Path

import db
import ingest
import normalize
import scoring
from scanners import ALL as SCANNERS
from scanners.base import ScannerError
from scanners.custom_rules import settle

log = logging.getLogger("vibeguard")


def initial_steps():
    return [{"key": "ingest", "label": "Preparing code", "state": "pending"}] + [
        {"key": s.name, "label": s.label, "tool": s.name, "state": "pending"} for s in SCANNERS
    ]


# ponytail: one scan at a time keeps a 512 MB Render instance alive; a real queue when there's real traffic
_slot = threading.Semaphore(1)
TIME_LIMIT = 15 * 60  # every tool has its own timeout; this catches our own Python stuck on a pathological file
CRASHED = "Something went wrong on our side while scanning. Try again in a minute."


def run_scan(scan_id, source_type, payload, label=None, verify_secrets=False):
    """Run one scan in a child process, so a scan that hangs can be stopped instead of holding the only slot forever."""
    with _slot:
        base = tempfile.mkdtemp(prefix="vibeguard-")
        child = multiprocessing.get_context("spawn").Process(  # spawn: forking a threaded server can deadlock
            target=_scan, args=(scan_id, source_type, payload, label, verify_secrets, base), daemon=True)
        child.start()
        child.join(TIME_LIMIT)
        stuck = child.is_alive()
        if stuck:
            # ponytail: a tool still running at this moment finishes on its own (each has its own timeout)
            child.kill()
            child.join()
        shutil.rmtree(base, ignore_errors=True)  # a killed child never cleans up its sandbox
        if isinstance(payload, Path):
            payload.unlink(missing_ok=True)
        scan = db.get_scan(scan_id)
        if scan and scan["status"] not in ("done", "failed"):
            log.error("scan %s %s", scan_id, "hit the time limit" if stuck else f"child exited with {child.exitcode}")
            steps = [s | {"state": "failed"} if s["state"] == "running" else s for s in scan["steps"]]
            error = f"This scan took longer than {TIME_LIMIT // 60} minutes, so we stopped it." if stuck else CRASHED
            db.update_scan(scan_id, status="failed", stage="Failed", steps=steps, error=error)


def _scan(scan_id, source_type, payload, label, verify_secrets, base):
    steps = initial_steps()
    try:
        db.update_scan(scan_id, status="running", stage="Preparing code…", steps=_set(steps, "ingest", "running"))
        with ingest.sandbox(source_type, payload, label, base) as root:
            n = sum(1 for p in root.rglob("*") if p.is_file())
            if not n:
                raise ingest.IngestError("There are no files to scan.")
            _set(steps, "ingest", "done", f"{n:,} file{'s' * (n != 1)}")
            work = root.parent / "work"
            work.mkdir()
            raw, scanners = [], [s(verify_secrets=verify_secrets) for s in SCANNERS]
            for scanner in scanners:
                raw += _run_one(scan_id, scanner, root, work, steps)
            if not any(s["state"] == "done" for s in steps[1:]):
                # an empty report here would read as "all clear", which would be a lie
                raise ingest.IngestError("None of the scanners could run on this server, so nothing was checked. Try again later.")
            findings = normalize.normalize(raw)
            for scanner, step in zip(scanners, steps[1:], strict=True):
                if scanner.passed and step["state"] == "done":  # "already right" only where the final report agrees
                    step["passed"] = settle(scanner.passed, findings)
        db.save_findings(scan_id, findings)
        db.update_scan(scan_id, status="done", stage="Done", steps=steps, risk_score=scoring.risk_score(findings))
    except Exception as e:  # any failure must still end the job, never leave it "running"
        if not isinstance(e, ingest.IngestError):
            log.exception("scan %s failed", scan_id)
        for s in steps:
            if s["state"] == "running":
                s["state"] = "failed"
        error = str(e) if isinstance(e, ingest.IngestError) else CRASHED
        db.update_scan(scan_id, status="failed", stage="Failed", steps=steps, error=error)


def _run_one(scan_id, scanner, root, work, steps):
    """Fail soft (§9 phase 3): a missing or broken scanner is noted in the report, never fatal."""
    skip = scanner.skip(root)  # not installed, turned off, or nothing for it to check (no Python files…)
    if skip:
        _set(steps, scanner.name, *skip)
        return []
    db.update_scan(scan_id, stage=scanner.label + "…", steps=_set(steps, scanner.name, "running"))
    try:
        found = scanner.run(root, work)
    except ScannerError as e:
        _set(steps, scanner.name, "failed", f"didn't finish ({e})")
        return []
    except Exception:
        log.exception("%s crashed", scanner.name)
        _set(steps, scanner.name, "failed", "didn't finish (unexpected error)")
        return []
    _set(steps, scanner.name, "done", f"{len(found)} finding{'s' * (len(found) != 1)}", checked=scanner.checked)
    return found


def _set(steps, key, state, note=None, **extra):
    for s in steps:
        if s["key"] == key:
            s["state"] = state
            if note:
                s["note"] = note
            s.update({k: v for k, v in extra.items() if v})
    return steps

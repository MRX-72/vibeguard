import logging
import threading

import db
import ingest
import normalize
import scoring
from scanners import ALL as SCANNERS
from scanners.base import ScannerError

log = logging.getLogger("vibeguard")


def initial_steps():
    return [{"key": "ingest", "label": "Preparing code", "state": "pending"}] + [
        {"key": s.name, "label": s.label, "tool": s.name, "state": "pending"} for s in SCANNERS
    ]


# ponytail: one scan at a time keeps a 512 MB Render instance alive; a real queue when there's real traffic
_slot = threading.Semaphore(1)


def run_scan(scan_id, source_type, payload, label=None, verify_secrets=False):
    steps = initial_steps()
    with _slot:
        try:
            db.update_scan(scan_id, status="running", stage="Preparing code…", steps=_set(steps, "ingest", "running"))
            with ingest.sandbox(source_type, payload, label) as root:
                n = sum(1 for p in root.rglob("*") if p.is_file())
                if not n:
                    raise ingest.IngestError("There are no files to scan.")
                _set(steps, "ingest", "done", f"{n:,} file{'s' * (n != 1)}")
                work = root.parent / "work"
                work.mkdir()
                raw = []
                for scanner in SCANNERS:
                    raw += _run_one(scan_id, scanner(verify_secrets=verify_secrets), root, work, steps)
                if not any(s["state"] == "done" for s in steps[1:]):
                    # an empty report here would read as "all clear", which would be a lie
                    raise ingest.IngestError("None of the scanners could run on this server, so nothing was checked. Try again later.")
                findings = normalize.normalize(raw)
            db.save_findings(scan_id, findings)
            db.update_scan(scan_id, status="done", stage="Done", steps=steps, risk_score=scoring.risk_score(findings))
        except Exception as e:  # any failure must still end the job, never leave it "running"
            if not isinstance(e, ingest.IngestError):
                log.exception("scan %s failed", scan_id)
            for s in steps:
                if s["state"] == "running":
                    s["state"] = "failed"
            error = str(e) if isinstance(e, ingest.IngestError) else "Something went wrong on our side while scanning. Try again in a minute."
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

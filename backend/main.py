import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.datastructures import UploadFile

import db
import export
import ingest
import pipeline
import scoring
from models import SEVERITIES, Finding

MAX_WAITING = 8


@asynccontextmanager
async def lifespan(app):
    db.init()
    yield


app = FastAPI(title="VibeGuard", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()],
    allow_methods=["GET", "POST"],
)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/scan")
async def create_scan(request: Request, background: BackgroundTasks):
    # browsers always send a length with a form; without one (chunked) the 50 MB cap couldn't apply until the disk filled
    if "content-length" not in request.headers:
        raise HTTPException(411, "Send the request with a Content-Length header.")
    if int(request.headers["content-length"]) > ingest.MAX_BYTES + 1024 * 1024:
        raise HTTPException(413, "Uploads are limited to 50 MB.")
    # ponytail: one global cap; per-IP limits if one visitor starts hogging the queue
    if db.active_scans() >= MAX_WAITING:  # scans run one at a time, and each waiting upload sits on disk
        raise HTTPException(429, "Too many scans are waiting right now. Try again in a few minutes.")
    form = await request.form(max_files=1, max_fields=5)
    source_type = form.get("source_type")
    payload = form.get("payload")
    if isinstance(payload, UploadFile):
        # spool to disk, not memory: the scan runs after this request (and its upload) is gone
        fd, path = tempfile.mkstemp(suffix=".zip")
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(payload.file, out)
        payload = Path(path)
    try:
        payload, label = ingest.validate(source_type, payload, form.get("filename"))
    except ingest.IngestError as e:
        if isinstance(payload, Path):
            payload.unlink(missing_ok=True)
        raise HTTPException(400, str(e)) from None
    if source_type == "zip":
        label = getattr(form.get("payload"), "filename", None) or "upload.zip"
    scan_id = str(uuid4())
    db.create_scan(scan_id, source_type, label, pipeline.initial_steps())
    # opt-in: testing found keys sends them to their providers (§20)
    verify = form.get("verify_secrets") in ("1", "true", "on")
    background.add_task(pipeline.run_scan, scan_id, source_type, payload, label, verify)
    return {"scan_id": scan_id}


def _scan_or_404(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found. Reports are kept only until the server restarts.")
    return scan


@app.get("/scan/{scan_id}/status")
def scan_status(scan_id: str):
    s = _scan_or_404(scan_id)
    return {k: s[k] for k in ("status", "stage", "risk_score", "steps", "error")}


def _report(scan_id):
    scan = _scan_or_404(scan_id)
    findings = [Finding.model_validate(r) for r in db.get_findings(scan_id)]
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.file, f.line))
    score = scan["risk_score"]
    return scan, scoring.grade(score) if score is not None else None, findings


@app.get("/scan/{scan_id}")
def scan_report(scan_id: str):
    scan, grade, findings = _report(scan_id)
    return {"scan": scan, "grade": grade, "summary": export.summary(findings), "findings": [f.model_dump() for f in findings]}


def _done(scan_id):
    scan, grade, findings = _report(scan_id)
    if scan["status"] != "done":
        raise HTTPException(409, "The scan hasn't finished yet.")
    return scan, grade, findings


@app.get("/scan/{scan_id}/report.md")
def report_markdown(scan_id: str):
    scan, grade, findings = _done(scan_id)
    return PlainTextResponse(export.markdown(scan, grade, findings), media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="vibeguard-{scan_id[:8]}.md"'})


@app.get("/scan/{scan_id}/report.sarif")
def report_sarif(scan_id: str):
    _, _, findings = _done(scan_id)
    return JSONResponse(export.sarif(findings), media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="vibeguard-{scan_id[:8]}.sarif"'})

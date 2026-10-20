import os
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import UploadFile

import db
import pipeline
import scoring
from models import SEVERITIES, Finding

SOURCE_TYPES = {"paste", "zip", "github", "demo"}


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
    form = await request.form()
    source_type = form.get("source_type")
    if source_type not in SOURCE_TYPES:
        raise HTTPException(400, "source_type must be one of: paste, zip, github, demo")
    payload = form.get("payload")
    if isinstance(payload, UploadFile):
        payload = await payload.read()
    scan_id = str(uuid4())
    db.create_scan(scan_id, source_type, None, pipeline.initial_steps())
    background.add_task(pipeline.run_scan, scan_id, source_type, payload, form.get("filename"))
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


@app.get("/scan/{scan_id}")
def scan_report(scan_id: str):
    scan = _scan_or_404(scan_id)
    findings = [Finding.model_validate(r) for r in db.get_findings(scan_id)]
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.file, f.line))
    score = scan["risk_score"]
    return {
        "scan": scan,
        "grade": scoring.grade(score) if score is not None else None,
        "findings": [f.model_dump() for f in findings],
    }

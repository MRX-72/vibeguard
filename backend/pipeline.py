import time
from uuid import uuid4

import db
import scoring
from models import Finding

STEPS = [
    ("ingest", "Preparing code"),
    ("secrets", "Scanning for secrets"),
    ("deps", "Checking dependencies"),
    ("sast", "Static analysis"),
    ("vibe", "Vibe-coded checks"),
    ("triage", "AI triage"),
]


def initial_steps():
    return [{"key": k, "label": label, "state": "pending"} for k, label in STEPS]


# ponytail: phase 1 stub, replaced by real scanners in phase 3
FAKE = [
    Finding(source="custom", severity="Critical", title="OpenAI key shipped to the browser", file="src/lib/ai.js", line=3,
            code_snippet='const openai = new OpenAI({ apiKey: "sk-proj-Ab12••••••••", dangerouslyAllowBrowser: true })',
            raw_rule_id="vibe.frontend-secret", money_risk=True,
            impact="Anyone who opens your site can copy this key and run up your OpenAI bill."),
    Finding(source="custom", severity="Critical", title="SQL query built from user input", file="server/routes/users.js", line=14,
            code_snippet="db.query(`SELECT * FROM users WHERE email = '${req.query.email}'`)", raw_rule_id="vibe.sql-string-concat",
            impact="An attacker can read or delete every row in your database by typing SQL into a form field."),
    Finding(source="custom", severity="High", title="User HTML rendered without sanitizing", file="src/components/Comment.jsx", line=8,
            code_snippet="<div dangerouslySetInnerHTML={{ __html: comment.body }} />", raw_rule_id="vibe.xss-sink",
            impact="A malicious comment can run JavaScript in every visitor's browser and steal their session."),
    Finding(source="custom", severity="High", title="CORS allows any website", file="server/index.js", line=6,
            code_snippet="app.use(cors())", raw_rule_id="vibe.cors-wildcard",
            impact="Any website can call your API from a visitor's browser."),
]


def run_scan(scan_id, source_type, payload, filename=None):
    steps = initial_steps()
    try:
        db.update_scan(scan_id, status="running")
        for step in steps:
            step["state"] = "running"
            db.update_scan(scan_id, stage=step["label"] + "…", steps=steps)
            time.sleep(0.6)
            step["state"] = "done"
        findings = [f.model_copy(update={"id": str(uuid4())}) for f in FAKE]
        db.save_findings(scan_id, findings)
        db.update_scan(scan_id, status="done", stage="Done", steps=steps, risk_score=scoring.risk_score(findings))
    except Exception as e:  # any failure must still end the job, never leave it "running"
        db.update_scan(scan_id, status="failed", stage="Failed", steps=steps, error=str(e))

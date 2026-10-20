import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = os.environ.get("VIBEGUARD_DB", str(Path(__file__).parent / "vibeguard.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_label TEXT,
  status TEXT NOT NULL,
  stage TEXT,
  risk_score INTEGER,
  error TEXT,
  steps TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id),
  source TEXT,
  severity TEXT,
  title TEXT,
  file TEXT,
  line INTEGER,
  code_snippet TEXT,
  raw_rule_id TEXT,
  explanation TEXT,
  fix_diff TEXT,
  is_false_positive INTEGER DEFAULT 0,
  severity_reason TEXT,
  impact TEXT,
  money_risk INTEGER DEFAULT 0,
  confidence TEXT,
  reprompt TEXT,
  refs TEXT DEFAULT '[]',
  evidence TEXT DEFAULT '[]',
  triage_note TEXT
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
"""

JSON_COLS = {"steps", "refs", "evidence"}


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with connect() as c:
        c.executescript(SCHEMA)


def _row(r):
    return {k: json.loads(r[k]) if k in JSON_COLS and r[k] else r[k] for k in r.keys()}


def create_scan(scan_id, source_type, source_label, steps):
    with connect() as c:
        c.execute(
            "INSERT INTO scans (id, created_at, source_type, source_label, status, stage, steps) VALUES (?, ?, ?, ?, 'queued', 'Queued', ?)",
            (scan_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), source_type, source_label, json.dumps(steps)),
        )


def update_scan(scan_id, **fields):
    # column names come from our own code, never from user input
    values = [json.dumps(v) if k in JSON_COLS else v for k, v in fields.items()]
    sets = ", ".join(f"{k} = ?" for k in fields)
    with connect() as c:
        c.execute(f"UPDATE scans SET {sets} WHERE id = ?", (*values, scan_id))


def save_findings(scan_id, findings):
    rows = [{**f.model_dump(), "scan_id": scan_id} for f in findings]
    if not rows:
        return
    cols = list(rows[0])
    sql = f"INSERT INTO findings ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
    with connect() as c:
        c.executemany(sql, [[json.dumps(r[k]) if k in JSON_COLS else r[k] for k in cols] for r in rows])


def get_scan(scan_id):
    with connect() as c:
        r = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _row(r) if r else None


def get_findings(scan_id):
    with connect() as c:
        rows = c.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    return [_row(r) for r in rows]

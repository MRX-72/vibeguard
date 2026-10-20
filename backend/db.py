import json
import os
import sqlite3
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
  scanners TEXT DEFAULT '{}'
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

JSON_COLS = {"scanners", "refs", "evidence"}


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with connect() as c:
        c.executescript(SCHEMA)


def _row(r):
    return {k: json.loads(r[k]) if k in JSON_COLS and r[k] else r[k] for k in r.keys()}

from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, PrivateAttr

SEVERITIES = ["Critical", "High", "Medium", "Low"]
Severity = Literal["Critical", "High", "Medium", "Low"]
Confidence = Literal["Confirmed reachable", "Likely", "Needs review"]
Kind = Literal["code", "secret", "dependency", "config"]


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str
    severity: Severity
    title: str
    file: str = ""
    line: int = 0
    code_snippet: str = ""
    raw_rule_id: str = ""
    explanation: str = ""
    fix_diff: str = ""
    is_false_positive: bool = False
    # report fields (§15)
    severity_reason: str = ""
    impact: str = ""
    money_risk: bool = False
    confidence: Confidence = "Likely"
    reprompt: str = ""
    refs: list[str] = []
    evidence: list[str] = []  # source→sink path, one "file:line code" per step
    triage_note: str = ""
    # normalization / dedupe (§16)
    kind: Kind = "code"
    end_line: int = 0
    cwe: list[str] = []  # bare ids, e.g. "CWE-89"
    package: str = ""  # dependency findings: "axios@0.21.1"
    detected_by: list[str] = []  # every scanner that reported this issue
    # the raw secret, only in memory so normalize can mask it everywhere; never dumped or stored
    _secret: str | None = PrivateAttr(default=None)

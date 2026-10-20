"""Download the Semgrep registry packs into rules/registry.json, so scans don't fetch them from the network.

Run at Docker build time (or once locally). Keeps only rules for the languages VibeGuard targets.
Registry rules are under the Semgrep Rules License v1.0, see VibeGuard.md §11.
"""

import json
import sys
import urllib.request
from pathlib import Path

import yaml

PACKS = ["p/default", "p/owasp-top-ten"]
LANGS = {"javascript", "js", "typescript", "ts", "python", "py", "generic", "regex", "json", "yaml", "html", "dockerfile", "bash", "sh"}

rules = {}
for pack in PACKS:
    with urllib.request.urlopen(f"https://semgrep.dev/c/{pack}", timeout=120) as res:
        for rule in yaml.safe_load(res)["rules"]:
            if LANGS & {lang.lower() for lang in rule.get("languages", [])}:
                rules.setdefault(rule["id"], rule)

out = Path(__file__).with_name("registry.json")
out.write_text(json.dumps({"rules": list(rules.values())}))
print(f"wrote {len(rules)} rules to {out}", file=sys.stderr)

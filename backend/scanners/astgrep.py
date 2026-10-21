"""Our own structural rules (rules/ast-grep/rules/*.yml), run with ast-grep: Supabase and Stripe mistakes the
registry rules don't know about. Each rule file carries its report text in `metadata`."""

from pathlib import Path

from models import Finding

from .base import Scanner, cwe_ids, has_files, read_json, rel, snippet
from .semgrep import EXCLUDE

CONFIG = Path(__file__).resolve().parent.parent / "rules" / "ast-grep" / "sgconfig.yml"
JS = ("*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs", "*.mts", "*.cts")


class AstGrep(Scanner):
    name = "ast-grep"
    binary = "ast-grep"
    label = "Supabase and Stripe checks"
    timeout = 60

    def skip(self, root):
        return super().skip(root) if has_files(root, *JS) else ("na", "no JavaScript or TypeScript files")

    def run(self, root, work):
        out = work / "ast-grep.json"
        args = [self.binary, "scan", "--config", str(CONFIG), "--json=compact", "--include-metadata"]
        for pattern in EXCLUDE:  # same "doesn't ship" exclusions as semgrep
            args += ["--globs", f"!**/{pattern}"]
        # exit 1 = a rule with severity "error" matched
        r = self.exec(args + [str(root)], ok=(0, 1))
        out.write_text(r.stdout)
        n = sum(1 for g in JS for p in root.rglob(g) if "node_modules" not in p.parts)
        self.checked = f"{n:,} source file{'s' * (n != 1)}"
        return [self._finding(root, m) for m in read_json(out, [])]

    def _finding(self, root, m):
        meta, file = m.get("metadata") or {}, rel(root, m["file"])
        line, end = m["range"]["start"]["line"] + 1, m["range"]["end"]["line"] + 1
        code, start = snippet(root, file, line, end)
        return Finding(
            source=self.name, severity=meta.get("severity", "Medium"), confidence=meta.get("confidence", "Likely"),
            title=m["message"], file=file, line=line, end_line=end, code_snippet=code, snippet_start=start,
            raw_rule_id=f"vibeguard.{m['ruleId']}", cwe=cwe_ids(meta.get("cwe")), money_risk=bool(meta.get("money_risk")),
            explanation=meta.get("explanation", ""), impact=meta.get("impact", ""), fix_diff=meta.get("fix", ""),
            reprompt=meta.get("reprompt", "").replace("{file}", file), refs=[meta["refs"]] if meta.get("refs") else [],
            severity_reason=meta.get("reason", ""),
        )

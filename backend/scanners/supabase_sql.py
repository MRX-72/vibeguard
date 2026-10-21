"""Reads Supabase migrations into their final state: tables and their Row-Level Security, functions, triggers,
column grants, storage policies and buckets (§7 vibe.supabase-rls-off and the Supabase rules built on it).

Supabase serves every table and view in the `public` schema over its REST API, and the key that calls it ships
in the app's JavaScript. So what protects data is RLS: enabled on the table, with policies narrower than "true".
Migrations replay in filename (timestamp) order; later statements override earlier ones.
"""

import re
from dataclasses import dataclass, field

EXPOSED_SCHEMAS = {"public"}
ANYONE = {"anon", "public"}  # no TO clause means PUBLIC
ALWAYS = {"true", "(true)", "1=1"}
SIGNED_IN = re.compile(r"^\(*(auth\.role\(\)='authenticated'|\(?(select)?auth\.uid\(\)\)?isnotnull|auth\.uid\(\)isnotnull)\)*$")


@dataclass
class Policy:
    name: str
    cmd: str  # all | select | insert | update | delete
    roles: set
    using: str  # normalized expression, "" when absent
    check: str
    permissive: bool
    file: str
    line: int


@dataclass
class Table:
    name: str
    file: str
    line: int
    kind: str = "table"  # or "view"
    rls: bool = False
    toggled: tuple = ()  # (file, line) of the last enable/disable
    invoker: bool = False  # views: security_invoker = true
    revoked: set = field(default_factory=set)  # roles whose access was revoked
    columns: str = ""
    policies: dict = field(default_factory=dict)


@dataclass
class Function:
    name: str
    body: str  # lowercased, whitespace collapsed
    returns: str
    definer: bool  # SECURITY DEFINER: runs with its owner's rights, ignoring RLS
    args: str  # argument types, e.g. "uuid, text" (what REVOKE/GRANT ON FUNCTION need)
    file: str
    line: int
    revoked: set = field(default_factory=set)  # roles whose EXECUTE was revoked


@dataclass
class Schema:
    tables: dict = field(default_factory=dict)  # qualified name -> Table (views included; storage.objects holds storage policies)
    functions: dict = field(default_factory=dict)  # qualified name -> Function (overloads collapse: the last one wins)
    triggers: list = field(default_factory=list)  # (table, timing+events, function, file, line)
    buckets: dict = field(default_factory=dict)  # id -> {"public": bool, "file": , "line": }
    column_grants: dict = field(default_factory=dict)  # (table, role) -> set of columns the role may UPDATE, when limited


def statements(text):
    """(line, statement) with comments blanked, split on ';' outside quotes, quoted identifiers and $$ bodies."""
    out, buf, start, line, i, n = [], [], None, 1, 0, len(text)
    while i < n:
        c = text[i]
        if c == "-" and text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            buf.append(" ")
            i = j
            continue
        if c in "'\"" or (c == "$" and re.match(r"\$\w*\$", text[i:])):
            close = c if c in "'\"" else re.match(r"\$\w*\$", text[i:])[0]
            j = text.find(close, i + len(close))
            j = n if j < 0 else j + len(close)
            if start is None:
                start = line
            buf.append(text[i:j])
            line += text.count("\n", i, j)
            i = j
            continue
        if c == ";":
            if start is not None:
                out.append((start, "".join(buf).strip()))
            buf, start = [], None
        else:
            if start is None and not c.isspace():
                start = line
            buf.append(c)
            line += c == "\n"
        i += 1
    if start is not None and "".join(buf).strip():
        out.append((start, "".join(buf).strip()))
    return out


def _name(raw):
    """'"public"."Profiles"' / 'profiles' -> 'public.profiles' (unqualified names land in public)."""
    parts = [p.strip('"') for p in re.findall(r'"[^"]+"|[^.\s"]+', raw)]
    return ".".join((["public"] if len(parts) == 1 else []) + parts).lower()


def _paren(s, start):
    """The balanced (...) group starting at s[start] == '(' -> its inner text."""
    depth = 0
    for j in range(start, len(s)):
        depth += {"(": 1, ")": -1}.get(s[j], 0)
        if depth == 0:
            return s[start + 1 : j]
    return s[start + 1 :]


def _expr(clause, s):
    m = re.search(rf"\b{clause}\s*\(", s, re.I)
    return re.sub(r"\s+", "", _paren(s, m.end() - 1)).lower() if m else ""


IDENT = r'(?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?'


def read(files):
    """files: [(relative path, text)] in apply order -> Schema."""
    schema = Schema()
    tables = schema.tables
    for file, text in files:
        for line, stmt in statements(text):
            s = re.sub(r"\s+", " ", stmt)
            low = s.lower()
            if m := re.match(rf"create (?:(?:global|local) )?(?:temp(?:orary)? |unlogged )?table (?:if not exists )?({IDENT})", s, re.I):
                name = _name(m[1])
                if name not in tables or "if not exists" not in low:
                    tables[name] = Table(name, file, line, columns=low)
            elif m := re.match(rf"create (?:or replace )?(?:materialized )?view (?:if not exists )?({IDENT})", s, re.I):
                name = _name(m[1])
                tables[name] = Table(name, file, line, kind="view", invoker=bool(re.search(r"security_invoker\s*=?\s*(true|on|1)", low)))
            elif m := re.match(rf"alter (?:materialized )?view (?:if exists )?({IDENT}) set \(([^)]*)\)", s, re.I):
                if (t := tables.get(_name(m[1]))) and re.search(r"security_invoker\s*=?\s*(true|on|1)", m[2].lower()):
                    t.invoker = True
            elif m := re.match(rf"alter table (?:if exists )?(?:only )?({IDENT}) (enable|disable|force|no force) row level security", s, re.I):
                if t := tables.get(_name(m[1])):
                    if m[2].lower() in ("enable", "disable"):
                        t.rls, t.toggled = m[2].lower() == "enable", (file, line)
            elif m := re.match(rf"alter table (?:if exists )?(?:only )?({IDENT}) (add column .+)$", s, re.I):
                if t := tables.get(_name(m[1])):
                    t.columns += " " + re.sub(r"\badd column (if not exists )?", ", ", m[2].lower())
            elif m := re.match(rf"alter table (?:if exists )?({IDENT}) rename to ({IDENT})", s, re.I):
                if t := tables.pop(_name(m[1]), None):
                    t.name = _name(m[2]) if "." in m[2] else t.name.rsplit(".", 1)[0] + "." + m[2].strip('"').lower()
                    tables[t.name] = t
            elif m := re.match(r"drop (?:materialized )?(?:table|view) (?:if exists )?(.+?)(?: cascade| restrict)?$", s, re.I):
                for raw in m[1].split(","):
                    tables.pop(_name(raw.strip()), None)
            elif m := re.match(rf"create (?:or replace )?function ({IDENT})\s*\(", s, re.I):
                name = _name(m[1])
                head = s[: s.find("$")] if "$" in s else s
                body = re.search(r"(\$\w*\$)(.*)\1", stmt, re.S)
                ret = re.search(r"\breturns\s+(setof\s+)?([\w.]+(?:\s*\([^)]*\))?)", head, re.I)
                schema.functions[name] = Function(
                    name, re.sub(r"\s+", " ", body[2] if body else "").lower(), (ret[0] if ret else "").lower(),
                    bool(re.search(r"\bsecurity definer\b", low)), _arg_types(_paren(s, m.end() - 1)), file, line)
            elif m := re.match(rf"alter function ({IDENT})\s*\(.*?\)\s*security (definer|invoker)", s, re.I):
                if f := schema.functions.get(_name(m[1])):
                    f.definer = m[2].lower() == "definer"
            elif m := re.match(rf"drop function (?:if exists )?({IDENT})", s, re.I):
                schema.functions.pop(_name(m[1]), None)
            elif m := re.match(rf"(revoke|grant) (?:execute|all)(?: privileges)? on function ({IDENT}).*? (from|to) (.+)$", s, re.I):
                if f := schema.functions.get(_name(m[2])):
                    roles = {r.strip().strip('"').lower() for r in m[4].split(",")}
                    f.revoked = f.revoked | roles if m[1].lower() == "revoke" else f.revoked - roles
            elif m := re.match(rf"create (?:or replace )?(?:constraint )?trigger \S+ (before|after|instead of) (.+?) on ({IDENT}) .*?execute (?:function|procedure) ({IDENT})", s, re.I):
                schema.triggers.append((_name(m[3]), f"{m[1]} {m[2]}".lower(), _name(m[4]), file, line))
            elif m := re.match(r"insert into storage\.buckets\s*\(([^)]*)\)\s*values\s*\((.*?)\)", s, re.I):
                cols = [c.strip().strip('"').lower() for c in m[1].split(",")]
                vals = [v.strip() for v in re.split(r",(?=(?:[^']*'[^']*')*[^']*$)", m[2])]
                row = dict(zip(cols, vals, strict=False))
                if "id" in row:
                    schema.buckets[row["id"].strip("'")] = {"public": row.get("public", "false").lower() == "true", "file": file, "line": line}
            elif m := re.match(rf"grant update \(([^)]*)\) on (?:table )?({IDENT}) to (.+)$", s, re.I):
                for role in m[3].split(","):
                    schema.column_grants[(_name(m[2]), role.strip().strip('"').lower())] = {c.strip().strip('"').lower() for c in m[1].split(",")}
            elif m := re.match(rf'create policy ("[^"]+"|\S+) on ({IDENT})(.*)$', s, re.I):
                if _name(m[2]) == "storage.objects" and "storage.objects" not in tables:
                    tables["storage.objects"] = Table("storage.objects", file, line, rls=True)
                if t := tables.get(_name(m[2])):
                    rest = m[3]
                    cmd = re.search(r"\bfor (all|select|insert|update|delete)\b", rest, re.I)
                    to = re.search(r"\bto ((?:\"?[\w]+\"?\s*,\s*)*\"?[\w]+\"?)", rest, re.I)
                    roles = {r.strip().strip('"').lower() for r in to[1].split(",")} if to else {"public"}
                    t.policies[m[1].strip('"')] = Policy(
                        m[1].strip('"'), cmd[1].lower() if cmd else "all", roles, _expr("using", rest), _expr("with check", rest),
                        not re.search(r"\bas restrictive\b", rest, re.I), file, line)
            elif m := re.match(rf'drop policy (?:if exists )?("[^"]+"|\S+) on ({IDENT})', s, re.I):
                if t := tables.get(_name(m[2])):
                    t.policies.pop(m[1].strip('"'), None)
            elif m := re.match(rf"grant .+? on (?:table )?({IDENT}(?:\s*,\s*{IDENT})*) to (.+)$", s, re.I):
                for raw in m[1].split(","):
                    if t := tables.get(_name(raw.strip())):
                        t.revoked -= {r.strip().strip('"').lower() for r in m[2].split(",")}
            elif re.search(r"\benable row level security\b", low) and t_names(s, tables):
                # dynamic: DO $$ FOREACH t IN ARRAY ['a','b'] LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t)
                for name in t_names(s, tables):
                    tables[name].rls, tables[name].toggled = True, (file, line)
            elif m := re.match(rf"revoke .+? on (?:table )?({IDENT}(?:\s*,\s*{IDENT})*) from (.+)$", s, re.I):
                for raw in m[1].split(","):
                    if t := tables.get(_name(raw.strip())):
                        t.revoked |= {r.strip().strip('"').lower() for r in m[2].split(",")}
    return schema


def _arg_types(args):
    """'target uuid, in note text default null' -> 'uuid, text'."""
    out = []
    for a in filter(None, (x.strip() for x in re.split(r",(?![^(]*\))", args))):
        a = re.split(r"\s+(?:default\b|=)", a, maxsplit=1, flags=re.I)[0]
        words = [w for w in a.split() if w.lower() not in ("in", "out", "inout", "variadic")]
        out.append(" ".join(words[1:]) if len(words) > 1 else " ".join(words))
    return ", ".join(out).lower()


def t_names(stmt, tables):
    """Tables a dynamic statement names in string literals, or every public table when it loops over the catalog."""
    names = {_name(x) for x in re.findall(r"'([\w.]+)'", stmt)} & {n for n, t in tables.items() if t.kind == "table"}
    if not names and re.search(r"pg_tables|information_schema\.tables|pg_class", stmt, re.I):
        names = {n for n, t in tables.items() if t.kind == "table" and n.startswith("public.")}
    return names


def exposed(t):
    """Reachable through the Data API by browsers: public schema, not revoked from both anon and authenticated."""
    return t.name.split(".")[0] in EXPOSED_SCHEMAS and not ({"anon", "authenticated"} <= t.revoked or "public" in t.revoked and "authenticated" in t.revoked)


def who(policy):
    """'anyone', 'signed-in', or None (narrower or server-only) for a permissive policy's effective audience."""
    if not policy.permissive or not (policy.roles & (ANYONE | {"authenticated"})):
        return None
    exprs = [e for e in (policy.using, policy.check) if e]
    if not exprs or any(e not in ALWAYS and not SIGNED_IN.match(e) for e in exprs):
        return None  # a real condition (auth.uid() = user_id, has_role(...)) narrows it
    if policy.roles & ANYONE and all(e in ALWAYS for e in exprs):
        return "anyone"
    return "signed-in"

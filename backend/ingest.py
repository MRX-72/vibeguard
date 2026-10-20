"""Turn a submission (paste / zip / GitHub URL / demo) into a throwaway directory."""

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

MAX_BYTES = 50 * 1024 * 1024
MAX_FILES = 20_000
SAMPLE_REPO = Path(__file__).resolve().parent.parent / "sample-repo"
SKIP_DIRS = {"node_modules", ".git", "__MACOSX"}
GITHUB = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:/.*)?$")


class IngestError(ValueError):
    """Raised with a message that is safe and useful to show the user."""


def validate(source_type, payload, filename=None):
    """Cheap checks done before queueing. Returns (payload, label for the report)."""
    if source_type == "paste":
        if not isinstance(payload, str) or not payload.strip():
            raise IngestError("Paste some code to scan.")
        name = _clean_name(filename) if filename else _guess_name(payload)
        return payload, name
    if source_type == "zip":
        if not isinstance(payload, Path) or not zipfile.is_zipfile(payload):
            raise IngestError("That file isn't a valid .zip archive.")
        with zipfile.ZipFile(payload) as zf:
            _check_zip(zf.infolist())
        return payload, None
    if source_type == "github":
        m = GITHUB.match((payload or "").strip()) if isinstance(payload, str) else None
        if not m or m[2] in (".", ".."):
            raise IngestError("Enter a GitHub repository URL like https://github.com/owner/repo.")
        # rebuilt from the validated parts, so nothing user-typed reaches git's argv
        return f"https://github.com/{m[1]}/{m[2]}.git", f"{m[1]}/{m[2]}"
    if source_type == "demo":
        return None, "Demo app"
    raise IngestError("source_type must be one of: paste, zip, github, demo")


@contextmanager
def sandbox(source_type, payload, filename=None):
    """Yield a directory holding the code. It is always deleted afterwards, even on error."""
    try:
        with tempfile.TemporaryDirectory(prefix="vibeguard-") as tmp:
            root = Path(tmp, "src")
            root.mkdir()
            if source_type == "paste":
                dest = _inside(root, filename)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(payload)
            elif source_type == "zip":
                _extract(payload, root)
            elif source_type == "github":
                _clone(payload, root)
            elif source_type == "demo":
                shutil.copytree(SAMPLE_REPO, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*SKIP_DIRS))
            if _size(root) > MAX_BYTES:
                raise IngestError("This code is over the 50 MB limit. Leave out dependencies, build output and media files.")
            yield root
    finally:
        if source_type == "zip" and isinstance(payload, Path):
            payload.unlink(missing_ok=True)


def _extract(zip_path, root):
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        _check_zip(infos)
        for info in infos:
            name = info.filename.replace("\\", "/")
            if info.is_dir() or SKIP_DIRS & set(PurePosixPath(name).parts):
                continue
            dest = _inside(root, name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:  # declared file_size bounds what zipfile yields
                shutil.copyfileobj(src, out)


def _check_zip(infos):
    if len(infos) > MAX_FILES:
        raise IngestError(f"The zip has more than {MAX_FILES:,} files. Leave out node_modules and build output.")
    for info in infos:
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in PurePosixPath(name).parts or re.match(r"^[A-Za-z]:", name):
            raise IngestError(f"The zip contains an unsafe path ({name[:80]}), so it was rejected.")
    if sum(i.file_size for i in infos) > MAX_BYTES:
        raise IngestError("The zip expands to more than 50 MB. Leave out node_modules, build output and media files.")


def _clone(url, root):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true", "GIT_CONFIG_NOSYSTEM": "1"}
    # ponytail: size is checked after cloning, bounded only by the timeout; use the GitHub API size field if huge repos bite
    try:
        r = subprocess.run(
            ["git", "-c", "credential.helper=", "clone", "--depth", "1", "--single-branch", "--no-tags", "-q", "--", url, str(root)],
            env=env, capture_output=True, text=True, timeout=90,
        )
    except subprocess.TimeoutExpired:
        raise IngestError("Cloning took too long. The repository is probably over the 50 MB limit.") from None
    if r.returncode != 0:
        raise IngestError("Couldn't clone that repository. Check the URL. Only public repositories are supported.")
    shutil.rmtree(root / ".git", ignore_errors=True)


def _inside(root, name):
    dest = (root / name).resolve()
    if not dest.is_relative_to(root.resolve()) or dest == root.resolve():
        raise IngestError(f"Unsafe file path: {name[:80]}")
    return dest


def _size(root):
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def _clean_name(name):
    parts = [p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("/", "..", ".")]
    return "/".join(parts)[:200] or "pasted.js"


def _guess_name(code):
    """Pick an extension so the right scanners and rules apply to a paste."""
    if re.search(r"service\s+(cloud\.firestore|firebase\.storage)|rules_version", code):
        return "firestore.rules"
    if re.search(r"^\s*(create|alter)\s+(table|policy)\b", code, re.I | re.M):
        return "migration.sql"
    if re.search(r"^\s*(def \w+\(|from [\w.]+ import |import \w+\s*$|class \w+(\(.*\))?:)", code, re.M):
        return "pasted.py"
    if re.search(r"^[A-Z][A-Z0-9_]*=", code, re.M) and not re.search(r"[;{}()]", code):
        return ".env"
    if re.search(r"^\s*(interface|type) \w+|:\s*(string|number|boolean)\b", code, re.M):
        return "pasted.tsx"
    return "pasted.js"

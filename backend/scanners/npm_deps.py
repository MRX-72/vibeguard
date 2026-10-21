"""Which npm packages actually ship, and which only build or test the app.

A raw CVE count treats `brace-expansion` (pulled in by eslint) like `axios` (called by the server). This module
reads package.json plus the lockfile's dependency graph so findings can say which packages reach production,
through which direct dependency, and whether the code imports them at all.
"""

import json
import re
from pathlib import Path

import yaml

# Build/test tooling. AI builders often list these under "dependencies" (Lovable puts vite there), but none of
# them ships in the browser bundle or runs in production.
BUILD_TOOLS = {
    "vite", "esbuild", "rollup", "postcss", "autoprefixer", "tailwindcss", "typescript", "prettier", "vitest", "jest",
    "webpack", "webpack-cli", "parcel", "turbo", "nodemon", "ts-node", "tsx", "concurrently", "cross-env", "husky",
    "lint-staged", "eslint", "sass", "less", "terser", "playwright", "cypress", "storybook", "wrangler", "vercel",
    "netlify-cli", "drizzle-kit", "prisma", "supabase", "lovable-tagger", "vite-tsconfig-paths", "tw-animate-css",
    "globals", "jsdom", "happy-dom", "msw", "@tanstack/router-plugin", "@tanstack/router-cli", "@tanstack/router-devtools",
    "@tanstack/react-query-devtools", "@tanstack/react-router-devtools", "@biomejs/biome", "@swc/core", "typescript-eslint",
    "@tanstack/start-plugin-core", "@tanstack/router-generator", "@tanstack/router-utils", "@tanstack/virtual-file-routes",
}
BUILD_PREFIXES = ("@vitejs/", "@types/", "@tailwindcss/", "eslint-", "@eslint/", "@typescript-eslint/", "@babel/",
                  "@storybook/", "@vitest/", "@testing-library/", "@rollup/", "@esbuild/", "vite-plugin-",
                  "rollup-plugin-", "postcss-", "babel-plugin-", "@swc/", "@playwright/")
SOURCE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
IMPORT = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"'./][^"']*)["']""")


# names that announce a bundler/linter/CSS-toolchain plugin: vite-plugin-x, @lovable.dev/vite-tanstack-config, tailwindcss-animate…
BUILD_WORDS = re.compile(r"(^|[/-])(vite|vitest|rollup|webpack|babel|esbuild|eslint|postcss|tailwindcss|prettier|jest|storybook)(-|$)")


def is_build_tool(name):
    return name in BUILD_TOOLS or name.startswith(BUILD_PREFIXES) or bool(BUILD_WORDS.search(name))


class Project:
    """One package.json and the lockfiles beside it."""

    def __init__(self, folder: Path):
        self.folder = folder
        manifest = _json(folder / "package.json") or {}
        self.manifest_found = bool(manifest)
        self.direct = {}  # name -> declared spec
        self.direct_dev = set()
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            for name, spec in (manifest.get(section) or {}).items():
                self.direct.setdefault(name, spec)
                if section == "devDependencies" or is_build_tool(name):
                    self.direct_dev.add(name)
        self.graph = {}  # name -> set of dependency names (all versions merged; good enough for "does it ship")
        self.dev_flagged = set()  # lockfile says dev-only
        self.has_graph = self._read_package_lock() | self._read_bun_lock() | self._read_pnpm_lock() | self._read_yarn_lock()
        self.via = self._reach([n for n in self.direct if n not in self.direct_dev])  # runtime pkg -> direct dep pulling it in
        self.dev_via = self._reach(sorted(self.direct_dev), stop_at_build=False)  # same, for build/test tooling

    def classify(self, name):
        """('runtime-direct' | 'runtime' | 'dev' | 'unknown', via)."""
        if name in self.direct:
            return ("dev", None) if name in self.direct_dev else ("runtime-direct", None)
        if name in self.via:
            return "runtime", self.via[name]
        if name in self.graph or name in self.dev_flagged:
            return "dev", None
        return "unknown", None

    def _read_package_lock(self):
        lock = _json(self.folder / "package-lock.json")
        if not lock or "packages" not in lock:  # lockfile v1 has no graph we use
            return False
        for key, pkg in lock["packages"].items():
            if not key:
                continue
            installed = key.rsplit("node_modules/", 1)[-1]
            name = pkg.get("name") or installed  # differs for npm aliases: "string-width-cjs" installs string-width
            for n in {installed, name}:
                self.graph.setdefault(n, set()).update(_deps(pkg))
                if pkg.get("dev") or pkg.get("devOptional"):
                    self.dev_flagged.add(n)
            if name != installed:
                self.graph[installed].add(name)  # the alias ships the real package
        return True

    def _read_bun_lock(self):
        try:
            text = (self.folder / "bun.lock").read_text()
        except OSError:
            return False
        try:  # bun.lock is JSON with trailing commas
            lock = json.loads(re.sub(r",(\s*[}\]])", r"\1", text))
        except ValueError:
            return False
        for entry in (lock.get("packages") or {}).values():
            if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
                continue
            name = entry[0].rsplit("@", 1)[0] if entry[0].count("@") > entry[0].startswith("@") else entry[0]
            meta = next((e for e in entry[1:] if isinstance(e, dict)), {})
            self.graph.setdefault(name, set()).update(_deps(meta))
        return bool(self.graph)

    def _read_pnpm_lock(self):
        try:  # pnpm-lock.yaml can be megabytes: use libyaml when PyYAML has it
            lock = yaml.load((self.folder / "pnpm-lock.yaml").read_text(), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
        except (OSError, yaml.YAMLError):
            return False
        if not isinstance(lock, dict):
            return False
        # v9: graph under "snapshots", keyed "name@1.2.3(peer@x)"; v6: under "packages", keyed "/name@1.2.3", with dev flags
        for importer in (lock.get("importers") or {}).values():  # aliases: string-width-cjs -> version "string-width@4.2.3"
            for section in ("dependencies", "optionalDependencies", "devDependencies"):
                for alias, info in ((importer or {}).get(section) or {}).items():
                    version = str(info.get("version", "")) if isinstance(info, dict) else ""
                    if "@" in version[1:] and spec_name(version) != alias:
                        self.graph.setdefault(alias, set()).add(spec_name(version))
        for key, meta in (lock.get("snapshots") or lock.get("packages") or {}).items():
            name = spec_name(str(key).lstrip("/").split("(", 1)[0])
            self.graph.setdefault(name, set()).update(_deps(meta or {}))
            if (meta or {}).get("dev") is True:
                self.dev_flagged.add(name)
        return bool(self.graph)

    def _read_yarn_lock(self):
        """yarn.lock, classic (v1) or berry: unindented headers list the specs, 4-space lines under "dependencies:" name the deps."""
        try:
            lines = (self.folder / "yarn.lock").read_text().splitlines()
        except OSError:
            return False
        names, section = [], None
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if indent == 0:
                specs = [s.strip().strip('"') for s in line.rstrip(":").split(",")]
                names = {spec_name(s) for s in specs} - {"__metadata"}
                for n in names:
                    self.graph.setdefault(n, set())
                for s in specs:  # "string-width-cjs@npm:string-width@^4.2.0": the alias ships the real package
                    alias, _, real = s.partition("@npm:")
                    if real and spec_name(real) != spec_name(alias):
                        self.graph[spec_name(alias)].add(spec_name(real))
            elif indent == 2:
                section = line.strip().rstrip(":")
            elif indent == 4 and section in ("dependencies", "optionalDependencies"):
                dep = line.strip().split(" ", 1)[0].rstrip(":").strip('"')
                for n in names:
                    self.graph[n].add(dep)
        return bool(self.graph)

    def _reach(self, roots, stop_at_build=True):
        """Breadth-first walk from `roots`, remembering which root each package came through.
        A framework can depend on its own bundler (TanStack Start -> vite); that subtree still doesn't ship."""
        via = {r: r for r in roots}
        queue = list(roots)
        while queue:
            name = queue.pop(0)
            for dep in sorted(self.graph.get(name, ())):
                if dep not in via and not (stop_at_build and is_build_tool(dep)):
                    via[dep] = via[name]
                    queue.append(dep)
        return via


def spec_name(spec):
    """'react@18.3.1', '@scope/pkg@npm:^1', 'alias@npm:real@4', pnpm v5's '/react/18.3.1' -> the package name."""
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec.rsplit("/", 1)[0] if spec.count("/") > spec.startswith("@") else spec


def npm_aliases(lock):
    """'string-width-cjs:string-width' for every npm alias in a package-lock (lockfile-lint would flag them as injection)."""
    out = set()
    for key, pkg in (lock.get("packages") or {}).items():
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for name, spec in (pkg.get(section) or {}).items():
                if isinstance(spec, str) and spec.startswith("npm:"):
                    out.add(f"{name}:{spec_name(spec[4:])}")
        installed = key.rsplit("node_modules/", 1)[-1]
        if key and pkg.get("name") and installed != pkg["name"]:
            out.add(f"{installed}:{pkg['name']}")
    return sorted(out)


def _deps(pkg):
    # peers are installed by the app itself (tailwindcss-animate's peer tailwindcss is the app's own dependency)
    return {d for k in ("dependencies", "optionalDependencies") for d in (pkg.get(k) or {})}


def _json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def imported_packages(root: Path):
    """Every bare package name imported or required anywhere in the source (scoped names kept whole)."""
    names = set()
    for path in root.rglob("*"):
        if path.suffix not in SOURCE_EXT or "node_modules" in path.parts or not path.is_file():
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for spec in IMPORT.findall(text):
            if spec.startswith(("node:", "http:", "https:", "npm:", "jsr:")):
                spec = spec.split(":", 1)[1].lstrip("/") if spec.startswith("npm:") else ""
            parts = spec.split("/")
            if parts[0]:
                name = "/".join(parts[:2]) if parts[0].startswith("@") else parts[0]
                names.add(re.sub(r"(?<=.)@[^/]*$", "", name))  # Deno-style "npm:axios@1" -> "axios"
    return frozenset(names)


def min_version(spec):
    """'^0.21.1' -> '0.21.1'; None for tags, ranges we can't pin, URLs and workspace links."""
    m = re.match(r"^\s*(?:[\^~]|>=|=|v)?\s*(\d+\.\d+\.\d+(?:-[\w.]+)?)\s*$", str(spec))
    return m[1] if m else None

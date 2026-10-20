"""Which npm packages actually ship, and which only build or test the app.

A raw CVE count treats `brace-expansion` (pulled in by eslint) like `axios` (called by the server). This module
reads package.json plus the lockfile's dependency graph so findings can say which packages reach production,
through which direct dependency, and whether the code imports them at all.
"""

import json
import re
from pathlib import Path

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
        self.has_graph = self._read_package_lock() | self._read_bun_lock()
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
            name = pkg.get("name") or key.rsplit("node_modules/", 1)[-1]
            self.graph.setdefault(name, set()).update(_deps(pkg))
            if pkg.get("dev") or pkg.get("devOptional"):
                self.dev_flagged.add(name)
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

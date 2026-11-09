#!/usr/bin/env python3
"""load_built.py - does the BUILT code load under plain Node?

  load_built.py REPO [--dir dist ...] [--entry dist/lib.js ...]

Lesson 2026-10-07 (a news-scoring app): @extractus/article-extractor 8.1.0 passed every
vitest test and broke under Node, because vitest resolves modules its own way
and the new version's exports map hid a subpath Node needed.

Two levels, both under Node itself, never vitest:
  1. built.resolve: every bare import and require in the built files (default
     dist/, build/, out/, lib/, .output/server/ (Nitro), .next/standalone/
     (Next), with .js/.mjs/.cjs) is resolved with Node's own resolver from that
     file (import.meta.resolve for imports, require.resolve for requires).
     Nothing is executed. Any ERR_PACKAGE_PATH_NOT_EXPORTED or
     ERR_MODULE_NOT_FOUND FAILs, and so does an import that resolves only
     because a devDependency is installed (the owning package.json lists it in
     devDependencies alone; production installs omit it). A template-literal
     specifier with no substitution (import(`pkg`)) is a specifier.
  2. built.import: only for entries named with --entry or listed in
     security/load-check.json {"entries": [...]}: each is imported in a child
     Node with a 20 s timeout and an EMPTY environment (no secrets reach it).
     Only list side-effect-free modules there; a main that starts a server or
     runs a job does not belong in the list.
No built output: UNKNOWN (build first; this check never builds).
Bundled output with no bare imports (a Worker bundle) is a PASS with that
noted: there is nothing left for Node to resolve.
What counts as an import: comments and every string body are blanked first
(same length, so positions hold), the import and require statements are found
in that blanked text, and each specifier is read back from the comment-free
original. A JSDoc example or a scaffolding template literal that contains an
import line is text, not an import. Minified files are read too: a server
bundle (esbuild --minify) is code Node runs; only a file that touches browser
globals (window, document, navigator, webpack chunk loaders) and no Node-only
API (process.env other than NODE_ENV, __dirname, node: modules) is skipped as a
browser bundle.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

# Matched against text whose string bodies are blanked: the specifier is a run of spaces between
# quotes here, read back from the comment-free original at the same span.
IMPORT_RX = re.compile(r"""(?:^|[;\s}])(?:import\s+(?:[\w*{}\s,$]+\s+from\s+)?|export\s+[\w*{}\s,$]*\s+from\s+)\s*(['"])([^'"]*)\1""", re.M)
# A call's specifier may also be a template literal with no substitution (import(`pkg`), require(`pkg`)).
DYNAMIC_RX = re.compile(r"""(?:^|[;\s}(,=:!&|?])import\(\s*(['"`])([^'"`]*)\1""", re.M)
REQUIRE_RX = re.compile(r"""\brequire\(\s*(['"`])([^'"`]*)\1\s*\)""")
BUILTIN_PREFIX = ("node:", "cloudflare:", "bun:", "data:", "http:", "https:", "virtual:")
BROWSER_RX = re.compile(r"\b(?:window|document|navigator)\s*[.\[]|webpackChunk|webpackJsonp|__next_f|\bself\.")
# process.env.NODE_ENV is NOT Node-only: browser bundles keep it (React and most UMD builds branch on it).
NODE_RX = re.compile(r"process\.(?:env(?!\.NODE_ENV\b)(?![\[]['\"]NODE_ENV)|argv|exit|cwd|stdout|stderr|platform)\b|__dirname|__filename|['\"]node:[a-z_/]+['\"]")
DEFAULT_DIRS = ["dist", "build", "out", "lib", ".output/server", ".next/standalone"]  # Nitro and Next standalone server output too

RESOLVER = r"""
import {createRequire, builtinModules} from 'node:module';
import {pathToFileURL} from 'node:url';
import {readFileSync} from 'node:fs';
const items = JSON.parse(readFileSync(0, 'utf8'));
const out = [];
for (const it of items) {
  const base = it.spec.startsWith('@') ? it.spec.split('/').slice(0, 2).join('/') : it.spec.split('/')[0];
  if (builtinModules.includes(it.spec) || builtinModules.includes(base)) continue;
  try {
    if (it.kind === 'import') import.meta.resolve(it.spec, pathToFileURL(it.file).href);
    else createRequire(it.file).resolve(it.spec);
  } catch (e) { out.push({file: it.file, spec: it.spec, kind: it.kind, code: e.code || e.name}); }
}
process.stdout.write(JSON.stringify(out));
"""


def browser_bundle(path):
    """A minified file that reaches browser globals and no Node-only API is a browser bundle, not
    code Node runs. A minified server bundle (`"use strict";var e=require("x")...`) is read."""
    if not path.endswith(".min.js"):
        return False
    t = walk.read(path, 400_000)
    return bool(BROWSER_RX.search(t)) and not NODE_RX.search(t)


def built_files(repo, dirs):
    out = []
    for d in dirs:
        root = os.path.join(repo, d)
        if not os.path.isdir(root):
            continue
        for r, ds, names in os.walk(root):
            # browser chunks (Next static output) are not code Node runs
            ds[:] = [x for x in ds if x not in ("node_modules", "static", "_next", "chunks", "assets", "client")]
            for n in names:
                p = os.path.join(r, n)
                if n.endswith((".js", ".mjs", ".cjs")) and not browser_bundle(p):
                    out.append(p)
    return out[:3000]


def imports_of(path):
    """(spec, kind) for every bare import and require in a built file. Comments and string bodies are
    blanked before matching (an import line quoted inside a template literal or a JSDoc example is text);
    the specifier itself is read from the comment-free text at the same span, which strip_comments keeps
    the same length as the original."""
    raw = walk.read(path)
    kept = walk.strip_comments(raw, path, strings=True)
    blank = walk.strip_comments(raw, path, strings=False)
    out = []
    for rx, kind in ((IMPORT_RX, "import"), (DYNAMIC_RX, "import"), (REQUIRE_RX, "require")):
        for m in rx.finditer(blank):
            s = kept[m.start(2):m.end(2)]
            if "${" in s:  # a computed specifier: nothing static to resolve
                continue
            if s and not s.startswith((".", "/")) and not s.startswith(BUILTIN_PREFIX):
                out.append((s, kind))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--dir", action="append")
    ap.add_argument("--entry", action="append", default=[])
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    node = shutil.which("node")
    if not node:
        return ledger.emit([result("built.resolve", "Built code resolves under Node", "UNKNOWN", repo, reason="node not installed")])
    dirs = a.dir or DEFAULT_DIRS
    files = built_files(repo, dirs)
    res = []
    if not files:
        res.append(result("built.resolve", "Built code resolves under Node", "UNKNOWN", "looked in %s" % ", ".join(dirs),
                          reason="no built output found; run the build, then re-run (this check never builds)"))
    else:
        items = []
        for f in files:
            # Comments AND string bodies blanked before matching: bundles carry JSDoc examples such as
            # "import { Hono } from 'hono'" (2026-10-15 false positive) and scaffolding CLIs carry whole
            # source files inside template literals; neither is an import.
            for s, kind in imports_of(f):
                items.append({"file": f, "spec": s, "kind": kind})
        seen, uniq = set(), []
        for it in items:
            k = (os.path.dirname(it["file"]), it["spec"], it["kind"])
            if k not in seen:
                seen.add(k)
                uniq.append(it)
        if not uniq:
            res.append(result("built.resolve", "Built code resolves under Node", "PASS",
                              "%d built file(s), no bare imports left (bundled)" % len(files)))
        else:
            r = _resolve(node, uniq)
            if r is not None:
                failed = {(x["file"], x["spec"], x["kind"]) for x in r}
                r += dev_only(repo, [it for it in uniq if (it["file"], it["spec"], it["kind"]) not in failed])
            if r is None:
                res.append(result("built.resolve", "Built code resolves under Node", "UNKNOWN", "node resolver", reason="resolver did not run"))
            elif r:
                ev = "; ".join("%s: %s %s (%s)" % (walk.rel(repo, x["file"]), x["kind"], x["spec"], x["code"]) for x in r[:6])
                res.append(result("built.resolve", "Built code resolves under Node", "FAIL", ev, severity="high",
                                  fix="pin the dependency to the last version that resolves, or fix the import path; do not trust the test runner for this",
                                  detail="%d of %d imports fail under Node's resolver" % (len(r), len(uniq))))
            else:
                res.append(result("built.resolve", "Built code resolves under Node", "PASS",
                                  "%d imports across %d built files resolve with Node %s" % (len(uniq), len(files), _node_version(node))))
    entries = list(a.entry)
    cfg = os.path.join(repo, "security", "load-check.json")
    if os.path.exists(cfg):
        try:
            entries += json.load(open(cfg)).get("entries", [])
        except ValueError:
            res.append(result("built.import", "Declared built modules import under Node", "UNKNOWN", "security/load-check.json", reason="unparseable JSON"))
    for e in entries:
        p = os.path.join(repo, e)
        cid = "built.import.%s" % re.sub(r"[^A-Za-z0-9_.-]", "_", e)
        if not os.path.exists(p):
            res.append(result(cid, "%s imports under Node" % e, "UNKNOWN", e, reason="file not found; build first"))
            continue
        try:
            r = subprocess.run([node, "--input-type=module", "-e", "await import(%s)" % json.dumps("file://" + os.path.abspath(p))],
                               capture_output=True, text=True, timeout=20, env={"PATH": os.environ.get("PATH", "")}, cwd=os.path.dirname(p))
        except subprocess.TimeoutExpired:
            res.append(result(cid, "%s imports under Node" % e, "UNKNOWN", e, reason="import did not finish in 20 s (it runs something; remove it from the entry list)"))
            continue
        if r.returncode == 0:
            res.append(result(cid, "%s imports under Node" % e, "PASS", "node import of %s exited 0" % e))
        else:
            code = re.search(r"\b(ERR_[A-Z_]+|SyntaxError|TypeError|ReferenceError)\b", r.stderr)
            res.append(result(cid, "%s imports under Node" % e, "FAIL", "%s: %s" % (e, code.group(1) if code else "exit %d" % r.returncode),
                              severity="high", fix="fix the import or pin the dependency that broke it, then re-run under Node"))
    return ledger.emit(res)


def _base(spec):
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def owner_manifest(repo, path):
    """The package.json that owns a built file: the nearest one above it, inside the repo, never in node_modules."""
    d = os.path.dirname(os.path.abspath(path))
    while True:
        if "node_modules" not in d.split(os.sep):
            pj = os.path.join(d, "package.json")
            if os.path.isfile(pj):
                return pj
        if os.path.realpath(d) == os.path.realpath(repo) or os.path.dirname(d) == d:
            return None
        d = os.path.dirname(d)


def dev_only(repo, items):
    """Imports that resolve here only because devDependencies are installed. Production installs with
    `npm ci --omit=dev` (or a pruned image), so a built file that imports a devDependency-only package
    fails to load there even though it resolves on this machine."""
    out, cache = [], {}
    for it in items:
        pj = owner_manifest(repo, it["file"])
        if not pj:
            continue
        if pj not in cache:
            try:
                m = json.load(open(pj))
            except (OSError, ValueError):
                m = {}
            prod = set()
            for k in ("dependencies", "optionalDependencies", "peerDependencies", "bundleDependencies", "bundledDependencies"):
                v = m.get(k) or {}
                prod |= set(v if isinstance(v, (dict, list)) else [])
            dev = set((m.get("devDependencies") or {}) if isinstance(m.get("devDependencies"), dict) else [])
            cache[pj] = (prod, dev)
        prod, dev = cache[pj]
        b = _base(it["spec"])
        if b in dev and b not in prod:
            out.append(dict(it, code="DEV_DEPENDENCY_ONLY: absent after npm ci --omit=dev"))
    return out


def _resolve(node, items):
    """Failures from Node's own resolver, or None when the resolver itself did not run."""
    try:
        r = subprocess.run([node, "--experimental-import-meta-resolve", "--no-warnings", "--input-type=module", "-e", RESOLVER],
                           input=json.dumps(items), capture_output=True, text=True, timeout=120)
        return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, ValueError):
        return None


def _node_version(node):
    return subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()


if __name__ == "__main__":
    sys.exit(main())

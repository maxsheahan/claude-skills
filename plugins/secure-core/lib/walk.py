"""walk.py - read a repo's own source the same way in every check.

Skips dependencies, build output, VCS and snapshot folders. `tests=False`
also skips test files and fixtures, so a check about production behavior is
not tripped by a test that deliberately exercises the bad case.
"""
import os
import re

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "out", ".next", ".open-next", ".wrangler",
    ".backups", "coverage", "vendor", ".venv", "venv", "__pycache__", ".turbo", ".vercel",
    ".svelte-kit", ".cache", ".parcel-cache", ".output",
}
# Only at the repo root: the suite's own output folders (a src/security/ module is still read).
ROOT_SKIP = {"security", "validation"}
CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".gs", ".html", ".vue", ".svelte")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|__mocks__|fixtures?|e2e|spec|cypress|playwright)(/|$)|\.(test|spec)\.[a-z]+$"
                       r"|(^|/)(fakes?|mocks?|stubs?)[A-Z_.\-][^/]*$")
# Local tooling a stranger cannot reach: one-off scripts, evals, notebooks, docs.
# Excluded from the app-layer checks (who can make the app spend or leak),
# still read by the inventory and the secret scan.
NOT_SERVED = re.compile(r"^(scripts|tools|bin|evals?|notebooks|docs|examples|bench|benchmarks)/")


_GIT_CACHE = {}


def git_files(repo):
    """Tracked plus untracked-but-not-ignored files, or None outside git.
    The repo's own source is what git would ship; ignored folders (build
    output, agent scratch copies) are not the repo's code."""
    key = os.path.abspath(repo)
    if key not in _GIT_CACHE:
        import subprocess
        r = subprocess.run(["git", "-C", key, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                           capture_output=True, text=True)
        top = subprocess.run(["git", "-C", key, "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
        if r.returncode != 0 or os.path.realpath(top) != os.path.realpath(key):
            _GIT_CACHE[key] = None  # not a repo root (a sub-folder or no git): walk the tree
        else:
            _GIT_CACHE[key] = {f for f in r.stdout.split("\0") if f}
    return _GIT_CACHE[key]


def files(repo, exts=CODE_EXT, tests=True, extra_skip=(), served=False):
    """Source files of the repo. Skips dependency, build, VCS and snapshot
    folders and every dot-folder (.agents, .claude, .vscode: scratch copies
    and tooling, not the app). Inside a git repo, only files git tracks or
    would track are read."""
    skip = SKIP_DIRS | set(extra_skip)
    allowed = git_files(repo)
    for root, dirs, names in os.walk(repo):
        at_root = os.path.abspath(root) == os.path.abspath(repo)
        dirs[:] = sorted(d for d in dirs if d not in skip and not d.startswith(".")
                         and not (at_root and d in ROOT_SKIP))
        for n in sorted(names):
            if exts and not n.endswith(exts):
                continue
            p = os.path.join(root, n)
            r = rel(repo, p)
            if allowed is not None and r not in allowed:
                continue
            if not tests and TEST_PATH.search(r):
                continue
            if served and NOT_SERVED.search(r):
                continue
            yield p


def rel(repo, path):
    return os.path.relpath(path, repo).replace(os.sep, "/")


def read(path, limit=2_000_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def find(repo, pattern, exts=CODE_EXT, tests=True, flags=0, served=False, strings=True):
    """Yield (relpath, line, match) for every regex match in the repo's source.
    strings=False blanks string contents first (see read_code)."""
    rx = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
    for p in files(repo, exts, tests, served=served):
        t = read_code(p, strings)
        for m in rx.finditer(t):
            yield rel(repo, p), line_of(t, m.start()), m


def exists_any(repo, *relpaths):
    return [r for r in relpaths if os.path.exists(os.path.join(repo, r))]


def package_json(repo):
    import json
    p = os.path.join(repo, "package.json")
    try:
        data = json.load(open(p, encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def deps(pkg):
    if not isinstance(pkg, dict):
        return {}  # a malformed package.json ([] or a string) has no dependencies to read
    d = {}
    for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        d.update(pkg.get(k) or {})
    return d


def all_package_jsons(repo):
    """Root plus workspace package.json files (monorepos keep the app in a subfolder)."""
    for p in files(repo, exts=("package.json",), tests=False):
        yield p


def strip_comments(text, path="", strings=True, interp=False):
    """Blank out comments, keeping every newline (so line numbers hold) and
    every string literal (so 'https://x' survives). A comment saying
    '// TODO: add a rate limit' must never satisfy a check (Phase 5 audit).
    interp=True (with strings=False) keeps the code inside a template literal's
    ${...}: `https://${host}/x` blanks the text but keeps `host`, the value
    that flows. The output is always the input's length (offsets hold)."""
    py = path.endswith(".py")
    out, i, n = [], 0, len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote == "`" and interp and not strings and text.startswith("${", i):
            j = _interp_end(text, i + 1)
            out.append(text[i:j])
            i = j
            continue
        if quote:
            if ch == "\\" and i + 1 < n:
                out.append(text[i:i + 2] if strings else "  ")
                i += 2
                continue
            if ch == quote:
                quote = None
                out.append(ch)
            else:
                out.append(ch if strings or ch == "\n" else " ")
            i += 1
            continue
        if py and text.startswith(('"""', "'''"), i):  # docstrings and triple-quoted strings
            q3 = text[i:i + 3]
            j = text.find(q3, i + 3)
            j = n if j < 0 else j + 3
            seg = text[i:j]
            out.append(seg if strings else "".join(c if c == "\n" else " " for c in seg))
            i = j
            continue
        if ch in "'\"`":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if not py and ch == "/" and not text.startswith(("//", "/*"), i) and _regex_context(out):
            j = _regex_end(text, i)  # a regex literal (/'/g) is not a quote or a comment start
            out.append(text[i:j] if strings else "/" + " " * max(0, j - i - 1))
            i = j
            continue
        if py and ch == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if not py and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if not py and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
            continue
        if path.endswith((".html", ".vue", ".svelte")) and text.startswith("<!--", i):
            j = text.find("-->", i + 4)
            j = n if j < 0 else j + 3
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _interp_end(text, i):
    """Index just past the `}` closing the `{` at i (a template interpolation), braces counted naively."""
    depth, n = 0, len(text)
    for j in range(i, n):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    return n


def _regex_context(out):
    """True when a '/' here starts a regex literal: after ( , = : [ ! & | ? { } ; or return."""
    k = len(out) - 1
    while k >= 0 and out[k] in " \t\n":
        k -= 1
    if k < 0:
        return True
    if out[k] in "(,=:[!&|?{};":
        return True
    tail = "".join(out[max(0, k - 5):k + 1])
    return tail.endswith("return")


def _regex_end(text, i):
    j, n, in_class = i + 1, len(text), False
    while j < n and text[j] != "\n":
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < n and text[j].isalpha():
                j += 1
            return j
        j += 1
    return i + 1  # not a regex after all: treat as a plain slash


def read_code(path, strings=True, interp=False):
    """The file's text with comments blanked, for every check that judges code.
    strings=False also blanks string contents: for evidence that must be an
    identifier or a call (a cap, a limiter), never prose in a prompt.
    interp=True keeps template-literal interpolations in that view (see strip_comments)."""
    t = read(path)
    if path.endswith(CODE_EXT):
        return strip_comments(t, path, strings, interp)
    return t


# ---- brace-balanced blocks and declarations (Phase 9, 2026-11-01: one home) ----
# Merged from check_spend._block / _function_body (6000-character cap), check_auth_gates._bal_block /
# _enclosing_block (4000-character cap) and the brace loop in check_metering._functions (no cap). The one
# disagreement, the cap on an unbalanced block, is resolved to the larger 6000: a block the file cuts short is
# read further, never shorter, and every unit assertion and bench case gives the same result either way.
BLOCK_LIMIT = 6000


def block_end(text, open_idx, limit=None):
    """Index just past the `}` that balances the `{` at open_idx, or None when the braces never balance
    (within `limit` characters when given). Strings and comments are the caller's business: pass the
    strings-blanked view (read_code(strings=False)) when a brace inside a template literal would mislead."""
    depth = 0
    stop = len(text) if limit is None else min(len(text), open_idx + limit)
    for j in range(open_idx, stop):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def block(text, start, limit=BLOCK_LIMIT):
    """Text of the `{...}` block that opens at or after `start`, braces balanced; the next `limit`
    characters when they never balance; '' when no brace follows."""
    i = text.find("{", start)
    if i < 0:
        return ""
    end = block_end(text, i, limit)
    return text[i:end] if end is not None else text[i:i + limit]


def enclosing_block(code, text, pos):
    """Text (strings kept) of the innermost `{...}` block containing pos, found by brace balance on the
    strings-blanked view `code`; the whole file when pos is at top level."""
    depth = 0
    for j in range(pos - 1, -1, -1):
        ch = code[j]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                return block(text, j)
            depth -= 1
    return text


def function_decl(text, name):
    """The match of `function name(` or `const|let|var name =` in text, or None."""
    return re.search(r"(?:function\s+%s\s*\(|(?:const|let|var)\s+%s\s*=)" % (re.escape(name), re.escape(name)), text)


def function_body(text, name):
    """The `{...}` body of `function name(` / `const name = (...) =>` in text, or ''."""
    m = function_decl(text, name)
    return block(text, m.end()) if m else ""


def decl_src(name, *scopes):
    """The right-hand side that binds `name`, in the first scope that has one: `const name = ...`,
    a destructuring `const { name, other } = ...`, or a Python / bare assignment `name = ...`. '' when none."""
    for sc in scopes:
        m = re.search(r"(?:const|let|var)\s+%s\s*(?::[^=\n]{0,80})?=\s*([^\n;]{1,240})" % re.escape(name), sc) or \
            re.search(r"(?:const|let|var)\s*\{[^}]*\b%s\b[^}]*\}\s*=\s*([^\n;]{1,240})" % re.escape(name), sc) or \
            re.search(r"(?m)^[ \t]*%s\s*=(?!=)\s*([^\n;]{1,240})" % re.escape(name), sc)
        if m:
            return m.group(1)
    return ""


# ---- import bindings (Phase 10, 2026-11-07) ----
# surface.import_names reads relative named and default imports. The spend and fetch checks also need the
# shapes a real app writes: `import * as geo from './geo'` (geo.reverseGeocode), a Next/Vite path alias
# (`@/lib/geo`, `~/lib/geo`), CommonJS `const geo = require('./geo')` and `const { a: b } = require(...)`.
IMPORT_BIND = re.compile(
    r"""\bimport\s+(?!type\b)(?:(?P<default>[A-Za-z_$][\w$]*)\s*,?\s*)?(?:\*\s*as\s+(?P<ns>[A-Za-z_$][\w$]*)\s*)?(?:\{(?P<named>[^}]*)\})?\s*from\s*['"](?P<spec>[^'"]+)['"]"""
    r"""|\b(?:const|let|var)\s+(?:(?P<cjs>[A-Za-z_$][\w$]*)|\{(?P<cjsnamed>[^}]*)\})\s*=\s*require\(\s*['"](?P<cjsspec>[^'"]+)['"]\s*\)""")
ALIAS_ROOTS = ("", "src/")  # where `@/x` and `~/x` point in the common Next, Vite and Nuxt setups
_EXTS = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js")


def resolve_spec(repo, rel, spec):
    """The repo-relative file an import specifier names: relative (./x, ../x, a .js naming the .ts it
    compiles from) or a root alias (@/x, ~/x); None for a package import or a file that is not there."""
    if spec.startswith("."):
        bases = [os.path.normpath(os.path.join(os.path.dirname(rel), spec))]
    elif re.match(r"^[@~]/", spec):
        bases = [os.path.normpath(root + spec[2:]) for root in ALIAS_ROOTS]
    else:
        return None
    for base in bases:
        for b in (base, re.sub(r"\.(?:js|mjs|cjs)$", "", base)):
            for e in _EXTS:
                cand = b + e
                if os.path.isfile(os.path.join(repo, cand)):
                    return cand.replace(os.sep, "/")
    return None


def import_bindings(repo, rel, text=None):
    """local name -> (file, exported name) for every import of a repo file in rel; a namespace import or a
    whole-module require maps to (file, '*'). Type-only members are skipped."""
    if text is None:
        text = read_code(os.path.join(repo, rel))
    out = {}
    for m in IMPORT_BIND.finditer(text):
        target = resolve_spec(repo, rel, m.group("spec") or m.group("cjsspec"))
        if not target:
            continue
        if m.group("default"):
            out[m.group("default")] = (target, "default")
        if m.group("ns") or m.group("cjs"):
            out[m.group("ns") or m.group("cjs")] = (target, "*")
        for x in (m.group("named") or m.group("cjsnamed") or "").split(","):
            x = x.strip()
            if x and not x.startswith("type "):
                parts = re.split(r"\s+as\s+|\s*:\s*", x)
                out[parts[-1].strip()] = (target, parts[0].strip())
    return out

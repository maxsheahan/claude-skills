#!/usr/bin/env python3
"""check_nextjs.py - Next.js (and OpenNext on Cloudflare) adapter.

  check_nextjs.py REPO

  next.server-actions        a server action with no ENFORCED auth check in its
                             body FAILs high: every server action is a public
                             POST endpoint. An action is an exported function
                             in a file-level 'use server' module (exported at
                             its declaration, in an export list or as the
                             default export), or any
                             function (exported or an inline closure inside a
                             component) whose body opens with 'use server'.
                             Enforced means a guard by name (requireUser,
                             verifySession, auth.protect(), 401/403, an owner
                             filter) or an identity read by any name (getSession,
                             auth(), loadViewer()) whose absence an `if` refuses:
                             if (!session) with a throw, return or redirect in
                             its consequent. Reading the session and only
                             logging it, a throw on bad input, or a redirect
                             after the write does not count.
  next.public-env-secrets    a NEXT_PUBLIC_ variable whose name is shaped like a
                             secret (SECRET, SERVICE_ROLE, PRIVATE, PASSWORD,
                             TOKEN, or a KEY / API_KEY suffix) FAILs high: it
                             ships in the browser bundle. Public-by-design names
                             PASS: *_PUBLISHABLE_KEY, *_SITE_KEY, *_ANON_KEY,
                             *_PUBLIC_KEY, MAPBOX_TOKEN, and the vendor keys
                             documented as browser-safe (Sentry DSN, Firebase
                             web API key, PostHog project key, Algolia
                             search-only key; the allowlist and why live in
                             secure-core/lib/names.py). In a committed .env file
                             a key-shaped VALUE FAILs whatever its name.
  next.static-export-headers a static export (output: 'export') that relies on
                             next.config headers() FAILs medium: headers() is
                             ignored by a static export, so the security
                             headers never reach the browser.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import surface  # noqa: E402
import walk  # noqa: E402
from names import secret_name  # noqa: E402  (one secret-name vocabulary for every adapter)
from ledger import result  # noqa: E402

# The head of a function declaration up to its parameter list: group 1/2 export prefix and name of
# `function name(`, group 3/4 the same for `const name = async (`. The parameter list, the return type
# and the body are then read by balance (find_body), never by a regex that stops at the first `{`
# (Phase 10: `Promise<{ error?: string }>` was read as the body).
FN = re.compile(r"(export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*(\w+)\s*(?:<[^>(){}]*>)?\s*\("
                r"|(export\s+)?(?:const|let)\s+(\w+)\s*(?::[^=;]+)?=\s*async\s*\(")
PUBLIC_VAR = re.compile(r"NEXT_PUBLIC_[A-Za-z0-9_]+")
# Auth names that only READ who is calling; on their own they enforce nothing.
SESSION_READ = re.compile(r"^(?:getSession|getServerSession|auth\(\)|currentUser|readSession|sessionFrom|getUser\(|signedInUser|userFromRequest)$", re.I)
# An identity value: the thing a session read returns (session, user, userId, viewer, account...).
IDENT = r"\w*(?:session|user|auth|uid|account|member|viewer|principal|identity|caller|claims)\w*"
# A condition that tests for a MISSING identity: `!session`, `!session?.user`, `user == null`.
MISSING = re.compile(r"!\s*\(?\s*(%s)\b|\b(%s)(?:\??\.\w+)*\s*===?\s*(?:null|undefined)\b" % (IDENT, IDENT), re.I)
# What a guard's consequent must do to refuse the caller.
REJECT = re.compile(r"\bthrow\b|\breturn\b|\b(?:permanentRedirect|redirect|notFound|unauthorized|forbidden)\s*\(")
# A guard by name that enforces on its own (Clerk's auth.protect() throws for a signed-out caller).
ENFORCING_CALL = re.compile(r"\bauth\s*\.\s*protect\s*\(")
# Calls that read the CALLER'S input, not who the caller is: a value bound from them is not an identity.
INPUT_CALL = re.compile(r"(?:^|\.)(?:get|getAll|json|formData|text|parse|safeParse|parseAsync)$|^(?:form|formData|params|searchParams|input|body|req|request|JSON|Object|String|Number)\b", re.I)


def body_at(t, open_index):
    """The balanced { ... } block that opens at open_index."""
    depth, i = 0, open_index
    for j in range(i, min(len(t), i + 20000)):
        if t[j] == "{":
            depth += 1
        elif t[j] == "}":
            depth -= 1
            if depth == 0:
                return t[i:j + 1]
    return t[i:i + 4000]


def _balanced(t, i, open_ch, close_ch):
    """Index just past the bracket that closes the one opening at t[i] (len(t) when unbalanced)."""
    depth = 0
    for j in range(i, len(t)):
        if t[j] == open_ch:
            depth += 1
        elif t[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
    return len(t)


PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}


def find_body(t, paren_open, arrow):
    """Index of the `{` that opens the function body whose parameter list opens at paren_open, or None.
    Skips the parameter list and a return type annotation by balance: an object type in the return
    type (`Promise<{ error?: string }>`, `: { ok: boolean }`) is part of the type, not the body. An
    arrow function must reach `=>` first; an expression-bodied arrow has no block (None)."""
    i = _balanced(t, paren_open, "(", ")")
    n = len(t)
    expecting_type = False
    while i < n:
        c = t[i]
        if c.isspace():
            i += 1
        elif c == ":" and not expecting_type:
            expecting_type, i = True, i + 1
        elif arrow and t.startswith("=>", i):
            i += 2
            while i < n and t[i].isspace():
                i += 1
            return i if i < n and t[i] == "{" else None
        elif c == "{" and not expecting_type:
            return None if arrow else i
        elif c in PAIRS:
            i = _balanced(t, i, c, PAIRS[c])
            expecting_type = False
        elif c in "|&,":
            expecting_type, i = True, i + 1
        elif c.isalnum() or c in "_$.?'\"":
            while i < n and (t[i].isalnum() or t[i] in "_$.?'\""):
                i += 1
            expecting_type = False
        else:
            return None
    return None


def exported_names(t):
    """Names a module exports through an export list or a default export of a name:
    `export { a, b as c }` and `export default a` (Phase 10: actions exported that way were read as
    private helpers). A re-export `export { a } from './b'` exports another module's function."""
    out = set()
    for m in re.finditer(r"\bexport\s*\{([^}]*)\}(?!\s*from\b)", t):
        for part in m.group(1).split(","):
            name = part.strip().split()[0] if part.strip() else ""
            if re.match(r"^\w+$", name) and name != "type":
                out.add(name)
    for m in re.finditer(r"\bexport\s+default\s+(\w+)\s*;?\s*$", t, re.M):
        if m.group(1) not in ("function", "async", "class"):
            out.add(m.group(1))
    return out


def _bound_from_call(body, var):
    """The callee a variable is bound from (`const viewer = await loadViewer()`,
    `const { userId } = await auth()`, `const { data: { user } } = await supabase.auth.getUser()`), or None."""
    for m in re.finditer(r"\b(?:const|let|var)\s+([^=;]*)=\s*(?:await\s+)?\(?\s*(?:await\s+)?([\w$.]+)\s*\(", body):
        if re.search(r"(?<![\w$])%s(?![\w$])" % re.escape(var), m.group(1)):
            return m.group(2)
    return None


def identity_guard(body):
    """An `if` that tests for a missing identity bound from a call (a session read, by any name) and
    whose consequent refuses: throws, returns or redirects. `if (!session) console.warn(...)` refuses
    nothing, and `if (!id) throw` tests the caller's input, not who the caller is (Phase 10)."""
    for m in re.finditer(r"\bif\s*\(", body):
        cond_end = _balanced(body, m.end() - 1, "(", ")")
        cond = body[m.end():cond_end - 1]
        rest = body[cond_end:].lstrip()
        if rest.startswith("{"):
            then = rest[:_balanced(rest, 0, "{", "}")]
        else:
            then = re.split(r";|\n", rest, 1)[0]
        if not REJECT.search(then):
            continue
        for mm in MISSING.finditer(cond):
            var = mm.group(1) or mm.group(2)
            callee = _bound_from_call(body, var)
            if callee and not INPUT_CALL.search(callee):
                return True
    # `const user = (await getUser()) ?? redirect('/login')`: the refusal sits on the read itself.
    return bool(re.search(r"\b(?:const|let)\s+[^=;]*\b%s\b[^=;]*=[^;\n]*(?:\?\?|\|\|)\s*(?:redirect|notFound|unauthorized|forbidden)\s*\(" % IDENT, body, re.I))


def enforced(body):
    """An auth guard by name that enforces on its own, or an identity guard: a missing identity is
    refused (see identity_guard). Reading the session and only logging it, a throw that rejects bad
    input, or a redirect after the write enforce nothing (Phase 10: GUARD matched those anywhere)."""
    if ENFORCING_CALL.search(body):
        return True
    hits = [m.group(0) for m in surface.AUTH_RX.finditer(body)]
    if any(not SESSION_READ.match(h) for h in hits):
        return True
    return identity_guard(body)


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    cfg_name, cfg = None, ""
    for f in ("next.config.ts", "next.config.mjs", "next.config.js"):
        cfg = walk.read_code(os.path.join(repo, f))
        if cfg:
            cfg_name = f
            break
    static_export = bool(re.search(r"""output\s*:\s*['"]export['"]""", cfg))

    actions, unguarded = 0, []
    if not static_export:
        for p in walk.files(repo, exts=(".ts", ".tsx", ".js", ".jsx"), tests=False, served=True):
            t = walk.read_code(p)
            file_level = re.match(r"""\s*(?:/\*.*?\*/\s*|//[^\n]*\n\s*)*['"]use server['"]""", t, re.S)
            if not file_level and "'use server'" not in t and '"use server"' not in t:
                continue
            listed = exported_names(t)
            for m in FN.finditer(t):
                name = m.group(2) or m.group(4)
                exported = bool(m.group(1) or m.group(3)) or name in listed
                open_i = find_body(t, m.end() - 1, arrow=m.group(4) is not None)
                if open_i is None:
                    continue
                b = body_at(t, open_i)
                inline = bool(re.match(r"""\{\s*['"]use server['"]""", b))
                # a file-level directive exports its actions; an inline directive makes any function an action
                if not inline and not (file_level and exported):
                    continue
                actions += 1
                if not enforced(b):
                    unguarded.append("%s:%d %s" % (walk.rel(repo, p), walk.line_of(t, m.start()), name))
        if unguarded:
            res.append(result("next.server-actions", "Server actions check who is calling", "FAIL", ledger.join_hits(unguarded, 8, "; "), severity="high",
                              fix="call the session check at the top of every server action and reject a missing session (throw or redirect); actions are public POST endpoints"))
        elif actions:
            res.append(result("next.server-actions", "Server actions check who is calling", "PASS", "%d server action(s), each with an enforced auth check" % actions))

    pub = ["%s:%d %s" % (r, ln, m.group(0)) for r, ln, m in walk.find(repo, PUBLIC_VAR, exts=walk.CODE_EXT + (".env", ".example", ".toml", ".json"), tests=False, served=True)
           if secret_name(m.group(0)[len("NEXT_PUBLIC_"):], browser=True)]
    for f in (".env", ".env.local", ".env.production", ".env.example", ".dev.vars.example"):
        for i, line in enumerate(walk.read_code(os.path.join(repo, f)).splitlines(), 1):
            name_part, _, value = line.partition("=")
            m = PUBLIC_VAR.search(name_part)
            # The value is read for its shape only (Phase 10: a live Stripe secret under NEXT_PUBLIC_BILLING
            # in a committed .env.production was judged by its benign name); it is never printed.
            value = value.strip().strip("'\"") or None
            if m and secret_name(m.group(0)[len("NEXT_PUBLIC_"):], value, browser=True):
                pub.append("%s:%d %s" % (f, i, m.group(0)))
    if pub:
        res.append(result("next.public-env-secrets", "No secret in a NEXT_PUBLIC_ variable", "FAIL", ledger.join_hits(sorted(set(pub)), 6, "; "), severity="high",
                          fix="drop the NEXT_PUBLIC_ prefix, read it server-side only, rotate it (it has shipped to browsers)"))
    else:
        res.append(result("next.public-env-secrets", "No secret in a NEXT_PUBLIC_ variable", "PASS", "no NEXT_PUBLIC_ name shaped like a secret (SECRET/SERVICE_ROLE/PRIVATE/PASSWORD/TOKEN/KEY; publishable, site and anon keys allowed)"))

    if static_export and re.search(r"async\s+headers\s*\(|headers\s*:\s*async", cfg):
        has_file = any(os.path.exists(os.path.join(repo, d, "_headers")) for d in ("public", ".", "static"))
        if has_file:
            res.append(result("next.static-export-headers", "Security headers reach a static export", "PASS", "static export with a _headers file (headers() in %s is ignored, the file is not)" % cfg_name))
        else:
            res.append(result("next.static-export-headers", "Security headers reach a static export", "FAIL", "%s: output 'export' plus headers(); no public/_headers" % cfg_name,
                              severity="medium", fix="move the headers into public/_headers (Cloudflare Pages reads it); headers() does nothing in a static export"))
    return ledger.emit(res, cannot_see=["Next middleware matchers are read as text: a matcher that skips a path is not evaluated",
                                        "OpenNext bindings and the deployed Worker's secrets: `npx wrangler secret list` (names only)"])


if __name__ == "__main__":
    sys.exit(main())

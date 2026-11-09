#!/usr/bin/env python3
"""check_app.py - ASVS-lite static checks on a repo's production code.

  check_app.py REPO

  app.cors           V3/V4: a wildcard or reflected origin together with
                     credentials FAILs high.
  app.error-leak     V16: a stack trace sent in a response FAILs medium.
  app.debug-routes   V13: a debug/seed/reset/test route with neither an
                     environment guard nor an auth reference FAILs high.
  app.signout        V7 (7.4.1): a sign-out route that only clears the browser
                     cookie, touching no server-side state, FAILs medium.
                     Emitted only when a sign-out route exists.
  app.object-writes  V8: a write route on an object id (:id, [id], a Worker
                     prefix like /api/notes/*) with no auth or ownership
                     reference in its handler and no auth middleware over its
                     path FAILs high. An ownerId the caller supplies in the
                     request, or a 403 whose condition names no identity, is
                     not a reference (surface.auth_ref). A PASS here means a
                     reference exists, not that ownership holds: that is proven
                     only by mutation-proven-tests.
  app.header-identity identity read from an X-User/Teacher/Account/Tenant-Id
                     request header (header('x-user-id'), headers['x-user-id'],
                     FastAPI Header()) FAILs high; writing such a response
                     header is not a read.
Test files are excluded. Every FAIL names file:line.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import names  # noqa: E402
import surface  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

# origin: '*', true, or a function that hands back its first argument unchanged ((o) => o, (o, c) => o, o => o)
# origin: '*', true, /.*/, or a function handing back its first argument unchanged (types and async allowed),
# or a callback that approves everything: function (o, cb) { cb(null, true) }
_REFLECT = (r"(?:['\"]\*['\"]|true|/\.\*/|(?:async\s*)?\(\s*(\w+)\s*(?::\s*[\w|<>\[\] ]+)?\s*(?:,[^)]*)?\)\s*(?::\s*[\w|<>\[\] ]+)?\s*=>\s*\1\b(?!\s*[.?(\[])"
            r"|(?:async\s+)?(\w+)\s*=>\s*\2\b(?!\s*[.?(\[])|function\s*\([^)]*\)\s*\{[^}]*\(\s*null\s*,\s*true\s*\)\s*;?\s*\}"
            r"|\([^)]*\)\s*=>\s*\{?\s*\w+\(\s*null\s*,\s*true\s*\)"  # (o, cb) => cb(null, true): the arrow form of the approve-all callback
            # the callback handing the request's origin straight back: (origin, cb) => cb(null, origin), function form too
            r"|(?:function\s*)?\(\s*(?P<cbo>\w+)\s*,\s*(?P<cbf>\w+)\s*\)\s*(?:=>)?\s*\{?\s*(?:return\s+)?(?P=cbf)\(\s*null\s*,\s*(?P=cbo)\s*\)\s*;?\s*\}?"
            # a function returning the request's own Origin header: (ctx) => ctx.get('Origin'), (c) => c.req.header('origin')
            r"|(?:async\s*)?\(?[\w\s,:]*\)?\s*=>\s*[\w$.]*(?:\.get|\.header|headers\.get)\(\s*['\"]origin['\"]\s*\)(?=\s*[,})\n])|(?:async\s*)?\(?[\w\s,:]*\)?\s*=>\s*[\w$.]*headers\.origin\b(?=\s*[,})\n]))")
# cors({...}) on Express, Hono and Koa; app.register(cors, {...}) / register(require('@fastify/cors'), {...}) on Fastify
_CORS_OPEN = r"(?:cors\(|register\(\s*(?:[\w.]*cors[\w.]*|(?:require|import)\(\s*['\"]@fastify/cors['\"]\s*\))\s*,)\s*\{"
CORS_BAD = [
    re.compile(_CORS_OPEN + r"[^}]*origin\s*:\s*" + _REFLECT + r"[^}]*credentials\s*:\s*true", re.S | re.I),
    re.compile(_CORS_OPEN + r"[^}]*credentials\s*:\s*true[^}]*origin\s*:\s*" + _REFLECT, re.S | re.I),
]
ACAO_STAR = re.compile(r"""Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]""", re.I)
ACAO_REFLECT = re.compile(r"""(?:Access-Control-Allow-Origin['"]?|\.(?:setHeader|header|set)\(\s*\w+)\s*[,:]\s*(?:(?:req|request|c\.req)[\w.]*(?:headers?\.get\(|header\(|get\()\s*['"]origin['"]|req(?:uest)?\.headers(?:\.origin\b|\[\s*['"]origin['"]\s*\]))""", re.I)
STARLETTE_STAR = re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]\s*\][^)]*allow_credentials\s*=\s*True|allow_credentials\s*=\s*True[^)]*allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]""", re.S)
ORIGIN_VAR = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*(?:req|request|c\.req)[\w.]*(?:headers?\.get\(|header\()\s*['"]origin['"]""", re.I)
ACAC_TRUE = re.compile(r"""Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true""", re.I)
PY_STACK_LEAK = re.compile(r"""(?:return|JSONResponse|jsonify|HTTPException)\b[^\n]{0,160}(?:traceback\.format_exc\(\)|format_exception\()""")
# Express res.status(500).json, Fastify reply.code(500).send, Hono c.json, the Fetch Response family
_RESPONSE_CALL = r"""(?:c\.(?:json|text|html)|\b(?:res|reply|response)\.(?:(?:status|code)\(\s*\d+\s*\)\.)?(?:send|json)|new\s+Response|Response\.json|NextResponse\.json)\s*\(\s*(?:\{[^{}]{0,300}?|[^;\n)]{0,200}?)"""
STACK_LEAK = re.compile(_RESPONSE_CALL + r"""\b\w*(?:err|error|e|ex|exception)\.stack\b""")
# the stack copied into a local first: const detail = err.stack / const { stack } = err, then sent (Phase 8)
# or into an object literal that is sent whole: const payload = { message: err.message, stack: err.stack } (Phase 10)
STACK_VAR = re.compile(r"""(?:const|let|var)\s+(?:(\w+)\s*=\s*(?:\{[^{}]{0,300}?)?\b\w*(?:err|error|e|ex|exception)\.stack\b|\{[^}]*\b(stack)\b[^}]*\}\s*=\s*\w*(?:err|error|e|ex|exception)\b)""")
STACK_VAR_LINES = 40  # a local sent within this many lines of its assignment
# A debug word starting a path segment. The unambiguous ones (debug, phpinfo, _internal, reset-db, dev-only,
# test-only, __x__) count with any continuation: /api/debug-info, /api/debugInfo. seed, dump and env are also
# product words (/api/seed-catalog, /api/dump-trucks, /api/env-settings), so they count as a whole segment
# or followed by a debug-shaped word (/seed_demo, /admin/seedDemo, /dump_state, /env-vars) (Phase 10).
_DEBUG_STRONG = r"(?:_*debug|__\w+__|phpinfo|_internal|reset-?db|dev-only|test-only)[\w-]*"
_DEBUG_TAIL = r"demo|data|db|database|dev|test|tests|fixtures?|state|env|vars?|all|users?|sample|local|memory|mem|cache|config|secrets?|keys?|info|debug|now|run"
_DEBUG_SOFT = r"(?:seed|dump|env)(?:[-_]?(?:%s)(?:[-_][\w-]*)?)?" % _DEBUG_TAIL
DEBUG_PATH = re.compile(r"(?:^|/)(?:%s|%s)(?:/|$)" % (_DEBUG_STRONG, _DEBUG_SOFT), re.I)
ENV_GUARD = re.compile(r"ENVIRONMENT|NODE_ENV|import\.meta\.env\.DEV|isDev|IS_DEV|DEBUG_ROUTES|ALLOW_DEBUG|env\.DEV\b", re.I)
SIGNOUT_PATH = re.compile(r"(?:log-?out|sign-?out)", re.I)
# Server-side state that ends a session: a KV/session-store delete, a revocation or invalidation call
# (judged on code, strings blanked), or SQL that writes a session, token or revocation table (judged on
# the body: the table name lives in the string). A cookie delete (cookies().delete, deleteCookie,
# Max-Age=0) only clears the browser (Phase 5 audit #9); a .prepare( or an INSERT into an audit log
# touches the server without revoking anything (Phase 8).
SERVER_STATE = re.compile(r"\b(?:KV|SESSIONS?|kv|sessionStore|store|redis|db)\w*\.(?:delete|del|put|set|destroy)\(|revoke\w*\(|invalidate\w*\(|destroySession\(|deleteSession\(|auth\.api\.signOut\(|signOut\(\s*\{[^}]*headers", re.I)
SERVER_STATE_SQL = re.compile(r"(?:INSERT\s+INTO|DELETE\s+FROM|UPDATE)\s+[`\"]?\w*(?:session|token|revok|revoc|blocklist|denylist|blacklist|logout|sign_?out)\w*"
                              # a session row found by its id, whatever the table is called: DELETE FROM auth WHERE sid = $1
                              r"|DELETE\s+FROM\s+[`\"]?\w+[`\"]?\s+WHERE\s+[^;'\"]{0,160}?\b(?:sid|session\w*|token\w*|jti)\b", re.I)
# A revocation column set on any other table (Phase 10 audit, 2026-11-07). Judged column by column, by the
# column name's word segments, never by a substring: `UPDATE users SET last_session_at = CURRENT_TIMESTAMP`
# records when a session happened and revokes nothing. A column revokes when it is
#   - a revocation marker: REVOKED / INVALIDATED / REVOCATION anywhere (tokens_revoked_at, sessions_invalidated);
#   - a session or token VERSION or COUNTER (session_version = session_version + 1, tokenGeneration, jwt_epoch);
#   - a stored session or token cleared (refresh_token = NULL, session_id = '');
#   - a logged-out / signed-out flag (logged_out = 1).
# Any other column whose last word is a time (last_session_at, token_refreshed_on, session_ts) is a timestamp.
SQL_UPDATE_SET = re.compile(r"""UPDATE\s+[`"]?\w+[`"]?\s+SET\s+([^;'"`]{1,400}?)(?=\s+(?:WHERE|RETURNING|FROM)\b|[;'"`]|$)""", re.I)
SQL_ASSIGN = re.compile(r"""[`"]?([A-Za-z_]\w*)[`"]?\s*=\s*([^,]+)""")
REVOKE_SEGS = {"REVOKED", "REVOKE", "REVOCATION", "REVOKES", "INVALIDATED", "INVALIDATE"}
SESSION_SEGS = {"SESSION", "SESSIONS", "TOKEN", "TOKENS", "JWT", "SID", "AUTH"}
VERSION_SEGS = {"VERSION", "VER", "COUNTER", "COUNT", "GENERATION", "GEN", "EPOCH", "NONCE", "SEQ", "SERIAL", "REV"}
TIME_SEGS = {"AT", "TIME", "TIMESTAMP", "TS", "DATE", "ON", "WHEN"}
CLEARED_VALUE = re.compile(r"^\s*(?:NULL|''|\"\")\s*$", re.I)


def _sql_column_revokes(col, value):
    segs = names._segments(col)
    if not segs:
        return False
    if REVOKE_SEGS & set(segs):
        return True
    if segs[-1] in TIME_SEGS:
        return False
    if any(a in ("LOGGED", "SIGNED") and b == "OUT" for a, b in zip(segs, segs[1:])):
        return True
    return bool(SESSION_SEGS & set(segs)) and bool(VERSION_SEGS & set(segs) or CLEARED_VALUE.match(value))


def sql_revokes(body):
    """True when the handler body's SQL ends a session server-side: a session/token/revocation table written,
    a session row deleted by its id, or a revocation column set on any table (see the comment above)."""
    if SERVER_STATE_SQL.search(body):
        return True
    for m in SQL_UPDATE_SET.finditer(body):
        if any(_sql_column_revokes(a.group(1), a.group(2)) for a in SQL_ASSIGN.finditer(m.group(1))):
            return True
    return False
OBJ_PATH = re.compile(r"/:[A-Za-z_]*id\b|\[[A-Za-z_]*id\]|/:[A-Za-z_]+(?:/|$)|/\{[A-Za-z_]+\}|(?<=.)/\*$", re.I)  # '/*' alone is a catch-all
# Identity taken from a request header the caller sets (a classroom app's authStub: X-Teacher-Id):
# a one-argument header('x-user-id') / get('x-user-id'[, default]) read, the Node property form
# headers['x-user-id'], or a FastAPI x_user_id: str = Header(...) parameter. header('X-Tenant-Id', value)
# with two arguments writes a response header and is not a read (Phase 8).
# The suffix may be a privilege as well as a name (x-user-role: admin is the caller's word too). Also read as
# Django's request.META['HTTP_X_USER_ID'] and a destructured `const { 'x-user-id': uid } = req.headers`;
# `headers['x-user-id'] = verified.id` assigns (a gateway forwarding identity it checked) and is not a read (Phase 10).
_ID_WHO = r"(?:user|teacher|account|tenant|member|owner|student|admin)"
_ID_HEADER = r"x-%s[-_]?(?:id|email|role|roles|groups|scopes?)?" % _ID_WHO
HEADER_IDENTITY = re.compile(r"""(?:\bheader\(\s*['"]%s['"]\s*\)|\bget\(\s*['"]%s['"]\s*[,)]|headers\[\s*['"]%s['"]\s*\](?!\s*=(?!=)))"""
                             r"""|\bx_%s(?:_id|_email|_role)?\s*:[^=\n]*=\s*Header\(|(?-i:Header)\([^)\n]*['"]%s['"]"""
                             r"""|\bMETA(?:\[\s*|\.get\(\s*)['"]HTTP_X_%s(?:_ID|_EMAIL|_ROLES?|_GROUPS)?['"]"""
                             r"""|\{[^{}]*['"]%s['"]\s*:[^{}]*\}\s*=\s*[\w$.]*headers\b""" % (_ID_HEADER, _ID_HEADER, _ID_HEADER, _ID_WHO, _ID_HEADER, _ID_WHO, _ID_HEADER), re.I)
ACCESS_HEADER = re.compile(r"Cf-Access-Jwt-Assertion|CF_Authorization")


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []

    cors_hits = []
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)
        r = walk.rel(repo, p)
        for rx in CORS_BAD + [STARLETTE_STAR]:
            for m in rx.finditer(t):
                cors_hits.append("%s:%d" % (r, walk.line_of(t, m.start())))
        if ACAC_TRUE.search(t) or re.search(r"credentials\s*:\s*true", t):
            for rx in (ACAO_STAR, ACAO_REFLECT):
                for m in rx.finditer(t):
                    cors_hits.append("%s:%d" % (r, walk.line_of(t, m.start())))
            for v in ORIGIN_VAR.finditer(t):  # origin read into a variable, then echoed back
                for m in re.finditer(r"""Access-Control-Allow-Origin['"]?\s*[,:]\s*%s\b""" % re.escape(v.group(1)), t, re.I):
                    if not re.search(r"(?:allowed|allowlist|ALLOWED|includes|has)\w*\s*\(?[^\n]{0,80}%s" % re.escape(v.group(1)), t):
                        cors_hits.append("%s:%d" % (r, walk.line_of(t, m.start())))
    if cors_hits:
        res.append(result("app.cors", "No wildcard or reflected origin with credentials", "FAIL", ledger.join_hits(sorted(set(cors_hits)), 6, ", "), severity="high",
                          fix="list the exact allowed origins; never combine * or a reflected Origin with credentials"))
    else:
        res.append(result("app.cors", "No wildcard or reflected origin with credentials", "PASS", "production source: no credentialed wildcard/reflected CORS"))

    leaks = ["%s:%d" % (r, ln) for r, ln, _ in walk.find(repo, STACK_LEAK, tests=False, served=True)]
    leaks += ["%s:%d" % (r, ln) for r, ln, _ in walk.find(repo, PY_STACK_LEAK, exts=(".py",), tests=False, served=True)]
    leaks += stack_via_variable(repo)
    if leaks:
        res.append(result("app.error-leak", "No stack traces in responses", "FAIL", ledger.join_hits(leaks, 6, ", "), severity="medium",
                          fix="log the stack server-side; answer with a generic message and an id"))
    else:
        res.append(result("app.error-leak", "No stack traces in responses", "PASS", "production source: no .stack sent in a response"))

    hs = list(surface.handlers(repo))
    mw = surface.middleware_auth(repo)
    # environment-gated middleware (for example app.use('/api/dev/*', devOnly, ...)) guards debug routes
    env_mw = [(m.group(1).rstrip("*").rstrip("/") or "/", "%s:%d" % (r, ln)) for r, ln, m in walk.find(repo, surface.MW_RX, tests=False, served=True)
              if re.search(r"dev\w*only|only\w*dev|require\w*dev|isDev|ENVIRONMENT|NODE_ENV", m.group(2), re.I)]
    debug, objw, signout_seen, signout_bad = [], [], [], []
    for h in hs:
        at = "%s:%d %s %s" % (h["file"], h["line"], h["method"], h["path"])
        # judged on code with comments AND strings blanked: a docstring or prose saying requireAuth gates nothing
        gated = surface.auth_ref(h["code"]) or ACCESS_HEADER.search(h["body"]) or surface.covered(h["path"], mw)
        dev_gated = surface.covered(h["path"], env_mw) or any(surface.covered(p, env_mw) for p in surface.mount_paths(repo, h["file"], h["path"]))
        if DEBUG_PATH.search(h["path"]) and not ENV_GUARD.search(h["code"]) and not gated and not dev_gated:
            debug.append(at)
        if SIGNOUT_PATH.search(h["path"]):
            signout_seen.append(at)
            if not SERVER_STATE.search(h["code"]) and not sql_revokes(h["body"]):
                signout_bad.append(at)
        if h["method"] in ("POST", "PUT", "PATCH", "DELETE", "ALL") and OBJ_PATH.search(h["path"]) and not gated:
            objw.append(at)
    routing = bool(surface.ROUTING_DEPS & set(_deps(repo)))
    if not hs and routing:
        for cid, title in (("app.debug-routes", "No unguarded debug or seed routes"), ("app.object-writes", "Write routes on objects check sign-in and ownership")):
            res.append(result(cid, title, "UNKNOWN", "0 routes recognised", reason="the repo has a routing framework but no route definition was recognised; list the routes by hand"))
        return ledger.emit(res + header_identity(repo))
    if debug:
        res.append(result("app.debug-routes", "No unguarded debug or seed routes", "FAIL", ledger.join_hits(debug, 6, "; "), severity="high",
                          fix="remove the route from production builds or guard it with an environment check AND auth"))
    else:
        res.append(result("app.debug-routes", "No unguarded debug or seed routes", "PASS",
                          "%d routes read; none debug-named without a guard" % len(hs) if hs else "the repo defines no route handlers"))
    if signout_seen:
        if signout_bad:
            res.append(result("app.signout", "Sign-out ends the session on the server", "FAIL", ledger.join_hits(signout_bad, 4, "; "), severity="medium",
                              fix="record the session as revoked server-side (hash of the cookie with its expiry) and refuse it after sign-out (ASVS 7.4.1)"))
        else:
            res.append(result("app.signout", "Sign-out ends the session on the server", "PASS", ledger.join_hits(signout_seen, 4, "; ") + ": handler touches server-side state"))
    access = [walk.rel(repo, p) for p in walk.files(repo, exts=(".md", ".sh", ".toml", ".jsonc"), tests=False)
              if re.search(r"Cloudflare Access|Zero Trust", walk.read_code(p))]
    if objw and access:
        res.append(result("app.object-writes", "Write routes on objects check sign-in and ownership", "FAIL", ledger.join_hits(objw, 8, "; "), severity="medium",
                          fix="validate the Cf-Access-Jwt-Assertion header in the Worker, so a policy change or a second hostname cannot expose these routes",
                          detail="no gate in code; the repo says Cloudflare Access fronts it (%s), which this scan cannot see" % ledger.join_hits(access, 2, ", ")))
    elif objw:
        res.append(result("app.object-writes", "Write routes on objects check sign-in and ownership", "FAIL", ledger.join_hits(objw, 8, "; "), severity="high",
                          fix="check the signed-in user owns the object before writing; prove it with mutation-proven-tests",
                          detail="no auth or ownership reference in the handler and no auth middleware over the path (read the router before reporting)"))
    else:
        n = sum(1 for h in hs if h["method"] in ("POST", "PUT", "PATCH", "DELETE", "ALL") and OBJ_PATH.search(h["path"]))
        res.append(result("app.object-writes", "Write routes on objects check sign-in and ownership", "PASS",
                          ("%d object write route(s), each with an auth/ownership reference or auth middleware (proof of ownership needs mutation-proven-tests)" % n)
                          if n else "no write route on an object id in %d route(s) read" % len(hs) if hs else "the repo defines no route handlers"))
    return ledger.emit(res + header_identity(repo))


def _deps(repo):
    import json
    d = {}
    for p in walk.all_package_jsons(repo):
        try:
            d.update(walk.deps(json.load(open(p))))
        except (OSError, ValueError):
            pass
    for f in ("requirements.txt", "pyproject.toml"):
        for name in ("fastapi", "flask", "starlette", "django"):
            if re.search(r"(?im)^\s*['\"]?%s\b" % name, walk.read(os.path.join(repo, f))):
                d[name] = "*"
    return d


def stack_via_variable(repo):
    """file:line of every response that sends a local the handler first copied a stack into."""
    """The local is read only inside the block that declares it (a later handler's `{ stack: [...] }` is
    another scope), and as a value: an object KEY named stack (`{ stack: ['hono'] }`) sends nothing (Phase 10)."""
    hits = []
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)
        code = walk.read_code(p, strings=False)
        for v in STACK_VAR.finditer(t):
            name = v.group(1) or v.group(2)
            scope_end = _scope_end(code, v.start())
            after = t[v.end():scope_end]
            cut = 0
            for _ in range(STACK_VAR_LINES):
                nxt = after.find("\n", cut + 1)
                if nxt < 0:
                    cut = len(after)
                    break
                cut = nxt
            for m in re.finditer(_RESPONSE_CALL + r"\b%s\b" % re.escape(name), after[:cut]):
                end = m.end()
                pre = after[:end - len(name)].rstrip()
                if re.match(r"\s*:(?!:)", after[end:]) and pre.endswith(("{", ",")):
                    continue  # an object key, not the local
                hits.append("%s:%d" % (walk.rel(repo, p), walk.line_of(t, v.end() + m.start())))
                break
    return hits


def _scope_end(code, pos):
    """Index just past the `}` closing the innermost block that contains pos; the file's end at top level."""
    depth = 0
    for j in range(pos - 1, -1, -1):
        ch = code[j]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                return walk.block_end(code, j) or len(code)
            depth -= 1
    return len(code)


def header_identity(repo):
    hits = ["%s:%d" % (r, ln) for r, ln, _ in walk.find(repo, HEADER_IDENTITY, tests=False, served=True)]
    if hits:
        return [result("app.header-identity", "Identity never comes from a header the caller sets", "FAIL", ledger.join_hits(hits, 6), severity="high",
                       fix="derive the user from a verified session or signed token; a plain X-*-Id header lets anyone act as anyone",
                       detail="who the caller is must be proven, not stated")]
    return [result("app.header-identity", "Identity never comes from a header the caller sets", "PASS", "no X-User/Teacher/Account-Id header read as identity")]


if __name__ == "__main__":
    sys.exit(main())

"""surface.py - the route and outbound-call vocabulary shared by the inventory
and the app-layer checks, so both read a handler the same way."""
import os
import re

import names as _names
import walk

PAID_HOSTS = {
    "api.anthropic.com": "Anthropic",
    "api.openai.com": "OpenAI",
    "generativelanguage.googleapis.com": "Google Gemini",
    "aiplatform.googleapis.com": "Google Vertex",
    "api.elevenlabs.io": "ElevenLabs",
    "api.deepgram.com": "Deepgram",
    "routes.googleapis.com": "Google Routes",
    "maps.googleapis.com": "Google Maps",
    "places.googleapis.com": "Google Places",
    "tile.googleapis.com": "Google Map Tiles",
    "api.replicate.com": "Replicate",
    "fal.run": "fal",
    "queue.fal.run": "fal",
    "api.perplexity.ai": "Perplexity",
    "openrouter.ai": "OpenRouter",
    "api.resend.com": "Resend",
    "api.twilio.com": "Twilio",
}
SDK_PAID = {
    "@anthropic-ai/sdk": "Anthropic", "openai": "OpenAI", "@google/generative-ai": "Google Gemini",
    "@google/genai": "Google Gemini", "elevenlabs": "ElevenLabs", "@elevenlabs/elevenlabs-js": "ElevenLabs",
    "@deepgram/sdk": "Deepgram", "replicate": "Replicate", "@fal-ai/client": "fal", "resend": "Resend",
    "twilio": "Twilio", "anthropic": "Anthropic",
}
# Any object's route method with a path literal (app, translationsRouter, gradebook...), and Python decorators.
ROUTE_RX = re.compile(r"""(?<![.\w])(?!(?:axios|got|ky|fetch|http|https|request|superagent|client|res|req|c|ctx|map|cache|params|headers|searchParams|url|kv|db|env|this)\.)[A-Za-z_$][\w$]*\.(get|post|put|patch|delete|all)\(\s*['"`](/[^'"`]*)['"`]""")
PY_ROUTE_RX = re.compile(r"""@\w+\.(get|post|put|patch|delete|route|api_route)\(\s*['"](/[^'"]*)['"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?""")
WORKER_PATH_RX = re.compile(r"""(?:pathname|url\.pathname|path)\s*(?:===|==|\.startsWith\()\s*['"`](/[^'"`]*)['"`]""")
# request.method === 'DELETE' / req.method == "POST" / method === 'PUT' on the same condition as a pathname test
WORKER_METHOD_RX = re.compile(r"""\bmethod\s*(?:===|==)\s*['"](GET|POST|PUT|PATCH|DELETE)['"]""", re.I)
AUTH_RX = re.compile(r"requireAuth|requireUser|requireAdmin|requireSession|getSession|getServerSession|auth\(\)|currentUser|verifySession|readSession|sessionFrom|getUser\(|isAdmin|jwtVerify|Cf-Access-Jwt-Assertion|ownerId|owner_id|user_id\s*=|passcode|checkPasscode|withAuth|authMiddleware|ensureSignedIn|signedInUser|userFromRequest|userSpace|requireOwner|\b40[13]\b\s*,?\s*\)|status\(\s*40[13]\s*\)|status:\s*40[13]\b|Unauthorized|Forbidden|SIGN_IN_REQUIRED|Depends\(\s*\w*(?:auth|user|session|verify)\w*|HTTPException\(\s*(?:status_code\s*=\s*)?40[13]\b|login_required|@requires_auth", re.I)
# The AUTH_RX alternatives that name only a refusal, not who is being refused: a 401/403 or a
# Forbidden/Unauthorized identifier. These gate a handler only when the condition that triggers
# them speaks of identity (auth_ref); `if (note.locked) return 403` refuses locked notes, not strangers.
STATUS_ONLY_RX = re.compile(r"^(?:\b40[13]\b\s*,?\s*\)|status\(\s*40[13]\s*\)|status:\s*40[13]\b|Unauthorized|Forbidden|HTTPException\(\s*(?:status_code\s*=\s*)?40[13]\b)$", re.I)
IDENTITY_WORD_RX = re.compile(r"user|session|auth|owner|token|login|logged|signed|identity|principal|account|member|admin|role|perm|allow|email|claim|jwt|\bsub\b|\buid\b|tenant|caller|actor|\bme\b|\bkey\b|secret|passcode|verif|can[A-Z]\w*|is(?:Owner|Admin|Allowed|Authori[sz]ed|Member|Mine)|teacher|student", re.I)
# Ownership identifiers that AUTH_RX credits; worthless when the caller supplies them (ownerId from the JSON body)
OWNER_ID_RX = re.compile(r"\b(?:ownerId|owner_id|user_id|userId|accountId|tenantId)\b")
CAP_RX = re.compile(r"(spend|budget|cost|usage|daily|monthly)[_\- ]?(cap|limit|ceiling|max)|max[_\-]?(spend|cost|usd|dollars)|free[_\-]?(uses|limit|walks)|\bquota\b"
                    r"|MAX_[A-Z_]*_PER_(?:RUN|DAY|REQUEST|HOUR)|(?:score|call|request|token)Limit\b|SPEND_CUTOFF|\w*_BUDGET\b|Budget(?:Exceeded|Error)\b", re.I)
# ---- where caller input enters a handler: ONE vocabulary (Phase 10 audit, 2026-11-07) ----
# Five overlapping request-input regexes (REQ_SOURCE_RX, REQ_INPUT_RX, REQ_SOURCE_BASE, DATA_INPUT_RX,
# CALLER_INPUT_RX) and two local REQ_EXTRA copies in check_spend and check_fetch disagreed on spellings, so a
# form one check knew another missed (Hono's typed c.req.json<T>() was in none of them). The forms live here
# once. Two readings remain because their meanings differ:
#   CALLER_INPUT_RX  everything the caller chooses: body, query, path params, form fields, and request
#                    headers other than the connecting address the edge sets (cf-connecting-ip, x-real-ip,
#                    x-forwarded-for). Use it to ask "did this value come from the request?".
#   DATA_INPUT_RX    the same minus every header. Use it only where a header is a credential CARRIER, not
#                    data: `const token = c.req.header('authorization'); if (!token) return 401` refuses a
#                    caller with no credential, so a binding from a header must not read as "the caller's
#                    own data" in the identity judgment (_bound_elsewhere, WHOLE_INPUT_RX).
# CALLER_SUPPLIED_RX (below) is a third, deliberately wider and case-insensitive reading for a value already
# known to be a limiter key component; it is never used to find where input enters.
# A TypeScript type argument may sit between the accessor and its call: c.req.json<{ link: string }>().
_CALL = r"(?:\s*<[^()\n;]{0,200}?>)?\s*\("
_CONNECTING = r"""['"](?:cf-connecting-ip|x-real-ip|x-forwarded-for)['"]"""
_DATA_FORMS = (
    r"\bc\.req\.(?:json|parseBody|formData|query|queries|param|text|valid)" + _CALL,  # Hono, incl. validated c.req.valid('json')
    r"\b(?:req|request)\.(?:json|formData|text)" + _CALL,          # Fetch API Request, Next req.json()
    r"\b(?:req|request)\.(?:body|query|params)\b",                 # Express, Fastify
    r"\bctx\.request\.(?:body|query)\b|\bctx\.(?:query|params)\b|\bcontext\.params\b",  # Koa, Next route context
    r"\bsearchParams\.get\(|\bformData\.get\(|\bevent\.body\b",    # with or without a receiver; Lambda events
    r"\brequest\.get_json\(|\brequest\.(?:form|args|json|values|query_params|path_params)\b",  # Flask, Starlette
)
_HEADER_FORMS = (
    r"\bc\.req\.header\(\s*(?!%s)" % _CONNECTING,
    r"\breq\.(?:get|header)\(\s*(?!%s)" % _CONNECTING,             # Express req.get('x-device')
    r"\b(?:req|request)\.headers\b(?!\s*(?:\[\s*|\.get\(\s*)%s)" % _CONNECTING,
)
DATA_INPUT_RX = re.compile("|".join(_DATA_FORMS))
CALLER_INPUT_RX = re.compile("|".join(_DATA_FORMS + _HEADER_FORMS))
FILE_ROUTE_RX = [re.compile(r"(?:^|/)app/(.*)/route\.(?:ts|js|tsx|jsx)$"), re.compile(r"(?:^|/)pages/(api/.*)\.(?:ts|js)$"),
                 re.compile(r"(?:^|/)functions/(.*)\.(?:ts|js)$")]
FETCH_RX = re.compile(r"""\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|ky|https?\.(?:get|request))\(\s*([^,\)\n]{1,160})""")
URL_HOST_RX = re.compile(r"""https?://([A-Za-z0-9.\-]+)""")
STUB_RX = re.compile(r"stub|fake|mock|dummy|noop|bypass", re.I)  # authStub trusts a header: not auth
# Frameworks whose routes are defined in code (a Next app with no route.ts simply has no handlers)
ROUTING_DEPS = {"hono", "express", "fastify", "koa", "itty-router", "@hono/node-server", "fastapi", "flask", "starlette"}
MW_RX = re.compile(r"""\b\w+\.use\(\s*['"`]([^'"`]*)['"`]\s*,\s*([^\n]{1,200})""")  # the whole chain: requireTier('a'), requireCaps


HANDLER_MAX = 200  # a handler runs to the next route definition, at most this many lines


def handlers(repo, served=True):
    """Yield dicts {file, line, method, path, body} for every route handler found.
    body is the handler's text: up to HANDLER_MAX lines, cut at the next route definition.
    File-based routes (Next app router, pages/api, Pages Functions) use the whole file."""
    for p in walk.files(repo, tests=False, served=served):
        t = walk.read_code(p)
        r = walk.rel(repo, p)
        lines = t.splitlines()
        code_text = walk.read_code(p, strings=False)
        code_lines = code_text.splitlines()
        found = [(m, "ROUTE") for m in ROUTE_RX.finditer(t)] + [(m, "WORKER") for m in WORKER_PATH_RX.finditer(t)]
        if r.endswith(".py"):
            found += [(m, "PY") for m in PY_ROUTE_RX.finditer(t)]
        starts = sorted(walk.line_of(t, m.start()) for m, _ in found)
        for m, kind in found:
            ln = walk.line_of(t, m.start())
            nxt = min([s for s in starts if s > ln] or [ln + HANDLER_MAX])
            body = "\n".join(lines[ln - 1: min(nxt - 1, ln + HANDLER_MAX)])
            code = "\n".join(code_lines[ln - 1: min(nxt - 1, ln + HANDLER_MAX)])
            if kind == "ROUTE":
                yield {"file": r, "line": ln, "method": m.group(1).upper(), "path": m.group(2), "body": body, "code": code}
            elif kind == "PY":
                meth = m.group(1).upper()
                if meth in ("ROUTE", "API_ROUTE"):
                    meth = (re.findall(r"[A-Z]+", (m.group(3) or "GET").upper()) or ["GET"])[0]
                yield {"file": r, "line": ln, "method": meth, "path": m.group(2), "body": body, "code": code}
            else:
                # a raw fetch handler: startsWith('/api/notes/') (or '/api/notes') is a prefix with something
                # after it, written /api/notes/*; the methods come from worker_methods()
                path = m.group(1)
                if "startsWith" in m.group(0):
                    path = path.rstrip("/") + "/*"
                for meth in worker_methods(t, code_text, m.start()):
                    yield {"file": r, "line": ln, "method": meth, "path": path, "body": body, "code": code}
        for rx in FILE_ROUTE_RX:
            fm = rx.search(r)
            if fm:
                path = "/" + re.sub(r"/?index$", "", fm.group(1))
                methods = re.findall(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|export\s+const\s+onRequest(Get|Post|Put|Patch|Delete)?", t)
                ms = sorted({(a or b or "ANY").upper() for a, b in methods}) or ["ANY"]
                for meth in ms:
                    yield {"file": r, "line": 1, "method": meth, "path": path, "body": t, "code": "\n".join(code_lines)}
                break


METHOD_NE_RX = re.compile(r"""\bmethod\s*(?:!==|!=)\s*['"](GET|POST|PUT|PATCH|DELETE)['"]""", re.I)
SWITCH_METHOD_RX = re.compile(r"""\bswitch\s*\(\s*[\w$.]*method\s*\)""")
IF_RX = re.compile(r"\bif\s*\(")
CASE_RX = re.compile(r"""\bcase\s+['"](GET|POST|PUT|PATCH|DELETE)['"]\s*:""", re.I)


def _cond_methods(cond):
    ne = METHOD_NE_RX.findall(cond)
    if ne:
        return ["ALL"]  # `method !== 'GET'`: every other method, writes included
    return sorted({x.upper() for x in WORKER_METHOD_RX.findall(cond)})


def _block_methods(t, code, k):
    """Methods a block at code[k] == '{' dispatches on: nested `if (method === 'X')` and switch/case."""
    end = walk.block_end(code, k)
    seg = t[k:end] if end else t[k:k + 6000]
    out = {x.upper() for x in WORKER_METHOD_RX.findall(seg)}
    for sw in SWITCH_METHOD_RX.finditer(code, k, end or k + 6000):
        bk = code.find("{", sw.end())
        be = walk.block_end(code, bk) if bk >= 0 else None
        out |= {x.upper() for x in CASE_RX.findall(t[bk:be or bk + 6000])}
    if METHOD_NE_RX.search(seg):
        out.add("ALL")
    return sorted(out)


def worker_methods(t, code, pos):
    """The methods a raw fetch handler serves for the path test at pos (Phase 10): the method compared in
    the same `if` condition (`&& request.method === 'DELETE'`, `!== 'GET'`), else the methods its block
    dispatches on (nested ifs, switch (request.method)), else a method test on an enclosing `if`. Read
    by balanced parens and braces, never a line window: the next route's condition is not this one's.
    `t` keeps strings (the method literals), `code` blanks them (the structure); positions agree."""
    prev = t.rfind("\n", 0, max(0, t.rfind("\n", 0, pos)))
    for b in reversed(list(IF_RX.finditer(code, max(0, prev), pos))):
        j = code.find("(", b.start())
        ce = _paren_end(code, j)
        if ce is None or ce <= pos:
            continue
        ms = _cond_methods(t[j:ce])
        if ms:
            return ms
        k = ce
        while k < len(code) and code[k] in " \t\n":
            k += 1
        if k < len(code) and code[k] == "{":
            ms = _block_methods(t, code, k)
            if ms:
                return ms
        else:
            ms = _cond_methods(t[k:_statement_end(code, k)])
            if ms:
                return ms
        # an enclosing `if (request.method === 'DELETE') { if (pathname...) {...} }`
        depth, j2 = 0, b.start()
        for _ in range(3):
            while j2 > 0:
                j2 -= 1
                ch = code[j2]
                if ch == "}":
                    depth += 1
                elif ch == "{":
                    if depth == 0:
                        break
                    depth -= 1
            if j2 <= 0:
                break
            l1 = code.rfind("\n", 0, j2)
            hs0 = code.rfind("\n", 0, l1) if l1 > 0 else -1
            head = code[max(0, hs0):j2]  # the opening brace's line and the one above it
            hm = list(re.finditer(r"\bif\s*\(", head))
            if hm:
                hs = j2 - len(head) + hm[-1].start()
                hj = code.find("(", hs)
                he = _paren_end(code, hj)
                if he and he <= j2:
                    ms = _cond_methods(t[hj:he])
                    if ms:
                        return ms
        break
    ls = t.rfind("\n", 0, pos) + 1
    le = t.find("\n", pos)
    return _cond_methods(t[ls:le if le >= 0 else len(t)]) or ["ANY"]


def auth_ref(code):
    """The first AUTH_RX match in a handler's code that actually speaks of identity, or None.

    Two AUTH_RX credits are withdrawn here (Phase 8 benchmark misses):
    - an ownership identifier (ownerId, owner_id, user_id...) that the handler reads from the
      request (destructured from c.req.json(), assigned from req.body, read as body.ownerId):
      the caller names the owner, so it is not an ownership check;
    - a bare 401/403 or Forbidden/Unauthorized whose triggering condition names no identity
      (user, session, token, owner, admin, role...): `if (note.locked) return 403` refuses locked
      notes, not strangers.
    `code` is the handler text with comments AND strings blanked (surface.handlers()['code']).
    Other callers of AUTH_RX (the inventory's route map) keep the wider reading on purpose."""
    # body / payload / input / params are caller input by convention, unless THIS handler binds the name to
    # something else: `const payload = await verifyToken(cookie)` is a verified token (Phase 10)
    conv = [n for n in CONVENTIONAL_INPUT if not _bound_elsewhere(n, code)]
    req_src = CALLER_INPUT_RX.pattern + ("|\\b(?:%s)\\b" % "|".join(conv) if conv else "")
    for name in set(OWNER_ID_RX.findall(code)):
        sourced = (re.search(r"\{[^}]*\b%s\b[^}]*\}\s*=\s*(?:await\s+)?(?:%s)" % (re.escape(name), req_src), code)
                   or re.search(r"\b%s\s*=\s*(?:await\s+)?(?:%s)" % (re.escape(name), req_src), code)
                   or re.search(r"\b(?:%s)\.%s\b" % ("|".join(conv + [r"req\.body", r"req\.query", r"req\.params"]), re.escape(name)), code))
        if sourced:
            code = re.sub(r"\b%s\b" % re.escape(name), " " * len(name), code)
    for m in AUTH_RX.finditer(code):
        if not STATUS_ONLY_RX.match(m.group(0)):
            return m
        # the condition that leads to this refusal: the `if` (or `catch`'s try) whose consequent holds it
        cond = refusal_condition(code, m.start())
        if cond is None:  # no enclosing branch: a ternary or `x || refuse()` on the lines just above
            start = code.rfind("\n", 0, m.start())
            for _ in range(3):
                start = code.rfind("\n", 0, max(0, start))
                if start <= 0:
                    start = 0
                    break
            cond = code[start: m.start()]
        if names_identity(cond, code):
            return m
    return None


# ---- does a refusal's condition speak of WHO the caller is? (Phase 10, 2026-11-07) ----
# A word test on the condition text credited `post.author !== body.author` (author contains auth),
# `team.member_count >= 50`, `!body.email` and `!c.env.ALLOW_WRITES`, and missed `!viewer`, `!who` and
# `!payload` bound from c.get() or a verify call. The condition is now read operand by operand: each root
# identifier is identity when it is a request object's identity member (req.user, c.get(...), the
# Authorization header), a name bound in the handler to a context read or an identity call, a name that
# itself names identity (user, session, ownerId) and is not bound to caller data, an access predicate call
# (hasAccess(...), canEdit(...)), or a shared-secret env var (env.ADMIN_TOKEN). A property of some other
# object (post.author, team.member_count), caller data (body.email) and a feature flag (env.ALLOW_WRITES) are not.
CONVENTIONAL_INPUT = ("body", "payload", "input", "params")
# the value is wholly the request's: `await c.req.json()`, `Schema.parse(await req.json())`, `body`, `body.x`
WHOLE_INPUT_RX = re.compile(r"(?:await\s+)?(?:[\w$.]*(?:parse|safeParse|validate)\w*\s*\(\s*)?(?:await\s+)?(?:%s|(?:%s)\b)" % (DATA_INPUT_RX.pattern, "|".join(CONVENTIONAL_INPUT)))
ENV_VALUE_RX = re.compile(r"(?:[\w$]+\.)*env\.([\w$]+)|os\.environ(?:\.get\(|\[)")
# A shared-secret env var is judged by its name's WORD SEGMENTS, never substrings: ENABLE_AUTHOR_EDITS holds
# AUTH and ALLOW_ADMINISTRATION holds ADMIN, yet both are feature flags. A credential-shaped name
# (names.secret_name: ADMIN_TOKEN, API_KEY, JWT_SECRET) or a segment in SHARED_SECRET_SEGMENTS counts.
SHARED_SECRET_SEGMENTS = {"TOKEN", "SECRET", "PASSWORD", "PASS", "PASSCODE", "KEY", "APIKEY", "JWT", "CREDENTIAL", "CREDENTIALS"}


def secret_env(name):
    """True when an env var NAME is a shared secret a caller can be checked against (not a feature flag)."""
    return bool(name) and (_names.secret_name(name) or bool(set(_names._segments(name)) & SHARED_SECRET_SEGMENTS))


# reads of what a middleware or the framework established about the caller
CONTEXT_IDENTITY_RX = re.compile(r"\bc\.get\(|\bc\.var\.|\bctx\.state\b|\b(?:req|request)\.(?:user|session|auth)\b|\blocals\.|\bgetCookie\(|\bcookies\(\)|\.cookies\b|\bauthorization\b|\bDepends\(", re.I)
ACCESS_CALL_RX = re.compile(r"^(?:has|can|may)[A-Z]|access|acl|authori[sz]|allowed|permit|verif|decode", re.I)
REQUEST_ROOTS = {"c", "ctx", "req", "request", "event", "context", "res", "reply", "locals"}
REQUEST_IDENTITY_MEMBERS = {"get", "var", "state", "locals", "user", "session", "auth", "account", "principal", "identity", "viewer", "member", "cookies"}
KEYWORDS = {"if", "elif", "else", "await", "return", "typeof", "new", "null", "undefined", "true", "false", "not", "and", "or", "is",
            "None", "True", "False", "in", "instanceof", "throw", "const", "let", "var", "unless", "guard", "void", "delete", "of"}
ROOT_RX = re.compile(r"(?<![\w$.])(?<!\.\s)(?<!\?\.)([A-Za-z_$][\w$]*)((?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)(\s*\()?")
BRANCH_RX = re.compile(r"\b(?:if|elif|unless|guard|catch)\b")
COND_LOOKBACK = 15  # lines above a refusal searched for the branch that leads to it


def _bound_elsewhere(name, code):
    """True when the handler binds `name` to something other than caller input."""
    src = walk.decl_src(name, code)
    return bool(src) and not DATA_INPUT_RX.search(src)


def _paren_end(code, i):
    """Index just past the `)` that balances the `(` at i, or None."""
    depth = 0
    for j in range(i, min(len(code), i + 4000)):
        depth += (code[j] == "(") - (code[j] == ")")
        if depth == 0:
            return j + 1
    return None


def _statement_end(code, i):
    """End of the brace-less statement starting at i: the first `;` or newline outside brackets."""
    depth = 0
    for j in range(i, min(len(code), i + 4000)):
        ch = code[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif ch in ";\n" and depth == 0 and code[i:j].strip():
            return j
    return len(code)


def refusal_condition(code, pos):
    """The condition text of the nearest branch whose consequent holds pos: `if (c) {...}`, `if (c) stmt`,
    Python `if c:` plus its indented block, or for a `catch` the try block it guards. None when pos sits
    in no branch within COND_LOOKBACK lines."""
    lo = pos
    for _ in range(COND_LOOKBACK):
        lo = code.rfind("\n", 0, max(0, lo))
        if lo <= 0:
            lo = 0
            break
    for b in reversed(list(BRANCH_RX.finditer(code, lo, pos))):
        j = b.end()
        while j < len(code) and code[j] in " \t":
            j += 1
        if b.group(0) == "catch":
            if j < len(code) and code[j] == "(":
                j = _paren_end(code, j) or j
            k = code.find("{", j)
            end = walk.block_end(code, k) if k >= 0 else None
            if end and k < pos < end:
                t = code.rfind("try", 0, b.start())
                return code[t:b.start()] if t >= 0 else ""
            continue
        if j < len(code) and code[j] == "(":
            ce = _paren_end(code, j)
            if ce is None or ce > pos:
                continue
            cond = code[j:ce]
            k = ce
            while k < len(code) and code[k] in " \t\n":
                k += 1
            if k < len(code) and code[k] == "{":
                end = walk.block_end(code, k)
                if end is not None and pos < end:
                    return cond
            elif pos < _statement_end(code, k):
                return cond
            continue
        # Python: `if cond:` then a deeper-indented block (or the rest of the line)
        eol = code.find("\n", j)
        eol = len(code) if eol < 0 else eol
        line = code[j:eol]
        colon = line.rfind(":")
        if colon < 0:
            continue
        if pos < eol:
            return line[:colon]
        ls = code.rfind("\n", 0, b.start()) + 1
        indent = len(code[ls:b.start()]) - len(code[ls:b.start()].lstrip())
        k = eol + 1
        while k < len(code):
            e = code.find("\n", k)
            e = len(code) if e < 0 else e
            ln = code[k:e]
            if ln.strip() and len(ln) - len(ln.lstrip()) <= indent:
                break
            if k <= pos < e + 1:
                return line[:colon]
            k = e + 1
    return None


def _root_identity(name, chain, called, code, depth):
    if name in KEYWORDS or name.isdigit():
        return False
    segs = [s for s in re.split(r"\s*\??\.\s*", chain.strip()) if s]
    if name == "env" or (segs[:1] == ["env"]) or (name == "process" and segs[:1] == ["env"]):
        return bool(segs) and secret_env(segs[-1])  # a shared secret, never a feature flag
    if name in REQUEST_ROOTS:
        if segs and segs[0] == "req":  # Hono: c.req.X
            segs = segs[1:]
        if any(s.lower() in ("headers", "header") for s in segs):
            return any(s.lower() in ("authorization", "cookie", "cookies") for s in segs)
        return bool(segs) and segs[0] in REQUEST_IDENTITY_MEMBERS
    src = walk.decl_src(name, code)
    ev = ENV_VALUE_RX.match(src.strip()) if src else None
    if src and (WHOLE_INPUT_RX.match(src.strip()) or (ev and not secret_env(ev.group(1) or ""))):
        return False  # the caller's own data, or a feature flag copied into a local
    if not src and name in CONVENTIONAL_INPUT:
        return False
    if IDENTITY_WORD_RX.search(name):
        return True
    if called and ACCESS_CALL_RX.search(name):
        return True
    if src and depth < 2:
        if CONTEXT_IDENTITY_RX.search(src):
            return True
        for cm in re.finditer(r"([A-Za-z_$][\w$]*)\s*\(", src):
            if IDENTITY_WORD_RX.search(cm.group(1)) or ACCESS_CALL_RX.search(cm.group(1)):
                return True
        return names_identity(src, code, depth + 1)
    return False


def names_identity(cond, code, depth=0):
    """True when some operand of the condition text is about who the caller is (see the block comment above).
    `code` is the handler (strings blanked), where the operands' bindings are looked up."""
    for m in ROOT_RX.finditer(cond):
        if _root_identity(m.group(1), m.group(2) or "", bool(m.group(3)), code, depth):
            return True
    return False


def middleware_auth(repo):
    """Path prefixes covered by an auth middleware mounted with app.use(prefix, fn)."""
    out = []
    for r, ln, m in walk.find(repo, MW_RX, tests=False):
        if AUTH_RX.search(m.group(2)) and not STUB_RX.search(m.group(2)):
            out.append((m.group(1).rstrip("*").rstrip("/") or "/", "%s:%d" % (r, ln)))
    for rel in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"):
        p = os.path.join(repo, rel)
        if os.path.exists(p) and AUTH_RX.search(walk.read_code(p)):
            t = walk.read_code(p)
            m = re.search(r"matcher\s*:\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", t)
            if m:  # only the matched prefixes are covered
                for pat in re.findall(r"['\"](/[^'\"]*)['\"]", m.group(1)):
                    out.append((re.sub(r"[:(].*$", "", pat).rstrip("/*") or "/", rel + " matcher"))
            else:
                out.append(("/", rel + " (Next middleware, no matcher: every path)"))
    return out


MOUNT_RX = re.compile(r"""\.(?:route|use)\(\s*['"](/[^'"]*)['"]\s*,\s*(\w+)\s*\)""")


def mount_paths(repo, rel, path):
    """Full paths for a sub-router file: app.route('/api/generate', generate) + '/lesson' -> /api/generate/lesson.
    Matches the mounted identifier against the file's import name or stem."""
    stem = os.path.splitext(os.path.basename(rel))[0].lower().replace("-", "").replace("_", "")
    out = []
    for r, ln, m in walk.find(repo, MOUNT_RX, tests=False, served=True):
        name = m.group(2).lower()
        if name == stem or name.startswith(stem[:5]) or stem.startswith(name[:5]):
            out.append(m.group(1).rstrip("/") + path)
    return out


def covered(path, mw):
    for prefix, at in mw:
        if prefix == "/" or path == prefix or path.startswith(prefix + "/"):
            return at
    return None


# ---- relative imports (Phase 9, 2026-11-01: one home) ----
# Merged from check_spend (_resolve, imported, _import_names) and check_auth_gates (_resolve, _import_names).
# The one disagreement: a default import (`import geo from './geo'`) mapped to the exported name "default" in
# check_spend and to the local name in check_auth_gates. Both callers then searched the target file for the
# LOCAL name (check_spend substituted it at its one use), so the local name is the one semantics kept here.
# `import type` brings no code: it is not a call path (a coaching app's prose.ts imports a TYPE from coach.ts).
IMPORT_REL = re.compile(r"""(?:^|[;\n])\s*(?:import\s+(?!type\b)(?:[^'";]*?\s+from\s+)?|export\s+(?!type\b)[^'";]*?\s+from\s+|[^\n]*?\brequire\(\s*)['"](\.{1,2}/[^'"]+)['"]""")
IMPORT_NAMES = re.compile(r"""import\s+(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s*['"](\.{1,2}/[^'"]+)['"]|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)""")
IMPORT_EXTS = ("", ".ts", ".tsx", ".js", ".mjs", "/index.ts", "/index.js")
JS_TO_TS = re.compile(r"\.(?:js|mjs)$")


def resolve_import(repo, rel, spec):
    """The repo-relative file a relative import specifier names, or None.
    TypeScript ESM imports name the .js that the .ts becomes, so './geo.js' resolves to geo.ts."""
    base = os.path.normpath(os.path.join(os.path.dirname(rel), spec))
    if not os.path.isfile(os.path.join(repo, base)):
        base = JS_TO_TS.sub("", base)
    for e in IMPORT_EXTS:
        cand = base + e
        if os.path.isfile(os.path.join(repo, cand)):
            return cand.replace(os.sep, "/")
    return None


def imported(repo, rel):
    """The file plus the relative files it imports or re-exports (one level), as repo-relative paths."""
    out = [rel]
    t = walk.read_code(os.path.join(repo, rel))
    for m in IMPORT_REL.finditer(t):
        target = resolve_import(repo, rel, m.group(1))
        if target:
            out.append(target)
    return out


def import_names(repo, rel, text=None):
    """local name -> (file, exported name) for every relative import in rel. A default import maps to its
    local name; `import { a as b }` maps b to (file, 'a'); `import type` members are skipped.
    `text` is the file's comment-stripped code when the caller already has it."""
    out = {}
    if text is None:
        text = walk.read_code(os.path.join(repo, rel))
    for m in IMPORT_NAMES.finditer(text):
        target = resolve_import(repo, rel, m.group(3) or m.group(5))
        if not target:
            continue
        if m.group(1):
            out[m.group(1)] = (target, m.group(1))
        for x in (m.group(2) or m.group(4) or "").split(","):
            x = x.strip()
            if x and not x.startswith("type "):
                parts = re.split(r"\s+as\s+|\s*:\s*", x)
                out[parts[-1]] = (target, parts[0])
    return out


# ---- caller input and the names it flows into (Phase 9, 2026-11-01: one home) ----
# Merged from check_spend._request_names (bindings whose value STARTS with a request accessor, through an
# optional schema parse; the connecting-address headers excluded) and check_ai._tainted (bindings whose value
# MENTIONS an accessor anywhere, flowing one level through earlier tainted names, plus Python assignments).
# The merge is the union: a binding is caller input when its right-hand side starts with an accessor or a
# conventional request-value name (body, payload, reqBody, requestBody), mentions an accessor anywhere, or
# mentions a name already bound to caller input earlier in the file. The conventional names count only at the
# START of a value: `const { model } = body` binds model, `fetch(url, { body: ... })` binds nothing. The
# connecting-address headers (cf-connecting-ip, x-real-ip, x-forwarded-for) are excluded for every consumer:
# the edge sets them, the caller does not, so a limiter keyed on them is a real per-client key.
REQUEST_VALUE_NAMES = ("body", "payload", "reqBody", "requestBody")
# `const input = Schema.parse(await c.req.json())`, `const q = c.req.query('q')`, `const { model } = body`: the
# whole value is the request's. `const chosen = ALLOWED.includes(body.model) ? ...` is NOT (the server chooses).
BOUND_TO_INPUT_RX = re.compile(r"(?:await\s+)?(?:[\w$.]*(?:parse|safeParse|validate|decode)\w*\s*\(\s*)?(?:await\s+)?(?:%s|\b(?:%s)\b)"
                               % (CALLER_INPUT_RX.pattern, "|".join(REQUEST_VALUE_NAMES)))
ASSIGN_RX = re.compile(r"\b(?:const|let|var)\b\s*(\{[^}]{1,300}\}|[\w$]+)\s*(?::[^=\n]{0,80})?\s*=\s*([^;\n]{1,240})")
PY_ASSIGN_RX = re.compile(r"^[ \t]*([\w]+)\s*=\s*([^\n]{1,240})", re.M)
# The wider reading for a value already known to be a key component (check_metering): any header, a context
# variable a middleware set from the request, a query/param accessor, the request body under any accessor.
# Case-insensitive. Never use it to find where input enters a file; `.query(` also matches `db.query(`.
CALLER_SUPPLIED_RX = re.compile(CALLER_INPUT_RX.pattern +
                                r"|\.header\(|headers\.get\(|headers\[|c\.get\(\s*['\"](?:teacher|user|account)|c\.var\.|\.query\(|\.param\("
                                r"|\bbody\b|\bpayload\b", re.I)  # the accessors themselves come from CALLER_INPUT_RX
IDENT_RX = re.compile(r"^[A-Za-z_$][\w$]*$")


def _destructured(lhs):
    """Names bound by a destructuring pattern's text: `{ a, b: c = 1 }` binds a and c."""
    return {x.split(":")[-1].split("=")[0].strip() for x in lhs.strip("{}").split(",") if x.strip()}


def request_names(text):
    """Identifiers bound to caller input in this file (one level of flow): destructured from the body or
    query, assigned the whole request value (possibly through a schema parse), assigned an expression that
    reads a request accessor, or assigned from a name bound earlier in the file (as a value, not as a
    property: `obj.model` does not carry a tainted `model`). Python assignments count when they read an
    accessor. Used to follow caller input past its first name."""
    names = set()
    for m in ASSIGN_RX.finditer(text):
        lhs, rhs = m.group(1), m.group(2)
        if CALLER_INPUT_RX.search(rhs) or BOUND_TO_INPUT_RX.match(rhs) or any(re.search(r"(?<![\w$.])%s\b" % re.escape(n), rhs) for n in names):
            if lhs.startswith("{"):
                names |= _destructured(lhs)
            else:
                names.add(lhs)
    for m in PY_ASSIGN_RX.finditer(text):
        if CALLER_INPUT_RX.search(m.group(2)):
            names.add(m.group(1))
    return {n for n in names if IDENT_RX.match(n)}

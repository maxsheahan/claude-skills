#!/usr/bin/env python3
"""check_auth_gates.py - auth gates that open on their own: static checks on a
repo for the four shapes the 2026-10-13 account audit found in production.

  check_auth_gates.py REPO

  auth.off-switch     a handler or middleware that SKIPS auth when an env
                      secret is absent (`if (!env.X) return next()`,
                      `if (!c.env.X) return next()`, the same with the secret
                      destructured into a local first, `enabled: !!env.X`
                      around auth, or a verification that only runs
                      `if (env.X)`) FAILs high. The skip counts only when the
                      guard is auth-shaped: the surrounding block compares a
                      token, secret or password, calls a verifier, answers 401
                      or 403, or sets an identity, or the secret's own name is
                      auth-shaped (AUTH, SESSION, ADMIN, JWT, ...). A skipped
                      analytics beacon (`if (!env.ANALYTICS_TOKEN) return
                      next()`) is a feature flag, not a gate. A missing secret
                      must mean 503, never open (a ledger app's /api/state was
                      readable and writable for three months through exactly
                      this branch).
  auth.header-identity identity read from a request header with no verification
                      anywhere in the tree (cf-access-authenticated-user-email,
                      x-teacher-id, x-user-*, x-email, the auth-proxy family
                      x-forwarded-email, x-forwarded-user, remote-user) FAILs
                      high: any path that reaches the Worker without the edge
                      policy gives the caller any identity.
  auth.access-jwt     a Worker with a custom domain or route in wrangler config
                      and no Cf-Access-Jwt-Assertion reference is UNKNOWN
                      ("cannot see whether Access fronts this host"); a
                      reference that is read but not verified (no jwtVerify or
                      other verify call; importing jose or calling decodeJwt is
                      not verification) FAILs high; jwtVerify without issuer and
                      audience in its options FAILs medium; verification with
                      both PASSes.
  auth.open-signup    better-auth with emailAndPassword enabled, no
                      disableSignUp and no user.create.before hook FAILs
                      medium: anyone can mint an account. The hook may be built
                      in another file (`databaseHooks: inviteOnlyHooks(env)`);
                      a Worker entry that refuses every /api/auth/sign-up*
                      request with 401/403/404 and fails closed when its
                      secret is unset also closes sign-up (reference, not
                      proof).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import surface  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

ENV = r"(?:[\w$]+\.)*(?:env|process\.env)\.[\w$]+"
# `if (!c.env.SECRET) return next()` and its braced and awaited forms.
SKIP_NEXT = re.compile(r"if\s*\(\s*!\s*(%s)\s*\)\s*\{?\s*return\s+(?:await\s+)?next\s*\(\s*\)" % ENV)
# `enabled: !!env.X` / `enabled: Boolean(env.X)`: a guard that is on only when the secret is set.
ENABLED_ENV = re.compile(r"\benabled\s*:\s*(?:!!\s*(%s)|Boolean\(\s*(%s)\s*\))" % (ENV, ENV))
# `if (env.WEBHOOK_SECRET) { ... verify ... }`: verification that runs only when the secret exists.
VERIFY_IF_SET = re.compile(r"if\s*\(\s*(%s)\s*\)\s*\{" % ENV)
VERIFY_WORDS = re.compile(r"verif|signature|constructEvent|jwt|session|authenticate", re.I)
SECRET_NAME = re.compile(r"SECRET|KEY|TOKEN|PASS", re.I)
AUTHISH = re.compile(r"auth|session|login|sign|turnstile|verify|jwt", re.I)

# A local that holds an env secret: `const { ADMIN_TOKEN } = c.env`, `const token = env.ADMIN_TOKEN`.
ENV_DESTRUCT = re.compile(r"(?:const|let|var)\s*\{([^}]{1,300})\}\s*=\s*(?:[\w$]+\.)*(?:env|process\.env)\b")
# the read may carry a TS cast or an empty default (`c.env.ADMIN_TOKEN as string`, `?? ''`, `|| ''`): still the secret
ENV_ALIAS = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*(?::[^=\n]{0,80})?=\s*(?:[\w$]+\.)*(?:env|process\.env)\.([\w$]+)\s*(?:(?:as\s+[^;\n]{1,80}|\?\?[^;\n]{1,80}|\|\|[^;\n]{1,80}))?\s*[;\n]")
# The guard around an off-switch is auth-shaped: it compares a token, secret or password, calls a
# verifier, answers 401/403, READS the Authorization header (an outbound fetch's `'Authorization':` key sends
# one, Phase 10), or sets or reads an identity (an allow-list over c.get('email') that redirects strangers).
AUTH_SHAPE = re.compile(r"\b40[13]\b|\b(?:bearerAuth|basicAuth|jwtVerify|getSession|verifySession|requireUser|requireAuth|authenticate|timingSafeEqual|verify\w*)\s*\("
                        r"|Unauthorized|Forbidden|(?:\.header|\.get|headers\.get|getHeader)\(\s*['\"]authorization['\"]|headers\.authorization\b|headers\[\s*['\"]authorization['\"]\s*\](?!\s*=(?!=))"
                        r"|c\.(?:set|get)\(\s*['\"](?:user|email|teacher|account|identity|session|auth)|c\.var\.(?:user|email|session)\b|req\.(?:user|session)\b|\bisAdmin\b", re.I)
AUTH_COMPARE = re.compile(r"(?:===|!==|==|!=)\s*[^\n;]{0,80}(?:TOKEN|SECRET|PASS|KEY|[Tt]oken|[Ss]ecret|[Pp]assword)|(?:TOKEN|SECRET|PASS|KEY|[Tt]oken|[Ss]ecret|[Pp]assword)\w*\s*(?:===|!==|==|!=)")
# Judged word by word on the env name (ADMIN_TOKEN -> ADMIN, TOKEN), never as a substring: BYPASS_CACHE has no
# PASS word and ACCESS_LOG_SINK names an access log, not Cloudflare Access (Phase 10). An allow-list of emails or
# users is identity (ALLOWED_EMAILS).
AUTH_WORD = re.compile(r"^(?:O?AUTH[NZ]?|AUTHORI[SZ]ATION|AUTHENTICATION|SESSIONS?|JWT|JWKS|ADMINS?|PASS|PASSWORD|PASSCODE|PASSPHRASE|LOGIN|SIGNIN|SIGNING|TURNSTILE"
                       r"|ACCESS|INVITES?|SECRETS?|CREDENTIALS?|APIKEY|ALLOWLIST|WHITELIST)$", re.I)

HEADER_READ = re.compile(
    r"""(?:\.header\(|headers\.get\(|headers\[|\.get\(|getHeader\()\s*['"](cf-access-authenticated-user-email|x-teacher-id|x-user(?:-[\w-]+)?|x-userid|x-email|x-auth-email"""
    r"""|x-forwarded-(?:email|user|preferred-username|groups)|remote-user|x-remote-user|x-auth-request-(?:email|user|preferred-username)|x-webauth-user|x-authenticated-user)['"]""",
    re.I)
ASSERTION = re.compile(r"Cf-Access-Jwt-Assertion", re.I)
# Verification is a verify CALL. Importing jose proves nothing, and decodeJwt reads the claims of a forged
# token just as happily as a real one (bench 2026-11-01).
# jsonwebtoken's jwt.verify(token, key, { issuer, audience }) is a verify call too (Phase 10), as is a bare
# verify(...) imported from a JWT library (hono/jwt, jsonwebtoken): see jwt_verify_names().
VERIFIER = re.compile(r"\b(?:jwtVerify|compactVerify|flattenedVerify|generalVerify|verifyAccessJwt|verify\w*(?:Jwt|JWT|Token|Access|Assertion)\w*)\s*\(|\bjose\.jwtVerify\s*\("
                      r"|\b(?:jwt|jsonwebtoken|JWT|jws)\.verify\s*\(")
JWT_LIB_IMPORT = re.compile(r"""import\s*\{([^}]*)\}\s*from\s*['"](?:hono/jwt|jsonwebtoken|@tsndr/cloudflare-worker-jwt|jose|@hono/jwt)['"]""")
DECODE_ONLY = re.compile(r"\bdecodeJwt\s*\(|\bjwtDecode\s*\(|\bjwt\.decode\s*\(")
# a key or the TS shorthand `{ issuer, audience }` (Phase 10)
ISSUER = re.compile(r"\bissuer\b\s*[:,}]")
AUDIENCE = re.compile(r"\baudience\b\s*[:,}]|\baud\b")
ROUTE_DECL = re.compile(r"""custom_domain\s*[=:]\s*true|^\s*routes?\s*[=:]|["']?pattern["']?\s*[=:]\s*["'][^"']+["']|["']routes["']\s*:""", re.M)

BETTER_AUTH = re.compile(r"betterAuth\s*\(|from\s+['\"]better-auth['\"]")
EMAIL_PW = re.compile(r"emailAndPassword\s*:\s*\{")  # the block is read brace-balanced (nested options)
CREATE_BEFORE = re.compile(r"user\s*:\s*\{\s*create\s*:\s*\{\s*before\s*:|user\.create\.before", re.S)
DB_HOOKS = re.compile(r"databaseHooks\s*:\s*([\w$]+)\s*(?:\(|,|\n|\})")  # a hook object built elsewhere
SIGNUP_PATH = re.compile(r"sign-?up", re.I)
# `if (!env.X) return true` / `return next()` inside the gate's helper: the refusal opens when the secret is unset.
FAILS_OPEN = re.compile(r"if\s*\(\s*!\s*(?:[\w$]+\.)*env\.[\w$]+\s*\)\s*\{?\s*return\s+(?:true|(?:await\s+)?next\s*\()")


def _env_locals(text):
    """local name -> env name for secrets copied into locals: `const { ADMIN_TOKEN } = c.env`,
    `const token = env.ADMIN_TOKEN`."""
    out = {}
    for m in ENV_DESTRUCT.finditer(text):
        for x in m.group(1).split(","):
            x = x.strip()
            if x:
                parts = re.split(r"\s*:\s*", x.split("=")[0].strip())
                out[parts[-1]] = parts[0]
    for m in ENV_ALIAS.finditer(text):
        out[m.group(1)] = m.group(2)
    return {k: v for k, v in out.items() if re.match(r"^[A-Za-z_$][\w$]*$", k)}


def _auth_shaped(code, text, pos, env_name):
    """The off-switch at pos guards auth: its block has an auth shape, or the secret's name is auth-shaped."""
    block = walk.enclosing_block(code, text, pos)
    return bool(AUTH_SHAPE.search(block) or AUTH_COMPARE.search(block) or auth_name(env_name))


def auth_name(env_name):
    """The env var's own name is auth-shaped, word by word: ADMIN_TOKEN, SESSION_SECRET, API_KEY, ALLOWED_EMAILS.
    ACCESS followed by LOG is an access log; ALLOW(ED) counts only before LIST/EMAILS/USERS/DOMAINS/IDS."""
    words = [w for w in re.split(r"_|(?<=[a-z])(?=[A-Z])", env_name) if w]
    up = [w.upper() for w in words]
    for i, w in enumerate(up):
        nxt = up[i + 1] if i + 1 < len(up) else ""
        if w == "ACCESS" and nxt in ("LOG", "LOGS"):
            continue
        if w in ("ALLOW", "ALLOWED") and nxt in ("LIST", "EMAILS", "USERS", "DOMAINS", "IDS"):
            return True
        if w == "API" and nxt == "KEY":
            return True
        if AUTH_WORD.match(w):
            return True
    # run-together names (ADMINTOKEN, SESSIONKEY): the words no product name hides
    return bool(re.search(r"ADMIN|SESSION|JWT|PASSWORD|PASSCODE|SECRET|CREDENTIAL|TURNSTILE", env_name, re.I))


def _call_args(text, pos):
    """The parenthesized argument text of the call (or `if`) whose name ends just before pos."""
    i = text.find("(", pos)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, min(len(text), i + 2000)):
        depth += (text[j] == "(") - (text[j] == ")")
        if depth == 0:
            return text[i:j + 1]
    return text[i:i + 2000]


def jwt_verify_names(text):
    """Local names of a `verify` imported from a JWT library: `import { verify } from 'hono/jwt'`."""
    out = []
    for m in JWT_LIB_IMPORT.finditer(text):
        for x in m.group(1).split(","):
            parts = re.split(r"\s+as\s+", x.strip())
            if parts[0] == "verify":
                out.append(parts[-1])
    return out


def _verify_options(text, m, repo=None, rel=None):
    """Text where jwtVerify's issuer and audience must appear: the call's arguments, plus the declaration of
    any bare identifier passed as an argument (`jwtVerify(t, JWKS, opts)` with `const opts = {...}`), in
    this file or, when the name is imported, in the file it comes from (Phase 10)."""
    args = _call_args(text, m.start())
    extra = ""
    imports = surface.import_names(repo, rel, text) if repo and rel else {}
    for name in re.findall(r"[(,]\s*([A-Za-z_$][\w$]*)\s*(?=[,)])", args):
        scopes = [(text, name)]
        if name in imports:
            scopes.append((walk.read_code(os.path.join(repo, imports[name][0])), imports[name][1]))
        for sc, nm in scopes:
            d = re.search(r"(?:const|let|var)\s+%s\s*(?::[^=\n]{0,80})?=\s*" % re.escape(nm), sc)
            if d:
                extra += walk.block(sc, d.end()) or sc[d.end():d.end() + 300]
                break
    return args + extra


def _hooks_close_signup(repo, rel, text, config):
    """The betterAuth config's databaseHooks names an object built elsewhere; follow it to its definition
    (same file or one import over) and look for user.create.before there."""
    m = DB_HOOKS.search(config)
    if not m:
        return False
    name = m.group(1)
    where = [(rel, text)]
    imp = surface.import_names(repo, rel, text).get(name)
    if imp:
        where.append((imp[0], walk.read_code(os.path.join(repo, imp[0]))))
        name = imp[1]
    for _, t2 in where:
        d = walk.function_decl(t2, name)
        if d and CREATE_BEFORE.search(walk.block(t2, d.end()) or t2[d.end():d.end() + 3000]):
            return True
    return False


def _split_top(expr, op):
    """Split expr on a top-level operator (`||` or `&&`), brackets and quotes respected."""
    parts, depth, quote, last, i = [], 0, None, 0, 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and expr.startswith(op, i):
            parts.append(expr[last:i])
            last = i + len(op)
            i += len(op)
            continue
        i += 1
    parts.append(expr[last:])
    return [p.strip() for p in parts]


SIGNUP_API = "/api/auth/sign-up/email"  # better-auth's sign-up endpoint under its default base path
SIGNUP_LIT = re.compile(r"""(['"`])([^'"`\n]*sign-?up[^'"`\n]*)\1""", re.I)
METHOD_EQ = re.compile(r"""\bmethod\s*(?:===|==)\s*['"](\w+)['"]|['"](\w+)['"]\s*(?:===|==)\s*[\w$.]*method\b""", re.I)


def _signup_term_covers(term):
    """A positive sign-up path test reaches the sign-up API: a substring or regex test always does; a
    startsWith prefix does when the API path starts with it or a base segment precedes sign-up (a custom
    basePath); an exact comparison only when it names the .../sign-up/email endpoint itself."""
    if re.match(r"!(?!=)", term) or re.search(r"!==?|===?\s*false\b", term):
        return False  # `!path.startsWith('/api/auth/sign-up')`: the allow-list EXEMPTS sign-up
    lm = SIGNUP_LIT.search(term)
    if not lm:
        return True  # a regex literal or a constant: read as a substring test
    lit = lm.group(2)
    before = term[:lm.start()]
    if re.search(r"(?:===|==)\s*$", before) or re.match(r"\s*(?:===|==)", term[lm.end():]):
        return bool(re.search(r"sign-?up/email/?$", lit, re.I))
    if re.search(r"\.startsWith\(\s*$", before):
        return SIGNUP_API.startswith(lit) or bool(re.match(r"^/?[^/]+/.*sign-?up", lit, re.I))
    return True


def _refuses_signup_api(cond):
    """The `if` condition refuses the sign-up API (Phase 10): some `||` branch holds a positive sign-up path
    test that reaches the API endpoint, and no `&&` partner narrows it to a page-only method (GET)."""
    inner = cond[1:-1] if cond.startswith("(") and cond.endswith(")") else cond
    for disj in _split_top(inner, "||"):
        conj = _split_top(disj, "&&")
        terms = [c for c in conj if SIGNUP_PATH.search(c)]
        if not terms or not all(_signup_term_covers(c) for c in terms):
            continue
        methods = {(a or b).upper() for c in conj for a, b in METHOD_EQ.findall(c)}
        if methods and "POST" not in methods:
            continue  # refuses only GET /sign-up: the page, not POST /api/auth/sign-up/email
        return True
    return False


def _signup_refused(repo, files):
    """A Worker entry (one layer above better-auth) that refuses sign-up paths: `if (<path has sign-up> ...)`
    whose consequent returns 401, 403 or 404, with no fail-open in its condition or its helpers. Returns the
    'file:line' of the refusal or None."""
    for p in files:
        rel = walk.rel(repo, p)
        if not rel.endswith((".ts", ".js", ".mjs")):
            continue
        t = walk.read_code(p)
        for m in re.finditer(r"\bif\s*\(", t):
            cond = _call_args(t, m.start())
            if not SIGNUP_PATH.search(cond) or not _refuses_signup_api(cond):
                continue
            after = t[t.find("(", m.start()) + len(cond):]
            body = walk.block(after, 0) if after.lstrip().startswith("{") else after.split("\n", 1)[0]
            if not (re.search(r"\b40[134]\b", body) and "return" in body):
                continue
            if re.search(r"(?<![!\w])(?:[\w$]+\.)*env\.[\w$]+\s*&&", cond):
                continue  # refuses only while the secret is set: fails open
            opened = False
            for name in re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", cond):
                d = walk.function_decl(t, name)
                if d and FAILS_OPEN.search(walk.block(t, d.end())):
                    opened = True
            if not opened:
                return "%s:%d" % (rel, walk.line_of(t, m.start()))
    return None


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    files = list(walk.files(repo, tests=False, served=True))

    # (a) auth off-switch
    offs = []
    for p in files:
        rel = walk.rel(repo, p)
        t = walk.read_code(p)
        tc = walk.read_code(p, strings=False)
        locals_ = _env_locals(tc)
        skips = [(m.start(), m.group(1).split(".")[-1]) for m in SKIP_NEXT.finditer(tc)]
        enabled = [(m.start(), (m.group(1) or m.group(2)).split(".")[-1]) for m in ENABLED_ENV.finditer(tc)]
        if_set = [(m.start(), m.end(), m.group(1).split(".")[-1]) for m in VERIFY_IF_SET.finditer(tc)]
        if locals_:
            alt = "|".join(sorted(re.escape(n) for n in locals_))
            skips += [(m.start(), locals_[m.group(1)]) for m in re.finditer(r"if\s*\(\s*!\s*(%s)\s*\)\s*\{?\s*return\s+(?:await\s+)?next\s*\(\s*\)" % alt, tc)]
            enabled += [(m.start(), locals_[m.group(1) or m.group(2)]) for m in re.finditer(r"\benabled\s*:\s*(?:!!\s*(%s)\b|Boolean\(\s*(%s)\s*\))" % (alt, alt), tc)]
            if_set += [(m.start(), m.end(), locals_[m.group(1)]) for m in re.finditer(r"if\s*\(\s*(%s)\s*\)\s*\{" % alt, tc)]
        for pos, name in skips:
            if _auth_shaped(tc, t, pos, name):
                offs.append("%s:%d (%s absent skips the guard)" % (rel, walk.line_of(t, pos), name))
        if AUTHISH.search(t) or AUTHISH.search(rel):
            for pos, name in enabled:
                offs.append("%s:%d (enabled only when %s is set)" % (rel, walk.line_of(t, pos), name))
        for pos, end, name in if_set:
            if not SECRET_NAME.search(name):
                continue
            block = walk.block(t, end - 1)
            if VERIFY_WORDS.search(block) and not re.search(r"\b(?:fetch|messages\.create|send)\b", block):
                offs.append("%s:%d (verification runs only when %s is set)" % (rel, walk.line_of(t, pos), name))
    if offs:
        res.append(result("auth.off-switch", "No auth gate switches itself off when a secret is missing", "FAIL", ledger.join_hits(offs, 6, "; "),
                          severity="high", fix="answer 503 (or throw) when the secret is absent; the only bypass may be an explicit test env, never an unset secret"))
    elif files:
        res.append(result("auth.off-switch", "No auth gate switches itself off when a secret is missing", "PASS",
                          "no env-gated skip of a guard in %d production source file(s)" % len(files)))

    # (b) identity from a header, (c) Access JWT verification
    header_reads, assertion_refs, verifier_refs, verifier_opts, decode_refs = [], [], [], [], []
    for p in files:
        rel = walk.rel(repo, p)
        t = walk.read_code(p)
        for m in HEADER_READ.finditer(t):
            header_reads.append("%s:%d (%s)" % (rel, walk.line_of(t, m.start()), m.group(1).lower()))
        for m in ASSERTION.finditer(t):
            assertion_refs.append("%s:%d" % (rel, walk.line_of(t, m.start())))
        vnames = jwt_verify_names(t)
        vcalls = list(VERIFIER.finditer(t))
        if vnames:
            vcalls += list(re.finditer(r"(?<![\w$.])(?:%s)\s*\(" % "|".join(re.escape(n) for n in vnames), t))
        for m in vcalls:
            verifier_refs.append("%s:%d" % (rel, walk.line_of(t, m.start())))
            verifier_opts.append(_verify_options(t, m, repo, rel))
        for m in DECODE_ONLY.finditer(t):
            decode_refs.append("%s:%d" % (rel, walk.line_of(t, m.start())))
    verified = bool(assertion_refs) and bool(verifier_refs)
    if header_reads and not verified:
        res.append(result("auth.header-identity", "Identity comes from a verified token, not a bare header", "FAIL", ledger.join_hits(header_reads, 6, "; "),
                          severity="high", fix="verify Cf-Access-Jwt-Assertion with the team JWKS (issuer, aud) and read the email from the claim; a header is forged in one curl flag"))
    elif header_reads:
        res.append(result("auth.header-identity", "Identity comes from a verified token, not a bare header", "PASS",
                          "header read at %s; JWT verification at %s" % (ledger.join_hits(header_reads, 2, ", "), ledger.join_hits(verifier_refs, 2, ", ")),
                          detail="a reference, not a proof: confirm the verification runs before the header is trusted on every route"))
    elif files:
        res.append(result("auth.header-identity", "Identity comes from a verified token, not a bare header", "PASS",
                          "no identity header read in %d production source file(s)" % len(files)))

    wcfg = None
    for f in ("wrangler.toml", "wrangler.jsonc", "wrangler.json"):
        if os.path.exists(os.path.join(repo, f)):
            wcfg = f
            break
    if wcfg:
        wt = walk.read(os.path.join(repo, wcfg))
        wt = "\n".join(l for l in wt.splitlines() if not l.lstrip().startswith(("#", "//")))
        routed = bool(ROUTE_DECL.search(wt))
        if assertion_refs and not verifier_refs:
            why = "assertion read at %s but no jwtVerify (or other verify call) in the tree" % ledger.join_hits(assertion_refs, 3, ", ")
            if decode_refs:
                why += "; decodeJwt at %s reads the claims without checking the signature" % ledger.join_hits(decode_refs, 2, ", ")
            res.append(result("auth.access-jwt", "The Worker verifies the Access JWT itself", "FAIL", why,
                              severity="high", fix="jwtVerify the assertion against https://<team>.cloudflareaccess.com/cdn-cgi/access/certs with issuer and audience, then read the email claim"))
        elif verified:
            near = next((ref for ref, opts in zip(verifier_refs, verifier_opts) if ISSUER.search(opts) and AUDIENCE.search(opts)), "")
            if near:
                res.append(result("auth.access-jwt", "The Worker verifies the Access JWT itself", "PASS", "jwtVerify with issuer and audience at %s" % near,
                                  detail="confirm the middleware covers every data route and that the email claim is compared to an allow-list"))
            else:
                res.append(result("auth.access-jwt", "The Worker verifies the Access JWT itself", "FAIL", "jwtVerify at %s without issuer and audience in its options" % ledger.join_hits(verifier_refs, 2, ", "),
                                  severity="medium", fix="pass issuer (the team domain) and audience (the Access application AUD tag) to jwtVerify"))
        elif routed:
            res.append(result("auth.access-jwt", "The Worker verifies the Access JWT itself", "UNKNOWN", "%s declares a custom domain or route; no Cf-Access-Jwt-Assertion reference in the tree" % wcfg,
                              reason="cannot see whether Access fronts this host; verify the JWT in the Worker or accept",
                              fix="verify Cf-Access-Jwt-Assertion in a middleware on every data route, or record the acceptance that the host is public by design"))

    # (d) better-auth open sign-up
    ba = []
    for p in files:
        rel = walk.rel(repo, p)
        t = walk.read_code(p)
        if not BETTER_AUTH.search(t):
            continue
        cfg = next((walk.block(t, m.end()) for m in re.finditer(r"betterAuth\s*\(", t)), "") or t
        for m in EMAIL_PW.finditer(t):
            body = walk.block(t, m.end() - 1)  # brace-balanced: a nested password: { hash, verify } no longer ends the block
            if not re.search(r"enabled\s*:\s*true", body):
                continue
            if re.search(r"disableSignUp\s*:\s*true", body) or CREATE_BEFORE.search(t) or _hooks_close_signup(repo, rel, t, cfg):
                ba.append(("PASS", "%s:%d" % (rel, walk.line_of(t, m.start()))))
            else:
                ba.append(("FAIL", "%s:%d" % (rel, walk.line_of(t, m.start()))))
    if ba:
        bad = [w for s, w in ba if s == "FAIL"]
        refused = _signup_refused(repo, files) if bad else None
        if bad and not refused:
            res.append(result("auth.open-signup", "Email and password sign-up is closed or allow-listed", "FAIL", ledger.join_hits(bad, 4, ", "), severity="medium",
                              fix="set emailAndPassword.disableSignUp: true, or add a databaseHooks.user.create.before hook that refuses every email not on the allow-list"))
        elif bad:
            res.append(result("auth.open-signup", "Email and password sign-up is closed or allow-listed", "PASS",
                              "sign-up enabled at %s; every sign-up path refused one layer up at %s (fails closed)" % (ledger.join_hits(bad, 2, ", "), refused),
                              detail="a reference, not a proof: confirm the refusal covers every sign-up route better-auth mounts and runs before the handler"))
        else:
            res.append(result("auth.open-signup", "Email and password sign-up is closed or allow-listed", "PASS", "disableSignUp or a user.create.before hook at %s" % ledger.join_hits([w for _, w in ba], 3, ", ")))

    if not res:
        res.append(result("auth.none", "Auth gate surface", "PASS", "no production source file found to judge"))
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

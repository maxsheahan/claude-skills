#!/usr/bin/env python3
"""check_spend.py - abuse and spend: who can make this app spend money or
forward traffic, and what stops them.

  check_spend.py REPO

  spend.cap.<provider>  a paid API called with no spend-cap reference in the
                        calling file or a file it imports FAILs high.
  spend.unset-cap       a cap read from config that falls back to unlimited
                        when unset (|| Infinity, ?? 1e9, "if (!cap) proceed",
                        a string default of "inf" or "Infinity" fed to float()
                        or Number(), or `isNaN(limit) || used < limit`, which
                        lets an unparseable limit through) FAILs high. So does a
                        cap binding that is unlimited on any branch (`cond ?
                        Number(env.CAP) : Infinity`, `or math.inf`, a typed or
                        pydantic field = math.inf) and `if (isNaN(limit))
                        return true` in a "within" check. Text inside a string
                        or docstring is prose. An unset cap must mean paused.
  spend.open-proxy      a route that takes request input and forwards it to a
                        third-party host with no bounds check in the handler
                        FAILs medium (a map app's /api/route and
                        /api/reverse before its service-area bounds). A handler
                        that hands request input to an imported helper which
                        does the fetch is the same proxy split in two: the
                        helper is followed one file over and its body may hold
                        the bound.
  spend.per-client      forwarding or paid routes exist and nothing in the repo
                        limits a single client (no limiter, no 429) FAILs medium.
                        A limiter keyed on a value the caller chose (a userId
                        from the JSON body) limits nothing: only an IP, a
                        session, or a server-derived id counts as a client key.
  spend.llm-params      max_tokens, n or model taken straight from the request
                        FAILs medium (a caller sets your bill). The request is
                        traced through the names it is bound to: `body`, a
                        destructuring, or a schema-parsed copy (`input =
                        Schema.parse(await c.req.json())`, then `input.model`),
                        through Number()/parseInt() wrappers, and as Python
                        kwargs (model=body['model']). A schema copy whose schema
                        allow-lists or bounds the key (z.enum, .max(1024)) is
                        the server's choice.
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

CAP_FALSY_SKIP = re.compile(r"""if\s*\(\s*[\w.]*(?:cap|limit|budget|ceiling)\w*\s*&&""", re.I)
UNLIMITED_VALUE = re.compile(r"""\b\w*(?:cap|limit|budget|ceiling|max)\w*\s*[:=]\s*(?:Number\.MAX_SAFE_INTEGER|Number\.POSITIVE_INFINITY|Infinity|1e\d{2,}|float\(['"]inf['"]\)|math\.inf)""", re.I)
# A string default of "inf"/"Infinity" (or a ten-digit number) that float()/Number() turns into an unlimited
# cap: float(os.environ.get("DAILY_CAP_USD", "inf")), Number(env.DAILY_LIMIT ?? 'Infinity'). Strings are kept
# for this one pattern because the fallback IS the string; the call shape around it keeps prose out.
UNLIMITED_DEFAULT = re.compile(
    r"""\b(?:float|int|Number|parseFloat|parseInt)\(\s*(?:os\.environ\.get|os\.getenv|getenv|environ\.get)\(\s*['"](?P<pyname>[^'"]+)['"]\s*(?:,|\)\s*or)\s*['"](?:inf|infinity|1e\d+|\d{9,})['"]"""
    r"""|\b(?:Number|parseFloat|parseInt|float)\(\s*(?:[\w$.]*env\.(?P<jsname>[\w$]+)|[\w$]+\.get\(\s*['"](?P<getname>[^'"]+)['"]\s*\))\s*(?:\?\?|\|\|)\s*['"](?:inf|infinity|1e\d+|\d{9,})['"]""", re.I)
CAP_NAME = re.compile(r"cap|limit|budget|ceiling|max|quota|spend|cost|cutoff", re.I)
# A value that means "no limit". Read in the strings-kept view at code positions only (float("inf") is a
# call on a string; the same words inside a docstring or prompt are prose).
UNLIMITED_TOKEN = (r"""Infinity\b|Number\.(?:POSITIVE_INFINITY|MAX_SAFE_INTEGER|MAX_VALUE)\b|\b1e\d{2,}\b|\b9{6,}\b"""
                   r"""|\bfloat\(\s*['"](?:inf|infinity)['"]\s*\)|\b(?:math|np|numpy)\.inf\b|\bsys\.maxsize\b""")
# A cap-named binding (JS const/let/var, a typed Python or pydantic field, a bare assignment) whose value can be
# unlimited on some branch: `cond ? Number(env.CAP) : Infinity`, `float(env.get("CAP") or math.inf)`.
UNLIMITED_BINDING = re.compile(
    r"""(?m)(?:\b(?:const|let|var)\s+|^[ \t]*(?:self\.)?)(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]{1,60})?=(?!=)\s*(?P<rhs>[^\n;]{0,300}?(?:%s)[^\n;]{0,120})""" % UNLIMITED_TOKEN, re.I)
# `if (Number.isNaN(limit)) return true` in a "within" check (the function then returns used < limit), or
# `return next()`: an unparseable limit lets the call through.
NAN_BRANCH = re.compile(
    r"""if\s*\(\s*(?:(?:Number\.)?isNaN\(\s*(?P<cap>[\w$.]*(?:cap|limit|budget|ceiling|max|quota)[\w$]*)\s*\)|!\s*(?:Number\.)?isFinite\(\s*(?P<cap2>[\w$.]*(?:cap|limit|budget|ceiling|max|quota)[\w$]*)\s*\))\s*\)\s*\{?\s*return\s+(?P<ret>true\b|(?:await\s+)?next\(\s*\))""", re.I)
# `Number.isNaN(limit) || used < limit`: an unset limit is NaN, the left side is true, and the call proceeds.
# The same test in front of an "over" comparison (`isNaN(cap) || spent >= cap`) pauses, so only a
# "within" comparison (the cap on the greater side) is the unlimited fallback.
NAN_PROCEEDS = re.compile(
    r"""(?:!\s*(?:Number\.)?isFinite|(?:Number\.)?isNaN)\(\s*(?P<cap>[\w$.]*(?:cap|limit|budget|ceiling|max|quota)[\w$]*)\s*\)\s*\|\|\s*"""
    r"""(?:[\w$.()\[\]]+\s*<=?\s*(?P=cap)\b|(?P=cap)\s*>=?\s*[\w$.()\[\]]+)""", re.I)
UNLIMITED = re.compile(r"""(?:(?:cap|limit|budget|ceiling|max)\w*\s*(?:\)|\b)\s*(?:\|\||\?\?)\s*(?:Infinity|Number\.(?:MAX_SAFE_INTEGER|POSITIVE_INFINITY)|1e\d+|9{4,}))|if\s*\(\s*!\s*[\w.]*(?:cap|limit|budget|ceiling)\w*\s*\)\s*(?:return\s+(?:await\s+)?next\(\)|\{\s*//\s*no\s+cap)""", re.I)
BOUNDS = re.compile(r"bounds|bbox|within|inBounds|isIn[A-Z]\w*|clamp|validate|schema|zod|\.parse\(|safeParse|MAX_|maxLength|\.slice\(0|allowlist|allowed|Math\.(?:min|max)\(|> ?\d{2,}|< ?-?\d{2,}|too (?:far|long|many)", re.I)
# A limiter is code that refuses: a limiter object or binding, or a 429 the app itself RETURNS.
# Reading an upstream's 429 (`if (r.status === 429)`) limits nothing.
# A limiter is code that refuses: a limiter object used or built, a rate-limit binding, or a 429 the app
# itself RETURNS. Not an upstream's 429 (isThrottled(res.status), KalshiRateLimitError), not an error class
# named *LimitError, not a test helper that resets one (Phase 5 audit, second pass).
LIMITER = re.compile(r"\b\w*[Ll]imiter\b\s*\.(?:hit|check|take|consume|limit|allow|tryAcquire|acquire|increment)\s*\(|\bnew\s+\w*[Ll]imiter\s*\(|\b(?:const|let|var)\s+\w*[Ll]imiter\s*="
                     r"|\benv\.\w*RATE_?LIMIT\w*\.limit\s*\(|\[\[unsafe\.bindings\]\]|\[\[ratelimits\]\]|\bratelimits\s*[=:]"
                     r"|\b(?:return|c\.json|c\.text|new\s+Response|Response\.json|HTTPException)\b[^;\n]{0,160}\b429\b|\bres\.status\(\s*429|\bstatus(?:_code)?\s*:\s*429\b|\bstatus_code\s*=\s*429\b|@limiter\.limit|slowapi")
# Per CLIENT: the limiter's neighborhood names who is being limited (an IP, a user, a session, an account).
CLIENT_KEY = re.compile(r"cf-connecting-ip|x-forwarded-for|x-real-ip|\bip\b|clientIp|remoteAddr|userId|user\.id|user_id|accountId|account_id|teacherId|session|sub\b|perClient|per_client|keyFor|clientKey", re.I)
# The request's fixed names; per file, the names it is bound to (surface.request_names) are added.
LLM_SOURCES = ("body", "req.body", "req.query", "payload", "c.req", "reqBody", "requestBody")
# A cap that guards: compared against, or a cap function called. Not an import, a type, or a value
# echoed back to the client (a coaching app's index.ts returns DAILY_OUTPUT_BUDGET for display only).
GUARD_SHAPE = re.compile(r"\s(?:<=?|>=?)\s|\bif\s*\(.*\b\w*(?:cap|limit|budget|quota|max)\w*|\b\w*(?:[Cc]ap|[Ll]imit|[Bb]udget|[Qq]uota)\w*\s*\(|\bthrow\b|raise\b|Math\.min\(", re.I)
CAP_MW_NAME = re.compile(r"(?:require|enforce|check|with)\w*(?:[Cc]aps?|[Bb]udget|[Ss]pend|[Qq]uota)|(?:[Cc]aps?|[Bb]udget|[Ss]pend|[Qq]uota)\w*(?:[Gg]uard|[Gg]ate|[Mm]iddleware)")
CAP_CALL = re.compile(r"\bnew\s+\w*(?:Spend|Budget|Quota|Cost)\w*\s*\(|\b(?:await\s+)?[\w.]*(?:[Ss]pend|[Bb]udget|[Qq]uota|[Cc]aps?|[Ll]imits?|[Mm]eter)\w*\s*\.\s*(?:reserve|check|assert|enforce|consume|begin|charge|allow)\w*\s*\(|\b(?:check|assert|enforce|over|within|reserve|charge|consume|guard)\w*(?:[Ss]pend|[Bb]udget|[Qq]uota|[Cc]aps?|[Ll]imits?)\w*\s*\(")
CLIENT_CODE = re.compile(r"(?:^|/)(?:components|hooks|public|client|frontend)/|\.(?:tsx|jsx|vue|svelte|html)$")

DESTRUCT = re.compile(r"""(?:const|let|var)\s*\{([^}]{1,300})\}\s*=\s*(?:await\s+)?([^;\n]{1,200})""")
LLM_KEYS = re.compile(r"""\b(model|max_tokens|maxTokens|max_output_tokens|n)\s*(?::\s*([A-Za-z_$][\w$]*))?\s*[,}\n]""")

# Request input: surface.CALLER_INPUT_RX (one vocabulary; the connecting-address headers the edge sets are not
# caller input) and surface.request_names for the names it is bound to.
REQ_ANY = surface.CALLER_INPUT_RX
request_names = surface.request_names


CALLER_CHOSEN_PREFIX = re.compile(r"(?:\bbody|\bpayload|\breqBody|\brequestBody|req\.body|\.data|\.(?:query|param|header)\(\s*['\"]?)\s*\.?\s*$")
IP_KEY = re.compile(r"cf-connecting-ip|x-forwarded-for|x-real-ip|\bip\b|clientIp|remoteAddr", re.I)


def _in_code(text, code, i):
    """text[i] is code, not inside a string: the strings-blanked view still has the same character."""
    return 0 <= i < len(code) and code[i] == text[i] and not text[i].isspace()


def _caller_chosen(window, m, names):
    """The client-key token at match m is a value the caller picked: a body or query field, or a name bound
    from the request. The connecting address is never caller-chosen here."""
    tok = m.group(0)
    if IP_KEY.search(tok):
        return False
    if tok in names:
        return True
    return bool(CALLER_CHOSEN_PREFIX.search(window[max(0, m.start() - 24):m.start()]))


# Value-preserving wrappers between the key and the request value: Number(body.maxTokens) is still the caller's.
WRAP = r"(?:(?:Number|parseInt|parseFloat|String|Math\.(?:floor|round|trunc|ceil|abs)|int|float|str)\(\s*)*"
LLM_KEY = r"max_tokens|maxTokens|max_output_tokens|model|n"
SCHEMA_BIND = re.compile(r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*|\{[^}]{1,300}\})\s*(?::[^=\n]{0,80})?=\s*(?:await\s+)?(?:(?P<schema>[A-Za-z_$][\w$]*)\s*\.\s*(?:parse|parseAsync|safeParse)\s*\(|(?P<valid>c\.req\.valid\s*\())")


def _balanced_from(t, i, open_ch="(", close_ch=")"):
    depth = 0
    for j in range(i, min(len(t), i + 6000)):
        depth += (t[j] == open_ch) - (t[j] == close_ch)
        if depth == 0:
            return t[i:j + 1]
    return t[i:i + 6000]


def _schema_text(t, name, at):
    """The schema text a request copy `name` was validated against, or None when it is not a schema copy:
    `const input = Req.parse(await c.req.json())` gives Req's definition; `c.req.valid('json')` gives the
    nearest zValidator('json', ...) schema above it."""
    for m in SCHEMA_BIND.finditer(t, 0, at):
        bound = m.group("name")
        names = {x.split(":")[-1].split("=")[0].strip() for x in bound.strip("{}").split(",")} if bound.startswith("{") else {bound}
        if name not in names:
            continue
        if m.group("schema"):
            d = re.search(r"(?:const|let|var)\s+%s\s*(?::[^=\n]{0,80})?=\s*" % re.escape(m.group("schema")), t)
            return t[d.end():d.end() + 3000] if d else None
        zv = [z for z in re.finditer(r"zValidator\s*\(\s*['\"]json['\"]\s*,\s*", t[:m.start()])]
        if not zv:
            return None
        rest = t[zv[-1].end():]
        if re.match(r"[A-Za-z_$][\w$]*\s*\)", rest):
            d = re.search(r"(?:const|let|var)\s+%s\s*=\s*" % re.escape(re.match(r"[A-Za-z_$][\w$]*", rest).group(0)), t)
            return t[d.end():d.end() + 3000] if d else None
        return rest[:3000]
    return None


def _schema_clamps(schema, key):
    """True when the schema fixes or bounds `key`: model as z.enum / z.literal (an allow-list), a number with
    .max() / .lte() / a literal. A key the object schema does not declare is stripped by the parse."""
    i = schema.find("{")
    obj = _balanced_from(schema, i, "{", "}") if i >= 0 else schema
    m = re.search(r"(?<![\w$])['\"]?%s['\"]?\s*:\s*" % re.escape(key), obj)
    if not m:
        return True
    val = obj[m.end():m.end() + 300]
    depth, end = 0, len(val)
    for k, ch in enumerate(val):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                end = k
                break
            depth -= 1
        elif ch == "," and depth == 0:
            end = k
            break
    val = val[:end]
    if key == "model":
        return bool(re.search(r"z\.(?:enum|literal|nativeEnum)\s*\(|\.refine\s*\(", val))
    return bool(re.search(r"\.(?:max|lte|lt)\s*\(|z\.(?:literal|enum)\s*\(", val))


def _llm_from_request(repo):
    """`max_tokens: body.maxTokens`, `max_tokens: Number(body.maxTokens)`, `model: input.model` where input
    is the request (c.req.json(), req.json(), c.req.valid('json'), a schema parse of either), Python
    `model=body['model']`: a request value, under any name the file binds it to, reaching model, n or
    max_tokens. A schema copy whose schema allow-lists or bounds that key (z.enum, .max(1024)) is the
    server's choice, not the caller's."""
    out = []
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)
        srcs = set(LLM_SOURCES) | request_names(t)
        alt = "|".join(sorted(re.escape(x) for x in srcs))
        if p.endswith(".py"):
            rx = re.compile(r"""\b(?P<key>%s)\s*=\s*%s(?P<src>%s)(?:\[\s*['"](?P<f1>\w+)['"]\s*\]|\.get\(\s*['"](?P<f2>\w+)['"]|\.(?P<f3>\w+))""" % (LLM_KEY, WRAP, alt))
        else:
            rx = re.compile(r"""\b(?P<key>%s)\s*:\s*%s(?P<src>%s)(?:\.data)?(?:\??\.(?P<f3>[\w$]+)|\[\s*['"](?P<f1>[\w$]+)['"]\s*\])""" % (LLM_KEY, WRAP, alt))
        for m in rx.finditer(t):
            field = m.group("f1") or m.group("f3") or (m.groupdict().get("f2") or "")
            schema = _schema_text(t, m.group("src"), m.start())
            if schema is not None and _schema_clamps(schema, field or m.group("key")):
                continue
            out.append("%s:%d" % (walk.rel(repo, p), walk.line_of(t, m.start())))
    return out


def _destructured_llm(repo):
    """`const { model, max_tokens } = await req.json()` then `{ model, max_tokens: max_tokens }` in the provider call."""
    out = []
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)
        if not re.search(r"messages\.create|chat\.completions\.create|generateContent|max_tokens|maxTokens", t):
            continue
        names = set()
        req_names = request_names(t)
        for m in DESTRUCT.finditer(t):
            src = m.group(2).strip()
            if REQ_ANY.search(src) or re.match(r"(?:body|payload|reqBody|requestBody)\b", src) or src.split(".")[0].rstrip(")") in req_names:
                bound = {x.split(":")[-1].split("=")[0].strip() for x in m.group(1).split(",")}
                sm = re.match(r"([A-Za-z_$][\w$]*)\s*\.\s*(?:parse|parseAsync|safeParse)\s*\(", src)
                if sm:
                    schema = _schema_text(t, next(iter(bound)), m.end()) if bound else None
                    bound = {b for b in bound if not (schema is not None and _schema_clamps(schema, b))}
                names |= bound
        if not names:
            continue
        for call in re.finditer(r"(?:messages\.create|chat\.completions\.create|generateContent)\s*\(\s*\{([^}]{1,600})\}|body:\s*JSON\.stringify\(\s*\{([^}]{1,600})\}", t):
            inner = call.group(1) or call.group(2) or ""
            for km in LLM_KEYS.finditer(inner + ","):
                val = km.group(2) or km.group(1)
                if val in names:
                    out.append("%s:%d" % (walk.rel(repo, p), walk.line_of(t, call.start())))
                    break
    return out


def _client_keyed(block, names):
    """A client key in this block that the caller did not choose."""
    return any(not _caller_chosen(block, m, names) for m in CLIENT_KEY.finditer(block))


def _near_client_key(repo, rel, ln, span=12):
    """The limiter is keyed by a client: a client key within `span` lines, or in the function it calls.
    A key the caller supplies (`const { userId } = await c.req.json()` then `limit({ key: userId })`)
    is not a client key: a new id per request and the limit never fires (bench 2026-11-01)."""
    text = walk.read_code(os.path.join(repo, rel))
    lines = text.splitlines()
    names = request_names(text)
    window = "\n".join(lines[max(0, ln - 1 - span): ln + span])
    if _client_keyed(window, names):
        return True
    # a call like geoUpstreamAllowed(c): look inside that function's body in the same file
    for name in re.findall(r"\b(\w+)\s*\(", window):
        m = re.search(r"(?:function\s+%s\s*\(|const\s+%s\s*=)" % (re.escape(name), re.escape(name)), text)
        if m:
            body = text[m.start(): m.start() + 2500]
            if _client_keyed(body, names):
                return True
    return False


def _comment_line(repo, rel, ln):
    lines = walk.read_code(os.path.join(repo, rel)).splitlines()
    s = lines[ln - 1].lstrip() if 0 < ln <= len(lines) else ""
    return s.startswith(("//", "*", "/*", "#", "<!--"))


def _importers(repo):
    """rel -> files that import it with a relative import (one level)."""
    out = {}
    for p in walk.files(repo, tests=False, served=True):
        src = walk.rel(repo, p)
        for g in surface.imported(repo, src)[1:]:
            out.setdefault(g, set()).add(src)
    return out


def _helper_forward(repo, h, own_hosts):
    """The handler hands request input to an imported helper that fetches a third-party host: the same
    open proxy split across two files (a map app's /api/reverse calling geo.ts). Followed one file over.
    Returns (hosts, helper body, 'file:function') or None."""
    text = walk.read_code(os.path.join(repo, h["file"]))
    # relative, path-alias (@/lib/geo) and namespace (import * as geo; geo.reverseGeocode) imports
    names = walk.import_bindings(repo, h["file"], text)
    req_names = request_names(text)
    for m in re.finditer(r"(?<![\w$.])(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(", h["code"]):
        ns, name = m.group(1), m.group(2)
        if ns and names.get(ns, (None, None))[1] == "*":
            target, orig = names[ns][0], name
        elif not ns and name in names and names[name][1] != "*":
            target, orig = names[name]
        else:
            continue
        args = h["body"][m.end() - 1:]
        depth, k = 0, 0
        for k, ch in enumerate(args):
            depth += (ch == "(") - (ch == ")")
            if depth == 0:
                break
        args = args[:k + 1]
        if not (REQ_ANY.search(args) or any(re.search(r"\b%s\b" % re.escape(n), args) for n in req_names)):
            continue
        ttext = walk.read_code(os.path.join(repo, target))
        if orig == "default":
            dm = re.search(r"export\s+default\s+(?:async\s+)?function\s*([A-Za-z_$][\w$]*)|export\s+default\s+([A-Za-z_$][\w$]*)", ttext)
            orig = (dm.group(1) or dm.group(2)) if dm else orig
        body = walk.function_body(ttext, orig)
        hosts = {hm.group(1) for hm in surface.URL_HOST_RX.finditer(body)} - own_hosts
        if hosts and re.search(r"\bfetch\(|axios|got\(", body):
            return hosts, body, "%s:%s" % (target, orig)
    return None


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    own_hosts = set()
    for f in ("wrangler.toml", "wrangler.jsonc"):
        own_hosts |= set(re.findall(r"""pattern\s*[=:]\s*["']([^"'/*]+)""", walk.read_code(os.path.join(repo, f))))

    sites = {}
    for host, prov in surface.PAID_HOSTS.items():
        for r, ln, _ in walk.find(repo, re.escape(host), tests=False, served=True):
            sites.setdefault(prov, []).append((r, ln))
    # SDK clients call the provider with no host string in the code (Phase 5 audit #8).
    for pkg, prov in surface.SDK_PAID.items():
        rx = re.compile(r"""(?:from\s+['"]%s['"]|require\(\s*['"]%s['"]\s*\)|^\s*(?:import|from)\s+%s\b)""" % ((re.escape(pkg),) * 3), re.M)
        for r, ln, _ in walk.find(repo, rx, tests=False, served=True):
            sites.setdefault(prov, []).append((r, ln))
    importers = _importers(repo)
    has_routes = any(True for _ in surface.handlers(repo))
    for prov, where in sorted(sites.items()):
        files = sorted({r for r, _ in where})
        caps, uncapped = [], []

        def guarded_here(rel):
            """Cap enforcement written in THIS file: a guard-shaped cap line, or a call to a cap function
            (overDailySpendCap(), checkBudget(), gate.reserve()). A guard in some imported module does
            not show this caller uses it (a coaching app's prose.ts, 2026-10-09)."""
            if walk.TEST_PATH.search(rel) or rel.endswith((".tsx", ".jsx", ".html", ".vue", ".svelte")):
                return []
            t2 = walk.read_code(os.path.join(repo, rel), strings=False)
            lines = t2.splitlines()
            out = []
            for m in surface.CAP_RX.finditer(t2):
                ln = walk.line_of(t2, m.start())
                if GUARD_SHAPE.search(lines[ln - 1]) and not re.match(r"\s*(?:import|export\s+(?:type|interface)|from\s+\S+\s+import)\b", lines[ln - 1]):
                    out.append("%s:%d" % (rel, ln))
            for m in CAP_CALL.finditer(t2):
                out.append("%s:%d" % (rel, walk.line_of(t2, m.start())))
            return out
        cap_mw = [(m.group(1).rstrip("*").rstrip("/") or "/", "%s:%d" % (r, ln)) for r, ln, m in walk.find(repo, surface.MW_RX, tests=False, served=True)
                  if CAP_MW_NAME.search(m.group(2))]

        def mw_covered(rel, callee=None):
            """Every route in this file that calls the paid client sits under a cap middleware mounted with
            app.use(path, ..., requireCaps)."""
            hs = [h for h in surface.handlers(repo) if h["file"] == rel]
            if callee:
                names = set()
                for m in re.finditer(r"""import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""", walk.read_code(os.path.join(repo, rel))):
                    base = os.path.normpath(os.path.join(os.path.dirname(rel), m.group(2)))
                    if os.path.splitext(callee)[0] in (base, surface.JS_TO_TS.sub("", base)):
                        names |= {x.split(" as ")[-1].strip() for x in m.group(1).split(",") if x.strip()}
                if names:
                    # one level of same-file helpers: function draft() { ... llmCall() ... } called by the route
                    code = walk.read_code(os.path.join(repo, rel))
                    defs = list(re.finditer(r"(?m)^(?:export\s+)?(?:async\s+)?function\s+(\w+)|^(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>", code))
                    helpers = set()
                    for i, d in enumerate(defs):
                        body = code[d.end(): defs[i + 1].start() if i + 1 < len(defs) else len(code)]
                        if any(re.search(r"\b%s\s*\(" % re.escape(n), body) for n in names):
                            helpers.add(d.group(1) or d.group(2))
                    calls = names | helpers
                    direct = [h for h in hs if any(re.search(r"\b%s\s*\(" % re.escape(n), h["code"]) for n in calls)]
                    hs = direct or hs  # nothing traced: judge every route in the file
            if not hs or not cap_mw:
                return []
            hits = []
            for h in hs:
                paths = [h["path"]] + surface.mount_paths(repo, rel, h["path"])
                at = next((surface.covered(p, cap_mw) for p in paths if surface.covered(p, cap_mw)), None)
                if not at:
                    return []
                hits.append(at)
            return sorted(set(hits))
        for f in files:
            own = guarded_here(f) or mw_covered(f)
            ups = sorted(u for u in importers.get(f, ()) if not walk.TEST_PATH.search(u))
            if own or not ups:
                (caps.extend(own) if own else uncapped.append(f))
                continue
            # a shared client module: every caller must enforce the cap itself
            for u in ups:
                found = guarded_here(u) or mw_covered(u, f)
                (caps.extend(found) if found else uncapped.append(u))
        cid = "spend.cap.%s" % re.sub(r"[^a-z0-9]+", "-", prov.lower()).strip("-")
        if caps and not uncapped:
            res.append(result(cid, "%s spend has a cap" % prov, "PASS", "cap reference at %s" % ledger.join_hits(sorted(set(caps)), 3, ", "),
                              detail="a reference, not a proof: confirm the cap is enforced before the call with a mutation-proven test"))
        else:
            res.append(result(cid, "%s spend has a cap" % prov, "FAIL", ledger.join_hits(sorted(set(uncapped)), 4, ", "), severity="high" if has_routes else "medium",
                              fix="add a daily spend cap checked before every call, paused (not unlimited) when unset",
                              detail=None if has_routes else "no public route found: spend here is driven by schedules or scripts, not by strangers"))

    # strings=False: a cap is code. Text inside a string literal (a bundled card embedded as JSON,
    # zod's "maximum: Number.MAX_SAFE_INTEGER" error text) is not a cap (2026-10-15 false positive).
    unl = ["%s:%d" % (r, ln) for r, ln, _ in walk.find(repo, UNLIMITED, tests=False, served=True, strings=False)]
    unl += ["%s:%d (cap enforced only when set)" % (r, ln) for r, ln, _ in walk.find(repo, CAP_FALSY_SKIP, tests=False, served=True, strings=False)]
    unl += ["%s:%d (a cap set to unlimited)" % (r, ln) for r, ln, _ in walk.find(repo, UNLIMITED_VALUE, tests=False, served=True, strings=False)]
    unl += ["%s:%d (an unparseable cap passes the guard)" % (r, ln) for r, ln, _ in walk.find(repo, NAN_PROCEEDS, tests=False, served=True, strings=False)]
    # strings kept here: the unlimited fallback IS a string ("inf") and the call around it is the code shape;
    # a match that starts inside a string (a docstring quoting the forbidden default) is prose.
    for p in walk.files(repo, tests=False, served=True):
        r = walk.rel(repo, p)
        t, code = walk.read_code(p), walk.read_code(p, strings=False)
        for m in UNLIMITED_DEFAULT.finditer(t):
            if _in_code(t, code, m.start()) and CAP_NAME.search(m.group("pyname") or m.group("jsname") or m.group("getname") or ""):
                unl.append("%s:%d (default of \"inf\" when unset)" % (r, walk.line_of(t, m.start())))
        for m in UNLIMITED_BINDING.finditer(t):
            tok = re.search(UNLIMITED_TOKEN, m.group("rhs"), re.I)
            at = m.start("rhs") + tok.start()
            if CAP_NAME.search(m.group("name")) and _in_code(t, code, m.start("name")) and _in_code(t, code, at):
                unl.append("%s:%d (a cap that can be unlimited: %s)" % (r, walk.line_of(t, m.start()), tok.group(0)))
        for m in NAN_BRANCH.finditer(code):
            cap = m.group("cap") or m.group("cap2")
            if m.group("ret").startswith("true"):
                rest = code[m.end():m.end() + 600]
                within = re.search(r"\breturn\s+[\w$.()\[\]]+\s*<=?\s*%s\b|\breturn\s+%s\s*>=?" % (re.escape(cap), re.escape(cap)), rest)
                if not within:
                    continue
            unl.append("%s:%d (an unparseable cap lets the call through)" % (r, walk.line_of(code, m.start())))
    unl = sorted(set(unl), key=unl.index)
    if unl:
        res.append(result("spend.unset-cap", "An unset cap means paused, not unlimited", "FAIL", ledger.join_hits(unl, 6, ", "), severity="high",
                          fix="treat a missing or unparseable cap as 0 (paused) and say so in the response"))
    elif sites:
        res.append(result("spend.unset-cap", "An unset cap means paused, not unlimited", "PASS", "no cap falls back to unlimited in production source"))

    hs = list(surface.handlers(repo))
    proxies, forwarders = [], []
    for h in hs:
        if not surface.CALLER_INPUT_RX.search(h["body"]):
            continue
        hosts = {m.group(1) for m in surface.URL_HOST_RX.finditer(h["body"])} - own_hosts
        calls_out = hosts and re.search(r"\bfetch\(|axios|got\(", h["body"])
        via = None if calls_out else _helper_forward(repo, h, own_hosts)
        if via:
            hosts, helper_body, where = via
        if calls_out or via:
            forwarders.append(h)
            if not (BOUNDS.search(h["body"]) or (via and BOUNDS.search(helper_body))):
                proxies.append("%s:%d %s %s -> %s%s" % (h["file"], h["line"], h["method"], h["path"], ",".join(sorted(hosts))[:60], " via %s" % where if via else ""))
    if proxies:
        res.append(result("spend.open-proxy", "Routes that forward to other services bound their input", "FAIL", ledger.join_hits(proxies, 6, "; "), severity="medium",
                          fix="bound every forwarded value (area, length, count) and refuse anything outside before calling out"))
    elif forwarders:
        res.append(result("spend.open-proxy", "Routes that forward to other services bound their input", "PASS",
                          "%d forwarding route(s), each with a bounds check in the handler" % len(forwarders)))
    if forwarders or sites:
        # Only server-side evidence counts: a 429 handled in a browser component limits nothing.
        lim = [("%s:%d" % (r, ln)) for r, ln, _ in walk.find(repo, LIMITER, exts=walk.CODE_EXT + (".toml", ".jsonc", "wrangler.json"), tests=False, served=True)
               if not CLIENT_CODE.search(r) and not re.match(r"""\s*['"]use client['"]""", walk.read_code(os.path.join(repo, r)))
               and not _comment_line(repo, r, ln) and _near_client_key(repo, r, ln)]
        if lim:
            res.append(result("spend.per-client", "One client cannot drive unbounded calls", "PASS", "limiter reference at %s" % ledger.join_hits(lim, 3, ", ")))
        else:
            res.append(result("spend.per-client", "One client cannot drive unbounded calls", "FAIL",
                              "%d paid provider(s), %d forwarding route(s), no limiter or 429 anywhere" % (len(sites), len(forwarders)), severity="medium",
                              fix="add a per-client ceiling in code (in memory if the privacy page promises no storage) and a zone rate-limit rule as a backstop"))

    llm = _llm_from_request(repo) + _destructured_llm(repo)
    if llm:
        res.append(result("spend.llm-params", "The caller cannot set model, n or max_tokens", "FAIL", ledger.join_hits(llm, 6, ", "), severity="medium",
                          fix="fix model and max_tokens server-side; clamp anything the client may tune"))
    elif any(p in sites for p in ("Anthropic", "OpenAI", "Google Gemini", "OpenRouter", "Perplexity")):
        res.append(result("spend.llm-params", "The caller cannot set model, n or max_tokens", "PASS", "no request value reaches model, n or max_tokens"))
    if not res:
        res.append(result("spend.none", "Paid or forwarding surface", "PASS", "no paid API host and no forwarding route found in production source"))
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

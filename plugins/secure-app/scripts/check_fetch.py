#!/usr/bin/env python3
"""check_fetch.py - server-side request forgery from the code.

  check_fetch.py REPO

  fetch.request-url  a route handler that fetches a URL taken from the request
                     (query, params, body, a validated body, a header) FAILs
                     high, unless that call goes through a public-address
                     guard. The value is followed through the handler's locals
                     (a concatenation, a template, `new URL(x)`, `x.trim()`,
                     an axios config object's `url:`), into a helper the
                     handler calls with it (two hops, any file), and through a
                     FastAPI or Flask handler's parameters. A request value
                     used only as a KEY into a constant map of owner-written
                     URLs is not a request URL; a fallback beside that lookup
                     (`MAP[k] ?? c.req.query('url')`) still is.
  fetch.data-url     raw fetches of a non-constant URL (feeds, article links,
                     image URLs from data):
                       PASS     none, or every one goes through a guard
                       FAIL     some exist and the repo defines no guard, or the
                                repo's guard resolves and checks the address
                                and these sites do not call it
                       UNKNOWN  raw sites remain beside a guard installed below
                                the call sites (a global dispatcher or an agent
                                with its own lookup), or beside guard-shaped
                                code that does not itself resolve and check the
                                address: read them
                     A URL is constant when every value it can take is owner
                     written: a literal, deployment config, a template or
                     concatenation whose literal part fixes the host, a member
                     of a constant map (also one imported from another
                     module). `x ?? 'https://fallback'` is not constant: x
                     wins when set. A site is guarded when the guard is called
                     on its URL before it in the same function, when it sits
                     inside the guard, or when its call passes an SSRF-filter
                     agent (request-filtering-agent, ssrf-req-filter).
                     Code that runs in the visitor's browser (a 'use client'
                     file, React hooks and components) is not a server fetch
                     site; a server entry in such a file (a Remix or React
                     Router loader or action, getServerSideProps) still is.
                     On a Cloudflare Worker the severity is low: Workers cannot
                     reach private addresses or cloud metadata, but the fetch
                     can still be an open proxy to the public internet.
  Clients read: fetch, axios (call and config-object forms), got, ky,
  https.get/request, undici request() and fetch() (request() counts where
  undici, superagent or request is imported); Python requests, httpx and
  urlopen inside a route handler.
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

GUARD_NAMES = {"safeFetch", "guardedFetch", "publicFetch", "fetchPublic", "safeGet", "ssrfSafeFetch"}
GUARD_DEF = re.compile(r"169\.254|isPrivate(?:Ip|Address)?|isPublic(?:Ip|Address|Url)|assertPublic|privateRanges|BLOCKED_RANGES|ipaddr\.|net\.BlockList|blockList", re.I)
# A guard that WORKS resolves the host and checks the address it resolved to; a name or a list of ranges
# alone cannot be told apart from a check of the URL string (which a DNS name pointing at 127.0.0.1 passes).
GUARD_RESOLVES = re.compile(r"\blookup\s*\(|\bresolve[46]?\s*\(|\bdns\.|\bresolveAny\b|getaddrinfo|\blookup\s*[,}]")
GUARD_CLASSIFIES = re.compile(r"ipaddr\.|BlockList|\.range\(\)|isPrivate|isLoopback|169\.254|127\.0\.0|192\.168|\bfe80\b|\bfc00\b", re.I)
# Guard IMPLEMENTATION, as opposed to a call to a guard (Phase 10 audit, 2026-11-07). GUARD_DEF is a word list:
# read on text with strings kept it credited `throw new Error('isPrivateIp: missing url')`, and anywhere in a
# function it credited `assertPublic(new URL(p.imageUrl))` before `fetch(p.fallbackUrl)`. Strings never count,
# and a CALL to a guard counts only when its argument is the value that reaches the client (_guarded). A body
# implements a guard when its code (strings blanked) classifies an address itself (ipaddr, a BlockList, a
# range table), or when it compares a value against a private-range literal (the one place a string IS the
# logic: h.startsWith('169.254.'), /^10\./.test(ip), host === '127.0.0.1'), or when its own name is a guard
# word (function isPrivateIp(ip) { ... }).
GUARD_IMPL = re.compile(r"ipaddr\.|\bBlockList\b|\bblockList\b|\bprivateRanges\b|\bBLOCKED_RANGES\b|\.range\(\)|\bisLoopback\w*\s*\(\s*\w+\s*\)\s*\{")
_PRIVATE_LIT = r"(?:169\\?\.254|127\\?\.|10\\?\.|192\\?\.168|172\\?\.(?:1[6-9]|2\d|3[01])|0\\?\.0\\?\.0\\?\.0|fe80|fc00|::1|localhost)"
IP_COMPARE = re.compile(r"""\.(?:startsWith|includes|endsWith|has|indexOf)\(\s*['"`]%s|/\^?\(?(?:\?:)?%s|[=!]==?\s*['"`]%s|['"`]%s[^'"`\n]{0,40}['"`]\s*[=!]==?""" % ((_PRIVATE_LIT,) * 4), re.I)


def implements_guard(text_seg, code_seg, name=""):
    """True when this function body is a guard implementation (see GUARD_IMPL above)."""
    return bool(GUARD_IMPL.search(code_seg) or IP_COMPARE.search(text_seg) or (name and GUARD_DEF.match(name)))


# SSRF-filter libraries: the agent they hand out refuses private, loopback and link-local at connect time.
SSRF_LIB = re.compile(r"""(?:from\s+|require\(\s*)['"](?:request-filtering-agent|ssrf-req-filter|ssrf-agent)['"]""")
# a guard installed below the call sites, where a raw fetch( still goes through it: a dispatcher or agent
# that does its own lookup (a keep-alive agent with no lookup filters nothing)
BELOW_CANDIDATE = re.compile(r"setGlobalDispatcher\s*\(|\bglobalAgent\s*=|new\s+(?:https?\.)?Agent\s*\(|connect\s*:\s*\{")
CLIENT_RX = re.compile(r"""(?<![.\w$])(?P<fn>fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got(?:\.(?:get|post|put|patch|delete|head))?"""
                       r"""|ky(?:\.(?:get|post|put|patch|delete|head))?|https?\.(?:get|request)|undici\.(?:request|fetch)|request)\s*\(""")
PY_CLIENT_RX = re.compile(r"""(?<![.\w])(?P<fn>(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|stream)|(?:urllib\.request\.)?urlopen)\s*\(""")
# request(url) is an outbound client only where one is imported (undici, superagent, request)
CLIENT_IMPORT = re.compile(r"""from\s+['"](?:undici|superagent|request|request-promise\w*)['"]|require\(\s*['"](?:undici|superagent|request)['"]\s*\)""")
ENV_URL = re.compile(r"^(?:c\.env|env|this\.env|ctx\.env|context\.env|process\.env|import\.meta\.env|Deno\.env)\b")
INCOMING = re.compile(r"^(?:request|req|c\.req\.raw|event\.request|input|init)$")
# Request input, read in the strings-blanked view: surface.CALLER_INPUT_RX is the one vocabulary (Next's
# req.json(), Fastify's request.body, Hono's c.req.valid('json') and typed c.req.json<T>(), Express req.get()).
def _req(code):
    return bool(surface.CALLER_INPUT_RX.search(code))


# code that runs in the visitor's browser: React hooks, or a Next client component
BROWSER_FILE = re.compile(r"""(?:^|\n)\s*['"]use client['"]|from\s+['"]react['"]""")
HOOK_USE = re.compile(r"\buse(?:Effect|LayoutEffect|State|Ref|Callback|Memo|Reducer)\s*\(")
# server entry points that live in route modules beside components (Remix / React Router, Next pages router)
SERVER_ENTRY = {"loader", "action", "getServerSideProps", "getStaticProps", "getStaticPaths", "generateMetadata", "generateStaticParams"}
FN_RX = re.compile(r"""\bfunction\b\s*\*?\s*(?P<f>[\w$]*)\s*(?:<[^>\n]{0,80}>)?\s*\("""
                   r"""|(?:(?:const|let|var)\s+(?P<c>[\w$]+)\s*(?::[^=\n]{0,80})?=\s*)?(?:async\s*)?(?:\([^()]*(?:\([^()]*\)[^()]*)*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=\n{]{0,80})?=>""")
TOP_FN = re.compile(r"""(?m)^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<f>[\w$]+)|^(?:export\s+)?(?:const|let|var)\s+(?P<c>[\w$]+)\s*(?::[^=\n]{0,80})?=""")
HELPER_DEPTH = 2
TRANSFORMS = {"String", "encodeURI", "decodeURI", "unescape"}
IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")
PATH_RX = re.compile(r"""^(?P<base>[A-Za-z_$][\w$]*)(?P<rest>(?:\s*\??\.\s*[A-Za-z_$][\w$]*|\[[^\]\n]*\]|\.get\([^)\n]*\)|\(\s*\))*)$""")


# ------------------------------------------------------------------ expression scanning
def _skip_quote(t, j):
    q, k, n = t[j], j + 1, len(t)
    while k < n:
        if t[k] == "\\":
            k += 2
            continue
        if t[k] == q or (q != "`" and t[k] == "\n"):
            return k + 1
        if q == "`" and t.startswith("${", k):
            k = _skip_braces(t, k + 1)
            continue
        k += 1
    return n


def _skip_braces(t, k):
    depth, n = 0, len(t)
    while k < n:
        c = t[k]
        if c in "'\"`":
            k = _skip_quote(t, k)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return n


def _top(e):
    """(index, char) of every character of e outside strings and brackets."""
    depth, k, n = 0, 0, len(e)
    while k < n:
        c = e[k]
        if c in "'\"`":
            k = _skip_quote(e, k)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            yield k, c
        k += 1


def _args(t, i, limit=4000):
    """Top-level argument texts of the call whose `(` is at t[i], and the index past its `)`; None when
    the parentheses never close within limit."""
    depth, start, k, n, out = 0, i + 1, i, min(len(t), i + limit), []
    while k < n:
        c = t[k]
        if c in "'\"`":
            k = _skip_quote(t, k)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                out.append(t[start:k])
                return [a for a in out if a.strip()] if any(a.strip() for a in out) else [], k + 1
        elif c == "," and depth == 1:
            out.append(t[start:k])
            start = k + 1
        k += 1
    return None


def _split(e, op):
    parts, last = [], 0
    for k, _ in _top(e):
        if e.startswith(op, k) and (op != "+" or not e.startswith("++", k)) and k >= last:
            parts.append(e[last:k])
            last = k + len(op)
    parts.append(e[last:])
    return parts


def _ternary(e):
    """(then, else) of a top-level `a ? b : c`, or None."""
    q = None
    for k, c in _top(e):
        if q is None and c == "?" and not e.startswith(("??", "?."), k) and not (k and e[k - 1] == "?"):
            q = k
        elif q is not None and c == ":":
            return e[q + 1:k], e[k + 1:]
    return None


def _clean(e):
    e = e.strip()
    while True:
        e0 = e
        e = re.sub(r"^(?:await|typeof|void)\s+", "", e).strip()
        e = re.sub(r"\s+as\s+(?:const|string|URL|any|unknown|[A-Z][\w$.<>\[\]]*)\s*$", "", e).strip()
        e = re.sub(r"!$", "", e).strip()
        if e.startswith("(") and _args(e, 0) and _args(e, 0)[1] == len(e):
            e = e[1:-1].strip()
        if e == e0:
            return e


def _literal_text(e):
    """The text inside e when e is exactly one '...' or "..." literal, else None."""
    if e[:1] in "'\"" and _skip_quote(e, 0) == len(e):
        return e[1:-1]
    return None


def _fixes_host(s):
    """A literal head that already fixes the host: https://host/... (a `/`, `?` or `#` after the host,
    so nothing appended can become part of the host or userinfo), or a same-origin path /x."""
    return bool(re.match(r"^https?://[A-Za-z0-9.\-]+(?::\d+)?[/?#]", s) or re.match(r"^/(?!/)", s) or s == "/")


def _template_parts(e):
    """(head, [interpolation expressions]) of a template literal e."""
    head, exprs, k, n = None, [], 1, len(e) - 1
    while k < n:
        if e[k] == "\\":
            k += 2
            continue
        if e.startswith("${", k):
            if head is None:
                head = e[1:k]
            j = _skip_braces(e, k + 1)
            exprs.append(e[k + 2:j - 1])
            k = j
            continue
        k += 1
    return (e[1:-1] if head is None else head), exprs


def _const_lookups(e, ctx):
    """e with every lookup into a constant map of owner URLs (SOURCES[key], SOURCES.get(key)) blanked to
    the map's name: the key does not choose the host."""
    out, k = e, 0
    for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(\[|\.get\s*\()", e):
        if m.start() < k or not ctx.const_map(m.group(1)):
            continue
        i = m.end() - 1
        if m.group(2) == "[":
            depth, j = 0, i
            while j < len(e):
                depth += (e[j] == "[") - (e[j] == "]")
                if depth == 0:
                    break
                j += 1
            end = j + 1
        else:
            a = _args(e, i)
            end = a[1] if a else len(e)
        out = out[:i] + " " * (end - i) + out[end:]
        k = end
    return out


# ------------------------------------------------------------------ owner-controlled URLs
class Ctx:
    """Where an expression is read: a file of the repo, and the text before the site (the scope a local
    name is bound in)."""

    def __init__(self, an, rel, scope):
        self.an, self.rel, self.scope = an, rel, scope

    def const_map(self, name):
        return self.an.const_map(self.rel, name)

    def binding(self, name):
        """('assign', rhs, scope) | ('destructure', rhs, scope) | ('for', collection, scope) |
        ('import', (file, orig)) | None, for the nearest binding of name before the site."""
        best = None
        for m in re.finditer(r"\b(?:const|let|var)\s+%s\s*(?::[^=\n]{0,80})?=(?!=)\s*" % re.escape(name), self.scope):
            best = ("assign", m)
        for m in re.finditer(r"\b(?:const|let|var)\s*\{([^}]{1,300})\}\s*(?::[^=\n]{0,80})?=\s*", self.scope):
            if name in {x.split(":")[-1].split("=")[0].strip() for x in m.group(1).split(",")}:
                if best is None or m.start() > best[1].start():
                    best = ("destructure", m)
        for m in re.finditer(r"\bfor\s*\(\s*(?:const|let|var)\s+%s\s+of\s+" % re.escape(name), self.scope):
            if best is None or m.start() > best[1].start():
                best = ("for", m)
        if best:
            kind, m = best
            if kind == "for":
                rhs = self.scope[m.end():].split(")", 1)[0]
            else:
                rhs = _rhs(self.scope, m.end())
            return kind, rhs, self.scope[:m.start()]
        imp = self.an.imports(self.rel).get(name)
        return ("import", imp, "") if imp else None


def _rhs(t, i):
    """The expression starting at t[i]: up to a `;` or a line end outside brackets and strings."""
    depth, k, n = 0, i, min(len(t), i + 1500)
    while k < n:
        c = t[k]
        if c in "'\"`":
            k = _skip_quote(t, k)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c == ";" or (c == "\n" and not re.match(r"\s*(?:\?\?|\|\||\+|\?|:|\.)", t[k + 1:k + 40]))):
            break
        k += 1
    return t[i:k].strip()


def is_const(e, ctx, depth=0):
    """True when every value expression e can take is owner-controlled: see the module docstring."""
    e = _clean(e)
    if not e or depth > 8:
        return False
    tern = _ternary(e)
    if tern:
        return is_const(tern[0], ctx, depth + 1) and is_const(tern[1], ctx, depth + 1)
    for op in ("??", "||"):
        parts = _split(e, op)
        if len(parts) > 1:
            return all(is_const(p, ctx, depth + 1) for p in parts)
    parts = _split(e, "+")
    if len(parts) > 1:
        head = ""
        for p in parts:
            lit = _literal_text(_clean(p))
            if lit is None:
                break
            head += lit
        return _fixes_host(head) or all(is_const(p, ctx, depth + 1) for p in parts)
    if _literal_text(e) is not None:
        return True  # an owner-written literal
    if e.startswith("`") and _skip_quote(e, 0) == len(e):
        head, exprs = _template_parts(e)
        if _fixes_host(head):
            return True
        if head == "" and exprs:
            return is_const(exprs[0], ctx, depth + 1)
        return all(is_const(x, ctx, depth + 1) for x in exprs)
    if ENV_URL.match(e):
        return True
    if _req(_const_lookups(e, ctx)):
        return False  # a request accessor: c.req.query('host') is the caller's, whatever its key
    m = re.match(r"^new\s+(URL|Request)\s*\(", e)
    if m:
        a = _args(e, m.end() - 1)
        if not a or not a[0] or a[1] != len(e):
            return False
        first = a[0][0]
        if not is_const(first, ctx, depth + 1):
            return False  # new URL(dataHref, base): an absolute href in the data wins over the base
        if m.group(1) == "URL" and len(a[0]) > 1 and not _absolute(first):
            return is_const(a[0][1], ctx, depth + 1)
        return True
    call = _final_call(e)
    if call:
        callee, cargs = call
        if not cargs:
            return False
        first = _clean(cargs[0])
        if callee in TRANSFORMS:
            return is_const(first, ctx, depth + 1)  # String(x), encodeURI(x): the value is x's
        # a function called on a fixed-host literal (rewrite('https://..')): the owner's URL
        return bool(re.match(r"""^['"`]https?://[A-Za-z0-9.\-]+""", first)) and is_const(first, ctx, depth + 1)
    m = re.match(r"^([A-Za-z_$][\w$.]*)\s*\(", e)
    if m:
        a = _args(e, m.end() - 1)
        if a and re.match(r"^\s*(?:\??\.\s*[A-Za-z_$][\w$]*(?:\(\s*\))?)+\s*$", e[a[1]:]):
            return is_const(e[:a[1]], ctx, depth + 1)  # new-ish chains: make(x).href
    m = re.match(r"^(.*\S)\s*\??\.\s*(?:trim|toString|toLowerCase|href|url|origin|valueOf)(?:\(\s*\))?$", e, re.S)
    if m and not PATH_RX.match(e):
        return is_const(m.group(1), ctx, depth + 1)
    m = PATH_RX.match(e)
    if m:
        return _name_const(m.group("base"), m.group("rest"), ctx, depth)
    return False


def _final_call(e):
    """(callee text, args) when e is one call whose argument list closes e: f(x), a.b(x), (g ?? h)(x)."""
    if not e.endswith(")") or e.startswith("new "):
        return None
    # the `(` that opens the last argument list: scan for top-level parens whose group ends at len(e)
    depth, k, n, opens = 0, 0, len(e), []
    while k < n:
        c = e[k]
        if c in "'\"`":
            k = _skip_quote(e, k)
            continue
        if c in "([{":
            if depth == 0 and c == "(":
                opens.append(k)
            depth += 1
        elif c in ")]}":
            depth -= 1
        k += 1
    for i in reversed(opens):
        if i == 0:
            continue
        a = _args(e, i)
        if a and a[1] == n:
            callee = e[:i].strip()
            if callee and not re.search(r"[+\-*/%?:|&=<>!,]\s*$", callee):
                return callee, a[0]
        break
    return None


def _absolute(e):
    e = _clean(e)
    lit = _literal_text(e)
    if lit is None and e.startswith("`"):
        lit = _template_parts(e)[0]
    return lit is None or not lit.startswith("/")


def _name_const(base, rest, ctx, depth):
    if ctx.const_map(base):
        return True  # an owner-written map or list of fixed-host URLs, any member of it
    b = ctx.binding(base)
    if not b:
        return False
    kind, val, scope = b
    if kind == "import":
        target, orig = val
        if orig == "*":
            mm = re.match(r"\s*\??\.\s*([A-Za-z_$][\w$]*)(.*)$", rest, re.S)
            if not mm:
                return False
            orig, rest = mm.group(1), mm.group(2)
        sub = Ctx(ctx.an, target, ctx.an.text(target))
        return _name_const(orig, rest, sub, depth + 1)
    sub = Ctx(ctx.an, ctx.rel, scope)
    if kind == "for":
        name = _clean(val)
        return bool(IDENT.match(name)) and sub.const_map(name)
    if kind == "destructure":
        name = _clean(val)
        return bool(PATH_RX.match(name)) and (sub.const_map(PATH_RX.match(name).group("base")) or is_const(val, sub, depth + 1))
    return is_const(val, sub, depth + 1)


# ------------------------------------------------------------------ repo-wide facts
class Analyzer:
    def __init__(self, repo):
        self.repo = repo
        self._text, self._code, self._imports, self._maps = {}, {}, {}, {}
        self.served = [walk.rel(repo, p) for p in walk.files(repo, tests=False, served=True)]
        self._guards = None

    def text(self, rel):
        if rel not in self._text:
            self._text[rel] = walk.read_code(os.path.join(self.repo, rel))
        return self._text[rel]

    def code(self, rel):
        """Strings blanked, template interpolations kept: same offsets as text(rel)."""
        if rel not in self._code:
            self._code[rel] = walk.read_code(os.path.join(self.repo, rel), strings=False, interp=True)
        return self._code[rel]

    def imports(self, rel):
        if rel not in self._imports:
            self._imports[rel] = walk.import_bindings(self.repo, rel, self.text(rel)) if os.path.isfile(os.path.join(self.repo, rel)) else {}
        return self._imports[rel]

    def const_map(self, rel, name, depth=0):
        key = (rel, name)
        if key not in self._maps:
            self._maps[key] = False
            t = self.text(rel)
            if _const_map(t, name):
                self._maps[key] = True
            elif depth < 3:
                imp = self.imports(rel).get(name)
                if imp and imp[1] != "*":
                    self._maps[key] = self.const_map(imp[0], imp[1], depth + 1)
        return self._maps[key]

    def guards(self):
        """(guard names, files that define a guard that resolves and checks the address, any guard-shaped
        code at all, a guard installed below the call sites, guard names plus wrappers). Guard names: the
        known fetching guards, SSRF-filter library exports, and every repo function whose body holds guard
        logic. Wrappers (const outboundGet = (u) => safeFetch(u)) only stop a request value being followed
        into them; calling a wrapper is not a check, and a function that merely calls a guard on some other
        value is not one."""
        if self._guards is None:
            names, verified, shaped, below = set(GUARD_NAMES), [], False, False
            defs = {}
            for rel in self.served:
                t, code = self.text(rel), self.code(rel)
                # strings never count: a guard word inside an error message is not guard code
                guard_code = bool(GUARD_DEF.search(code) or IP_COMPARE.search(t))
                if guard_code or SSRF_LIB.search(t):
                    shaped = True
                if SSRF_LIB.search(t) or (guard_code and GUARD_RESOLVES.search(code) and (GUARD_CLASSIFIES.search(code) or IP_COMPARE.search(t))):
                    verified.append(rel)
                below = below or _below_guard(t)
                for name, s, e in functions(code):
                    if name:
                        defs.setdefault(name, []).append((t[s:e], code[s:e]))
                for m in re.finditer(r"""import\s*\{([^}]*)\}\s*from\s*['"](?:request-filtering-agent|ssrf-req-filter|ssrf-agent)['"]|import\s+(\w+)\s+from\s*['"](?:ssrf-req-filter|ssrf-agent)['"]""", t):
                    names |= {x.split(" as ")[-1].strip() for x in (m.group(1) or m.group(2) or "").split(",") if x.strip()}
            # impl: functions that ARE a guard. names: every function a value can be checked by, which also
            # takes a function whose code calls a guard (assertSafe(u) { await assertPublic(u) }); calling one
            # counts only on the value that reaches the client (_guarded). Wrappers are followed from impl only,
            # so a function that calls a guard on some other value is still read for the fetch it makes.
            impl = set(GUARD_NAMES) | set(names)
            for name, bodies in defs.items():
                if any(implements_guard(bt, bc, name) for bt, bc in bodies):
                    impl.add(name)
            names |= impl
            for _ in range(2):  # a function calling any guard (a guard word, or a guard this repo defines)
                call = re.compile(r"(?<![\w$.])(?:%s)\s*\(" % "|".join(map(re.escape, sorted(names))))
                for name, bodies in defs.items():
                    if name not in names and any(GUARD_DEF.search(bc) or call.search(bc) for _bt, bc in bodies):
                        names.add(name)
            wrapped = set(impl)
            for _ in range(2):  # wrappers: const outboundGet = (u) => safeFetch(u)
                for name, bodies in defs.items():
                    if name not in wrapped and any(re.search(r"(?<![\w$.])(?:%s)\s*\(" % "|".join(map(re.escape, sorted(wrapped))), bc) for _bt, bc in bodies):
                        wrapped.add(name)
            self._guards = (names, verified, shaped, below, wrapped, impl)
        return self._guards


def _const_map(text, name):
    """True when `name` is a literal map/array of owner-written fixed-host URLs (an allowlist)."""
    m = re.search(r"(?:const|let|var)\s+%s\b[^=;\n]*=\s*(?:new\s+Map\(\s*)?([\[{])" % re.escape(name), text)
    if not m:
        return False
    open_ch = m.group(1)
    close = "}" if open_ch == "{" else "]"
    depth, lit = 0, ""
    for i in range(m.end() - 1, min(len(text), m.end() + 6000)):
        depth += (text[i] == open_ch) - (text[i] == close)
        if depth == 0:
            lit = text[m.end() - 1:i + 1]
            break
    return bool(lit) and bool(re.search(r"""['"`]https?://[A-Za-z0-9.\-]+""", lit)) and "${" not in lit \
        and not surface.CALLER_INPUT_RX.search(lit)


def _below_guard(t):
    for m in BELOW_CANDIDATE.finditer(t):
        i = t.find("(", m.start()) if "(" in m.group(0) else m.end() - 1
        window = t[i:i + 600]
        a = _args(t, i) if t[i:i + 1] == "(" else None
        if a:
            window = t[i:a[1]]
        if re.search(r"\blookup\b", window):
            return True
    return False


def functions(code):
    """[(name, start, end)] of every function-ish block in the strings-blanked code: declarations, named
    and anonymous arrows (a block or an expression body). name is '' for an anonymous one."""
    out = []
    for m in FN_RX.finditer(code):
        name = m.group("f") or m.group("c") or ""
        if m.group(0).startswith("function") or re.match(r"\bfunction", m.group(0)):
            i = _body_open(code, m.end() - 1)
            if i < 0:
                continue
            end = walk.block_end(code, i)
        else:
            j = m.end()
            while j < len(code) and code[j] in " \t\n":
                j += 1
            if j < len(code) and code[j] == "{":
                end = walk.block_end(code, j)
            else:
                end = j + len(_rhs(code, j))
        out.append((name, m.start(), len(code) if end is None else end))
    return out


def _body_open(code, start):
    paren = angle = 0
    for j in range(start, min(len(code), start + 2000)):
        ch = code[j]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "<" and paren == 0:
            angle += 1
        elif ch == ">" and angle and code[j - 1] != "=":
            angle -= 1
        elif ch == "{" and paren == 0 and angle == 0:
            return j
        elif ch == ";" and paren == 0 and angle == 0:
            return -1
    return -1


def _enclosing(funcs, pos):
    best = None
    for f in funcs:
        if f[1] <= pos < f[2] and (best is None or f[1] > best[1]):
            best = f
    return best


# ------------------------------------------------------------------ call sites
def sites(text, code, py=False, client_ok=None):
    """(pos, fn, url_text, url_code, call_text) for every outbound client call; a call with no URL the
    check can read (a config object without url:) is skipped. client_ok: request() is a client here."""
    if client_ok is None:
        client_ok = bool(CLIENT_IMPORT.search(text))
    for m in (PY_CLIENT_RX if py else CLIENT_RX).finditer(code):
        fn = m.group("fn")
        if fn == "request" and not client_ok:
            continue
        a = _args(code, m.end() - 1)
        if not a or not a[0]:
            continue
        args, end = a
        if re.match(r"\s*(?::[^=;{}\n]{0,120})?\{", code[end:end + 160]) and not py:
            continue  # `fetch(request: Request, env) {`: a method definition, not a call
        offs, k = [], m.end()
        for x in args:  # offsets of each argument in the original text
            j = code.find(x, k)
            offs.append((j, j + len(x)))
            k = j + len(x)
        idx = 1 if (py and fn.endswith(".request")) else 0
        if py:
            kw = [o for o in offs if re.match(r"\s*url\s*=", code[o[0]:o[1]])]
            if kw:
                o = kw[0]
                eq = code.index("=", o[0]) + 1
                offs, idx = [(eq, o[1])], 0
            elif idx >= len(offs):
                continue
        s, e = offs[idx]
        arg_code = code[s:e]
        if not py and arg_code.strip().startswith("{"):
            prop = _object_prop(code, s, e, "hostname" if fn.startswith("http") else "url")
            if not prop:
                continue
            s, e = prop
        yield m.start(), fn, text[s:e], code[s:e], text[m.start():end]


def _object_prop(code, s, e, key):
    """(start, end) of the value of `key:` (or the shorthand `{ key }`) at the top level of the object
    literal in code[s:e]."""
    obj = code[s:e]
    i = obj.find("{")
    inner_start = s + i + 1
    inner = code[inner_start:e]
    last = 0
    pieces = []
    for k, c in _top(inner.rstrip().rstrip("}")):
        if c == ",":
            pieces.append((last, k))
            last = k + 1
    pieces.append((last, len(inner.rstrip().rstrip("}"))))
    for a, b in pieces:
        piece = inner[a:b]
        mm = re.match(r"\s*%s\s*(?::\s*|$)" % key, piece)
        if mm:
            if mm.group(0).strip() == key:
                return inner_start + a + piece.index(key), inner_start + a + piece.index(key) + len(key)
            return inner_start + a + mm.end(), inner_start + b
    return None


# ------------------------------------------------------------------ request taint
ASSIGN_ANY = re.compile(r"\b(?:const|let|var)\s+(?:(?P<one>[A-Za-z_$][\w$]*)|\{(?P<many>[^}]{1,300})\})\s*(?::[^=\n]{0,80})?=(?!=)\s*")
PY_ASSIGN = re.compile(r"(?m)^[ \t]*(?P<one>[A-Za-z_]\w*)\s*(?::[^=\n]{0,60})?=(?!=)\s*")


def _mentions(code, names):
    return any(re.search(r"(?<![\w$.])%s\b" % re.escape(n), code) for n in names)


def tainted_names(text, code, ctx, seeds=(), py=False):
    """Names bound (in this handler or helper) to a request value: an accessor, or a name already bound
    to one, after constant-map lookups are blanked."""
    names = set(seeds)
    binds = []
    for m in (PY_ASSIGN if py else ASSIGN_ANY).finditer(code):
        rhs_code = _rhs(code, m.end())
        rhs_text = text[m.end():m.end() + len(rhs_code)]
        lhs = {m.group("one")} if m.group("one") else {x.split(":")[-1].split("=")[0].strip().lstrip(".") for x in m.group("many").split(",")}
        binds.append((lhs, rhs_text, rhs_code))
    for _ in range(4):
        before = len(names)
        for lhs, rhs_text, rhs_code in binds:
            eff = _blank_like(rhs_code, _const_lookups(rhs_text, ctx))
            if _req(eff) or _mentions(eff, names) or (not py and re.match(r"\s*(?:body|payload)\b", eff)):
                names |= {x for x in lhs if IDENT.match(x)}
        if len(names) == before:
            break
    return names


def _blank_like(code, blanked_text):
    """code with the spans blanked_text blanked (both have the same offsets)."""
    return "".join(" " if b == " " and c != "\n" else c for c, b in zip(code, blanked_text))


def _url_tainted(url_text, url_code, ctx, names):
    eff = _blank_like(url_code, _const_lookups(url_text, ctx))
    return (_req(eff) or _mentions(eff, names)) and not is_const(url_text, ctx)


def _py_params(body):
    """Request-value parameters of the first Python def in a route body (FastAPI / Flask): every
    parameter except the request object, dependencies and background tasks."""
    m = re.search(r"\bdef\s+\w+\s*\(([^)]*)\)", body)
    out = set()
    if not m:
        return out
    for p in m.group(1).split(","):
        p = p.strip()
        name = re.split(r"[:=]", p)[0].strip().lstrip("*")
        if not name or name in ("self", "cls") or re.search(r":\s*(?:Request|BackgroundTasks|Response|WebSocket)\b|Depends\(", p):
            continue
        out.add(name)
    return out


# ------------------------------------------------------------------ guards at a site
def _guarded(an, rel, text, code, pos, url_text, call_text, funcs):
    names, impl = an.guards()[0], an.guards()[5]
    if names and re.search(r"(?<![\w$.])(?:%s)\s*\(" % "|".join(map(re.escape, sorted(names))), call_text[call_text.find("(") + 1:]):
        return True  # useAgent(target) handed to the call, or the call's URL wrapped in a guard
    f = _enclosing(funcs, pos)
    if not f:
        return False
    fname, s, e = f
    if fname in impl or implements_guard(text[s:pos], code[s:pos]):
        return True  # inside the guard implementation itself (a function that merely CALLS a guard is not)
    want = _roots(url_text, Ctx(an, rel, text[:pos]))
    if not want or not names:
        return False
    for m in re.finditer(r"(?<![\w$.])(%s)\s*\(" % "|".join(map(re.escape, sorted(names))), code[s:pos]):
        a = _args(text, s + m.end() - 1)
        if a and any(_roots(x, Ctx(an, rel, text[:s + m.start()])) & want for x in a[0]):
            return True  # ensurePublicHost(u) before fetch(u): the guard saw this URL
    return False


def _roots(e, ctx, depth=0):
    """The value an expression carries, through the wrappers that keep it (new URL(x), new Request(x),
    String(x), x.href, x.toString()) and the locals bound to it: `u` with const u = new URL(p.avatarUrl)
    gives {u, p.avatarUrl}. Two expressions with a common root are the same URL."""
    e = re.sub(r"\s+", "", _clean(e))
    out = {e} if e else set()
    if depth > 4 or not e:
        return out
    m = re.match(r"^(?:new(?:URL|Request)|String|encodeURI)\((.*)\)$", e)
    if m:
        a = _args("(" + m.group(1) + ")", 0)
        if a and a[0]:
            out |= _roots(a[0][0], ctx, depth + 1)
        return out
    m = re.match(r"^(.*)\.(?:href|toString\(\)|trim\(\))$", e)
    if m:
        return out | _roots(m.group(1), ctx, depth + 1)
    if IDENT.match(e):
        b = ctx.binding(e)
        if b and b[0] == "assign":
            out |= _roots(b[1], Ctx(ctx.an, ctx.rel, b[2]), depth + 1)
    return out


# ------------------------------------------------------------------ helpers a request value flows into
class Helpers:
    def __init__(self, an):
        self.an = an
        self.defs = None

    def _build(self):
        self.defs = {}
        for rel in self.an.served:
            if rel.endswith(".py"):
                continue
            t, code = self.an.text(rel), self.an.code(rel)
            for m in re.finditer(r"""(?:^|\n)[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"""
                                 r"""|(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,80})?=\s*(?:async\s*)?\(([^)]*)\)\s*(?::\s*[^=\n]{0,80})?=>""", code):
                name = m.group(1) or m.group(3)
                sig = t[m.start(2):m.end(2)] if m.group(1) else t[m.start(4):m.end(4)]
                j = m.end()
                while j < len(code) and code[j] in " \t\n":
                    j += 1
                bo = _body_open(code, m.end()) if m.group(1) else j
                if bo < 0 or bo >= len(code):
                    continue
                if code[bo] == "{":
                    be = walk.block_end(code, bo) or min(len(code), bo + walk.BLOCK_LIMIT)
                else:
                    be = bo + len(_rhs(code, bo))
                self.defs.setdefault(name, []).append({"file": rel, "start": bo, "end": be, "params": _params(sig)})

    def flows_to_fetch(self, fname, argpos, depth=0):
        if self.defs is None:
            self._build()
        guard_names = self.an.guards()[4]
        if fname in guard_names or depth > HELPER_DEPTH:
            return None
        for d in self.defs.get(fname, []):
            if argpos >= len(d["params"]) or not d["params"][argpos]:
                continue
            rel = d["file"]
            t, code = self.an.text(rel), self.an.code(rel)
            body_t, body_c = t[d["start"]:d["end"]], code[d["start"]:d["end"]]
            if fname in self.an.guards()[5] or implements_guard(body_t, body_c, fname):
                continue  # this helper is the guard
            ctx = Ctx(self.an, rel, t[:d["end"]])
            names = tainted_names(body_t, body_c, ctx, seeds={d["params"][argpos]})
            funcs = functions(code)
            for pos, fn, ut, uc, call in sites(body_t, body_c):
                sctx = Ctx(self.an, rel, t[:d["start"] + pos])
                if _url_tainted(ut, uc, sctx, names) and not _guarded(self.an, rel, t, code, d["start"] + pos, ut, call, funcs):
                    return rel, walk.line_of(t, d["start"] + pos)
            for c in re.finditer(r"(?<![\w$])(?:[A-Za-z_$][\w$]*\.)?([A-Za-z_$][\w$]*)\s*\(", body_c):
                if c.group(1) in (fname, "fetch"):
                    continue
                a = _args(body_c, c.end() - 1)
                for i, x in enumerate(a[0] if a else []):
                    if _mentions(x, names):
                        hit = self.flows_to_fetch(c.group(1), i, depth + 1)
                        if hit:
                            return hit
        return None


def _params(sig):
    out = []
    for p in sig.split(","):
        p = re.sub(r"[:=].*$", "", p.strip().lstrip(".")).strip()
        out.append(p if IDENT.match(p) else "")
    return out


def _view(full, body, line):
    """The slice of a whole-file view matching a handler body that starts at `line`."""
    if line == 1 and len(body) == len(full):
        return full
    lines = full.split("\n")
    return "\n".join(lines[line - 1: line - 1 + body.count("\n") + 1])


def _browser_site(text, code, pos, top_funcs):
    """True when the site runs in the visitor's browser: a 'use client' module, or a module with React
    hooks where the site is not inside a server entry (loader, action, getServerSideProps)."""
    if re.match(r"""\s*['"]use client['"]""", text):
        return True
    if re.match(r"""\s*['"]use server['"]""", text):
        return False
    if not (BROWSER_FILE.search(text) and HOOK_USE.search(code)):
        return False
    f = _enclosing(top_funcs, pos)
    return not (f and f[0] in SERVER_ENTRY)


def _top_functions(code):
    out = []
    for m in TOP_FN.finditer(code):
        name = m.group("f") or m.group("c")
        i = _body_open(code, m.end()) if m.group("f") else m.end()
        if m.group("c"):
            j = code.find("=>", m.end(), m.end() + 400)
            k = code.find("{", j if j >= 0 else m.end())
            i = k
        if i is None or i < 0:
            continue
        end = walk.block_end(code, i)
        out.append((name, m.start(), len(code) if end is None else end))
    return out


def main():
    repo = os.path.abspath(sys.argv[1])
    worker = bool(walk.exists_any(repo, "wrangler.toml", "wrangler.jsonc", "wrangler.json")) and not walk.exists_any(repo, "fly.toml", "railway.json", "railway.toml")
    res = []
    an = Analyzer(repo)
    helpers = Helpers(an)
    req_hits = []
    funcs_by = {}

    def funcs(rel):
        if rel not in funcs_by:
            funcs_by[rel] = functions(an.code(rel))
        return funcs_by[rel]

    for h in surface.handlers(repo):
        rel = h["file"]
        py = rel.endswith(".py")
        t, fcode = an.text(rel), an.code(rel)
        body = h["body"]
        bcode = _view(fcode, body, h["line"])
        base_off = len("\n".join(t.split("\n")[:h["line"] - 1])) + 1 if h["line"] > 1 else 0
        at = "%s:%d %s %s" % (rel, h["line"], h["method"], h["path"])
        ctx = Ctx(an, rel, t[:base_off + len(body)])
        names = tainted_names(body, bcode, ctx, seeds=_py_params(body) if py else (), py=py)
        for pos, fn, ut, uc, call in sites(body, bcode, py=py, client_ok=bool(CLIENT_IMPORT.search(t))):
            sctx = Ctx(an, rel, t[:base_off + pos])
            if not _url_tainted(ut, uc, sctx, names):
                continue
            if not py and _guarded(an, rel, t, fcode, base_off + pos, ut, call, funcs(rel)):
                continue
            req_hits.append("%s:%d %s %s" % (rel, h["line"] + body[:pos].count("\n"), h["method"], h["path"]))
        if py:
            continue
        # the request value handed to a helper that fetches it, in this file or another
        for c in re.finditer(r"(?<![\w$])(?:[A-Za-z_$][\w$]*\.)?([A-Za-z_$][\w$]*)\s*\(", bcode):
            callee = c.group(1)
            if callee in ("fetch", "request") or callee in an.guards()[4]:
                continue
            a = _args(bcode, c.end() - 1)
            for i, x in enumerate(a[0] if a else []):
                if _req(x) or _mentions(x, names):
                    hit = helpers.flows_to_fetch(callee, i)
                    if hit:
                        req_hits.append("%s via %s() at %s:%d" % (at, callee, hit[0], hit[1]))
                        break
    # direct request-to-fetch in one expression, e.g. fetch(c.req.query('url'))
    for r, ln, m in walk.find(repo, re.compile(r"\bfetch\(\s*(?:c\.req\.query|c\.req\.param|url\.searchParams\.get|req\.query)"), tests=False, served=True):
        tag = "%s:%d" % (r, ln)
        if not any(x.startswith(tag) for x in req_hits):
            req_hits.append(tag)
    if req_hits:
        res.append(result("fetch.request-url", "No fetch of a URL taken from the request", "FAIL", ledger.join_hits(sorted(set(req_hits)), 6, "; "),
                          severity="medium" if worker else "high",
                          fix="never fetch a caller-supplied URL; if required, allow-list hosts and route it through a public-address guard (outbound-fetch-guard)"))
    else:
        res.append(result("fetch.request-url", "No fetch of a URL taken from the request", "PASS", "route handlers: no request value reaches a fetch URL unguarded, directly or through a helper"))

    raw, guarded, browser = [], 0, set()
    for rel in an.served:
        if rel.endswith(".py"):
            continue
        t, code = an.text(rel), an.code(rel)
        top = None
        for pos, fn, ut, uc, call in sites(t, code):
            if top is None:
                top = _top_functions(code)
            if _browser_site(t, code, pos, top):
                browser.add(rel)  # runs in the visitor's browser: there is no server here to forge from
                continue
            name = _clean(ut)
            ctx = Ctx(an, rel, t[:pos])
            if (INCOMING.match(name) and not ctx.binding(name)) or is_const(ut, ctx):
                continue
            if _guarded(an, rel, t, code, pos, ut, call, funcs(rel)):
                guarded += 1
                continue
            raw.append("%s:%d %s(%s)" % (rel, walk.line_of(t, pos), "fetch" if fn == "fetch" else fn, re.sub(r"\s+", " ", name)[:40]))
    _, verified, shaped, below, _, _ = an.guards()
    note = "; %d browser-only file(s) skipped" % len(browser) if browser else ""
    title = "Data-supplied URLs go through a public-address guard"
    if not raw:
        res.append(result("fetch.data-url", title, "PASS",
                          ("%d guarded, 0 raw variable-URL fetches" % guarded if guarded else "no fetch of a non-constant URL in production code") + note))
    elif not shaped:
        res.append(result("fetch.data-url", title, "FAIL", ledger.join_hits(raw, 6, "; "),
                          severity="low" if worker else "high",
                          fix="route every data-URL fetch through one guard that checks URL, DNS, connect and each redirect (outbound-fetch-guard)",
                          detail="%d raw variable-URL fetch(es), no guard in the repo%s%s" % (len(raw), "; Worker runtime blocks private addresses" if worker else "", note)))
    elif below:
        res.append(result("fetch.data-url", title, "UNKNOWN", ledger.join_hits(raw, 6, "; "),
                          reason="a guard is installed below the call sites (a dispatcher or agent with its own lookup); %d raw variable-URL fetch(es) may or may not go through it; read each" % len(raw)))
    elif verified:
        res.append(result("fetch.data-url", title, "FAIL", ledger.join_hits(raw, 6, "; "),
                          severity="low" if worker else "high",
                          fix="call the repo's own guard at every data-URL fetch site; a raw fetch( next to a guard function is outside it (outbound-fetch-guard)",
                          detail="a guard function exists (%s) but %d raw variable-URL fetch(es) do not call it (%d do)%s" % (ledger.join_hits(verified, 2, ", "), len(raw), guarded, note)))
    else:
        res.append(result("fetch.data-url", title, "UNKNOWN", ledger.join_hits(raw, 6, "; "),
                          reason="guard-shaped code exists (a private-range list or an address check by name) but nothing in the repo resolves the host and checks the address it resolves to; %d raw variable-URL fetch(es) remain beside it; read each and the guard" % len(raw)))
    blind = []
    if any(r.endswith(".py") for r in an.served):
        blind.append("Python: a route parameter or request accessor reaching requests/httpx/urlopen inside the handler is traced; a Python helper hop and data-URL fetches outside handlers are not; read those by hand")
    return ledger.emit(res, cannot_see=blind)


if __name__ == "__main__":
    sys.exit(main())

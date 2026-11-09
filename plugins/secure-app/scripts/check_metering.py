#!/usr/bin/env python3
"""check_metering.py - every paid-model call sits behind a daily counter that is
reserved BEFORE the call, and the Worker also carries a rate-limit binding.

  check_metering.py REPO

  meter.<provider>      each call site of a paid API (Anthropic, OpenAI, Gemini,
                        Vertex, ElevenLabs, Deepgram, Replicate, fal, Perplexity,
                        OpenRouter) must sit in a function (a JS function, arrow,
                        method or route callback, or a Python def) that reads and
                        writes a daily counter ABOVE the call, or be called from a
                        function that does. A counter is a store touched (KV
                        get/put, a Redis incr, a D1 usage row) or a call named
                        for reserving (reserve*, *Budget*, *Quota*, *Counter*,
                        checkSpendCap, overDailyLimit): a name that merely
                        contains Daily (buildDailyDigest) counts nothing. A
                        helper the repo defines is judged by its body, not its
                        name: allowCall() that reserves a KV count is a counter,
                        buildBudgetSummary() and reserveSeat() are not. No
                        counter FAILs high; a counter touched only AFTER the
                        call FAILs medium (a burst outruns it); a counter keyed
                        only on a value the caller supplies (a header, or a body
                        field whether read as body.x or destructured) FAILs
                        medium (rotate the id, reset the cap).
  meter.ratelimit-binding a [[ratelimits]] binding in wrangler config when paid
                        calls exist, AND a `.limit(` call on that binding in
                        served code (directly, through an alias, or through a
                        helper parameter it is passed in as); FAILs medium
                        without either (a declared binding nobody calls limits
                        nothing).

The binding is best-effort (per edge machine, eventually consistent); the
counter is the hard cap. Measured 2026-10-13: a dashboard API's 20-a-minute
binding first answered 429 after about 30 requests; a coaching app's limiter
fired at request 69 on one connection and never across fresh connections.
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

AI = {"Anthropic", "OpenAI", "Google Gemini", "Google Vertex", "ElevenLabs", "Deepgram", "Replicate", "fal", "Perplexity", "OpenRouter"}
SDK_CALL = re.compile(r"\.(?:messages|completions|responses|images|embeddings)\.(?:create|stream)\s*\(|generateContent(?:Stream)?\s*\(|\.(?:textToSpeech|convert|generate)\s*\(|\.transcribe\w*\s*\(|listen\.prerecorded|\.(?:run|subscribe)\s*\(\s*['\"]")
# A counter touched: a KV get/put on a key that names a count, a Redis incr, a D1 usage/count row, or a call
# whose NAME says it reserves (judged by _counter_call: tokens, not substrings, so buildDailyDigest and
# kilometers are not counters; bench 2026-11-01).
COUNTER = re.compile(
    r"\b(?:[\w$]+\.)*(?:env|c\.env|ctx\.env)\.[\w$]+\.(?:get|put|increment)\s*\(\s*(?P<key>[^)]{0,200})"
    r"|\b[\w$.]+\.(?:incr|incrby|hincrby|incrementBy|incrementAndGet)\s*\(\s*(?P<rkey>[^)]{0,200})"
    r"|\.prepare\s*\(\s*(?P<sql>[`'\"][^`'\"]{0,300}\b(?:usage|count|budget|quota|spend|llm_usage)\b[^`'\"]{0,300}[`'\"])"
    # any SQL driver (asyncpg fetchval, pg query, sqlite execute): an UPDATE or INSERT of a usage/count row
    r"|\.(?:execute|executemany|fetchval|fetchrow|fetchone|fetch|query|run|exec|sql)\s*\(\s*(?P<sqlw>[`'\"][^`'\"]{0,300}\b(?:UPDATE|INSERT|UPSERT)\b[^`'\"]{0,300}\b(?:usage|count|calls|budget|quota|spend)\w*\b[^`'\"]{0,300}[`'\"])"
    r"|\b(?P<call>(?:await\s+)?[\w$.]*(?:[Rr]eserve|[Bb]udget|[Qq]uota|[Cc]ounter|[Mm]eter|[Ss]pend|[Cc]ap|[Ll]imit|[Uu]sage)[\w$]*)\s*\(")
COUNTER_TOKENS = {"reserve", "budget", "quota", "counter", "meter"}
CAP_NOUNS = {"spend", "cap", "limit", "usage"}
CAP_VERBS = {"check", "over", "within", "under", "assert", "enforce", "exceed", "exceeds", "exceeded", "consume", "take", "charge", "guard", "gate", "hit"}
KEY_WORDS = re.compile(r"count|usage|budget|quota|daily|spend|calls|llm", re.I)
DATEISH = re.compile(r"today|day|date|utc|toISOString|slice|month|hour|now|isoformat", re.I)
PY_DEF = re.compile(r"^(?P<ind>[ \t]*)(?:async\s+)?def\s+(?P<name>\w+)\s*\(", re.M)
CLIENT_SIGNAL = re.compile(r"cf-connecting-ip|x-real-ip|x-forwarded-for|\bip\b|clientKey|client_key|sha|hash|session|sub\b", re.I)
RATELIMIT_CFG = re.compile(r"\[\[ratelimits\]\]|[\"']ratelimits[\"']\s*:|\[\[unsafe\.bindings\]\][^\[]*type\s*=\s*[\"']ratelimit", re.S)
FUNC_START = re.compile(
    r"^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<f>[\w$]*)\s*(?:<[^>\n]{0,80}>)?\s*\(|"
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+(?P<c>[\w$]+)\s*(?::[^=\n]{0,80})?=\s*(?:async\s*)?(?:<[^>\n]{0,80}>)?\s*(?:\([^)]{0,300}\)|[\w$]+)\s*(?::\s*[^=\n]{0,80})?=>|"
    r"^[ \t]*(?:public\s+|private\s+|static\s+)*(?:async\s+)?(?P<m>[\w$]+)\s*(?:<[^>\n]{0,80}>)?\s*\([^)]{0,300}\)\s*(?::\s*[^{\n]{0,80})?\{|"
    # a route callback, behind any middleware arguments on the same line (zValidator(...), requireAuth)
    r"^[ \t]*[\w$.]+\.(?:get|post|put|patch|delete|all|use)\s*\(\s*['\"`](?P<p>[^'\"`]*)['\"`]\s*,(?:[^\n]*?,)??\s*(?:async\s*)?(?:\([^)]{0,120}\)\s*=>|function\s*\w*\s*\([^)]{0,120}\))\s*\{", re.M)
# A cap middleware mounted over the calling route (app.use('/api/x/generate', requireCaps)) reserves before the handler runs.
CAP_MW_NAME = re.compile(r"(?:require|enforce|check|with)\w*(?:[Cc]aps?|[Bb]udget|[Ss]pend|[Qq]uota|[Mm]eter)|(?:[Cc]aps?|[Bb]udget|[Ss]pend|[Qq]uota|[Mm]eter)\w*(?:[Gg]uard|[Gg]ate|[Mm]iddleware)")


def _body_open(code, start):
    """Index of the `{` that opens the body: the first brace outside the parameter
    list and outside a type annotation (`): Promise<{ chart?: string }> {` has a
    brace in its return type, which once cut a function at its signature)."""
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


def _counter_call(name):
    """A call name reserves when its tokens (camelCase and snake_case split) name a reservation: reserve,
    budget, quota, counter or meter, or a cap noun (spend, cap, limit, usage) with a checking verb.
    `buildDailyDigest` and `dailyLimit` are not reservations; `overDailySpendCap` and `reserve_daily_call` are."""
    parts = name.replace("await", " ").strip().split(".")
    split = lambda w: {t.lower() for t in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", w)}
    toks = split(parts[-1])
    if len(parts) > 1 and toks and toks <= (CAP_VERBS | {"reserve", "increment", "incr"}):
        toks |= split(parts[-2])  # a bare verb on a named object: spendGuard.check(), budget.consume()
    return bool(toks & COUNTER_TOKENS) or bool(toks & CAP_NOUNS and toks & CAP_VERBS)


def _py_functions(code):
    """[(name, start, end)] for Python defs: the body runs to the first later non-blank line indented at or
    below the def (after the signature's closing paren)."""
    out = []
    starts = [0] + [i + 1 for i, ch in enumerate(code) if ch == "\n"]
    for m in PY_DEF.finditer(code):
        ind = len(m.group("ind").expandtabs(8))
        first = code.count("\n", 0, m.start())
        depth, end, in_sig = 0, len(code), True
        for li in range(first, len(starts)):
            line = code[starts[li]: starts[li + 1] - 1 if li + 1 < len(starts) else len(code)]
            if in_sig:
                depth += line.count("(") - line.count(")")
                if depth <= 0:
                    in_sig = False
                continue
            if not line.strip():
                continue
            if len(line) - len(line.lstrip(" \t")) <= ind:
                end = starts[li]
                break
        out.append((m.group("name"), m.start(), end))
    return out


def _functions(code, text=None, py=False):
    """[(name, start, end)] for top-level and nested function-ish blocks, by brace balance (Python: by
    indentation). `code` has strings blanked (structure); `text` keeps them (the route path)."""
    if py:
        return _py_functions(code)
    out = []
    for m in FUNC_START.finditer(code):
        path = (text or code)[m.start("p"):m.end("p")] if m.group("p") is not None else None
        name = m.group("f") or m.group("c") or m.group("m") or ("<route %s>" % path)
        if name in ("if", "for", "while", "switch", "catch", "return"):
            continue
        i = m.end() - 1 if m.group(0).endswith("{") else _body_open(code, m.end() - 1)
        if i < 0:
            continue
        end = walk.block_end(code, i)
        out.append((name, m.start(), len(code) if end is None else end))
    return out


def _enclosing(funcs, pos):
    """The innermost function containing pos."""
    best = None
    for f in funcs:
        if f[1] <= pos < f[2] and (best is None or f[1] > best[1]):
            best = f
    return best


class Defs:
    """Function definitions across the served tree, to judge a called helper by what its body does."""

    def __init__(self, codes, texts, all_funcs):
        self.codes, self.texts, self.by_name = codes, texts, {}
        for rel, funcs in all_funcs.items():
            for f in funcs:
                if not f[0].startswith("<"):
                    self.by_name.setdefault(f[0], []).append((rel, f))
        self._memo = {}

    def store_counter(self, name, depth=0):
        """True / False when `name` is defined in the repo and its body does (or does not) read and write
        a counter store, following its own helper calls; None when the repo does not define it."""
        if name not in self.by_name:
            return None
        if name in self._memo:
            return self._memo[name]
        self._memo[name] = False
        ok = False
        for rel, f in self.by_name[name]:
            if _counter_in(self.texts[rel], f[1], f[2], self if depth < 2 else None, depth + 1, code=self.codes[rel], skip=f[0]):
                ok = True
                break
        self._memo[name] = ok
        return ok


CALL_NAME = re.compile(r"(?<![\w$])(?:await\s+)?((?:[\w$]+\.)*([A-Za-z_$][\w$]*))\s*\(")
NOT_HELPERS = {"if", "for", "while", "switch", "catch", "return", "function", "fetch", "Number", "String", "Boolean", "JSON", "Date", "Math", "Error"}


def _counter_in(text, start, end, defs=None, depth=0, code=None, skip=None):
    """Counter ops inside text[start:end] (comments stripped, strings kept): (position, key_text).
    A bare identifier as the key is resolved to its declaration, so `env.KV.get(key)` with
    const key = ai:count:<day> above it counts. A called helper the repo defines counts when its body
    reads and writes a counter (dailyLimitOk(env), allowCall(env)), whatever its name, and does not count
    when its body touches no counter store (buildBudgetSummary(), reserveSeat()); a helper the repo does
    not define is judged by its name (_counter_call)."""
    hits = []
    seen = set()
    for m in COUNTER.finditer(text, start, end):
        if code is not None and not (code[m.start()] == text[m.start()]):
            continue  # inside a string
        key = m.group("key") if m.group("key") is not None else m.group("rkey")
        if key is not None:
            key = key.strip()
            if re.match(r"^[\w$]+$", key):
                key = walk.decl_src(key, text[start:end], text) or key
            if not KEY_WORDS.search(key):
                continue
        if m.group("call") is not None:
            last = m.group("call").split(".")[-1].replace("await", "").strip()
            if last == skip or re.search(r"\bfunction\s*\*?\s*$", text[max(0, m.start() - 20):m.start()]):
                continue  # the function's own name in its signature, or a recursive call
            judged = defs.store_counter(last) if defs else None
            if judged is False or (judged is None and not _counter_call(m.group("call"))):
                continue
            seen.add(m.start("call"))
        hits.append((m.start(), key or m.group("sql") or m.group("sqlw") or m.group("call") or ""))
    if defs is not None and code is not None:
        for m in CALL_NAME.finditer(code, start, end):
            name = m.group(2)
            if m.start(1) in seen or name in NOT_HELPERS or name == skip or any(abs(m.start(1) - p) < 8 for p in seen):
                continue
            judged = defs.store_counter(name)
            if judged or (judged is None and _counter_call(m.group(1))):
                hits.append((m.start(), m.group(1)))  # a repo helper that counts, or a package's meter.reserve()
    return sorted(hits)


def _caller_keyed(code, func, key_text):
    """True when the counter's key is built ONLY from caller-supplied values (plus a date)."""
    names = set(re.findall(r"\$\{\s*([\w$]+)", key_text)) | set(re.findall(r"\+\s*([\w$]+)", key_text)) | set(re.findall(r"^\s*([\w$]+)\s*$", key_text))
    names = {n for n in names if not DATEISH.search(n)}
    if not names:
        return False
    body = code[func[1]:func[2]]
    supplied, other = 0, 0
    for n in names:
        src = walk.decl_src(n, body, code)  # `const { deviceId } = await c.req.json()` is caller-supplied too
        if CLIENT_SIGNAL.search(src) or CLIENT_SIGNAL.search(n):
            other += 1
        elif surface.CALLER_SUPPLIED_RX.search(src) or re.match(r"(?:teacherId|userId|accountId|user_id|teacher_id)$", n):
            supplied += 1
        else:
            other += 1
    return supplied > 0 and other == 0


MAX_DEPTH = 3  # call site -> helper -> route is the deepest chain seen in production (a classroom app)


def _judge_site(repo, rel, pos, codes, texts, all_funcs, cap_mw, defs=None):
    """Walk from the call site up through its callers (at most MAX_DEPTH levels) until a counter
    or a cap middleware is found. Returns (verdict, note): verdict is ok / after / keyed / none."""
    f = _enclosing(all_funcs.get(rel, []), pos)
    if not f:
        return "none", "top level"
    frames, seen, origin = [(rel, f, pos, 0)], set(), f[0]
    while frames:
        rel, f, pos, depth = frames.pop(0)
        if (rel, f[1]) in seen:
            continue
        seen.add((rel, f[1]))
        code, text = codes[rel], texts[rel]
        hits = _counter_in(text, f[1], f[2], defs, code=code, skip=f[0])
        pre = [(hp, k) for hp, k in hits if hp < pos]
        if pre:
            kp, ktext = pre[0]
            if ktext and _caller_keyed(code, f, ktext):
                return "keyed", f[0]
            return "ok", "counter at %s:%d" % (rel, walk.line_of(code, kp))
        if hits:
            return "after", f[0]
        at = _mw_covered(repo, rel, f, codes, all_funcs, cap_mw)
        if at:
            return "ok", "cap middleware at %s" % at
        if depth >= MAX_DEPTH or f[0].startswith("<route"):
            continue
        for r2, code2 in codes.items():
            for cm in re.finditer(r"\b%s\s*\(" % re.escape(f[0]), code2):
                g = _enclosing(all_funcs[r2], cm.start())
                if g and g[0] != f[0]:
                    frames.append((r2, g, cm.start(), depth + 1))
    return "none", origin


def _mw_covered(repo, rel, f, codes, all_funcs, cap_mw):
    """The route that calls this function (or the function itself when it is a route) sits under a
    cap middleware: app.use(prefix, ..., requireCaps). Returns the middleware's file:line or None."""
    if not cap_mw:
        return None
    routes = []
    if f[0].startswith("<route "):
        routes.append((rel, f[0][7:-1]))
    else:
        for r2, code2 in codes.items():
            for cm in re.finditer(r"\b%s\s*\(" % re.escape(f[0]), code2):
                g = _enclosing(all_funcs[r2], cm.start())
                if g and g[0].startswith("<route "):
                    routes.append((r2, g[0][7:-1]))
    for r2, path in routes:
        for p in [path] + surface.mount_paths(repo, r2, path):
            at = surface.covered(p, cap_mw)
            if at:
                return at
    return None


def _ratelimit_names(cfg):
    """Binding names declared in [[ratelimits]] (toml), "ratelimits": [...] (jsonc) or an unsafe ratelimit binding."""
    names = set()
    for blk in re.finditer(r"\[\[ratelimits\]\]([^\[]*)", cfg):
        names |= set(re.findall(r"""\bname\s*=\s*["'](\w+)["']""", blk.group(1)))
    for blk in re.finditer(r"""["']ratelimits["']\s*:\s*\[(.*?)\]""", cfg, re.S):
        names |= set(re.findall(r"""["']name["']\s*:\s*["'](\w+)["']""", blk.group(1)))
    for blk in re.finditer(r"\[\[unsafe\.bindings\]\]([^\[]*)", cfg):
        if re.search(r"""type\s*=\s*["']ratelimit""", blk.group(1)):
            names |= set(re.findall(r"""\bname\s*=\s*["'](\w+)["']""", blk.group(1)))
    return names


def _binding_calls(codes, all_funcs, names):
    """file:line of every `.limit(` on a declared binding: env.AI_LIMITER.limit(, an alias of it
    (const limiter = c.env.AI_LIMITER), or a helper parameter it was passed in as (perIp(c.env.AI_LIMITER, c)
    then binding.limit( inside perIp)."""
    alt = "|".join(sorted(re.escape(n) for n in names)) if names else None
    hits, passed = [], []
    for rel, code in codes.items():
        if rel.endswith((".tsx", ".jsx", ".py")):
            continue
        if alt is None:
            hits += ["%s:%d" % (rel, walk.line_of(code, m.start())) for m in re.finditer(r"\benv\.[\w$]+\.limit\s*\(", code)]
            continue
        aliases = set(names)
        for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]{0,60})?=\s*[\w$.]*\b(?:%s)\b\s*(?=[;\n)])" % alt, code):
            aliases.add(m.group(1))
        for m in re.finditer(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*[\w$.]*\benv\b", code):
            for x in m.group(1).split(","):
                if x.split(":")[0].strip() in names:
                    aliases.add(x.split(":")[-1].strip())
        ali = "|".join(sorted(re.escape(a) for a in aliases if a))
        hits += ["%s:%d" % (rel, walk.line_of(code, m.start())) for m in re.finditer(r"(?<![\w$])(?:[\w$]+\.)*(?:%s)\s*\.\s*limit\s*\(" % ali, code)]
        for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(([^()]*)\)", code):
            for i, a in enumerate(m.group(2).split(",")):
                if re.match(r"^\s*(?:[\w$]+\.)*(?:%s)\s*$" % ali, a):
                    passed.append((m.group(1), i))
    for fname, i in passed:
        for rel, funcs in all_funcs.items():
            code = codes[rel]
            for f in funcs:
                if f[0] != fname:
                    continue
                sig = re.search(r"\(([^)]*)\)", code[f[1]:f[2]])
                params = [re.split(r"[:=]", p)[0].strip() for p in sig.group(1).split(",")] if sig else []
                if i < len(params) and re.match(r"^[A-Za-z_$][\w$]*$", params[i]):
                    for m in re.finditer(r"(?<![\w$.])%s\s*\.\s*limit\s*\(" % re.escape(params[i]), code[f[1]:f[2]]):
                        hits.append("%s:%d" % (rel, walk.line_of(code, f[1] + m.start())))
    return sorted(set(hits))


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    sites = {}  # provider -> [(rel, line, pos, code)]
    files = list(walk.files(repo, tests=False, served=True))
    for p in files:
        rel = walk.rel(repo, p)
        if rel.endswith((".tsx", ".jsx", ".html", ".vue", ".svelte")) or walk.TEST_PATH.search(rel):
            continue
        t = walk.read_code(p)
        tcode = walk.read_code(p, strings=False)
        found = []
        for host, prov in surface.PAID_HOSTS.items():
            if prov not in AI:
                continue
            for m in re.finditer(re.escape(host), t):
                found.append((prov, m.start()))
        sdk = {pkg: prov for pkg, prov in surface.SDK_PAID.items() if prov in AI}
        used = {prov for pkg, prov in sdk.items() if re.search(r"""from\s+['"]%s['"]|require\(\s*['"]%s['"]\s*\)""" % (re.escape(pkg), re.escape(pkg)), t)}
        if used:
            for m in SDK_CALL.finditer(tcode):
                for prov in used:
                    found.append((prov, m.start()))
        for prov, pos in found:
            sites.setdefault(prov, []).append((rel, walk.line_of(t, pos), pos))

    # Two views of each file with identical offsets: strings blanked for structure
    # (function boundaries, call positions), strings kept for the counter's key text.
    codes = {walk.rel(repo, p): walk.read_code(p, strings=False) for p in files if p.endswith((".ts", ".js", ".mjs", ".cjs", ".py"))}
    texts = {walk.rel(repo, p): walk.read_code(p) for p in files if p.endswith((".ts", ".js", ".mjs", ".cjs", ".py"))}
    all_funcs = {r: _functions(c, texts[r], py=r.endswith(".py")) for r, c in codes.items()}
    cap_mw = [(m.group(1).rstrip("*").rstrip("/") or "/", "%s:%d" % (r, ln)) for r, ln, m in walk.find(repo, surface.MW_RX, tests=False, served=True)
              if CAP_MW_NAME.search(m.group(2))]
    defs = Defs(codes, texts, all_funcs)
    for prov, where in sorted(sites.items()):
        ok, none, after, keyed = [], [], [], []
        for rel, ln, pos in where:
            verdict, note = _judge_site(repo, rel, pos, codes, texts, all_funcs, cap_mw, defs)
            if verdict == "none":
                none.append("%s:%d (%s)" % (rel, ln, note))
            elif verdict == "after":
                after.append("%s:%d (%s: counter touched only after the call)" % (rel, ln, note))
            elif verdict == "keyed":
                keyed.append("%s:%d (%s: counter keyed only on a caller-supplied id)" % (rel, ln, note))
            else:
                ok.append("%s:%d (%s)" % (rel, ln, note))
        cid = "meter.%s" % re.sub(r"[^a-z0-9]+", "-", prov.lower()).strip("-")
        title = "%s calls are reserved against a daily counter before the call" % prov
        if none:
            res.append(result(cid, title, "FAIL", ledger.join_hits(none, 5, "; "), severity="high",
                              fix="read, increment and write a KV or D1 daily counter (keyed on the day, not on a caller id) above the call; refuse with 429 when the cap is reached"))
        elif after:
            res.append(result(cid, title, "FAIL", ledger.join_hits(after, 5, "; "), severity="medium",
                              fix="move the counter reservation above the call: a burst of parallel requests outruns a counter written afterwards"))
        elif keyed:
            res.append(result(cid, title, "FAIL", ledger.join_hits(keyed, 5, "; "), severity="medium",
                              fix="key the counter on the day (global) or on cf-connecting-ip; a caller-chosen id resets the cap on every rotation"))
        else:
            res.append(result(cid, title, "PASS", ledger.join_hits(ok, 4, "; "),
                              detail="a reference, not a proof: confirm with a mutation test that removing the reservation makes the test fail"))
    if sites:
        cfg = ""
        for f in ("wrangler.toml", "wrangler.jsonc", "wrangler.json"):
            cfg += walk.read(os.path.join(repo, f))
        cfg = "\n".join(l for l in cfg.splitlines() if not l.lstrip().startswith(("#", "//")))
        if RATELIMIT_CFG.search(cfg):
            names = _ratelimit_names(cfg)
            called = _binding_calls(codes, all_funcs, names)
            if called:
                res.append(result("meter.ratelimit-binding", "A rate-limit binding backs the counter", "PASS", "ratelimits binding declared in wrangler config and called at %s" % ledger.join_hits(called, 3, ", "),
                                  detail="best-effort only: per edge machine and eventually consistent (measured 2026-10-13: first 429 after about 30 requests; never across fresh connections); the counter is the hard cap"))
            else:
                res.append(result("meter.ratelimit-binding", "A rate-limit binding backs the counter", "FAIL",
                                  "ratelimits binding %sdeclared in wrangler config but no code calls .limit() on it" % ("(%s) " % ", ".join(sorted(names)) if names else ""), severity="medium",
                                  fix="call env.<NAME>.limit({ key: cf-connecting-ip }) in every route that reaches the paid call, before the counter; a declared binding nobody calls limits nothing"))
        elif cfg:
            res.append(result("meter.ratelimit-binding", "A rate-limit binding backs the counter", "FAIL", "no [[ratelimits]] block in wrangler config", severity="medium",
                              fix="add [[ratelimits]] name = \"AI_LIMITER\" simple = { limit = 20, period = 60 } and call env.AI_LIMITER.limit({ key: cf-connecting-ip }) before the counter"))
    if not res:
        res.append(result("meter.none", "Paid-model call surface", "PASS", "no paid-model API host or SDK import in production source"))
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

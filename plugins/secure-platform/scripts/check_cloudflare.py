#!/usr/bin/env python3
"""check_cloudflare.py - Cloudflare Pages and Workers adapter, from the repo.

  check_cloudflare.py REPO

  cf.headers.framing / .hsts / .nosniff / .referrer
      each security header set for every path: in a `/*` block of a committed
      _headers file, by hono/secure-headers mounted on every path (its options
      are read: an option set to false switches that header off; mounted on
      /api/* only it does not cover the pages), or by code or next.config that
      SETS it (a set/append/setHeader/header call with a value, an object key,
      a next.config `key:`, a subscript assignment, a [name, value] pair; a
      one-argument header(name) READS a request header, and the header's name
      in a string or a docs table is not the header being sent). A literal
      value set in code is judged like a _headers value (max-age=0, ALLOWALL
      or prose protects nothing). Found nowhere FAILs (framing medium; others
      low; HSTS notes the HSTS-preloaded TLDs where plain http is never loaded).
  cf.vars-secrets
      a secret-shaped name with a value in wrangler vars FAILs high: vars are
      plaintext and committed (an empty placeholder holds nothing; a key-shaped
      value FAILs under any name). Read from wrangler.toml ([vars],
      [env.X.vars], the inline form `vars = { ... }` and dotted keys
      `vars.X = ...`) and from wrangler.json/.jsonc
      (comments and trailing commas allowed; a file that still does not parse
      is UNKNOWN, never PASS). Names are judged by whole segments and suffix
      forms (_KEY, API_KEY, SECRET, TOKEN, PASSWORD; camelCase names split
      the same way, plural compounds like ALLOWED_API_KEYS count), so KEYBOARD_LAYOUT,
      MAX_TOKENS and SESSION_TOKEN_TTL_SECONDS are config, and public-by-design
      names (SITE_KEY, PUBLISHABLE, ANON_KEY) are allowed.
  cf.env-bindings
      an env.<name> block that reuses the production D1/KV/R2/Hyperdrive id
      FAILs medium: the preview writes production data (found 2026-08-25).
      Production is the top level and any env named production/prod/live/main
      (a top level used for local dev does not hide [env.staging] sharing
      [env.production]'s database). Read from TOML and from
      wrangler.json/.jsonc; a `preview_id` is not a production id.
What it cannot see is printed under cannot_see (zone rules, Access, WAF,
Pages project secrets, the pages.dev alias's exposure).
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402
from names import secret_name  # noqa: E402  (one secret-name vocabulary for every adapter)

REFERRER_TOKENS = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin",
                   "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}


def _referrer_ok(v):
    """A Referrer-Policy value is a comma list of policy tokens; the browser uses the last one it
    knows. Prose ('limits referrer leaks') is not a policy, and unsafe-url protects nothing."""
    toks = [x.strip().strip("'\"").lower() for x in v.split(",") if x.strip()]
    return bool(toks) and all(x in REFERRER_TOKENS for x in toks) and toks[-1] != "unsafe-url"


# A header that is present but says nothing does not count (Phase 5 audit #9).
VALUE_OK = {
    "framing": lambda v: bool(re.search(r"frame-ancestors\s+(?!\*\s*(?:;|$))[^;]+", v, re.I)) or v.strip().upper() in ("DENY", "SAMEORIGIN"),
    "hsts": lambda v: bool(re.search(r"max-age\s*=\s*(\d+)", v)) and int(re.search(r"max-age\s*=\s*(\d+)", v).group(1)) >= 15552000,
    "nosniff": lambda v: v.strip().lower() == "nosniff",
    "referrer": lambda v: _referrer_ok(v),
}
HEADER_LINE = {
    "framing": re.compile(r"^\s*(?:Content-Security-Policy|X-Frame-Options)\s*:\s*(.+)$", re.I | re.M),
    "hsts": re.compile(r"^\s*Strict-Transport-Security\s*:\s*(.+)$", re.I | re.M),
    "nosniff": re.compile(r"^\s*X-Content-Type-Options\s*:\s*(.+)$", re.I | re.M),
    "referrer": re.compile(r"^\s*Referrer-Policy\s*:\s*(.+)$", re.I | re.M),
}
HEADERS = {
    "framing": (re.compile(r"frame-ancestors|X-Frame-Options", re.I), "medium",
                "Content-Security-Policy: frame-ancestors 'self' <each origin that embeds the site> (run find_embedders.sh first)"),
    "hsts": (re.compile(r"Strict-Transport-Security", re.I), "low", "Strict-Transport-Security: max-age=31536000 (no preload: reversible)"),
    "nosniff": (re.compile(r"X-Content-Type-Options", re.I), "low", "X-Content-Type-Options: nosniff"),
    "referrer": (re.compile(r"Referrer-Policy", re.I), "low", "Referrer-Policy: strict-origin-when-cross-origin"),
}


Q = r"""['"`]"""


def _val(i):
    """The value after the name: a plain string literal (group v<i>), or anything else (a variable, a call: unread)."""
    return r"""\s*(?:(?P<q{i}>['"`])(?P<v{i}>(?:(?!(?P=q{i}))[^\\\n])*)(?P=q{i}))?""".format(i=i)


def _set_shape(header_name):
    """Code that SETS a response header by name, with the literal value when there is one:
    - a set/append/setHeader/header call whose name argument is FOLLOWED by a value
      (`c.req.header('X-Frame-Options')` with one argument READS a request header, Phase 10);
    - an object key ('Name': value), a next.config `{ key: 'Name', value: '...' }`;
    - a subscript assignment (h['Name'] = v, resp.headers['Name'] = v in a Python Worker);
    - a [name, value] pair (new Headers([['Name', 'v']])).
    The name alone in a string, a docs table ({ name: 'X-Frame-Options', why: ... }) or a help page
    is not a header being sent (bench 2026-11-01). A literal value is judged by VALUE_OK (Phase 10:
    `.set('Strict-Transport-Security', 'max-age=0')` and a help map keyed by header name read as set)."""
    n = Q + re.escape(header_name) + Q
    alts = [r"\.(?:set|append|setHeader|header)\s*\(\s*%s\s*,%s" % (n, _val(1)),
            r"\bkey\s*:\s*%s\s*,\s*value\s*:%s" % (n, _val(2)),
            r"\bkey\s*:\s*%s(?!\s*,\s*value\s*:)" % n,
            r"%s\s*:(?!:)%s" % (n, _val(3)),
            r"\[\s*%s\s*\]\s*=(?!=)%s" % (n, _val(4)),
            r"\[\s*%s\s*,%s\s*\]" % (n, _val(5))]
    return re.compile("|".join(alts), re.I)


SET_SHAPE = {
    "framing": (_set_shape("X-Frame-Options"), _set_shape("Content-Security-Policy")),
    "hsts": (_set_shape("Strict-Transport-Security"),),
    "nosniff": (_set_shape("X-Content-Type-Options"),),
    "referrer": (_set_shape("Referrer-Policy"),),
}


def _set_value(m):
    """The literal value a set-shape match carries, or None when it is not a plain literal."""
    for k, v in m.groupdict().items():
        if k.startswith("v") and v is not None:
            return None if "${" in v else v
    return None


# hono/secure-headers option per header; `option: false` switches that header off.
SECURE_HEADERS_OPT = {"framing": "xFrameOptions", "hsts": "strictTransportSecurity", "nosniff": "xContentTypeOptions", "referrer": "referrerPolicy"}

PRELOADED = (".app", ".dev", ".page")


def headers_files(repo):
    out = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in ("node_modules", "out", "dist", "build") and not d.startswith(".")]
        if "_headers" in names:
            out.append(os.path.join(root, "_headers"))
    return out


def all_paths_block(text):
    """Header lines in blocks whose path covers every page (/* or /)."""
    out, cur = [], None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            cur = line.strip()
        elif cur in ("/*", "/", "https://:project.pages.dev/*") or (cur and cur.endswith("/*") and cur.count("/") <= 3 and "://" in cur):
            out.append(line.strip())
    return "\n".join(out)


def wrangler(repo):
    for f in ("wrangler.toml", "wrangler.jsonc", "wrangler.json"):
        t = walk.read(os.path.join(repo, f))
        if t:
            return f, t
    return None, ""


def toml_sections(t):
    """[(section, body)] for a TOML file, good enough for wrangler.toml."""
    out, cur, buf = [], "", []
    for line in t.splitlines():
        m = re.match(r"^\s*\[\[?([^\]]+)\]\]?\s*$", line)
        if m:
            out.append((cur, "\n".join(buf)))
            cur, buf = m.group(1).strip(), []
        else:
            buf.append(line)
    out.append((cur, "\n".join(buf)))
    return out


TOML_PAIR = re.compile(r"""([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(['"])(.*?)\2""")


def toml_vars(t):
    """(label, name, value) for every string var in wrangler.toml: [vars], [env.X.vars],
    the inline-table form `vars = { A = "x", B = "y" }` at top level or in an [env.X]
    block (bench 2026-11-01: the inline form was never read), and TOML dotted keys
    (`vars.A = "x"` at top level or in [env.X], `env.X.vars.A = "x"` at top level,
    `X.vars.A = "x"` in [env]) (Phase 10, 2026-11-07)."""
    out = []
    for sec, body in toml_sections(t):
        if sec == "vars" or sec.endswith(".vars"):
            for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(['\"])(.*?)\2", body, re.M):
                out.append(("[%s]" % sec, m.group(1), m.group(3)))
        for m in re.finditer(r"^\s*vars\s*=\s*\{(.*?)\}\s*$", body, re.M | re.S):
            label = "vars" if not sec else "[%s] vars" % sec
            for p in TOML_PAIR.finditer(m.group(1)):
                out.append((label, p.group(1), p.group(3)))
        if sec == "":
            dotted = r"(?:env\.([A-Za-z0-9_-]+)\.)?vars"
        elif sec == "env":
            dotted = r"([A-Za-z0-9_-]+)\.vars"
        elif re.match(r"^env\.[A-Za-z0-9_-]+$", sec):
            dotted = r"()vars"
        else:
            continue
        for m in re.finditer(r"^\s*%s\.([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(['\"])(.*?)\3" % dotted, body, re.M):
            env = m.group(1) or (sec[4:] if sec.startswith("env.") else "")
            out.append(("env.%s vars" % env if env else "vars", m.group(2), m.group(4)))
    return out


def jsonc_load(text):
    """wrangler.json/.jsonc as a dict, or None when it does not parse. Comments
    go through walk.strip_comments (string-aware, line-preserving: a `//.*$`
    with re.S once blanked the whole file after its first comment), then
    trailing commas, which JSONC allows, are dropped."""
    s = walk.strip_comments(text, "wrangler.jsonc")
    s = re.sub(r",(\s*[}\]])", r"\1", s)
    try:
        data = json.loads(s)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _binding_ids(block):
    """Production-style binding ids in one wrangler JSON block (top level or one env): every
    binding list's database_id, id or bucket_name (D1, KV, R2, Hyperdrive, Vectorize...), as the
    TOML path reads any `id =` (Phase 10: a shared Hyperdrive id in JSON was never read). A
    preview_id / preview_database_id is a different field and is not read."""
    ids = set()
    if not isinstance(block, dict):
        return ids
    for key, val in block.items():
        if key in ("env", "vars") or not isinstance(val, list):
            continue
        for b in val:
            if isinstance(b, dict):
                for field in ("database_id", "id", "bucket_name"):
                    if isinstance(b.get(field), str) and b[field]:
                        ids.add(b[field])
    return ids


# An env whose name says production: its ids are production data too, even when the top level is local dev
# (Phase 10: [env.staging] and [env.production] sharing one D1 id were each compared with the top level only).
PROD_ENV = re.compile(r"^(?:prod|production|live|main)$", re.I)


def _env_name(sec):
    """`production` for env.production, env.production.d1_databases or env.production.vars."""
    parts = sec.split(".")
    return parts[1] if len(parts) > 1 else sec


# `\b` so preview_id / preview_database_id / preview_bucket_name are not read as the production id.
ID_RX = re.compile(r"\b(?:database_id|id|bucket_name)\s*=\s*['\"]([^'\"]+)")


def secure_headers_calls(repo):
    """[(relpath, line, options_text, mount_path)] for every hono secureHeaders( call, with
    the text inside its parentheses (empty for secureHeaders()) and the path it is mounted on
    with app.use (None when no path is given)."""
    out = []
    for p in walk.files(repo, tests=False):
        t = walk.read_code(p)
        for m in re.finditer(r"secureHeaders\s*\(", t):
            depth, i, j = 0, m.end() - 1, m.end() - 1
            while j < len(t):
                if t[j] == "(":
                    depth += 1
                elif t[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            mount = MOUNT_RX.search(t[max(0, m.start() - 300):m.start()])
            out.append((walk.rel(repo, p), walk.line_of(t, m.start()), t[i + 1:j], mount.group(2) if mount else None))
    return out


# `app.use('/api/*', secureHeaders())`: the mount path in front of the call (other middleware may sit between).
MOUNT_RX = re.compile(r"""\.use\s*\(\s*(['"`])([^'"`]*)\1\s*,(?:\s*[\w.]+\s*\([^()]*\)\s*,)*\s*$""")
ALL_PATHS = {"*", "/*", "/**", ""}


def mounted_everywhere(call):
    """A secureHeaders() call covers every path when it is mounted with no path or on `*` / `/*`
    (Phase 10: on /api/* the HTML at / gets nothing)."""
    return call[3] is None or call[3] in ALL_PATHS


def secure_headers_sends(name, opts):
    """Does this secureHeaders(opts) call send the header? Defaults on; an
    option set to false switches it off; a string value must protect; framing
    also counts a CSP frameAncestors directive."""
    opt = SECURE_HEADERS_OPT[name]
    m = re.search(r"\b%s\s*:\s*(false|['\"`]([^'\"`]*)['\"`])" % opt, opts)
    if m is None:
        on = True
    elif m.group(1) == "false":
        on = False
    else:
        on = VALUE_OK[name](m.group(2))
    if name == "framing" and not on:
        on = bool(re.search(r"\bframeAncestors\s*:", opts))
    return on


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    hfiles = headers_files(repo)
    covered_text = "\n".join(all_paths_block(walk.read(p)) for p in hfiles)
    # Every place code SETS each header: (where, value). value None = not a plain literal (a variable,
    # a call): set, value unread. A literal is judged like a _headers value (Phase 10). next.config
    # headers() of a static export are ignored by Next, so they set nothing.
    static_cfg = {f for f in ("next.config.js", "next.config.mjs", "next.config.ts")
                  if re.search(r"""output\s*:\s*['"]export['"]""", walk.read_code(os.path.join(repo, f)))}
    code_sets = {}
    for name in HEADERS:
        for r, ln, m in walk.find(repo, SET_SHAPE[name][0], exts=walk.CODE_EXT + (".mjs", ".cjs"), tests=False):
            if r not in static_cfg:
                code_sets.setdefault(name, []).append(("%s:%d" % (r, ln), _set_value(m)))
    # A CSP set in code protects framing only when it carries frame-ancestors: a literal value is read,
    # an unread value counts when the same file says frame-ancestors.
    for r, ln, m in walk.find(repo, SET_SHAPE["framing"][1], exts=walk.CODE_EXT + (".mjs", ".cjs"), tests=False):
        v = _set_value(m)
        if r in static_cfg or (v is None and "frame-ancestors" not in walk.read_code(os.path.join(repo, r))):
            continue
        code_sets.setdefault("framing", []).append(("%s:%d" % (r, ln), v))
    code_hits, code_bad = {}, {}
    for name, sets in code_sets.items():
        good = [w for w, v in sets if v is None or VALUE_OK[name](v)]
        if good:
            code_hits[name] = good[0]
        else:
            code_bad[name] = sets[0]
    sh_calls = secure_headers_calls(repo)
    _, wt = wrangler(repo)
    # Cloudflare Pages adds nosniff and Referrer-Policy to static assets by
    # default: measured 2026-10-08 on a production *.pages.dev project (no zone, so no
    # zone transform) with neither header in the repo. Not for Pages Functions
    # responses, not for Workers static assets.
    pages = any("pages_build_output_dir" in walk.read(os.path.join(repo, f))
                for f in os.listdir(repo) if f.startswith("wrangler") and f.endswith((".toml", ".json", ".jsonc")))
    deploy_texts = [walk.read(p) for p in walk.all_package_jsons(repo)]
    wfd = os.path.join(repo, ".github", "workflows")
    if os.path.isdir(wfd):
        deploy_texts += [walk.read(os.path.join(wfd, n)) for n in os.listdir(wfd)]
    sd = os.path.join(repo, "scripts")
    if os.path.isdir(sd):
        deploy_texts += [walk.read(os.path.join(sd, n)) for n in os.listdir(sd) if n.endswith((".sh", ".mjs", ".js", ".ts"))]
    # Comment lines do not deploy anything ("do NOT run wrangler pages deploy" in a coaching app's deploy.sh).
    live = ["\n".join(l for l in t.splitlines() if not l.lstrip().startswith(("#", "//", "*", "/*"))) for t in deploy_texts]
    worker = bool(re.search(r"""^\s*["']?main["']?\s*[=:]""", wt, re.M)) and "pages_build_output_dir" not in wt
    pages = pages or (not worker and any(re.search(r"""wrangler\S*["']?\s+pages\s+deploy""", t, re.I) for t in live))
    routes = re.findall(r"""pattern\s*[=:]\s*["']([^"']+)""", wt)
    preloaded = any(r.split("/")[0].endswith(PRELOADED) for r in routes)
    for name, (rx, sev, fix) in HEADERS.items():
        cid = "cf.headers." + name
        title = "%s header on every path" % {"framing": "Framing (frame-ancestors)", "hsts": "HSTS", "nosniff": "nosniff", "referrer": "Referrer-Policy"}[name]
        vals = [m.group(1) for m in HEADER_LINE[name].finditer(covered_text)]
        sh_on = [c for c in sh_calls if secure_headers_sends(name, c[2]) and mounted_everywhere(c)]
        if vals and not any(VALUE_OK[name](v) for v in vals):
            res.append(result(cid, title, "FAIL", "_headers /* block sets it to a value that does not protect (%s)" % vals[0][:60], severity=sev, fix=fix))
        elif vals:
            src = [walk.rel(repo, p) for p in hfiles if rx.search(all_paths_block(walk.read(p)))]
            res.append(result(cid, title, "PASS", "%s (/* block)" % ledger.join_hits(src, 3, ", ")))
        elif sh_on:
            res.append(result(cid, title, "PASS", "hono secureHeaders() at %s:%d (sets it by default)" % sh_on[0][:2]))
        elif pages and name in ("nosniff", "referrer"):
            res.append(result(cid, title, "PASS", "Cloudflare Pages default on static assets (pages_build_output_dir set)",
                              detail="measured on a pages.dev alias 2026-10-08; Pages Functions responses do not get it, set it there in code"))
        elif name in code_hits:
            res.append(result(cid, title, "PASS", "set in code at %s" % code_hits[name], detail="set in code: confirm it applies to every response, including static assets"))
        elif name in code_bad:
            res.append(result(cid, title, "FAIL", "set in code at %s to a value that does not protect (%s)" % (code_bad[name][0], code_bad[name][1][:60]), severity=sev, fix=fix))
        else:
            where = ", ".join(walk.rel(repo, p) for p in hfiles) if hfiles else "no _headers file"
            sub = [c for c in sh_calls if not mounted_everywhere(c) and secure_headers_sends(name, c[2])]
            if sub:
                where += "; secureHeaders() at %s:%d is mounted on %s only" % (sub[0][0], sub[0][1], sub[0][3])
            elif sh_calls and not sh_on:
                where += "; secureHeaders() at %s:%d switches it off (%s: false)" % (sh_calls[0][0], sh_calls[0][1], SECURE_HEADERS_OPT[name])
            res.append(result(cid, title, "FAIL", "%s; not set in code" % where, severity=sev, fix=fix,
                              detail="HSTS-preloaded TLD: browsers never load it over http, HSTS adds little" if name == "hsts" and preloaded else None))
    wf, wt = wrangler(repo)
    if wf:
        bad, data, unparsed = [], None, False
        if wf.endswith(".toml"):
            # An empty placeholder ("") holds nothing, as in the JSON branch; a key-shaped VALUE under an
            # innocent name is a secret too (names.secret_name reads it for its shape only).
            for label, name, value in toml_vars(wt):
                if value and secret_name(name, value):
                    bad.append("%s %s %s" % (wf, label, name))
        else:
            data = jsonc_load(wt)
            if data is None:
                unparsed = True
            else:
                blocks = [("vars", data.get("vars"))]
                for env_name, env in (data.get("env") or {}).items() if isinstance(data.get("env"), dict) else []:
                    if isinstance(env, dict):
                        blocks.append(("env.%s vars" % env_name, env.get("vars")))
                for label, vars_ in blocks:
                    for k, v in (vars_ or {}).items() if isinstance(vars_, dict) else []:
                        if v and secret_name(k, v if isinstance(v, str) else None):
                            bad.append("%s %s %s" % (wf, label, k))
        if unparsed:
            res.append(result("cf.vars-secrets", "No secrets in wrangler [vars]", "UNKNOWN", "%s did not parse as JSONC" % wf,
                              reason="%s did not parse (after comments and trailing commas were removed); its vars could not be read" % wf,
                              fix="run `npx wrangler deploy --dry-run` to find the syntax error, then re-run"))
        elif bad:
            res.append(result("cf.vars-secrets", "No secrets in wrangler [vars]", "FAIL", ledger.join_hits(bad, 6, "; "), severity="high",
                              fix="move each to `wrangler secret put` / `wrangler pages secret put`, delete it from [vars], rotate it (it is in git history)"))
        else:
            res.append(result("cf.vars-secrets", "No secrets in wrangler [vars]", "PASS", "%s: no secret-shaped name in vars" % wf))
        # env bindings: production ids vs each env's ids, TOML or JSON alike
        envs, prod_ids = [], set()
        if wf.endswith(".toml"):
            secs = toml_sections(wt)
            for sec, body in secs:
                if not sec.startswith("env."):
                    prod_ids |= set(ID_RX.findall(body))
            for sec, body in secs:
                if sec.startswith("env."):
                    envs.append((sec, set(ID_RX.findall(body))))
        elif data is not None:
            prod_ids = _binding_ids(data)
            for env_name, env in (data.get("env") or {}).items() if isinstance(data.get("env"), dict) else []:
                envs.append(("env.%s" % env_name, _binding_ids(env)))
        if unparsed and '"env"' in wt:
            res.append(result("cf.env-bindings", "Non-production environments use their own data", "UNKNOWN", "%s did not parse as JSONC" % wf,
                              reason="%s did not parse; its env blocks could not be compared with production" % wf))
        elif envs:
            prod_env_ids = set()
            for sec, ids in envs:
                if PROD_ENV.match(_env_name(sec)):
                    prod_env_ids |= ids
            shared = sorted({"%s [%s] reuses a production binding id" % (wf, sec) for sec, ids in envs if ids & prod_ids}
                            | {"%s [%s] reuses an id of a production env" % (wf, sec) for sec, ids in envs
                               if not PROD_ENV.match(_env_name(sec)) and ids & prod_env_ids})
            if shared:
                res.append(result("cf.env-bindings", "Non-production environments use their own data", "FAIL", ledger.join_hits(shared, 4, "; "), severity="medium",
                                  fix="give the preview its own D1/KV/R2 (or document the ruling that it shares production) before it runs writes"))
            else:
                res.append(result("cf.env-bindings", "Non-production environments use their own data", "PASS", "%s: env.* binding ids differ from production" % wf))
    cannot = [
        "Cloudflare zone rules (rate limiting, WAF, Always Use HTTPS, zone HSTS): dashboard or a zone-write API token; the connector and wrangler were zone-read-only on 2026-10-07",
        "Cloudflare Access policies in front of any path: Zero Trust dashboard",
        "Pages/Worker secrets actually set in production: `npx wrangler pages secret list --project-name P` (names only)",
        "The *.pages.dev / *.workers.dev alias: zone rules do not apply there, so any limit that must hold belongs in code",
    ]
    return ledger.emit(res, cannot_see=cannot)


if __name__ == "__main__":
    sys.exit(main())

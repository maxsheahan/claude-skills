#!/usr/bin/env python3
"""check_fly_supabase.py - Fly.io and Supabase adapter.

  check_fly_supabase.py REPO

  fly.env-secrets        a secret-looking name in fly.toml [env] FAILs high
                         ([env] is plaintext and committed; use fly secrets).
                         A name is a secret by its words (KEY, TOKEN, SECRET,
                         PASSWORD, PRIVATE, CREDENTIAL, DSN, a database URL) or
                         by a key-shaped value; public-by-design names (ANON_KEY,
                         PUBLISHABLE_KEY, SITE_KEY, PUBLIC_KEY) and names that
                         hold a setting about a secret (TOKEN_ISSUER, KEY_ID,
                         PRIVATE_KEY_PATH, SESSION_TOKEN_TTL_SECONDS) are not.
                         A connection-string name with a variant word after it
                         (DATABASE_URL_UNPOOLED, POSTGRES_URL_NON_POOLING) is one.
                         Every fly.toml and fly.<env>.toml in the repo is read
                         (`fly deploy -c`; one app per folder in a monorepo); with
                         several, the id carries the folder and the variant.
                         TOML # comments are not configuration.
  fly.exposure           a public [[services.ports]] port is a web port only
                         when its handlers include "http"; a raw TCP port, a
                         tls-only or pg_tls handler, or any database port (5432,
                         3306, 6379, 27017, ...) FAILs medium; force_https =
                         false FAILs low. ["proxy_proto", "http"] is a web port.
  supabase.rls           every table a migration creates in the public schema
                         has ENABLE ROW LEVEL SECURITY in some migration; a
                         missing one FAILs high. A public view without
                         security_invoker (or a materialized view) bypasses the
                         tables' RLS and FAILs. A write policy whose condition
                         is always true (true, 1=1) or true for every signed-in
                         user (auth.uid() is not null, auth.role() =
                         'authenticated') FAILs; owner-bound conditions
                         (auth.uid() = user_id) and SELECT policies pass.
                         Schemas are parsed: private.audit_log is not a public
                         table. Identifiers follow Postgres (unquoted names fold to
                         lowercase, quoted names keep case); TEMP tables are not
                         public. DROP TABLE / VIEW / POLICY and ALTER POLICY are
                         replayed; casts (::text) and the JWT role claim are read
                         through. Migrations: supabase/, migrations/, drizzle/ and
                         a drizzle.config `out` folder. No migrations: UNKNOWN.
  supabase.service-role  the service-role key referenced from browser code
                         FAILs critical: 'use client' files, components/,
                         public/, client/ paths, a public env prefix
                         (NEXT_PUBLIC_/VITE_/PUBLIC_) on the key, any .html
                         page, every src/ file of a Vite SPA (judged per
                         workspace package; src/api/ and src/workers/ included,
                         src/server/, *.server.ts and entry-server.tsx not), a
                         module a browser file imports (./, ../, @/, ~/, #/), or
                         a vite.config `define` that inlines the key. Vite with a
                         meta-framework, a Vite server plugin (@hono/vite-*), or a
                         server framework and no UI library is a server build; a
                         vitest-only config is not Vite. An App Router page.tsx
                         without 'use client' is a Server Component.
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

DB_PORTS = {5432, 5433, 6432, 3306, 3307, 6379, 27017, 27018, 9200, 9300, 11211, 5672, 9042, 7000, 7001, 2379, 8086, 1433, 1521}
# "pg_tls" and friends: a handler whose protocol is a database wire protocol, not the web.
# proxy_proto is not here: it only prepends the client address, so ["proxy_proto", "http"] is still
# an http port, and proxy_proto alone has no "http" and FAILs on that (2026-11-07 audit).
NON_WEB_HANDLERS = re.compile(r"^(?:pg|mysql|redis|mongo|tcp)\w*$", re.I)
# fly.toml, fly.staging.toml, fly.production.toml, fly-worker.toml: `fly deploy -c <file>` reads any of them
FLY_CONFIG = re.compile(r"^fly(?:[.-][\w.-]+)?\.toml$", re.I)


def toml_code(text):
    """fly.toml with every # comment blanked (outside quoted strings), newlines kept."""
    out = []
    for line in text.split("\n"):
        q, cut, i = None, len(line), 0
        while i < len(line):
            ch = line[i]
            if q:
                if ch == "\\" and q == '"':
                    i += 1  # a basic string's escape: the next character is literal
                elif ch == q:
                    q = None
            elif ch in "\"'":
                q = ch
            elif ch == "#":
                cut = i
                break
            i += 1
        out.append(line[:cut] + " " * (len(line) - cut))
    return "\n".join(out)


# ---- SQL ----
IDENT = r"(\"?[A-Za-z_]\w*\"?)(?:\s*\.\s*(\"?[A-Za-z_]\w*\"?))?"
CREATE = re.compile(r"\bcreate\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?" + IDENT, re.I)
CREATE_VIEW = re.compile(r"\bcreate\s+(?:or\s+replace\s+)?(?:(?:temp|temporary)\s+)?(?:(materialized)\s+)?(?:recursive\s+)?view\s+(?:if\s+not\s+exists\s+)?" + IDENT, re.I)
IDENT_NC = r"\"?[A-Za-z_]\w*\"?(?:\s*\.\s*\"?[A-Za-z_]\w*\"?)?"
DROP = re.compile(r"\bdrop\s+(?:(materialized)\s+)?(table|view)\s+(?:if\s+exists\s+)?((?:" + IDENT_NC + r")(?:\s*,\s*" + IDENT_NC + r")*)", re.I)
ALTER_RLS = re.compile(r"\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:only\s+)?" + IDENT + r"\s+(enable|disable)\s+row\s+level\s+security", re.I)
# ALTER VIEW v SET (opt = x, security_invoker = on) / RESET (security_invoker): the option list is parsed, not matched whole
ALTER_VIEW_OPTS = re.compile(r"\balter\s+(?:materialized\s+)?(?:view|table)\s+(?:if\s+exists\s+)?" + IDENT + r"\s+(set|reset)\s*\(", re.I)
INVOKER_OPT = re.compile(r"^\s*security_invoker\s*(?:=\s*(\w+|'\w+'))?\s*$", re.I)
INVOKER_ON = re.compile(r"security_invoker\s*(?:=\s*)?(?:true|on)\b|\bsecurity_invoker\s*(?:,|\))", re.I)
POL_NAME = r"(\"[^\"]*\"|\w+)"
POLICY = re.compile(r"\bcreate\s+policy\s+" + POL_NAME + r"\s+on\s+" + IDENT, re.I)
ALTER_POLICY = re.compile(r"\balter\s+policy\s+" + POL_NAME + r"\s+on\s+" + IDENT, re.I)
DROP_POLICY = re.compile(r"\bdrop\s+policy\s+(?:if\s+exists\s+)?" + POL_NAME + r"\s+on\s+" + IDENT, re.I)
RENAME_POLICY = re.compile(r"\brename\s+to\s+" + POL_NAME, re.I)
POLICY_CMD = re.compile(r"\bfor\s+(select|insert|update|delete|all)\b", re.I)
CLAUSE = re.compile(r"\b(using|with\s+check)\s*\(", re.I)
# conditions true for anyone, or for every signed-in user, after normalization (see _normalize_cond)
ALWAYS_TRUE = re.compile(r"^(?:true|1=1|true is true|'t'|'true'|'1'|not false)$")
# the caller's role, however it is read: auth.role(), the JWT's role claim, current_user / current_role
ROLE_SRC = r"(?:auth\.role\(\)|auth\.jwt\(\)->>'role'|current_user|current_role|session_user|current_setting\('request\.jwt\.claim\.role'(?:,true)?\))"
SIGNED_ROLE = r"'(?:authenticated|anon|service_role)'"
ANY_SIGNED_IN = re.compile(r"^(?:auth\.(?:uid|jwt|role|email)\(\) is not null|" + ROLE_SRC + "=" + SIGNED_ROLE + "|" + SIGNED_ROLE + "=" + ROLE_SRC + "|"
                           + ROLE_SRC + r" in \((?:" + SIGNED_ROLE + r",?)+\)|"
                           r"auth\.uid\(\)(?:<>|!=)''|coalesce\(auth\.uid\(\)[^)]*\) is not null)$")


def _paren(text, start):
    """The text inside the balanced parentheses that open at or after `start`."""
    i = text.find("(", start)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j]
    return None


def _strip_parens(e):
    e = e.strip()
    while e.startswith("(") and e.endswith(")") and _paren(e, 0) == e[1:-1]:
        e = e[1:-1].strip()
    return e


def _normalize_cond(expr):
    e = re.sub(r"\s+", " ", expr.strip().lower())
    e = re.sub(r"::\s*(?:character varying|double precision|\"?[a-z_]\w*\"?)(?:\[\])?", "", e)  # 'authenticated'::text, the dashboard export's casts
    e = re.sub(r"\(\s*select\s+(auth\.\w+\(\))\s*\)", r"\1", e)  # (select auth.uid()) is the cached form
    e = re.sub(r"\s*(->>|->|<>|!=|=)\s*", r"\1", e)
    e = re.sub(r"\s*,\s*", ",", e)
    e = _strip_parens(e)
    # a parenthesized operand on either side of a comparison: (auth.jwt()->>'role')='authenticated'
    e = re.sub(r"\((auth\.jwt\(\)->>'\w+')\)", r"\1", e)
    return _strip_parens(e)


def open_policy_reason(expr):
    """'always true', 'any signed-in user' or None for a policy condition."""
    e = _normalize_cond(expr)
    if ALWAYS_TRUE.match(e):
        return "always true"
    if ANY_SIGNED_IN.match(e):
        return "true for any signed-in user"
    return None


def _ident(x):
    """Postgres identifier rules: a quoted name keeps its case, an unquoted one folds to lowercase."""
    return x[1:-1] if x.startswith('"') and x.endswith('"') else x.lower()


def qual(m, i=1):
    """(schema, table) from an IDENT match at groups i, i+1; schema defaults to public."""
    a, b = m.group(i), m.group(i + 1)
    if b:
        return _ident(a), _ident(b)
    return "public", _ident(a)


def _clauses(st):
    """{'using': expr, 'check': expr} for the USING / WITH CHECK clauses of a policy statement."""
    out = {}
    for k in CLAUSE.finditer(st):
        out["check" if k.group(1).lower().startswith("with") else "using"] = _paren(st, k.end() - 1) or ""
    return out


def statements(sql):
    """(start_index, statement_text) for each ;-terminated statement, comments removed."""
    t = re.sub(r"--[^\n]*", lambda mm: " " * len(mm.group(0)), sql)  # SQL comments never enable anything
    t = re.sub(r"/\*.*?\*/", lambda mm: "".join(c if c == "\n" else " " for c in mm.group(0)), t, flags=re.S)
    out, start = [], 0
    for m in re.finditer(r";", t):
        out.append((start, t[start:m.start()]))
        start = m.end()
    if t[start:].strip():
        out.append((start, t[start:]))
    return t, out


def replay(repo, migs):
    """Replay migrations in order: the last word on each table counts (enable then a later disable is OFF;
    a dropped table, view or policy is gone; ALTER POLICY replaces the clauses it names)."""
    created, rls, views, view_ok, pols = {}, {}, {}, {}, {}
    for m_path in sorted(migs):
        t, stmts = statements(walk.read(m_path))
        rel = walk.rel(repo, m_path)
        for st_start, st in stmts:
            at = lambda off: "%s:%d" % (rel, walk.line_of(t, st_start + off))
            m = CREATE.search(st)
            if m:
                schema, name = qual(m, 2)
                if schema == "public" and not m.group(1):  # a TEMP table lives in the session's own schema
                    created.setdefault(name, at(m.start()))
                continue
            m = CREATE_VIEW.search(st)
            if m:
                schema, name = qual(m, 2)
                if schema == "public" and not re.search(r"\bcreate\s+(?:or\s+replace\s+)?temp", st, re.I):
                    head = st[m.end():]
                    head = head[:re.search(r"\bas\b", head, re.I).start()] if re.search(r"\bas\b", head, re.I) else head
                    views[name] = (at(m.start()), bool(m.group(1)))
                    view_ok[name] = bool(INVOKER_ON.search(head)) and not m.group(1)
                continue
            m = DROP.search(st)
            if m:
                for one in re.finditer(IDENT, m.group(3)):
                    schema, name = qual(one)
                    if schema != "public":
                        continue
                    if m.group(2).lower() == "table":
                        created.pop(name, None)
                        rls.pop(name, None)
                        for k in [k for k in pols if k[0] == name]:
                            pols.pop(k)
                    else:
                        views.pop(name, None)
                        view_ok.pop(name, None)
                continue
            m = ALTER_VIEW_OPTS.search(st)
            if m and qual(m)[0] == "public" and qual(m)[1] in views:
                name = qual(m)[1]
                for opt in (_paren(st, m.end() - 1) or "").split(","):
                    o = INVOKER_OPT.match(opt)
                    if o:
                        val = (o.group(1) or "true").strip("'").lower()
                        view_ok[name] = m.group(3).lower() == "set" and val in ("true", "on", "1", "yes") and not views[name][1]
                continue
            m = ALTER_RLS.search(st)
            if m:
                schema, name = qual(m)
                if schema == "public":
                    rls[name] = m.group(3).lower() == "enable"
                continue
            m = DROP_POLICY.search(st)
            if m:
                schema, name = qual(m, 2)
                pols.pop((name, _ident(m.group(1))), None)
                continue
            m = ALTER_POLICY.search(st)
            if m:
                schema, name = qual(m, 2)
                if schema != "public":
                    continue
                key = (name, _ident(m.group(1)))
                p = pols.get(key) or {"cmd": "all", "at": at(m.start()), "to_auth": False, "using": None, "check": None}
                rn = RENAME_POLICY.search(st)
                if rn:
                    pols.pop(key, None)
                    pols[(name, _ident(rn.group(1)))] = p
                    continue
                p.update(_clauses(st))
                p["at"] = at(m.start())
                if re.search(r"\bto\s+\"?authenticated\b", st, re.I):
                    p["to_auth"] = True
                pols[key] = p
                continue
            m = POLICY.search(st)
            if m:
                schema, name = qual(m, 2)
                if schema != "public":
                    continue
                cmd = POLICY_CMD.search(st)
                c = _clauses(st)
                pols[(name, _ident(m.group(1)))] = {"cmd": cmd.group(1).lower() if cmd else "all", "at": at(m.start()),
                                                    "to_auth": bool(re.search(r"\bto\s+\"?authenticated\b", st, re.I)),
                                                    "using": c.get("using"), "check": c.get("check")}
    open_pol = []
    for (name, _pn), p in pols.items():
        if p["cmd"] == "select":
            continue  # a public-read or members-read SELECT policy is a design choice, not a hole
        for kw in ("using", "check"):
            why = open_policy_reason(p[kw]) if p[kw] is not None else None
            if why:
                open_pol.append("%s %s: policy %s%s" % (p["at"], name, why, " to authenticated" if p["to_auth"] else ""))
                break
    return created, rls, views, view_ok, open_pol


# ---- browser code ----
PUBLIC_ADMIN = re.compile(r"\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_)\w*(?:SERVICE|ADMIN|SECRET)\w*")
SERVICE = re.compile(r"service_role|SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY|sb_secret_", re.I)
# Paths that are browser code whatever the framework. An App Router page.tsx is NOT here:
# it is a Server Component unless it says 'use client'.
CLIENT_PATH = re.compile(r"(?:^|/)(?:components|public|client|frontend|web/src|src/client|src/components)/")
SERVER_PATH = re.compile(r"(?:^|/)(?:server|api|functions|worker|workers|edge|scripts|supabase|netlify)(?:/|$)|\.server\.[cm]?[jt]sx?$|(?:^|/)server\.[cm]?[jt]s$"
                         r"|(?:^|/)entry-server\.[cm]?[jt]sx?$")
# Inside a Vite SPA's src/ the whole folder is the bundle: src/api/ is the browser's fetch layer and
# src/workers/ holds Web Workers. Only an unmistakable server file is exempt there (src/server/,
# *.server.ts, server.ts, Vite's SSR entry-server.tsx).
SPA_SERVER_PATH = re.compile(r"(?:^|/)server(?:/|$)|\.server\.[cm]?[jt]sx?$|(?:^|/)server\.[cm]?[jt]s$|(?:^|/)entry-server\.[cm]?[jt]sx?$")
HTML_EXT = (".html", ".htm")
USE_CLIENT = re.compile(r"""^\s*['"]use client['"]""")
META_FRAMEWORKS = {"@sveltejs/kit", "astro", "nuxt", "@remix-run/dev", "vinxi", "@tanstack/start", "@tanstack/react-start", "@solidjs/start", "vike", "@analogjs/platform"}
# Vite as a SERVER build tool: these plugins make src/ a server entry, not a browser bundle
VITE_SERVER_PLUGINS = {"@hono/vite-dev-server", "@hono/vite-build", "@hono/vite-cloudflare-pages", "vite-plugin-node", "vite-node"}
SERVER_FRAMEWORKS = {"hono", "express", "fastify", "koa", "@nestjs/core", "@hapi/hapi", "elysia", "h3"}
UI_FRAMEWORKS = {"react", "react-dom", "vue", "svelte", "solid-js", "preact", "lit", "@angular/core", "alpinejs", "three"}
VITE_CONFIGS = ("vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.mts", "vite.config.cjs")
DEFINE_INLINE = re.compile(r"\bdefine\s*:\s*\{[^}]*?(?:SERVICE_ROLE|SERVICE_KEY|sb_secret_)", re.S)
ALIAS_IMPORT = re.compile(r"""(?:\bfrom|\bimport|\brequire\s*\(|\bimport\s*\()\s*['"]((?:\.{1,2}|[@~#])/[^'"]+)['"]""")


def _pkg_deps(path):
    try:
        return walk.deps(json.load(open(path, encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def spa_roots(repo):
    """Folders ('' for the repo root) whose src/ is a Vite browser bundle. Judged per package: a
    workspace app's own package.json (plus the root's hoisted dev dependencies) decides for its src/.
    Vite counts when it is a dependency or a vite.config imports from 'vite' (a vitest-only config
    is a test runner, not a bundler). A meta-framework, a Vite server plugin, or a server framework
    with no UI library means src/ is server code."""
    root_deps = _pkg_deps(os.path.join(repo, "package.json"))
    dirs = {""} | {os.path.dirname(walk.rel(repo, p)) for p in walk.all_package_jsons(repo)}
    out = set()
    for d in dirs:
        here = os.path.join(repo, d)
        deps = dict(root_deps)
        deps.update(_pkg_deps(os.path.join(here, "package.json")))
        cfg = "".join(walk.read_code(os.path.join(here, c)) for c in VITE_CONFIGS)
        vite_cfg = bool(re.search(r"""(?:from\s*|require\s*\(\s*)['"]vite['"]""", cfg))
        if not ("vite" in deps or vite_cfg):
            continue
        names = set(deps)
        if names & META_FRAMEWORKS or names & VITE_SERVER_PLUGINS or re.search(r"""['"]@hono/vite-""", cfg):
            continue
        if names & SERVER_FRAMEWORKS and not names & UI_FRAMEWORKS:
            continue
        out.add(d)
    return out


def _in_spa_src(rel, roots):
    return any(rel.startswith((r + "/src/") if r else "src/") for r in roots)


def resolve_import(repo, from_file, spec):
    """The file a relative or alias import names (./x, ../x, @/x, ~/x, #/x), or None. Aliases are
    tried at the importing package's root and its src/, then the repo root and its src/."""
    if spec.startswith("."):
        bases = [os.path.normpath(os.path.join(os.path.dirname(from_file), spec))]
    else:
        tail = spec[2:]
        pkg = os.path.dirname(from_file)
        while pkg.startswith(repo) and pkg != repo and not os.path.isfile(os.path.join(pkg, "package.json")):
            pkg = os.path.dirname(pkg)
        roots = [pkg, os.path.join(pkg, "src"), repo, os.path.join(repo, "src")]
        bases = [os.path.normpath(os.path.join(r, tail)) for r in dict.fromkeys(roots)]
    for base in bases:
        for ext in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", "/index.ts", "/index.tsx", "/index.js"):
            if os.path.isfile(base + ext):
                return base + ext
    return None


def migration_dirs(repo):
    """The `out` folder a drizzle.config names (drizzle-kit writes its SQL migrations there; default ./drizzle)."""
    out = set()
    for n in ("drizzle.config.ts", "drizzle.config.js", "drizzle.config.mjs", "drizzle.config.cjs", "drizzle.config.json"):
        m = re.search(r"""["']?\bout["']?\s*:\s*["']([^"']+)["']""", walk.read_code(os.path.join(repo, n)))
        if m:
            out.add(os.path.normpath(m.group(1)).replace(os.sep, "/").strip("/"))
    return out


def fly_checks(repo, fly_paths):
    res = []
    for fp in fly_paths:
        rel = walk.rel(repo, fp)
        base = os.path.basename(fp)
        where = os.path.dirname(rel) or "root"
        if base.lower() != "fly.toml":  # fly.staging.toml beside fly.toml is a second app config, not the same one
            where += "_" + re.sub(r"(?i)^fly[.-]|\.toml$", "", base)
        tag = "" if len(fly_paths) == 1 else "." + re.sub(r"[^A-Za-z0-9]+", "_", where)
        fly = toml_code(walk.read(fp))  # a commented-out line is not configuration
        env_sec = re.search(r"^\[env\]\s*$(.*?)(?=^\[|\Z)", fly, re.M | re.S)
        bad = []
        if env_sec:
            for m in re.finditer(r"""^\s*([A-Za-z_]\w*)\s*=\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\n#]*))""", env_sec.group(1), re.M):
                val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else (m.group(4) or "").strip())
                if secret_name(m.group(1), val):
                    bad.append(m.group(1))
        if bad:
            res.append(result("fly.env-secrets" + tag, "No secrets in fly.toml [env]", "FAIL", "%s [env]: %s" % (rel, ", ".join(bad)), severity="high",
                              fix="`fly secrets set NAME=...` (from the clipboard), delete it from [env], rotate it"))
        else:
            res.append(result("fly.env-secrets" + tag, "No secrets in fly.toml [env]", "PASS", "%s [env]: no secret-looking name" % rel))
        exp = []
        for port in re.finditer(r"^\s*\[\[services\.ports\]\]\s*$(.*?)(?=^\s*\[|\Z)", fly, re.M | re.S):
            blk = port.group(1)
            hm = re.search(r"handlers\s*=\s*\[([^\]]*)\]", blk)
            handlers = [h.lower() for h in re.findall(r"""["']([^"']+)["']""", hm.group(1))] if hm else []
            num = re.search(r"^\s*port\s*=\s*(\d+)", blk, re.M)
            pnum = int(num.group(1)) if num else None
            web = "http" in handlers and not any(NON_WEB_HANDLERS.match(h) for h in handlers)
            if pnum in DB_PORTS:
                exp.append("%s services port %s is a database port (handlers: %s)" % (rel, pnum, ", ".join(handlers) or "none"))
            elif not web:
                exp.append("%s services port %s has no http handler (handlers: %s)" % (rel, pnum if pnum is not None else "?", ", ".join(handlers) or "none"))
        if re.search(r"force_https\s*=\s*false", fly):
            exp.append("%s force_https = false" % rel)
        if exp:
            res.append(result("fly.exposure" + tag, "Only web ports are public, over https", "FAIL", "; ".join(exp), severity="medium",
                              fix="remove raw TCP and database services from public exposure (fly proxy / private networking, .internal addresses) and set force_https = true"))
        else:
            res.append(result("fly.exposure" + tag, "Only web ports are public, over https", "PASS", "%s: public ports use http handlers" % rel))
    return res


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    fly_paths = sorted(p for p in walk.files(repo, exts=(".toml",)) if FLY_CONFIG.match(os.path.basename(p)))
    if not fly_paths:
        fly_paths = sorted(os.path.join(repo, n) for n in os.listdir(repo) if FLY_CONFIG.match(n) and os.path.isfile(os.path.join(repo, n)))
    res += fly_checks(repo, fly_paths)

    migs = []
    mig_dirs = migration_dirs(repo)
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in ("node_modules",) and not d.startswith(".")]  # never .claude/worktrees copies
        r = walk.rel(repo, root)
        if re.search(r"(?:supabase|migrations|migrate|drizzle)", root.replace(repo, "")) or any(r == d or r.startswith(d + "/") for d in mig_dirs):
            migs += [os.path.join(root, n) for n in names if n.endswith(".sql")]
    uses_supabase = bool(migs) or os.path.isdir(os.path.join(repo, "supabase")) or any(walk.find(repo, r"@supabase/supabase-js|from supabase import|create_client\(", tests=False))
    if uses_supabase:
        created, rls, views, view_ok, open_pol = replay(repo, migs)
        enabled = {k for k, v in rls.items() if v}
        if not migs:
            res.append(result("supabase.rls", "Row level security on every public table", "UNKNOWN", "no SQL migrations in the repo",
                              reason="RLS lives in the database; with no migrations to read, check the Supabase dashboard (Table Editor, RLS badge)"))
        else:
            missing = [v + " " + k for k, v in created.items() if k not in enabled]
            missing += ["%s %s: %s" % (views[k][0], k, "materialized view (no RLS applies, no security_invoker)" if views[k][1] else "view without security_invoker (runs as its owner, bypasses RLS)")
                        for k in views if not view_ok.get(k)]
            missing += open_pol
            if missing:
                res.append(result("supabase.rls", "Row level security on every public table", "FAIL", ledger.join_hits(missing, 8, "; "), severity="high",
                                  fix="ALTER TABLE <t> ENABLE ROW LEVEL SECURITY plus owner-bound policies (auth.uid() = owner_id), in a new migration; views get `with (security_invoker = true)` or move to a private schema; no write policy using (true) or auth.uid() is not null",
                                  detail="migrations replayed in order: a later DISABLE counts; a public view without security_invoker serves the tables' rows regardless of RLS; a write policy true for every signed-in user is the same hole as using (true)"))
            else:
                res.append(result("supabase.rls", "Row level security on every public table", "PASS", "%d table(s) created, RLS enabled on each, %d view(s) with security_invoker, in %d migration(s)" % (len(created), len(views), len(migs))))
        client_refs = ["%s:%d %s" % (r, ln, m.group(0)) for r, ln, m in walk.find(repo, PUBLIC_ADMIN, exts=walk.CODE_EXT + (".example", ".toml"), tests=False)]
        for f in (".env", ".env.local", ".env.production", ".env.example", ".dev.vars.example"):
            for i, line in enumerate(walk.read(os.path.join(repo, f)).splitlines(), 1):
                m = PUBLIC_ADMIN.search(line.split("=")[0])
                if m:
                    client_refs.append("%s:%d %s" % (f, i, m.group(0)))
        roots = spa_roots(repo)
        cfg_dirs = sorted({""} | {os.path.dirname(walk.rel(repo, p)) for p in walk.all_package_jsons(repo)})
        for d in cfg_dirs:
            for cfg in VITE_CONFIGS:
                cp = os.path.join(repo, d, cfg)
                t = walk.read_code(cp)
                m = DEFINE_INLINE.search(t)
                if m:
                    client_refs.append("%s:%d define inlines a service-role variable into the browser bundle" % (walk.rel(repo, cp), walk.line_of(t, m.end())))

        def is_browser(rel, text):
            if rel.endswith(HTML_EXT) or USE_CLIENT.search(text):
                return True  # an HTML page (or a template rendered into one) is what the browser receives
            if _in_spa_src(rel, roots):
                return not SPA_SERVER_PATH.search(rel)
            if SERVER_PATH.search(rel):
                return False
            return bool(CLIENT_PATH.search(rel))

        client_files = set()
        for p in walk.files(repo, exts=walk.CODE_EXT + (".htm",), tests=False):
            r = walk.rel(repo, p)
            if r.endswith(".py"):
                continue  # Python never runs in a browser
            t = walk.read_code(p)
            browser = is_browser(r, t)
            for m in SERVICE.finditer(t):
                line = t[t.rfind("\n", 0, m.start()) + 1: t.find("\n", m.end())]
                if browser or re.search(r"(?:NEXT_PUBLIC_|VITE_|PUBLIC_)\w*SERVICE", line):
                    client_refs.append("%s:%d" % (r, walk.line_of(t, m.start())))
            if browser:
                client_files.add(p)
        # one level of imports from browser code (relative or an @/ ~/ #/ alias): a shared module holding the service key ships too
        for cf in client_files:
            for imp in ALIAS_IMPORT.finditer(walk.read_code(cf)):
                target = resolve_import(repo, cf, imp.group(1))
                if target and not target.endswith(".py") and SERVICE.search(walk.read_code(target)):
                    client_refs.append("%s (imported by %s)" % (walk.rel(repo, target), walk.rel(repo, cf)))
        if client_refs:
            res.append(result("supabase.service-role", "Service-role key never in browser code", "FAIL", ledger.join_hits(sorted(set(client_refs)), 6, ", "), severity="critical",
                              fix="use the service-role key only server-side; the browser gets the anon/publishable key; rotate the service key"))
        else:
            res.append(result("supabase.service-role", "Service-role key never in browser code", "PASS", "no service-role reference in client paths, a Vite src/ bundle, a vite define, or public env names"))
    return ledger.emit(res, cannot_see=["Fly secrets actually set: `fly secrets list` (names and digests, no values)",
                                        "Supabase policies' contents and tables created outside migrations: dashboard or `supabase db dump --schema public` read by hand",
                                        "Whether Supabase Auth allows open signups: a policy `to authenticated` is only as narrow as who can sign up (Authentication, Providers)"])


if __name__ == "__main__":
    sys.exit(main())

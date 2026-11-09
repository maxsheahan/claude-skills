#!/usr/bin/env python3
"""inventory.py - map a repo's attack surface from its code.

  inventory.py REPO [--out DIR]     writes DIR/inventory.json and DIR/inventory.md
                                    (default DIR: REPO/security). Prints the JSON path.

Read-only on REPO except the output folder, and --out can point anywhere.
Every entry carries file:line. "gate" on a route is what the code shows near the
handler: "auth reference" when a sign-in or ownership call appears in the
handler (up to 40 lines, cut at the next route), else "none found" (which means look,
not "public": middleware mounted elsewhere is invisible to a line scan).
Secret NAMES are listed; values are never read.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import walk  # noqa: E402

from surface import PAID_HOSTS, SDK_PAID, AUTH_RX, CAP_RX, FETCH_RX, URL_HOST_RX  # noqa: E402
import surface  # noqa: E402

SECRET_NAME_RX = re.compile(r"""(?:process\.env|c\.env|env|context\.env|ctx\.env|Deno\.env\.get\(|os\.environ(?:\.get\()?)\s*[\.\[\(]?\s*['"]?([A-Z][A-Z0-9_]{2,})""")
SECRETISH = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSCODE|PRIVATE|CREDENTIAL|SALT|DSN|WEBHOOK", re.I)
STORE_RX = {
    "D1": re.compile(r"\.prepare\(|d1_databases|D1Database"),
    "KV": re.compile(r"kv_namespaces|KVNamespace"),
    "R2": re.compile(r"r2_buckets|R2Bucket"),
    "Durable Objects": re.compile(r"durable_objects|DurableObject\b"),
    "Supabase": re.compile(r"createClient\([^)]*supabase|@supabase/supabase-js|supabase\.from\("),
    "Postgres": re.compile(r"from ['\"](pg|postgres|@neondatabase/serverless)['\"]|psycopg|asyncpg"),
    "SQLite": re.compile(r"better-sqlite3|node:sqlite|sqlite3"),
    "Redis": re.compile(r"ioredis|@upstash/redis|redis\.createClient"),
    "PropertiesService": re.compile(r"PropertiesService"),
    "Google Sheets": re.compile(r"SpreadsheetApp"),
}


def detect_stack(repo):
    stack = set()
    deps = {}
    for p in walk.all_package_jsons(repo):
        try:
            deps.update(walk.deps(json.load(open(p, encoding="utf-8"))))
        except (OSError, ValueError):
            pass
    if deps:
        stack.add("node")
    if "hono" in deps:
        stack.add("hono")
    # Code that runs under Node itself (a server, a job), not only under workerd or a browser.
    node_server = {"express", "fastify", "koa", "@hono/node-server", "@nestjs/core", "@extractus/article-extractor", "node-cron", "bullmq"}
    if node_server & set(deps) or _node_start_script(repo):
        stack.add("node-runtime")
    if "next" in deps:
        stack.add("nextjs")
    if "@opennextjs/cloudflare" in deps:
        stack.add("opennext")
    if "@supabase/supabase-js" in deps or os.path.isdir(os.path.join(repo, "supabase")) or _nested_supabase(repo, depth=None) or _python_supabase(repo):
        stack.add("supabase")
    cf_files = walk.exists_any(repo, "wrangler.toml", "wrangler.jsonc", "wrangler.json", "_headers", "public/_headers", "functions")
    if cf_files or "wrangler" in deps:
        stack.add("cloudflare")
    # A monorepo keeps one fly or railway config per service folder: any depth, not only the root, and
    # whatever the folder is called (a load-test service under tests/ deploys too). Named fly configs
    # (fly.production.toml, used with `fly deploy -c`) count. A sample under docs/ or examples/ does not.
    if _deploy_configs(repo, FLY_CONFIG):
        stack.add("fly")
    if _deploy_configs(repo, RAILWAY_CONFIG):
        stack.add("railway")
    if walk.exists_any(repo, "appsscript.json", ".clasp.json") or list(walk.files(repo, exts=("appsscript.json",))):
        stack.add("google-apps-script")
    if walk.exists_any(repo, "pyproject.toml", "requirements.txt"):
        stack.add("python")
    if os.path.isdir(os.path.join(repo, ".github", "workflows")):
        stack.add("github-actions")
    return sorted(stack), deps


FLY_CONFIG = re.compile(r"^fly(?:\.[\w-]+)?\.toml$")
RAILWAY_CONFIG = re.compile(r"^railway\.(?:json|toml)$")
# Documentation and sample folders: a config there illustrates, it does not deploy.
SAMPLE_PATH = re.compile(r"(^|/)(docs?|examples?|samples?|fixtures?|__fixtures__)/")


def _deploy_configs(repo, name_rx):
    """Repo-relative paths of deploy configs named like name_rx, at any depth, outside sample folders."""
    out = []
    for p in walk.files(repo, exts=(), tests=True):
        r = walk.rel(repo, p)
        if name_rx.match(os.path.basename(p)) and not SAMPLE_PATH.search(r):
            out.append(r)
    return out


def _nested_supabase(repo, depth=2):
    """A supabase/ project folder (config.toml, migrations/ or functions/) up to `depth` levels down
    (depth None: any depth), outside documentation and sample folders."""
    base = os.path.abspath(repo)
    for root, dirs, names in os.walk(base):
        rel = os.path.relpath(root, base)
        level = 0 if rel == "." else rel.count(os.sep) + 1  # the folder that CONTAINS supabase/
        dirs[:] = [d for d in dirs if d not in walk.SKIP_DIRS and not d.startswith(".")]
        if "supabase" in dirs and level >= 1 and not SAMPLE_PATH.search(walk.rel(base, os.path.join(root, "supabase")) + "/"):
            sd = os.path.join(root, "supabase")
            if os.path.isfile(os.path.join(sd, "config.toml")) or any(os.path.isdir(os.path.join(sd, m)) for m in ("migrations", "functions")):
                return True
        if depth is not None and level >= depth:
            dirs[:] = []
    return False


def _python_supabase(repo):
    """The Python client: supabase in a requirements/pyproject manifest, or imported in code."""
    for p in walk.files(repo, exts=("requirements.txt", "pyproject.toml", "Pipfile"), tests=False):
        if re.search(r"""^\s*["']?supabase(?:-py)?\b""", walk.read(p), re.M | re.I):
            return True
    return any(walk.find(repo, r"^\s*(?:from\s+supabase(?:\.\w+)*\s+import|import\s+supabase\b)", exts=(".py",), tests=False, flags=re.M))


def _node_start_script(repo):
    for p in walk.all_package_jsons(repo):
        try:
            pj = json.load(open(p, encoding="utf-8"))
            scripts = (pj.get("scripts") or {}) if isinstance(pj, dict) else {}
        except (OSError, ValueError):
            continue
        for k in ("start", "serve", "ingest", "worker", "job"):
            if re.search(r"(?:^|\s)(?:node|tsx|ts-node)\s", scripts.get(k, "")):
                return True
    return False


def routes(repo):
    return [{"method": h["method"], "path": h["path"], "at": "%s:%d" % (h["file"], h["line"]),
             "gate": "auth reference" if AUTH_RX.search(h["body"]) else "none found"} for h in surface.handlers(repo)]


def secrets_read(repo):
    seen = {}
    for r, ln, m in walk.find(repo, SECRET_NAME_RX, tests=False):
        name = m.group(1)
        if SECRETISH.search(name):
            seen.setdefault(name, []).append("%s:%d" % (r, ln))
    for cfg in ("wrangler.toml", ".dev.vars.example", ".env.example", "fly.toml"):
        p = os.path.join(repo, cfg)
        for i, line in enumerate(walk.read(p).splitlines(), 1):
            mm = re.match(r"\s*([A-Z][A-Z0-9_]{2,})\s*=", line)
            if mm and SECRETISH.search(mm.group(1)):
                seen.setdefault(mm.group(1), []).append("%s:%d" % (cfg, i))
    return [{"name": k, "read_at": v[:6], "count": len(v)} for k, v in sorted(seen.items())]


def outbound(repo):
    out = []
    for r, ln, m in walk.find(repo, FETCH_RX, tests=False):
        arg = m.group(1).strip()
        host = URL_HOST_RX.search(arg)
        if arg[:1] in "'\"" and host:
            kind = "constant"
        elif arg.startswith("`") and host:
            kind = "template with fixed host"
        else:
            kind = "variable"
        h = host.group(1) if host else None
        out.append({"at": "%s:%d" % (r, ln), "kind": kind, "host": h, "paid": PAID_HOSTS.get(h) if h else None})
    return out


def paid_apis(repo, deps, fetches):
    found = {}
    for f in fetches:
        if f["paid"]:
            found.setdefault(f["paid"], []).append(f["at"])
    for host, prov in PAID_HOSTS.items():
        for r, ln, _ in walk.find(repo, re.escape(host), tests=False):
            found.setdefault(prov, [])
            if not any(a.startswith(r + ":") for a in found[prov]):
                found[prov].append("%s:%d" % (r, ln))
    for pkg, prov in SDK_PAID.items():
        if pkg in deps:
            found.setdefault(prov, []).append("package.json: %s" % pkg)
    out = []
    for prov, sites in sorted(found.items()):
        files = {s.split(":")[0] for s in sites if not s.startswith("package.json")}
        caps = []
        for f in files:
            t = walk.read(os.path.join(repo, f))
            for m in CAP_RX.finditer(t):
                caps.append("%s:%d" % (f, walk.line_of(t, m.start())))
        out.append({"provider": prov, "call_sites": sites[:10], "spend_cap_reference": caps[:5] or None})
    return out


def stores(repo):
    out = {}
    for name, rx in STORE_RX.items():
        for r, ln, _ in walk.find(repo, rx, exts=walk.CODE_EXT + (".toml", ".json", ".jsonc"), tests=False):
            out.setdefault(name, []).append("%s:%d" % (r, ln))
    return [{"store": k, "at": v[:5], "count": len(v)} for k, v in sorted(out.items())]


def deploy_targets(repo):
    out = []
    for f in ("wrangler.toml", "wrangler.jsonc", "wrangler.json"):
        t = walk.read(os.path.join(repo, f))
        if t:
            name = re.search(r"""["']?name["']?\s*[=:]\s*["']([^"']+)""", t)
            kind = "Cloudflare Pages" if "pages_build_output_dir" in t else "Cloudflare Worker"
            out.append({"target": kind, "name": name.group(1) if name else None, "config": f})
    if walk.exists_any(repo, "fly.toml"):
        app = re.search(r"""^app\s*=\s*["']([^"']+)""", walk.read(os.path.join(repo, "fly.toml")), re.M)
        out.append({"target": "Fly.io", "name": app.group(1) if app else None, "config": "fly.toml"})
    for f in ("railway.json", "railway.toml"):
        if walk.exists_any(repo, f):
            out.append({"target": "Railway", "name": None, "config": f})
    if walk.exists_any(repo, ".clasp.json"):
        out.append({"target": "Google Apps Script", "name": None, "config": ".clasp.json"})
    for f in ("vercel.json", "netlify.toml"):
        if walk.exists_any(repo, f):
            out.append({"target": f.split(".")[0].title(), "name": None, "config": f})
    wf = os.path.join(repo, ".github", "workflows")
    if os.path.isdir(wf):
        for n in sorted(os.listdir(wf)):
            t = walk.read(os.path.join(wf, n))
            if re.search(r"wrangler|pages deploy|flyctl|railway up|clasp push|vercel", t):
                out.append({"target": "CI deploy", "name": n, "config": ".github/workflows/" + n})
    return out


def build(repo):
    stack, deps = detect_stack(repo)
    fetches = outbound(repo)
    rts = routes(repo)
    return {
        "repo": os.path.abspath(repo),
        "stack": stack,
        "routes": rts,
        "route_count": len(rts),
        "routes_without_auth_reference": sum(1 for r in rts if r["gate"] == "none found"),
        "outbound_fetches": fetches,
        "paid_apis": paid_apis(repo, deps, fetches),
        "secrets_read": secrets_read(repo),
        "data_stores": stores(repo),
        "deploy_targets": deploy_targets(repo),
        "auth_mechanism": auth_mechanism(repo, deps),
    }


def auth_mechanism(repo, deps):
    names = []
    for pkg in ("better-auth", "next-auth", "@auth/core", "@clerk/nextjs", "lucia", "jose", "@supabase/auth-helpers-nextjs", "@supabase/ssr", "hono/jwt"):
        if pkg in deps:
            names.append("package " + pkg)
    for label, rx in (("signed cookie", r"getSignedCookie|setSignedCookie|createHmac|crypto\.subtle\.sign"),
                      ("Cloudflare Access", r"Cf-Access-Jwt-Assertion|CF_Authorization"),
                      ("Google sign-in", r"accounts\.google\.com|oauth2\.googleapis\.com/token"),
                      ("passcode", r"passcode|PASSCODE")):
        hits = list(walk.find(repo, rx, tests=False))
        if hits:
            names.append("%s (%s:%d)" % (label, hits[0][0], hits[0][1]))
    return names


def markdown(inv):
    L = ["# Attack surface: %s" % os.path.basename(inv["repo"]), "",
         "Stack: %s" % (", ".join(inv["stack"]) or "nothing recognized"),
         "Auth: %s" % ("; ".join(inv["auth_mechanism"]) or "no sign-in mechanism found"),
         "Routes: %d (%d with no auth reference near the handler: look at those first)" % (inv["route_count"], inv["routes_without_auth_reference"]),
         "Outbound fetch sites: %d (%d with a variable URL)" % (len(inv["outbound_fetches"]), sum(1 for f in inv["outbound_fetches"] if f["kind"] == "variable")),
         "", "## Paid APIs", ""]
    for p in inv["paid_apis"]:
        L.append("- %s at %s; spend cap reference: %s" % (p["provider"], ", ".join(p["call_sites"][:3]), ", ".join(p["spend_cap_reference"]) if p["spend_cap_reference"] else "NONE FOUND"))
    L += ["", "## Secrets read (names only)", ""] + ["- %s (%d reads, first %s)" % (s["name"], s["count"], s["read_at"][0]) for s in inv["secrets_read"]]
    L += ["", "## Data stores", ""] + ["- %s (%s)" % (s["store"], s["at"][0]) for s in inv["data_stores"]]
    L += ["", "## Deploy targets", ""] + ["- %s %s (%s)" % (d["target"], d["name"] or "", d["config"]) for d in inv["deploy_targets"]]
    L += ["", "## Routes", ""] + ["- %s %s  %s  [%s]" % (r["method"], r["path"], r["at"], r["gate"]) for r in inv["routes"][:200]]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--out")
    a = ap.parse_args()
    if not os.path.isdir(a.repo):
        print("not a directory: %s" % a.repo, file=sys.stderr)
        return 2
    out = a.out or os.path.join(a.repo, "security")
    os.makedirs(out, exist_ok=True)
    inv = build(a.repo)
    p = os.path.join(out, "inventory.json")
    json.dump(inv, open(p, "w"), indent=1)
    open(os.path.join(out, "inventory.md"), "w").write(markdown(inv))
    print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())

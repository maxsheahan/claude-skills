#!/usr/bin/env python3
"""secure-platform tests: one known-bad and one known-good fixture per adapter,
plus the moved probe_headers/find_embedders cases through the live-header check."""
import http.server
import json
import os
import socket
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "secure-core", "lib"))
import testkit as T  # noqa: E402

S = os.path.join(HERE, "..", "scripts")
run = lambda script, repo, *a: T.run(os.path.join(S, script), repo, *a)

# ---------- Cloudflare ----------
bad = T.tree({
    "wrangler.toml": 'name = "app"\n[vars]\nSTRIPE_SECRET_KEY = "not-a-real-value-just-a-placeholder"\nSITE_NAME = "x"\n[[d1_databases]]\nbinding = "DB"\ndatabase_id = "prod-123"\n[env.preview]\n[[env.preview.d1_databases]]\nbinding = "DB"\ndatabase_id = "prod-123"\n',
    "public/_headers": "/api/*\n  X-Content-Type-Options: nosniff\n",
    "src/index.ts": "export default { fetch() { return new Response('ok') } }\n",
})
rc, c, out = run("check_cloudflare.py", bad)
for cid in ("cf.headers.framing", "cf.headers.hsts", "cf.headers.nosniff", "cf.headers.referrer", "cf.vars-secrets", "cf.env-bindings"):
    T.status_is("cf bad", c, cid, "FAIL", out)
T.expect("cf: a header only on /api/* does not count for every path", c.get("cf.headers.nosniff", {}).get("status") == "FAIL")
T.expect("cf: cannot_see lists zone rules and the pages.dev alias", "pages.dev" in out and "zone rules" in out.lower())
good = T.tree({
    "wrangler.toml": 'name = "app"\n[vars]\nSITE_NAME = "x"\n[[d1_databases]]\nbinding = "DB"\ndatabase_id = "prod-123"\n[env.preview]\n[[env.preview.d1_databases]]\nbinding = "DB"\ndatabase_id = "preview-456"\n',
    "public/_headers": "/*\n  Content-Security-Policy: frame-ancestors 'self' https://example.com\n  Strict-Transport-Security: max-age=31536000\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n",
})
rc, c, out = run("check_cloudflare.py", good)
T.expect("cf good: all PASS", rc == 0 and len(c) == 6 and all(v["status"] == "PASS" for v in c.values()), out[-500:])
hono = T.tree({"wrangler.toml": 'name = "w"\n', "src/index.ts": "import { secureHeaders } from 'hono/secure-headers'\napp.use(secureHeaders())\n"})
rc, c, out = run("check_cloudflare.py", hono)
T.status_is("hono secureHeaders", c, "cf.headers.framing", "PASS", out)

# ---------- live headers (probe_headers.sh against a local server) ----------
class H(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        if self.path.startswith("/good"):
            for k, v in [("Content-Security-Policy", "frame-ancestors 'self'"), ("Strict-Transport-Security", "max-age=31536000"),
                         ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")]:
                self.send_header(k, v)
        self.end_headers()
    def do_GET(self):
        if self.path == "/" and self.server.redirects:
            self.send_response(301)
            self.send_header("Location", "https://127.0.0.1:%d/" % self.server.server_address[1])
            self.end_headers()
            return
        self.do_HEAD()
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
srv.redirects = False
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
rc, c, out = run("check_live_headers.py", good, "--url", "http://127.0.0.1:%d/bad" % port)
T.status_is("live bad", c, "live.127.0.0.1:%d.https-redirect" % port, "FAIL", out)
T.status_is("live bad", c, "live.127.0.0.1:%d.framing" % port, "FAIL", out)
T.status_is("live bad", c, "live.127.0.0.1:%d.hsts" % port, "FAIL", out)
srv.redirects = True
rc, c, out = run("check_live_headers.py", good, "--url", "http://127.0.0.1:%d/good" % port)
T.status_is("live good", c, "live.127.0.0.1:%d.https-redirect" % port, "PASS", out)
T.status_is("live good", c, "live.127.0.0.1:%d.framing" % port, "PASS", out)
T.status_is("live good", c, "live.127.0.0.1:%d.referrer" % port, "PASS", out)
srv.shutdown()
s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
rc, c, out = run("check_live_headers.py", good, "--url", "http://127.0.0.1:%d/" % dead)
T.status_is("live no answer", c, "live.127.0.0.1:%d" % dead, "UNKNOWN", out)

# ---------- Next.js ----------
bad = T.tree({
    "package.json": json.dumps({"dependencies": {"next": "16.2.10"}}),
    "next.config.mjs": "export default { output: 'export', async headers() { return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }] } }\n",
    "app/actions.ts": "'use server'\nexport async function deleteWalk(id: string) {\n  await db.delete(walks).where(eq(walks.id, id))\n}\n",
    ".env.example": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n",
})
rc, c, out = run("check_nextjs.py", bad)
T.status_is("next bad", c, "next.public-env-secrets", "FAIL", out)
T.status_is("next bad", c, "next.static-export-headers", "FAIL", out)
bad_sa = T.tree({"next.config.ts": "export default {}\n", "app/actions.ts": "'use server'\nexport async function deleteWalk(id: string) {\n  await db.delete(walks).where(eq(walks.id, id))\n}\n"})
rc, c, out = run("check_nextjs.py", bad_sa)
T.status_is("next bad", c, "next.server-actions", "FAIL", out)
good = T.tree({
    "next.config.ts": "export default {}\n",
    "app/actions.ts": "'use server'\nexport async function deleteWalk(id: string) {\n  const user = await requireUser()\n  await db.delete(walks).where(and(eq(walks.id, id), eq(walks.ownerId, user.id)))\n}\n",
    ".env.example": "NEXT_PUBLIC_SUPABASE_ANON_KEY=\n",
})
rc, c, out = run("check_nextjs.py", good)
T.status_is("next good", c, "next.server-actions", "PASS", out)
T.status_is("next good", c, "next.public-env-secrets", "PASS", out)
static_ok = T.tree({"next.config.mjs": "export default { output: 'export', async headers() { return [] } }\n", "public/_headers": "/*\n  X-Frame-Options: DENY\n"})
rc, c, out = run("check_nextjs.py", static_ok)
T.status_is("next static export with _headers", c, "next.static-export-headers", "PASS", out)

# ---------- Fly + Supabase ----------
bad = T.tree({
    "fly.toml": 'app = "bot"\n[env]\n  LOG_LEVEL = "info"\n  SUPABASE_SERVICE_KEY = "x"\n[http_service]\n  force_https = false\n[[services]]\n  internal_port = 5432\n  [[services.ports]]\n    port = 5432\n',
    "infra/supabase/migrations/001.sql": "create table public.trades (id int);\ncreate table picks (id int);\nalter table public.trades enable row level security;\n",
    "src/components/Admin.tsx": "'use client'\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY\n",
})
rc, c, out = run("check_fly_supabase.py", bad)
for cid in ("fly.env-secrets", "fly.exposure", "supabase.rls", "supabase.service-role"):
    T.status_is("fly/supabase bad", c, cid, "FAIL", out)
T.expect("supabase: the table without RLS is named, the one with it is not", "picks" in c.get("supabase.rls", {}).get("evidence", "") and "trades" not in c.get("supabase.rls", {}).get("evidence", ""))
good = T.tree({
    "fly.toml": 'app = "bot"\n[env]\n  LOG_LEVEL = "info"\n[http_service]\n  internal_port = 8080\n  force_https = true\n',
    "infra/supabase/migrations/001.sql": "create table public.trades (id int);\ncreate table picks (id int);\nalter table public.trades enable row level security;\nALTER TABLE picks ENABLE ROW LEVEL SECURITY;\n",
    "src/server/db.ts": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n",
})
rc, c, out = run("check_fly_supabase.py", good)
T.expect("fly/supabase good: all PASS", rc == 0 and len(c) == 4 and all(v["status"] == "PASS" for v in c.values()), out[-500:])
nomig = T.tree({"package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}}), "src/db.ts": "import { createClient } from '@supabase/supabase-js'\n"})
rc, c, out = run("check_fly_supabase.py", nomig)
T.status_is("supabase without migrations", c, "supabase.rls", "UNKNOWN", out)

# ---------- Apps Script ----------
gk = T.fake_key("google", 9)
bad = T.tree({
    "appsscript.json": json.dumps({"webapp": {"access": "ANYONE_ANONYMOUS", "executeAs": "USER_DEPLOYING"},
                                   "oauthScopes": ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/script.external_request"]}),
    "Index.html": "<script>const KEY = '%s';</script>\n" % gk,
    "Code.gs": "function doGet() { return HtmlService.createHtmlOutputFromFile('Index') }\n",
})
rc, c, out = run("check_gas.py", bad)
for cid in ("gas.webapp-access", "gas.scopes", "gas.keys-in-code"):
    T.status_is("gas bad", c, cid, "FAIL", out)
T.expect("gas: anonymous + execute-as-deployer is critical", c.get("gas.webapp-access", {}).get("severity") == "critical")
T.expect("gas: the key value is never printed", gk not in out)
good = T.tree({
    "appsscript.json": json.dumps({"webapp": {"access": "DOMAIN", "executeAs": "USER_ACCESSING"}, "oauthScopes": ["https://www.googleapis.com/auth/drive.file"]}),
    "Code.gs": "function key() { return PropertiesService.getScriptProperties().getProperty('MAPS_KEY') }\n",
})
rc, c, out = run("check_gas.py", good)
T.expect("gas good: all PASS", rc == 0 and len(c) == 3 and all(v["status"] == "PASS" for v in c.values()), out[-400:])
auto = T.tree({"appsscript.json": json.dumps({"timeZone": "America/Los_Angeles"}), "Code.gs": "function f(){}\n"})
rc, c, out = run("check_gas.py", auto)
T.status_is("gas auto-detected scopes", c, "gas.scopes", "UNKNOWN", out)

# ---------- Railway ----------
bad = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "npm run dev"}}), "src/server.js": "console.log(process.env)\n"})
rc, c, out = run("check_railway.py", bad)
T.status_is("railway bad", c, "railway.env-dump", "FAIL", out)
T.status_is("railway bad", c, "railway.config", "FAIL", out)
T.expect("railway: cannot_see gives the count-only command", "grep -c" in out)
good = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "node dist/server.js"}}), "src/server.js": "console.log(Object.keys(process.env).length)\n"})
rc, c, out = run("check_railway.py", good)
T.expect("railway good: all PASS", rc == 0 and all(v["status"] == "PASS" for v in c.values()), out[-300:])

# ---------- find_embedders (moved) ----------
site = T.tree({"index.html": '<iframe src="https://demo.example.test/"></iframe>\n', "node_modules/x.html": '<iframe src="https://demo.example.test/"></iframe>\n'})
r = subprocess.run(["bash", os.path.join(S, "find_embedders.sh"), "demo.example.test", site], capture_output=True, text=True)
T.expect("embedders: found once, node_modules skipped", r.stdout.count("index.html") == 1 and "node_modules" not in r.stdout)

# ---------- Phase 4 false-positive regressions ----------
pages = T.tree({"wrangler.app.toml": 'name = "site"\npages_build_output_dir = "out"\n',
                "public/_headers": "/*\n  Content-Security-Policy: frame-ancestors 'self'\n  Strict-Transport-Security: max-age=31536000\n",
                ".claude/worktrees/old/public/_headers": "/api/*\n  X-Frame-Options: DENY\n"})
rc, c, out = run("check_cloudflare.py", pages)
T.status_is("FP: Pages default", c, "cf.headers.nosniff", "PASS", out)
T.status_is("FP: Pages default", c, "cf.headers.referrer", "PASS", out)
T.expect("FP: _headers under a dot-folder worktree is not read", ".claude" not in out)
worker = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n', "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", worker)
T.status_is("a Worker gets no Pages default", c, "cf.headers.nosniff", "FAIL", out)
py = T.tree({"infra/supabase/migrations/001.sql": "create table t (id int);\nalter table t enable row level security;\n",
             "src/bot/db/client.py": "key = os.environ['SUPABASE_SERVICE_ROLE_KEY']\n"})
rc, c, out = run("check_fly_supabase.py", py)
T.status_is("FP: server-side Python named client.py is not browser code", c, "supabase.service-role", "PASS", out)

ci_pages = T.tree({".github/workflows/daily.yml": "jobs:\n  d:\n    steps:\n      - run: npx wrangler pages deploy dist --project-name news-app\n", "package.json": "{}"})
rc, c, out = run("check_cloudflare.py", ci_pages)
T.status_is("Pages deployed from CI also gets the default", c, "cf.headers.nosniff", "PASS", out)
T.status_is("...but framing is still the repo's job", c, "cf.headers.framing", "FAIL", out)

wk_comment = T.tree({"wrangler.toml": 'name = "coach"\nmain = "src/worker/index.ts"\n[assets]\ndirectory = "./dist"\n',
                     "scripts/deploy.sh": "#!/bin/sh\n# do NOT run `wrangler pages deploy dist` from here; this is a Worker\nnpx wrangler deploy\n"})
rc, c, out = run("check_cloudflare.py", wk_comment)
T.status_is("a Worker whose script only MENTIONS pages deploy in a comment gets no Pages default", c, "cf.headers.nosniff", "FAIL", out)

# ---------- Phase 5 audit: platform bypasses ----------
weak = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/i.ts"\n', "public/_headers": "/*\n  X-Frame-Options: ALLOWALL\n  Strict-Transport-Security: max-age=0\n",
               "src/i.ts": "// sets X-Content-Type-Options and Referrer-Policy later\nexport default {}\n"})
rc, c, out = run("check_cloudflare.py", weak)
T.status_is("audit #9: X-Frame-Options ALLOWALL does not protect", c, "cf.headers.framing", "FAIL", out)
T.status_is("audit #9: HSTS max-age=0 does not protect", c, "cf.headers.hsts", "FAIL", out)
T.status_is("audit #9: header names in a comment are not headers", c, "cf.headers.nosniff", "FAIL", out)
rls = T.tree({"supabase/migrations/001.sql": "create table public.picks (id int);\nalter table public.picks enable row level security;\n",
              "supabase/migrations/002.sql": "alter table public.picks disable row level security;\n"})
rc, c, out = run("check_fly_supabase.py", rls)
T.status_is("audit #10: RLS enabled then disabled is off", c, "supabase.rls", "FAIL", out)
pol = T.tree({"supabase/migrations/001.sql": "create table t (id int);\nalter table t enable row level security;\ncreate policy p on t for all using (true);\n"})
rc, c, out = run("check_fly_supabase.py", pol)
T.status_is("audit #10: a write policy using (true) opens the table", c, "supabase.rls", "FAIL", out)
cm = T.tree({"supabase/migrations/001.sql": "create table t (id int);\n-- alter table t enable row level security;\n"})
rc, c, out = run("check_fly_supabase.py", cm)
T.status_is("audit: a commented-out ENABLE does not count", c, "supabase.rls", "FAIL", out)
vite = T.tree({"package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}}), "supabase/migrations/1.sql": "",
               "src/lib/db.ts": "export const admin = createClient(url, import.meta.env.VITE_SUPABASE_ADMIN_KEY)\n",
               "src/App.tsx": "import { admin } from './lib/db'\n"})
rc, c, out = run("check_fly_supabase.py", vite)
T.status_is("audit #11: a VITE_ admin key ships to the browser", c, "supabase.service-role", "FAIL", out)
shared = T.tree({"supabase/migrations/1.sql": "", "src/lib/db.ts": "export const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n",
                 "src/components/Page.tsx": "import { k } from '../lib/db'\n"})
rc, c, out = run("check_fly_supabase.py", shared)
T.status_is("audit #11: a service key in a module a client component imports", c, "supabase.service-role", "FAIL", out)
import random as _r
hexkey = "%032x" % _r.Random(3).getrandbits(128)
pw = (lambda g: "".join(g.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%") for _ in range(22)))(_r.Random(4))
gk = T.tree({"appsscript.json": json.dumps({"webapp": {"access": "DOMAIN"}, "oauthScopes": []}),
             "Code.gs": "var WEATHER_KEY = '%s';\nvar DB_PASSWORD = '%s';\n" % (hexkey, pw)})
rc, c, out = run("check_gas.py", gk)
T.status_is("audit #12: an unshaped hex key and a password literal", c, "gas.keys-in-code", "FAIL", out)
T.expect("audit #12: neither value printed", hexkey not in out and pw not in out)
ign = T.git_init(T.tree({".gitignore": "appsscript.json\n", ".clasp.json": "{}", "Code.gs": "function f(){}\n"}))
open(os.path.join(ign, "appsscript.json"), "w").write(json.dumps({"webapp": {"access": "ANYONE_ANONYMOUS", "executeAs": "USER_DEPLOYING"}}))
rc, c, out = run("check_gas.py", ign)
T.status_is("audit #2: a git-ignored appsscript.json is still read", c, "gas.webapp-access", "FAIL", out)
pwd = (lambda g: "".join(g.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(22)))(_r.Random(6))
leak = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "DATABASE_URL=postgres://admin:%s@db.example.com/app node server.js" % pwd}})})
rc, c, out = run("check_railway.py", leak)
T.expect("audit #5: a password in the start command never reaches the output", pwd not in out and c.get("railway.config", {}).get("status") == "PASS", out[-300:])

# ---------- second audit: open RLS policy variants ----------
for label, pol in (("no FOR clause (defaults to ALL)", "create policy p on t to authenticated using (true);"), ("using (1=1)", "create policy p on t for update using (1=1);"),
                   ("using (true is true)", "create policy p on t for delete using (true is true);")):
    rp = T.tree({"supabase/migrations/001.sql": "create table t (id int);\nalter table t enable row level security;\n" + pol + "\n"})
    rc, c, out = run("check_fly_supabase.py", rp)
    T.status_is("audit 2: RLS %s" % label, c, "supabase.rls", "FAIL", out)
rp = T.tree({"supabase/migrations/001.sql": "create table t (id int);\nalter table t enable row level security;\ncreate policy p on t for select using (true);\n"})
rc, c, out = run("check_fly_supabase.py", rp)
T.status_is("a public-read SELECT policy using (true) is allowed", c, "supabase.rls", "PASS", out)

# ---------- Cloudflare account (API snapshot; findings Z-1 to Z-6 of the 2026-10-13 audit) ----------
import copy
ACCT = os.path.join(S, "check_cloudflare_account.py")

def zone(name, zid, **over):
    z = {"id": zid, "name": name,
         "settings": {"ssl": "strict", "min_tls_version": "1.2", "always_use_https": "on",
                      "security_header": {"strict_transport_security": {"enabled": True, "max_age": 15552000}}},
         "dnssec": {"status": "active"}, "dns_records": [{"type": "A", "name": name, "content": "192.0.2.1"}], "worker_routes": []}
    z.update(over)
    return z

GOOD_SNAP = {
    "account_id": "acct1",
    "zones": [
        zone("good.example", "z1", dns_records=[{"type": "CNAME", "name": "app.good.example", "content": "live-site.pages.dev", "proxied": True}],
             worker_routes=[{"pattern": "good.example/api/*", "script": "api-worker"}]),
        zone("empty.example", "z2", dns_records=[]),
    ],
    "pages_projects": [{"name": "live-site", "deployment_configs": {
        "production": {"env_vars": {"API_KEY": {"type": "secret_text"}, "SITE": {"type": "plain_text", "value": "x"}}, "kv_namespaces": {"KV": {"namespace_id": "kv-pages"}}},
        "preview": {"env_vars": {"API_KEY_TEST": {"type": "secret_text"}, "SITE": {"type": "plain_text", "value": "y"}}}}}],
    "members": [{"id": "m1", "status": "accepted", "user": {"email": "owner@example.com", "two_factor_authentication_enabled": True}}],
    "kv_namespaces": [{"id": "kv-pages", "title": "SITE_KV"}, {"id": "kv-api", "title": "API_CACHE"}],
    "workers": [
        {"id": "api-worker", "subdomain": {"enabled": True, "previews_enabled": False},
         "settings": {"bindings": [{"type": "kv_namespace", "name": "CACHE", "namespace_id": "kv-api"}, {"type": "secret_text", "name": "API_KEY"}]}},
        {"id": "static-site", "subdomain": {"enabled": True}, "settings": {"bindings": [{"type": "assets", "name": "ASSETS"}]}},
    ],
    "worker_domains": [],
    "errors": [],
}
BAD_SNAP = copy.deepcopy(GOOD_SNAP)
BAD_SNAP["zones"][0]["settings"] = {"ssl": "full", "min_tls_version": "1.0", "always_use_https": "off", "security_header": {"strict_transport_security": {"enabled": False}}}
BAD_SNAP["zones"][0]["dnssec"] = {"status": "disabled"}
BAD_SNAP["zones"][0]["dns_records"].append({"type": "CNAME", "name": "intent.good.example", "content": "deleted-project.pages.dev", "proxied": True})
BAD_SNAP["members"][0]["user"]["two_factor_authentication_enabled"] = False
BAD_SNAP["pages_projects"][0]["deployment_configs"]["preview"]["env_vars"] = {"API_KEY": {"type": "secret_text"}, "SITE": {"type": "plain_text", "value": "y"}}
BAD_SNAP["kv_namespaces"].append({"id": "kv-orphan", "title": "CACHE_preview"})
BAD_SNAP["workers"].append({"id": "ledger-api", "subdomain": {"enabled": True}, "settings": {"bindings": [{"type": "d1", "name": "DB", "id": "d1-1"}]}})
BAD_SNAP["zones"].append({"id": "z3", "name": "unread.example", "settings": None, "dnssec": None, "dns_records": None, "worker_routes": None})
BAD_SNAP["errors"] = [{"call": "zone_settings:unread.example", "code": 9109, "message": "Unauthorized"},
                      {"call": "dnssec:unread.example", "code": 10000, "message": "Authentication error"},
                      {"call": "dns_records:unread.example", "code": 9109, "message": "Unauthorized"}]

def snap_run(snap):
    d = T.tree({"account.json": json.dumps(snap)})
    r = subprocess.run([sys.executable, ACCT, "--snapshot", os.path.join(d, "account.json")], capture_output=True, text=True)
    try:
        checks = {c["id"]: c for c in json.loads(r.stdout)["checks"]}
    except (ValueError, KeyError):
        checks = {}
    cov = os.environ.get("SL_COVERAGE")
    if cov:
        with open(cov, "a") as fh:
            for c in checks.values():
                fh.write("check_cloudflare_account.py\t%s\t%s\n" % (c["id"], c["status"]))
    return r.returncode, checks, r.stdout + r.stderr

rc, c, out = snap_run(BAD_SNAP)
for cid, sev in (("cfacct.ssl.good-example", "medium"), ("cfacct.tls.good-example", "low"), ("cfacct.https.good-example", "medium"), ("cfacct.hsts.good-example", "low"),
                 ("cfacct.dnssec.good-example", "low"), ("cfacct.dangling-cname", "high"), ("cfacct.members-2fa", "high"), ("cfacct.pages-preview-secrets", "medium"),
                 ("cfacct.kv-orphans", "info"), ("cfacct.workers-dev-exposed", "medium")):
    T.expect("account bad: %s FAILs %s" % (cid, sev), c.get(cid, {}).get("status") == "FAIL" and c[cid].get("severity") == sev, "%s; %s" % (c.get(cid), out[-200:]))
T.expect("account bad: the dangling CNAME names the record and the missing project", "intent.good.example" in c.get("cfacct.dangling-cname", {}).get("evidence", "") and "deleted-project" in c["cfacct.dangling-cname"]["evidence"])
T.expect("account bad: the preview-secret FAIL names the project and the secret NAME only", "live-site: API_KEY" in c.get("cfacct.pages-preview-secrets", {}).get("evidence", ""))
T.expect("account bad: the exposed Worker names its binding kinds", "ledger-api (d1)" in c.get("cfacct.workers-dev-exposed", {}).get("evidence", ""))
T.expect("account bad: an orphan KV is listed by title", "CACHE_preview" in c.get("cfacct.kv-orphans", {}).get("evidence", ""))
for cid in ("cfacct.ssl.unread-example", "cfacct.hsts.unread-example", "cfacct.dnssec.unread-example"):
    r = c.get(cid, {})
    T.expect("account bad: %s is UNKNOWN naming the permission" % cid, r.get("status") == "UNKNOWN" and ("Zone Settings: Read" in r.get("reason", "") or "DNS: Read" in r.get("reason", "")), str(r))
T.expect("account bad: a 10000 error is UNKNOWN too", "10000" in c.get("cfacct.dnssec.unread-example", {}).get("reason", ""))
T.expect("account bad: exit 1", rc == 1, str(rc))

rc, c, out = snap_run(GOOD_SNAP)
T.expect("account good: every check PASS, exit 0", rc == 0 and c and all(v["status"] == "PASS" for v in c.values()), "%s %s" % (rc, {k: v["status"] for k, v in c.items()}))
T.expect("account good: an empty zone's HSTS is PASS with an info detail", c.get("cfacct.hsts.empty-example", {}).get("status") == "PASS" and "info" in c["cfacct.hsts.empty-example"].get("detail", ""))
T.expect("account good: a routed data Worker and a bindingless static Worker are not exposed", c.get("cfacct.workers-dev-exposed", {}).get("status") == "PASS")
T.expect("account good: cannot_see names Access and the token inventory", "Access" in out and "token" in out)

nomember = copy.deepcopy(GOOD_SNAP); nomember["members"] = None; nomember["errors"] = [{"call": "members", "code": 9109, "message": "Unauthorized"}]
rc, c, out = snap_run(nomember)
T.expect("account: an unreadable member list is UNKNOWN with Account Settings: Read, never PASS", c.get("cfacct.members-2fa", {}).get("status") == "UNKNOWN" and "Account Settings: Read" in c["cfacct.members-2fa"]["reason"] and rc == 3, str(c.get("cfacct.members-2fa")))
nopages = copy.deepcopy(GOOD_SNAP); nopages["pages_projects"] = None; nopages["errors"] = [{"call": "pages_projects", "code": 9109, "message": "Unauthorized"}]
rc, c, out = snap_run(nopages)
T.expect("account: a CNAME with an unreadable project list is UNKNOWN (Cloudflare Pages: Read), not PASS", c.get("cfacct.dangling-cname", {}).get("status") == "UNKNOWN" and "Cloudflare Pages: Read" in c["cfacct.dangling-cname"]["reason"], str(c.get("cfacct.dangling-cname")))
no_token_env = {k: v for k, v in os.environ.items() if k != "CLOUDFLARE_API_TOKEN"}
r = subprocess.run([sys.executable, ACCT], capture_output=True, text=True, env=no_token_env)
T.expect("account: no token and no snapshot is UNKNOWN (exit 3), never a pass", r.returncode == 3 and '"cfacct.token"' in r.stdout and "UNKNOWN" in r.stdout, r.stdout[-200:])

# fetch mode against a local mock of the API: pagination, an unauthorized call, the token never written
class CF(http.server.BaseHTTPRequestHandler):
    seen = []
    def do_GET(self):
        CF.seen.append(self.path)
        p = self.path.split("?")[0]
        q = dict(x.split("=") for x in self.path.split("?")[1].split("&")) if "?" in self.path else {}
        if "Bearer " not in self.headers.get("Authorization", ""):
            body = {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}; code = 400
        elif p == "/client/v4/accounts":
            body = {"success": True, "result": [{"id": "acct1"}], "result_info": {"page": 1, "total_pages": 1}}; code = 200
        elif p == "/client/v4/zones":
            page = int(q.get("page", "1"))
            body = {"success": True, "result": [{"id": "z%d" % page, "name": "zone%d.example" % page}], "result_info": {"page": page, "total_pages": 2}}; code = 200
        elif p.endswith("/settings") and "/zones/" in p:
            body = {"success": True, "result": [{"id": "ssl", "value": "strict"}, {"id": "min_tls_version", "value": "1.2"}, {"id": "always_use_https", "value": "on"},
                                                 {"id": "security_header", "value": {"strict_transport_security": {"enabled": True}}}]}; code = 200
        elif p.endswith("/dnssec"):
            body = {"success": True, "result": {"status": "active"}}; code = 200
        elif p.endswith("/dns_records"):
            body = {"success": True, "result": [{"type": "A", "name": "x", "content": "192.0.2.1"}], "result_info": {"page": 1, "total_pages": 1}}; code = 200
        elif p.endswith("/workers/routes"):
            body = {"success": True, "result": []}; code = 200
        elif p.endswith("/members"):
            body = {"success": False, "errors": [{"code": 9109, "message": "Unauthorized to access requested resource"}]}; code = 403
        elif p.endswith("/pages/projects"):
            body = {"success": True, "result": [], "result_info": {"page": 1, "total_pages": 1}}; code = 200
        elif p.endswith("/storage/kv/namespaces"):
            body = {"success": True, "result": [], "result_info": {"page": 1, "total_pages": 1}}; code = 200
        elif p.endswith("/workers/scripts"):
            body = {"success": True, "result": [{"id": "w1"}]}; code = 200
        elif p.endswith("/subdomain"):
            body = {"success": True, "result": {"enabled": False}}; code = 200
        elif p.endswith("/w1/settings"):
            body = {"success": True, "result": {"bindings": []}}; code = 200
        elif p.endswith("/workers/domains"):
            body = {"success": True, "result": []}; code = 200
        else:
            body = {"success": False, "errors": [{"code": 7003, "message": "no route"}]}; code = 404
        data = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        CF.seen.append("POST " + self.path); self.send_response(405); self.end_headers()
    def log_message(self, *a): pass
cf = http.server.HTTPServer(("127.0.0.1", 0), CF)
threading.Thread(target=cf.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d/client/v4" % cf.server_address[1]
FAKE_TOKEN = "fixture-token-" + T.fake_key("github", 5)[4:30]   # a throwaway string, never a real credential
outd = T.tree({})
fetch_env = dict(os.environ, CLOUDFLARE_API_TOKEN=FAKE_TOKEN, CLOUDFLARE_API_BASE=base)
r = subprocess.run([sys.executable, ACCT, "fetch", "--out", os.path.join(outd, "snap.json")], capture_output=True, text=True, env=fetch_env)
snap_txt = open(os.path.join(outd, "snap.json")).read() if os.path.exists(os.path.join(outd, "snap.json")) else ""
T.expect("fetch: writes the snapshot and exits 3 on an unauthorized call", r.returncode == 3 and snap_txt, r.stdout + r.stderr[-200:])
T.expect("fetch: names the unauthorized call and its permission", "unauthorized: members" in r.stdout and "Account Settings: Read" in r.stdout, r.stdout)
T.expect("fetch: follows pagination (two zone pages)", '"zone2.example"' in snap_txt, snap_txt[:300])
T.expect("fetch: the token value is in no output", FAKE_TOKEN not in snap_txt and FAKE_TOKEN not in r.stdout + r.stderr)
T.expect("fetch: only GETs were issued", not any(s.startswith("POST") for s in CF.seen), str(CF.seen[:5]))
rc, c, out = snap_run(json.loads(snap_txt))
T.expect("fetch then judge: zone checks PASS and members is UNKNOWN", c.get("cfacct.ssl.zone1-example", {}).get("status") == "PASS" and c.get("cfacct.members-2fa", {}).get("status") == "UNKNOWN", {k: v["status"] for k, v in c.items()})
# An API base that is not Cloudflare or a 127.0.0.1 test server never receives the token (Semgrep dynamic-urllib, secure-launch#1).
for _bad in ("http://cloudflare.example.test/client/v4", "file:///etc/passwd", "http://localhost.evil.test:%d/client/v4" % cf.server_address[1]):
    CF.seen.clear()
    r = subprocess.run([sys.executable, ACCT, "fetch", "--out", os.path.join(outd, "bad.json")], capture_output=True, text=True,
                       env=dict(fetch_env, CLOUDFLARE_API_BASE=_bad))
    T.expect("fetch: refuses API base %s" % _bad, r.returncode != 0 and "refused" in (r.stdout + r.stderr) and not CF.seen, r.stdout[-300:] + r.stderr[-200:])
cf.shutdown()

# --- Phase 8: cloudflare / nextjs regressions ---
# Each former bench known_miss (2026-11-01) as a unit fixture: the bad shape still FAILs, the decoy PASSes.
sys.path.insert(0, S)
import check_cloudflare as _cf  # noqa: E402
for _n, _want in (("STRIPE_SECRET_KEY", True), ("GITHUB_TOKEN", True), ("ANTHROPIC_API_KEY", True), ("DB_PASSWORD", True), ("SUPABASE_SERVICE_ROLE_KEY", True),
                  ("OPENAI_API_KEY", True), ("SSH_PRIVATE_KEY", True), ("SENTRY_DSN", True), ("MAPS_KEY", True),
                  ("KEYBOARD_LAYOUT", False), ("MAX_TOKENS", False), ("SESSION_TOKEN_TTL_SECONDS", False), ("TURNSTILE_SITE_KEY", False),
                  ("STRIPE_PUBLISHABLE_KEY", False), ("SUPABASE_ANON_KEY", False), ("MAPBOX_TOKEN", False), ("PUBLIC_SITE_URL", False), ("MODEL", False)):
    T.expect("secret_name(%s) is %s" % (_n, _want), _cf.secret_name(_n) is _want)
gh = T.fake_key("github", 21)
jsonc_bad = T.tree({"wrangler.jsonc": '// Worker config\n{\n  "name": "w",\n  "main": "src/index.ts",\n  "vars": {\n    "LOG_LEVEL": "info",\n    "GITHUB_TOKEN": "%s", // TODO move to a secret\n  },\n}\n' % gh,
                    "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", jsonc_bad)
T.status_is("P8 cf: JSONC with // comments and trailing commas is read", c, "cf.vars-secrets", "FAIL", out)
T.expect("P8 cf: the token value is never printed", gh not in out)
jsonc_ok = T.tree({"wrangler.jsonc": '{\n  // see the wrangler docs\n  "name": "w",\n  "main": "src/index.ts",\n  "vars": { "LOG_LEVEL": "info", "MAX_TOKENS": "1024", },\n}\n', "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", jsonc_ok)
T.status_is("P8 cf: JSONC with only config PASSes", c, "cf.vars-secrets", "PASS", out)
jsonc_broken = T.tree({"wrangler.jsonc": '{\n  "name": "w",\n  "vars": { "GITHUB_TOKEN": "x" \n', "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", jsonc_broken)
T.status_is("P8 cf: a JSONC file that does not parse is UNKNOWN, never PASS", c, "cf.vars-secrets", "UNKNOWN", out)
ak = T.fake_key("anthropic", 22)
inline = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\nvars = { MODEL = "claude-sonnet-4-5", ANTHROPIC_API_KEY = "%s" }\n' % ak, "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", inline)
T.status_is("P8 cf: a top-level inline table vars = { ... } is read", c, "cf.vars-secrets", "FAIL", out)
T.expect("P8 cf: the inline-table key value is never printed", ak not in out)
inline_env = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n[env.staging]\nvars = { STRIPE_SECRET_KEY = "placeholder-not-a-key" }\n', "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", inline_env)
T.status_is("P8 cf: an inline vars table inside [env.X] is read", c, "cf.vars-secrets", "FAIL", out)
numbers = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n[vars]\nMODEL = "claude-haiku-4-5"\nMAX_TOKENS = "1024"\nSESSION_TOKEN_TTL_SECONDS = "3600"\nKEYBOARD_LAYOUT = "qwerty"\nTURNSTILE_SITE_KEY = "1x00000000000000000000AA"\n', "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", numbers)
T.status_is("P8 cf: MAX_TOKENS, *_TTL_SECONDS, KEYBOARD_LAYOUT and a site key are config", c, "cf.vars-secrets", "PASS", out)
still_bad = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n[vars]\nGITHUB_TOKEN = "placeholder"\nDB_PASSWORD = "placeholder"\n', "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", still_bad)
T.status_is("P8 cf: TOKEN and PASSWORD suffixes still FAIL after the segment rule", c, "cf.vars-secrets", "FAIL", out)
D1 = '{"binding": "DB", "database_name": "notes", "database_id": "%s"}'
shared_json = T.tree({"wrangler.json": '{"name": "w", "main": "src/index.ts", "d1_databases": [%s], "env": {"preview": {"d1_databases": [%s]}}}' % (D1 % "74bf20f876ffc474c0251908fcdce4b3", D1 % "74bf20f876ffc474c0251908fcdce4b3"),
                      "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", shared_json)
T.status_is("P8 cf: env binding reuse is read from wrangler.json", c, "cf.env-bindings", "FAIL", out)
own_json = T.tree({"wrangler.json": '{"name": "w", "main": "src/index.ts", "d1_databases": [%s], "env": {"preview": {"d1_databases": [%s]}}}' % (D1 % "74bf20f876ffc474c0251908fcdce4b3", D1 % "0a1b2c3d4e5f60718293a4b5c6d7e8f9"),
                   "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", own_json)
T.status_is("P8 cf: separate ids in wrangler.json PASS", c, "cf.env-bindings", "PASS", out)
prev_id = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n[[kv_namespaces]]\nbinding = "CACHE"\nid = "793cf4220c917b853860886599b2ac75"\npreview_id = "8b0e7153bf7c3706d85c524e44006655"\n[env.preview]\nname = "w-preview"\n[[env.preview.kv_namespaces]]\nbinding = "CACHE"\nid = "8b0e7153bf7c3706d85c524e44006655"\n',
                  "src/index.ts": "export default {}\n"})
rc, c, out = run("check_cloudflare.py", prev_id)
T.status_is("P8 cf: a preview_id is not a production id", c, "cf.env-bindings", "PASS", out)
docs = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n', "src/index.ts": "import { helpPage } from './pages/help'\nexport default { fetch: () => new Response(helpPage()) }\n",
               "src/pages/help.ts": "const H = [\n  { name: 'Strict-Transport-Security', why: 'keeps browsers on https' },\n  { name: 'X-Frame-Options', why: 'stops clickjacking' },\n]\nexport const helpPage = () => H.map((h) => `${h.name}: ${h.why}`).join('\\n')\n"})
rc, c, out = run("check_cloudflare.py", docs)
T.status_is("P8 cf: a header NAME in a docs table is not the header being set", c, "cf.headers.framing", "FAIL", out)
T.status_is("P8 cf: same for HSTS", c, "cf.headers.hsts", "FAIL", out)
setcode = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n',
                  "src/index.ts": "export default { fetch(req) {\n  const r = new Response('ok', { headers: { 'X-Content-Type-Options': 'nosniff' } })\n  r.headers.set('Strict-Transport-Security', 'max-age=31536000')\n  r.headers.append('Referrer-Policy', 'no-referrer')\n  r.headers.set('Content-Security-Policy', \"default-src 'self'; frame-ancestors 'none'\")\n  return r\n} }\n"})
rc, c, out = run("check_cloudflare.py", setcode)
for cid in ("cf.headers.framing", "cf.headers.hsts", "cf.headers.nosniff", "cf.headers.referrer"):
    T.status_is("P8 cf: a set/append call or an object key is the header being set", c, cid, "PASS", out)
csp_only = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n', "src/index.ts": "export default { fetch() { const r = new Response('ok'); r.headers.set('Content-Security-Policy', \"default-src 'self'\"); return r } }\n"})
rc, c, out = run("check_cloudflare.py", csp_only)
T.status_is("P8 cf: a CSP set in code without frame-ancestors does not protect framing", c, "cf.headers.framing", "FAIL", out)
sh_off = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n', "src/index.ts": "import { secureHeaders } from 'hono/secure-headers'\napp.use('*', secureHeaders({ xFrameOptions: false, strictTransportSecurity: false }))\n"})
rc, c, out = run("check_cloudflare.py", sh_off)
T.status_is("P8 cf: secureHeaders with xFrameOptions: false does not frame-protect", c, "cf.headers.framing", "FAIL", out)
T.status_is("P8 cf: secureHeaders with strictTransportSecurity: false sends no HSTS", c, "cf.headers.hsts", "FAIL", out)
T.status_is("P8 cf: the headers secureHeaders still sends PASS", c, "cf.headers.nosniff", "PASS", out)
T.expect("P8 cf: the FAIL names the option that switched it off", "xFrameOptions: false" in c.get("cf.headers.framing", {}).get("evidence", ""))
sh_csp = T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n', "src/index.ts": "import { secureHeaders } from 'hono/secure-headers'\napp.use('*', secureHeaders({ xFrameOptions: false, contentSecurityPolicy: { frameAncestors: [\"'self'\"] } }))\n"})
rc, c, out = run("check_cloudflare.py", sh_csp)
T.status_is("P8 cf: secureHeaders CSP frameAncestors protects framing without X-Frame-Options", c, "cf.headers.framing", "PASS", out)

PAGE = "export default async function PostPage({ params }: { params: Promise<{ id: string }> }) {\n  const { id } = await params\n  async function deletePost() {\n    'use server'\n%s    await db.delete(posts).where(eq(posts.id, Number(id)))\n    redirect('/posts')\n  }\n  return <form action={deletePost}><button>Delete</button></form>\n}\n"
closure = T.tree({"next.config.ts": "export default {}\n", "app/posts/[id]/page.tsx": PAGE % ""})
rc, c, out = run("check_nextjs.py", closure)
T.status_is("P8 next: an inline 'use server' closure in a component is an action", c, "next.server-actions", "FAIL", out)
closure_ok = T.tree({"next.config.ts": "export default {}\n", "app/posts/[id]/page.tsx": PAGE % "    const session = await getSession()\n    if (!session?.user) throw new Error('Unauthorized')\n"})
rc, c, out = run("check_nextjs.py", closure_ok)
T.status_is("P8 next: an inline closure that rejects a missing session PASSes", c, "next.server-actions", "PASS", out)
helper = T.tree({"next.config.ts": "export default {}\n", "app/actions.ts": "'use server'\nasync function toRow(id: string) {\n  return { id }\n}\nexport async function archive(id: string) {\n  const user = await requireUser()\n  await db.update(notes).set(toRow(id)).where(eq(notes.ownerId, user.id))\n}\n"})
rc, c, out = run("check_nextjs.py", helper)
T.expect("P8 next: a non-exported helper in a 'use server' file is not an action", c.get("next.server-actions", {}).get("status") == "PASS" and "1 server action" in c["next.server-actions"]["evidence"], str(c.get("next.server-actions")))
logged = T.tree({"next.config.ts": "export default {}\n", "app/invoices/actions.ts": "'use server'\nimport { getSession } from '@/lib/auth'\nexport async function deleteInvoice(id: string) {\n  const session = await getSession()\n  console.log('requested by', session?.user?.email ?? 'anonymous')\n  await db.delete(invoices).where(eq(invoices.id, id))\n}\n"})
rc, c, out = run("check_nextjs.py", logged)
T.status_is("P8 next: getSession() that is only logged does not enforce", c, "next.server-actions", "FAIL", out)
redir = T.tree({"next.config.ts": "export default {}\n", "app/invoices/actions.ts": "'use server'\nimport { getSession } from '@/lib/auth'\nimport { redirect } from 'next/navigation'\nexport async function deleteInvoice(id: string) {\n  const session = await getSession()\n  if (!session) redirect('/login')\n  await db.delete(invoices).where(and(eq(invoices.id, id), eq(invoices.ownerId, session.user.id)))\n}\n"})
rc, c, out = run("check_nextjs.py", redir)
T.status_is("P8 next: getSession() plus a redirect on null enforces", c, "next.server-actions", "PASS", out)
destr = T.tree({"next.config.ts": "export default {}\n", "app/actions.ts": "'use server'\nexport async function rename({ id, title }: { id: string; title: string }) {\n  const user = await requireUser()\n  await db.update(notes).set({ title }).where(and(eq(notes.id, id), eq(notes.ownerId, user.id)))\n}\n"})
rc, c, out = run("check_nextjs.py", destr)
T.status_is("P8 next: destructured parameters do not hide the action body", c, "next.server-actions", "PASS", out)
destr_bad = T.tree({"next.config.ts": "export default {}\n", "app/actions.ts": "'use server'\nexport async function rename({ id, title }: { id: string; title: string }) {\n  await db.update(notes).set({ title }).where(eq(notes.id, id))\n}\n"})
rc, c, out = run("check_nextjs.py", destr_bad)
T.status_is("P8 next: ...and an unguarded destructured action still FAILs", c, "next.server-actions", "FAIL", out)
apikey = T.tree({"next.config.ts": "export default {}\n", ".env.example": "NEXT_PUBLIC_OPENAI_API_KEY=\n", "app/chat/page.tsx": "'use client'\nconst k = process.env.NEXT_PUBLIC_OPENAI_API_KEY\n"})
rc, c, out = run("check_nextjs.py", apikey)
T.status_is("P8 next: NEXT_PUBLIC_*_API_KEY ships a paid key to the browser", c, "next.public-env-secrets", "FAIL", out)
pubkeys = T.tree({"next.config.ts": "export default {}\n", ".env.example": "NEXT_PUBLIC_MAPBOX_TOKEN=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\nNEXT_PUBLIC_TURNSTILE_SITE_KEY=\nNEXT_PUBLIC_SITE_URL=\n",
                  "app/map/Map.tsx": "'use client'\nmapboxgl.accessToken = process.env.NEXT_PUBLIC_MAPBOX_TOKEN!\n"})
rc, c, out = run("check_nextjs.py", pubkeys)
T.status_is("P8 next: public-by-design names (Mapbox token, anon, publishable, site key) PASS", c, "next.public-env-secrets", "PASS", out)
srk = T.tree({"next.config.ts": "export default {}\n", "lib/stripe.ts": "export const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY!)\n"})
rc, c, out = run("check_nextjs.py", srk)
T.status_is("P8 next: a SECRET_KEY under NEXT_PUBLIC_ still FAILs", c, "next.public-env-secrets", "FAIL", out)

# --- Phase 8: fly / supabase / gas / railway / account regressions ---
# Each former bench known_miss, in the bench case's shape: the bad fixture FAILs, the decoy PASSes.
# fly.exposure: the handler's protocol and the port number decide, not the substring "tls"
pg = T.tree({"fly.toml": 'app = "orders-db"\n[[services]]\n  internal_port = 5432\n  protocol = "tcp"\n  [[services.ports]]\n    handlers = ["pg_tls"]\n    port = 5432\n'})
rc, c, out = run("check_fly_supabase.py", pg)
T.status_is("P8 fly: a public 5432 with the pg_tls handler is a database port", c, "fly.exposure", "FAIL", out)
T.expect("P8 fly: the evidence names the port and the handler", "5432" in c.get("fly.exposure", {}).get("evidence", "") and "pg_tls" in c["fly.exposure"]["evidence"])
tlsonly = T.tree({"fly.toml": 'app = "q"\n[[services]]\n  internal_port = 9000\n  [[services.ports]]\n    handlers = ["tls"]\n    port = 10000\n'})
rc, c, out = run("check_fly_supabase.py", tlsonly)
T.status_is("P8 fly: a tls-only handler (TLS-terminated raw TCP) is not a web port", c, "fly.exposure", "FAIL", out)
web = T.tree({"fly.toml": 'app = "w"\n[[services]]\n  internal_port = 8080\n  protocol = "tcp"\n  [services.concurrency]\n    hard_limit = 25\n  [[services.ports]]\n    force_https = true\n    handlers = ["http"]\n    port = 80\n  [[services.ports]]\n    handlers = ["tls", "http"]\n    port = 443\n'})
rc, c, out = run("check_fly_supabase.py", web)
T.status_is("P8 fly: 80 http and 443 tls+http are web ports (a [services.concurrency] table in between does not hide them)", c, "fly.exposure", "PASS", out)
# fly.env-secrets: secret by name words or key-shaped value; public-by-design and setting names are not
pubenv = T.tree({"fly.toml": 'app = "c"\n[env]\n  SUPABASE_URL = "https://x.supabase.co"\n  SUPABASE_ANON_KEY = "public-dashboard-value"\n  TOKEN_ISSUER = "https://auth.example.com"\n  PRIVATE_KEY_PATH = "/run/keys/signing.pem"\n  KEYBOARD_LAYOUT = "qwerty"\n  SESSION_TOKEN_TTL_SECONDS = "3600"\n  TURNSTILE_SITE_KEY = "0x4AAA"\n[http_service]\n  internal_port = 8080\n  force_https = true\n'})
rc, c, out = run("check_fly_supabase.py", pubenv)
T.status_is("P8 fly: ANON_KEY, TOKEN_ISSUER, *_PATH, *_TTL_SECONDS, SITE_KEY and KEYBOARD_LAYOUT are not secrets", c, "fly.env-secrets", "PASS", out)
sk = T.fake_key("stripe", 21)
secenv = T.tree({"fly.toml": 'app = "c"\n[env]\n  SUPABASE_SERVICE_KEY = "x"\n  DATABASE_URL = "postgres://app:pw@db.internal/app"\n  BILLING_PROVIDER = "%s"\n  JWT_SECRET = "y"\n' % sk})
rc, c, out = run("check_fly_supabase.py", secenv)
ev = c.get("fly.env-secrets", {}).get("evidence", "")
T.status_is("P8 fly: SERVICE_KEY, DATABASE_URL, JWT_SECRET and a key-shaped value under an innocent name FAIL", c, "fly.env-secrets", "FAIL", out)
T.expect("P8 fly: every offending NAME is listed and no value is printed", all(n in ev for n in ("SUPABASE_SERVICE_KEY", "DATABASE_URL", "BILLING_PROVIDER", "JWT_SECRET")) and sk not in out and "pw@" not in out, ev)
# nested fly.toml (one app per service folder)
nested = T.tree({"services/api/fly.toml": 'app = "api"\n[env]\n  DATABASE_PASSWORD = "correct-horse"\n[http_service]\n  internal_port = 8080\n  force_https = true\n', "README.md": "# mono\n"})
rc, c, out = run("check_fly_supabase.py", nested)
T.status_is("P8 fly: a fly.toml under services/api/ is read, id untagged when it is the only one", c, "fly.env-secrets", "FAIL", out)
two = T.tree({"services/api/fly.toml": 'app = "api"\n[env]\n  DATABASE_PASSWORD = "x"\n', "services/web/fly.toml": 'app = "web"\n[env]\n  PORT = "8080"\n'})
rc, c, out = run("check_fly_supabase.py", two)
T.expect("P8 fly: two fly.toml files get folder-tagged ids, each judged on its own", c.get("fly.env-secrets.services_api", {}).get("status") == "FAIL" and c.get("fly.env-secrets.services_web", {}).get("status") == "PASS", sorted(c))
# supabase.rls: views, signed-in-user write policies, schema parsing
PROF = "create table public.profiles (id uuid primary key, full_name text, phone text);\nalter table public.profiles enable row level security;\ncreate policy \"own\" on public.profiles for select using (auth.uid() = id);\n"
view = T.tree({"supabase/migrations/001.sql": PROF, "supabase/migrations/002.sql": "-- directory\ncreate view public.member_directory as\n  select p.id, p.full_name, u.email from public.profiles p join auth.users u on u.id = p.id;\n"})
rc, c, out = run("check_fly_supabase.py", view)
T.status_is("P8 rls: a public view without security_invoker bypasses RLS", c, "supabase.rls", "FAIL", out)
T.expect("P8 rls: the evidence names the view", "member_directory" in c.get("supabase.rls", {}).get("evidence", ""))
view_ok = T.tree({"supabase/migrations/001.sql": PROF, "supabase/migrations/002.sql": "create or replace view public.member_directory with (security_invoker = true) as select id, full_name from public.profiles;\n"})
rc, c, out = run("check_fly_supabase.py", view_ok)
T.status_is("P8 rls: a view with security_invoker = true PASSes", c, "supabase.rls", "PASS", out)
view_alter = T.tree({"supabase/migrations/001.sql": PROF, "supabase/migrations/002.sql": "create view public.dir as select id from public.profiles;\n", "supabase/migrations/003.sql": "alter view public.dir set (security_invoker = on);\n"})
rc, c, out = run("check_fly_supabase.py", view_alter)
T.status_is("P8 rls: a later ALTER VIEW ... set (security_invoker = on) counts", c, "supabase.rls", "PASS", out)
matview = T.tree({"supabase/migrations/001.sql": PROF, "supabase/migrations/002.sql": "create materialized view public.stats as select count(*) n from public.profiles;\n"})
rc, c, out = run("check_fly_supabase.py", matview)
T.status_is("P8 rls: a public materialized view (no RLS, no invoker) FAILs", c, "supabase.rls", "FAIL", out)
POSTS = "create table public.posts (id bigint primary key, author_id uuid);\nalter table public.posts enable row level security;\n"
for label, pol in (("auth.uid() is not null on delete", "create policy \"m\" on public.posts for delete to authenticated using (auth.uid() is not null);"),
                   ("auth.role() = 'authenticated' on update", "create policy \"m\" on public.posts for update using (auth.role() = 'authenticated');"),
                   ("(select auth.uid()) is not null with check on insert", "create policy \"m\" on public.posts for insert with check ((select auth.uid()) is not null);")):
    sp = T.tree({"supabase/migrations/001.sql": POSTS + pol + "\n"})
    rc, c, out = run("check_fly_supabase.py", sp)
    T.status_is("P8 rls: a write policy %s is open to every signed-in user" % label, c, "supabase.rls", "FAIL", out)
T.expect("P8 rls: the evidence says why", "signed-in" in c.get("supabase.rls", {}).get("evidence", ""), c.get("supabase.rls"))
owner = T.tree({"supabase/migrations/001.sql": POSTS + "create policy \"m\" on public.posts for delete using (auth.uid() = author_id);\ncreate policy \"r\" on public.posts for select using (auth.uid() is not null);\ncreate policy \"w\" on public.posts for insert with check (auth.uid() = author_id and auth.uid() is not null);\n"})
rc, c, out = run("check_fly_supabase.py", owner)
T.status_is("P8 rls: owner-bound writes and a signed-in-only SELECT PASS", c, "supabase.rls", "PASS", out)
priv = T.tree({"supabase/migrations/001.sql": PROF, "supabase/migrations/002.sql": "create schema if not exists private;\ncreate table private.audit_log (id bigint primary key, actor uuid);\n-- create table public.scratch (id int);\ncreate table if not exists public.tags (id serial primary key);\nalter table public.tags enable row level security;\ncreate policy \"t\" on public.tags for select using (true);\n"})
rc, c, out = run("check_fly_supabase.py", priv)
T.status_is("P8 rls: private.audit_log is not a public table (schema parsed, no `privat`)", c, "supabase.rls", "PASS", out)
priv_bad = T.tree({"supabase/migrations/001.sql": "create table private.audit_log (id int);\ncreate table public.notes (id int);\ncreate table \"public\".\"Rooms\" (id int);\n"})
rc, c, out = run("check_fly_supabase.py", priv_bad)
ev = c.get("supabase.rls", {}).get("evidence", "")
T.expect("P8 rls: the public tables are named, the private one is not", c.get("supabase.rls", {}).get("status") == "FAIL" and "notes" in ev and "Rooms" in ev and "audit_log" not in ev, ev)
# supabase.service-role: a Vite SPA ships all of src/; define inlines; App Router pages are server components
VITE_PKG = json.dumps({"dependencies": {"@supabase/supabase-js": "2.45.0", "vite": "6.0.0", "react": "19.0.0"}})
vdef = T.tree({"package.json": VITE_PKG, "supabase/config.toml": "project_id = \"d\"\n",
               "vite.config.ts": "import { defineConfig, loadEnv } from 'vite'\nexport default defineConfig(({ mode }) => {\n  const env = loadEnv(mode, process.cwd(), '')\n  return { define: { 'process.env.SUPABASE_SERVICE_ROLE_KEY': JSON.stringify(env.SUPABASE_SERVICE_ROLE_KEY) } }\n})\n",
               "src/lib/admin.ts": "import { createClient } from '@supabase/supabase-js'\nexport const admin = createClient(import.meta.env.VITE_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n",
               "src/main.tsx": "import { admin } from './lib/admin'\n"})
rc, c, out = run("check_fly_supabase.py", vdef)
ev = c.get("supabase.service-role", {}).get("evidence", "")
T.status_is("P8 service-role: a define-inlined service key read from src/ of a Vite SPA FAILs", c, "supabase.service-role", "FAIL", out)
T.expect("P8 service-role: both the define and the src/ read are evidence", "vite.config.ts" in ev and "src/lib/admin.ts" in ev, ev)
vsrc = T.tree({"package.json": VITE_PKG, "supabase/config.toml": "project_id = \"d\"\n", "src/lib/admin.ts": "export const k = import.meta.env.SUPABASE_SERVICE_ROLE_KEY\n"})
rc, c, out = run("check_fly_supabase.py", vsrc)
T.status_is("P8 service-role: any src/ file of a Vite SPA is browser code", c, "supabase.service-role", "FAIL", out)
kit = T.tree({"package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2.45.0", "vite": "6.0.0", "@sveltejs/kit": "2.0.0"}}), "supabase/config.toml": "project_id = \"d\"\n",
              "src/lib/server/admin.ts": "export const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n", "src/routes/+page.server.ts": "const a = process.env.SUPABASE_SERVICE_ROLE_KEY\n"})
rc, c, out = run("check_fly_supabase.py", kit)
T.status_is("P8 service-role: SvelteKit keeps server files in src/ (server/ path, .server. file): not browser code", c, "supabase.service-role", "PASS", out)
rsc = T.tree({"package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2.45.0", "next": "16.2.10"}}), "supabase/migrations/001.sql": PROF,
              "app/admin/users/page.tsx": "import 'server-only'\nimport { createClient } from '@supabase/supabase-js'\nexport default async function UsersPage() {\n  const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n  return <ul />\n}\n"})
rc, c, out = run("check_fly_supabase.py", rsc)
T.status_is("P8 service-role: an App Router page.tsx without 'use client' is a Server Component", c, "supabase.service-role", "PASS", out)
csc = T.tree({"package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2.45.0", "next": "16.2.10"}}), "supabase/migrations/001.sql": PROF,
              "app/admin/users/page.tsx": "'use client'\nimport { createClient } from '@supabase/supabase-js'\nconst admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)\nexport default function P() { return <ul /> }\n"})
rc, c, out = run("check_fly_supabase.py", csc)
T.status_is("P8 service-role: the same page WITH 'use client' still FAILs", c, "supabase.service-role", "FAIL", out)
# gas.keys-in-code: clasp TypeScript sources are scanned; a Drive id called a key is not a credential
ak = T.fake_key("anthropic", 31)
ts = T.tree({".clasp.json": json.dumps({"scriptId": "s2", "rootDir": "src", "fileExtension": "ts"}),
             "src/appsscript.json": json.dumps({"webapp": {"access": "DOMAIN", "executeAs": "USER_ACCESSING"}, "oauthScopes": ["https://www.googleapis.com/auth/script.external_request"]}),
             "src/config.ts": "export const CONFIG = {\n  model: 'claude-haiku-4-5',\n  anthropicKey: '%s',\n};\n" % ak})
rc, c, out = run("check_gas.py", ts)
T.status_is("P8 gas: a key in a clasp TypeScript source FAILs", c, "gas.keys-in-code", "FAIL", out)
T.expect("P8 gas: the .ts key value is never printed", ak not in out)
import random as _r8
_g8 = _r8.Random(41)
sid = "1" + "".join(_g8.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") for _ in range(43))
sheet = T.tree({"appsscript.json": json.dumps({"webapp": {"access": "DOMAIN"}, "oauthScopes": ["https://www.googleapis.com/auth/spreadsheets"]}),
                "Code.gs": "var SPREADSHEET_KEY = '%s';\nvar ROSTER_KEY = '%s';\nfunction roster() { return SpreadsheetApp.openById(SPREADSHEET_KEY).getSheetByName('Roster'); }\nfunction other() { return DocumentApp.openById(ROSTER_KEY); }\n" % (sid, sid[::-1])})
rc, c, out = run("check_gas.py", sheet)
T.status_is("P8 gas: SPREADSHEET_KEY (Drive-object name) and ROSTER_KEY (passed to openById) are ids, not keys", c, "gas.keys-in-code", "PASS", out)
idkey = T.tree({"appsscript.json": json.dumps({"webapp": {"access": "DOMAIN"}, "oauthScopes": []}), "Code.gs": "var WEATHER_KEY = '%s';\nfunction w() { return UrlFetchApp.fetch('https://api.example.com/?k=' + WEATHER_KEY); }\n" % sid[1:40]})
rc, c, out = run("check_gas.py", idkey)
T.status_is("P8 gas: an id-shaped value under a non-Drive name sent to an API is still a key", c, "gas.keys-in-code", "FAIL", out)
# railway.env-dump: the whole environment as ANY argument or a return value; names and counts are fine
pre = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "node dist/index.js"}}), "src/index.ts": "console.log('[boot] starting with config', process.env)\n"})
rc, c, out = run("check_railway.py", pre)
T.status_is("P8 railway: console.log('prefix', process.env) is a dump", c, "railway.env-dump", "FAIL", out)
ret = T.tree({"railway.toml": "[deploy]\nstartCommand = \"uvicorn app.main:app --host 0.0.0.0 --port $PORT\"\n", "app/main.py": "import os\nfrom fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/env')\ndef env():\n    return dict(os.environ)\n"})
rc, c, out = run("check_railway.py", ret)
T.status_is("P8 railway: return dict(os.environ) is a dump", c, "railway.env-dump", "FAIL", out)
for label, code in (("res.json({ env: process.env })", "app.get('/d', (_req, res) => res.json({ ok: true, env: process.env }))\n"),
                    ("return {...process.env}", "export function cfg() {\n  return { ...process.env }\n}\n"),
                    ("console.log(JSON.stringify(process.env, null, 2))", "console.log(JSON.stringify(process.env, null, 2))\n")):
    d = T.tree({"railway.json": "{}", "src/s.ts": code})
    rc, c, out = run("check_railway.py", d)
    T.status_is("P8 railway: %s is a dump" % label, c, "railway.env-dump", "FAIL", out)
safe = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "node dist/server.js"}}),
               "src/server.ts": "console.log('env names:', Object.keys(process.env).sort().join(','))\nconsole.log('port', process.env.PORT)\nconsole.log('loaded process.env from the platform')\nconst cfg = { region: process.env.RAILWAY_REGION }\nconsole.info('cfg', cfg)\nconst env = { region: cfg.region }\nexport function getEnv() { return env }\n",
               "app/main.py": "import os\nprint('env var count', len(os.environ))\nprint('has key', 'X' in os.environ)\nsettings = {k: os.environ.get(k) for k in ('A', 'B')}\nprint('settings', settings)\n"})
rc, c, out = run("check_railway.py", safe)
T.status_is("P8 railway: names, counts, one value, a string mentioning process.env, and a helper returning its own env object are not dumps", c, "railway.env-dump", "PASS", out)
# railway.config: npm start resolved through package.json scripts; nested configs
nd = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "npm start"}}), "package.json": json.dumps({"scripts": {"dev": "next dev", "build": "next build", "start": "next dev -p $PORT"}})})
rc, c, out = run("check_railway.py", nd)
T.status_is("P8 railway: `npm start` whose start script is `next dev` FAILs", c, "railway.config", "FAIL", out)
T.expect("P8 railway: the evidence names the script it resolved through", "start" in c.get("railway.config", {}).get("evidence", "") and "next dev" in c["railway.config"]["evidence"], c.get("railway.config"))
hop = T.tree({"railway.toml": "[deploy]\nstartCommand = \"yarn start\"\n", "package.json": json.dumps({"scripts": {"start": "npm run serve", "serve": "nodemon server.js"}})})
rc, c, out = run("check_railway.py", hop)
T.status_is("P8 railway: two hops of scripts (yarn start -> npm run serve -> nodemon) FAIL", c, "railway.config", "FAIL", out)
ok = T.tree({"railway.json": json.dumps({"deploy": {"startCommand": "npm start"}}), "package.json": json.dumps({"scripts": {"dev": "next dev", "start": "next start -p $PORT"}})})
rc, c, out = run("check_railway.py", ok)
T.status_is("P8 railway: `npm start` resolving to `next start` PASSes", c, "railway.config", "PASS", out)
nest = T.tree({"package.json": json.dumps({"private": True, "workspaces": ["services/*"]}), "services/mcp/package.json": json.dumps({"scripts": {"start": "node server.js", "dev": "nodemon server.js"}}),
               "services/mcp/railway.json": json.dumps({"deploy": {"startCommand": "npm run dev"}}), "services/mcp/server.js": "const x = 1\n"})
rc, c, out = run("check_railway.py", nest)
T.status_is("P8 railway: a railway.json under services/mcp/ is read (untagged when it is the only one)", c, "railway.config", "FAIL", out)
# cfacct: pending invitee is UNKNOWN; hyperdrive is data; HSTS max_age 0 is off
pend = copy.deepcopy(GOOD_SNAP)
pend["members"].append({"id": "m2", "status": "pending", "user": {"email": "contractor@example.com"}})
rc, c, out = snap_run(pend)
T.status_is("P8 account: a member with no 2FA field (pending invite) is UNKNOWN, not PASS", c, "cfacct.members-2fa", "UNKNOWN", out)
T.expect("P8 account: the UNKNOWN names the member and the reason", "contractor@example.com" in c.get("cfacct.members-2fa", {}).get("evidence", "") and "pending" in c["cfacct.members-2fa"].get("reason", ""))
both = copy.deepcopy(pend)
both["members"][0]["user"]["two_factor_authentication_enabled"] = False
rc, c, out = snap_run(both)
T.expect("P8 account: a member with 2FA false still FAILs when another is pending, and the detail counts the pending one", c.get("cfacct.members-2fa", {}).get("status") == "FAIL" and "pending" in c["cfacct.members-2fa"].get("detail", ""), c.get("cfacct.members-2fa"))
hd = copy.deepcopy(GOOD_SNAP)
hd["workers"] = [{"id": "reports-api", "subdomain": {"enabled": True}, "settings": {"bindings": [{"type": "hyperdrive", "name": "PG", "id": "hd1"}, {"type": "plain_text", "name": "REGION", "text": "us"}]}}]
rc, c, out = snap_run(hd)
T.status_is("P8 account: a Hyperdrive binding is data; workers.dev-only FAILs", c, "cfacct.workers-dev-exposed", "FAIL", out)
T.expect("P8 account: the evidence names hyperdrive", "hyperdrive" in c.get("cfacct.workers-dev-exposed", {}).get("evidence", ""))
hz = copy.deepcopy(GOOD_SNAP)
hz["zones"][0]["settings"]["security_header"] = {"strict_transport_security": {"enabled": True, "max_age": 0, "include_subdomains": False}}
rc, c, out = snap_run(hz)
T.status_is("P8 account: HSTS enabled with max_age 0 FAILs", c, "cfacct.hsts.good-example", "FAIL", out)
T.expect("P8 account: the known-good snapshot's HSTS (max_age 15552000) still PASSes", snap_run(GOOD_SNAP)[1].get("cfacct.hsts.good-example", {}).get("status") == "PASS")


# Phase 8 follow-up: a browser Maps key is public by design (referrer-restricted); a server Maps key is not
nx_maps = T.tree({"package.json": json.dumps({"dependencies": {"next": "16.2.0"}}), "next.config.js": "module.exports = {}\n",
                  "app/map/page.tsx": "'use client'\nconst k = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY\nexport default function P() { return null }\n"})
rc, c, out = T.run(os.path.join(S, "check_nextjs.py"), nx_maps)
T.status_is("P8 maps: NEXT_PUBLIC_GOOGLE_MAPS_API_KEY is public by design", c, "next.public-env-secrets", "PASS", out)
nx_srv = T.tree({"package.json": json.dumps({"dependencies": {"next": "16.2.0"}}), "next.config.js": "module.exports = {}\n",
                 "app/map/page.tsx": "'use client'\nconst k = process.env.NEXT_PUBLIC_GOOGLE_SERVER_KEY\nexport default function P() { return null }\n"})
rc, c, out = T.run(os.path.join(S, "check_nextjs.py"), nx_srv)
T.status_is("P8 maps: a NEXT_PUBLIC_ server key still FAILs", c, "next.public-env-secrets", "FAIL", out)
T.expect("P8 maps: MAPS_KEY in a server config is still a secret", __import__("importlib").import_module("check_cloudflare").secret_name("MAPS_KEY") is True)

# ---- Phase 10 platform-b ----
# One FAIL and one PASS fixture per mechanism added in Phase 10 (check_fly_supabase.py, check_railway.py).
def _st(script, files, check):
    rc, c, out = run(script, T.tree(files))
    return c.get(check, {}).get("status"), out
SB = {"supabase/config.toml": "project_id = \"p10\"\n"}
# fly: comments are not configuration; every fly*.toml is an app config; a connection-string name with a variant word
st, out = _st("check_fly_supabase.py", {"fly.toml": 'app = "a"\n[[services]]\n  [[services.ports]]\n    port = 7000\n    # handlers = ["http"]\n'}, "fly.exposure")
T.expect("P10 fly: a commented-out handlers line is not a handler (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", {"fly.toml": 'app = "a"\n[[services]]\n  [[services.ports]]\n    handlers = ["http"]  # web\n    port = 80\n'}, "fly.exposure")
T.expect("P10 fly: a trailing comment after a live handlers line is kept (PASS)", st == "PASS", out)
st, out = _st("check_fly_supabase.py", {"fly.production.toml": 'app = "p"\n[env]\n  JWT_SECRET = "x"\n'}, "fly.env-secrets")
T.expect("P10 fly: fly.production.toml is read (FAIL)", st == "FAIL", out)
rc, c, out = run("check_fly_supabase.py", T.tree({"fly.toml": 'app = "a"\n[env]\n  PORT = "8080"\n', "fly.production.toml": 'app = "p"\n[env]\n  PORT = "8080"\n'}))
T.expect("P10 fly: fly.toml and fly.production.toml in one folder get distinct ids", {"fly.env-secrets.root", "fly.env-secrets.root_production"} <= set(c), sorted(c))
st, out = _st("check_fly_supabase.py", {"fly.toml": 'app = "a"\n[env]\n  POSTGRES_URL_NON_POOLING = "unset"\n'}, "fly.env-secrets")
T.expect("P10 fly: POSTGRES_URL_NON_POOLING is a connection string (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", {"fly.toml": 'app = "a"\n[env]\n  DB_HOST_PRIMARY = "db.internal"\n  APP_URL_STAGING = "https://s.example.com"\n'}, "fly.env-secrets")
T.expect("P10 fly: a host or a non-database URL with a variant word is not (PASS)", st == "PASS", out)
# rls: identifier folding and TEMP tables; DROP / ALTER POLICY replay; casts and the role claim; ALTER VIEW option lists; drizzle out dir
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": "CREATE TABLE Rooms (id int);\nALTER TABLE ROOMS ENABLE ROW LEVEL SECURITY;\nCREATE TEMPORARY TABLE staging_rows (id int);\n"}), "supabase.rls")
T.expect("P10 rls: unquoted names fold to lowercase and a TEMPORARY table is not public (PASS)", st == "PASS", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": 'CREATE TABLE "Rooms" (id int);\nALTER TABLE rooms ENABLE ROW LEVEL SECURITY;\n'}), "supabase.rls")
T.expect("P10 rls: a quoted mixed-case name stays distinct (FAIL)", st == "FAIL", out)
POL = "create table public.items (id int, owner uuid);\nalter table public.items enable row level security;\ncreate policy writer on public.items for update using (true);\n"
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": POL, "supabase/migrations/2.sql": "drop policy if exists writer on public.items;\n"}), "supabase.rls")
T.expect("P10 rls: a later DROP POLICY removes the open policy (PASS)", st == "PASS", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": POL.replace("using (true)", "using (auth.uid() = owner)"), "supabase/migrations/2.sql": "alter policy writer on public.items with check (1 = 1);\n"}), "supabase.rls")
T.expect("P10 rls: a later ALTER POLICY that opens the check FAILs", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": POL.replace("using (true)", "using ((auth.jwt() ->> 'role')::text = 'authenticated'::text)")}), "supabase.rls")
T.expect("P10 rls: the JWT role claim with casts is any signed-in user (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": POL.replace("using (true)", "using ((auth.jwt() ->> 'sub')::uuid = owner)")}), "supabase.rls")
T.expect("P10 rls: an owner-bound JWT claim with a cast PASSes", st == "PASS", out)
VW = "create view public.board as select 1 as n;\n"
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": VW + "alter view public.board set (check_option = local, security_invoker = on);\n"}), "supabase.rls")
T.expect("P10 rls: security_invoker inside a multi-option SET counts (PASS)", st == "PASS", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"supabase/migrations/1.sql": VW + "alter view public.board set (security_invoker = on, check_option = local);\nalter view public.board reset (security_invoker);\n"}), "supabase.rls")
T.expect("P10 rls: a later RESET (security_invoker) turns it off (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"drizzle.config.ts": "export default { out: './db/sql', dialect: 'postgresql' }\n", "db/sql/0000_x.sql": 'CREATE TABLE "items" ("id" int);\n'}), "supabase.rls")
T.expect("P10 rls: SQL in the drizzle.config out folder is a migration (FAIL, not UNKNOWN)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"drizzle.config.ts": "export default { out: './db/sql', dialect: 'postgresql' }\n", "db/sql/0000_x.sql": 'CREATE TABLE "items" ("id" int);\nALTER TABLE "items" ENABLE ROW LEVEL SECURITY;\n'}), "supabase.rls")
T.expect("P10 rls: ...and with RLS enabled there it PASSes", st == "PASS", out)
# service-role: per-package Vite SPA roots, Vite server plugins, HTML pages, alias imports
VP = json.dumps({"dependencies": {"vite": "6.0.0", "vue": "3.5.0"}})
st, out = _st("check_fly_supabase.py", dict(SB, **{"package.json": json.dumps({"private": True}), "packages/admin/package.json": VP, "packages/admin/src/workers/x.ts": "const k = SUPABASE_SERVICE_ROLE_KEY\n"}), "supabase.service-role")
T.expect("P10 service-role: a workspace Vite app's src/workers/ is its bundle (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"package.json": json.dumps({"private": True}), "packages/admin/package.json": VP, "packages/admin/src/server/x.ts": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"}), "supabase.service-role")
T.expect("P10 service-role: ...but its src/server/ is not (PASS)", st == "PASS", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"package.json": json.dumps({"dependencies": {"vite": "6.0.0", "fastify": "5.0.0"}}), "src/db.ts": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"}), "supabase.service-role")
T.expect("P10 service-role: Vite plus a server framework and no UI library is a server build (PASS)", st == "PASS", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"templates/admin.html": "<script>const k = '{{ SUPABASE_SERVICE_ROLE_KEY }}'</script>\n"}), "supabase.service-role")
T.expect("P10 service-role: an HTML page is browser code wherever it lives (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"components/Admin.tsx": "import { k } from '~/server-lib/keys'\n", "server-lib/keys.ts": "export const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"}), "supabase.service-role")
T.expect("P10 service-role: a ~/ alias import from browser code is followed (FAIL)", st == "FAIL", out)
st, out = _st("check_fly_supabase.py", dict(SB, **{"components/Admin.tsx": "import { k } from '~/server-lib/flags'\n", "server-lib/flags.ts": "export const k = true\n", "server-lib/keys.ts": "export const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"}), "supabase.service-role")
T.expect("P10 service-role: ...and a followed alias without the key PASSes", st == "PASS", out)
# railway.env-dump: aliases of the whole env, response chains, body assignment, interpolation, .items()
st, out = _st("check_railway.py", {"src/a.js": "const all = { ...process.env }\nlogger.warn('boot', all)\n"}, "railway.env-dump")
T.expect("P10 railway: a name bound to the whole env is the env (FAIL)", st == "FAIL", out)
st, out = _st("check_railway.py", {"src/a.js": "const mode = process.env.MODE\nlogger.warn('boot', mode)\n", "app.py": "from jinja2 import Environment\nenv = Environment()\nlogging.info('env %r', env)\n"}, "railway.env-dump")
T.expect("P10 railway: a name bound to one variable, or to a Jinja Environment, is not (PASS)", st == "PASS", out)
st, out = _st("check_railway.py", {"src/a.js": "app.get('/e', (q, r) => r.status(200).json(process.env))\nrouter.get('/b', (ctx) => { ctx.body = Bun.env })\n"}, "railway.env-dump")
T.expect("P10 railway: a chained response and a Koa body assignment of the env FAIL", st == "FAIL" and "src/a.js:1" in out and "src/a.js:2" in out, out)
st, out = _st("check_railway.py", {"src/a.js": "app.get('/e', (q, res) => res.status(200).json({ ok: Object.keys(process.env).length }))\nrouter.get('/b', (ctx) => { ctx.body = process.env.VERSION })\n"}, "railway.env-dump")
T.expect("P10 railway: a chained response of a count and a body of one variable PASS", st == "PASS", out)
st, out = _st("check_railway.py", {"app.py": "import os\nlogging.warning(f'cfg={dict(os.environ)}')\nprint(sorted(os.environ.values()))\n"}, "railway.env-dump")
T.expect("P10 railway: an f-string interpolating the env and sorted(os.environ.values()) FAIL", st == "FAIL" and "app.py:2" in out and "app.py:3" in out, out)
st, out = _st("check_railway.py", {"app.py": "import os\nlogging.warning(f'port={os.environ[\"PORT\"]}')\nprint(len(os.environ.items()))\n"}, "railway.env-dump")
T.expect("P10 railway: an f-string of one variable and a count of items PASS", st == "PASS", out)
# railway.config: command segments (cd, env prefixes), default start sources, dev-server vocabulary
st, out = _st("check_railway.py", {"railway.json": json.dumps({"deploy": {"startCommand": "PORT=8080 cd web && yarn start"}}), "web/package.json": json.dumps({"scripts": {"start": "ng serve --host 0.0.0.0"}})}, "railway.config")
T.expect("P10 railway: cd and an env prefix are followed into the package's start script (FAIL)", st == "FAIL", out)
st, out = _st("check_railway.py", {"railway.json": json.dumps({"deploy": {"startCommand": "cd web && NODE_ENV=production yarn start"}}), "web/package.json": json.dumps({"scripts": {"start": "node --watch-path=./x dist/main.js"}})}, "railway.config")
T.expect("P10 railway: ...and a production start script there PASSes (--watch-path is not --watch)", st == "PASS", out)
st, out = _st("check_railway.py", {"railway.toml": '[build]\nbuilder = "DOCKERFILE"\ndockerfilePath = "ops/Dockerfile"\n', "ops/Dockerfile": "FROM python:3.12\nCMD python manage.py runserver 0.0.0.0:8000\n"}, "railway.config")
T.expect("P10 railway: the CMD of the configured Dockerfile is the start command (FAIL)", st == "FAIL", out)
st, out = _st("check_railway.py", {"railway.toml": '[build]\nbuilder = "DOCKERFILE"\ndockerfilePath = "ops/Dockerfile"\n', "ops/Dockerfile": "FROM python:3.12\nCMD [\"gunicorn\", \"app.wsgi\"]\n"}, "railway.config")
T.expect("P10 railway: ...and a production CMD PASSes", st == "PASS", out)
st, out = _st("check_railway.py", {"railway.json": "{}", "Procfile": "worker: node q.js\nweb: fastapi dev main.py\n"}, "railway.config")
T.expect("P10 railway: the Procfile web process counts (FAIL)", st == "FAIL", out)
st, out = _st("check_railway.py", {"railway.json": "{}", "nixpacks.toml": "[start]\ncmd = \"fastapi run main.py\"\n", "Procfile": "web: fastapi dev main.py\n"}, "railway.config")
T.expect("P10 railway: nixpacks.toml [start] wins over the Procfile, and fastapi run is production (PASS)", st == "PASS", out)
# ---- end Phase 10 platform-b ----

# ---- Phase 10 platform-a ----
# One FAIL and one PASS fixture per mechanism introduced in Phase 10 (check_cloudflare, check_nextjs,
# check_gas, check_cloudflare_account). The audit's own fixtures become bench cases later.
_W = 'name = "w"\nmain = "src/index.ts"\n'
_IDX = "export default {}\n"
_gk = T.fake_key("github", 31)


def _pa(script, files, cid):
    rc_, c_, out_ = run(script, T.tree(files))
    return c_.get(cid, {}).get("status"), out_


st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W + 'vars.APP_ENV = "prod"\nvars.STRIPE_SECRET_KEY = "%s"\n' % _gk, "src/index.ts": _IDX}, "cf.vars-secrets")
T.expect("P10 cf vars: a TOML dotted key vars.X is a var (FAIL)", st == "FAIL", out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W + '[vars]\nAPP_ENV = "prod"\nSTRIPE_SECRET_KEY = ""\n', "src/index.ts": _IDX}, "cf.vars-secrets")
T.expect("P10 cf vars: an empty TOML placeholder holds no value (PASS)", st == "PASS", out)
st, out = _pa("check_cloudflare.py", {"wrangler.json": json.dumps({"name": "w", "main": "src/index.ts", "vars": {"openaiApiKey": _gk}}), "src/index.ts": _IDX}, "cf.vars-secrets")
T.expect("P10 cf vars: a camelCase JSON var name reads as its SNAKE twin (FAIL)", st == "FAIL", out)
_D1 = '[[d1_databases]]\nbinding = "DB"\ndatabase_id = "dev-1"\n[env.staging]\n[[env.staging.d1_databases]]\nbinding = "DB"\ndatabase_id = "%s"\n[env.production]\n[[env.production.d1_databases]]\nbinding = "DB"\ndatabase_id = "prod-1"\n'
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W + _D1 % "prod-1", "src/index.ts": _IDX}, "cf.env-bindings")
T.expect("P10 cf env: staging sharing [env.production]'s id FAILs though the top level is dev", st == "FAIL", out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W + _D1 % "staging-1", "src/index.ts": _IDX}, "cf.env-bindings")
T.expect("P10 cf env: ...its own id PASSes", st == "PASS", out)
st, out = _pa("check_cloudflare.py", {"wrangler.json": json.dumps({"name": "w", "main": "src/index.ts", "hyperdrive": [{"binding": "PG", "id": "h-1"}], "env": {"staging": {"hyperdrive": [{"binding": "PG", "id": "h-1"}]}}}), "src/index.ts": _IDX}, "cf.env-bindings")
T.expect("P10 cf env: a Hyperdrive id shared in wrangler.json FAILs", st == "FAIL", out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": "export default { fetch() { const r = new Response('ok'); r.headers.set('Strict-Transport-Security', 'max-age=0'); return r } }\n"}, "cf.headers.hsts")
T.expect("P10 cf headers: a literal value set in code is judged (max-age=0 FAILs)", st == "FAIL" and "does not protect" in out, out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": "export default { fetch() { const r = new Response('ok'); r.headers.set('Strict-Transport-Security', 'max-age=31536000'); return r } }\n"}, "cf.headers.hsts")
T.expect("P10 cf headers: ...a protective literal PASSes", st == "PASS", out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": "app.get('*', (c) => { console.log(c.req.header('X-Frame-Options')); return c.text('ok') })\n"}, "cf.headers.framing")
T.expect("P10 cf headers: a one-argument header(name) reads a request header (FAIL)", st == "FAIL", out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": "const h = {}\nh['X-Frame-Options'] = 'DENY'\nconst H = new Headers([['Referrer-Policy', 'no-referrer']])\n"}, "cf.headers.framing")
st2, out2 = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": "const h = {}\nh['X-Frame-Options'] = 'DENY'\nconst H = new Headers([['Referrer-Policy', 'no-referrer']])\n"}, "cf.headers.referrer")
T.expect("P10 cf headers: a subscript assignment and a [name, value] pair set a header (PASS)", st == "PASS" and st2 == "PASS", out + out2)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": "export const WHY = { 'Referrer-Policy': 'limits referrer leaks' }\n"}, "cf.headers.referrer")
T.expect("P10 cf headers: prose is not a Referrer-Policy value (FAIL)", st == "FAIL", out)
_SH = "import { secureHeaders } from 'hono/secure-headers'\napp.use(%s, secureHeaders())\n"
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": _SH % "'/api/*'"}, "cf.headers.hsts")
T.expect("P10 cf headers: secureHeaders() mounted on /api/* only does not cover the pages (FAIL)", st == "FAIL" and "mounted on /api/* only" in out, out)
st, out = _pa("check_cloudflare.py", {"wrangler.toml": _W, "src/index.ts": _SH % "'*'"}, "cf.headers.hsts")
T.expect("P10 cf headers: ...mounted on * it does (PASS)", st == "PASS", out)

_NX = {"next.config.ts": "export default {}\n"}
st, out = _pa("check_nextjs.py", dict(_NX, **{"app/a.ts": "'use server'\nasync function wipe(id: string) {\n  await db.delete(t).where(eq(t.id, id))\n}\nexport { wipe as remove }\n"}), "next.server-actions")
T.expect("P10 next: a function exported through an export list is an action (FAIL)", st == "FAIL", out)
st, out = _pa("check_nextjs.py", dict(_NX, **{"app/a.ts": "'use server'\nexport async function wipe(id: string) {\n  const s = await getSession()\n  if (!s) console.warn('no session')\n  await db.delete(t).where(eq(t.id, id))\n}\n"}), "next.server-actions")
T.expect("P10 next: a session null test whose consequent only logs does not enforce (FAIL)", st == "FAIL", out)
st, out = _pa("check_nextjs.py", dict(_NX, **{"app/a.ts": "'use server'\nexport async function wipe(id: string) {\n  if (!id) throw new Error('id')\n  const session = await getSession()\n  await db.delete(t).where(eq(t.id, id))\n}\n"}), "next.server-actions")
T.expect("P10 next: a throw on bad input is not a rejection of a missing session (FAIL)", st == "FAIL", out)
st, out = _pa("check_nextjs.py", dict(_NX, **{"app/a.ts": "'use server'\nexport async function wipe(id: string): Promise<{ error?: string }> {\n  const viewer = await loadViewer()\n  if (!viewer) return { error: 'sign in' }\n  await db.delete(t).where(eq(t.id, id))\n  return {}\n}\n"}), "next.server-actions")
T.expect("P10 next: an object return type is not the body, and a custom identity read refused when missing enforces (PASS)", st == "PASS", out)
st, out = _pa("check_nextjs.py", dict(_NX, **{"app/a.ts": "'use server'\nexport async function wipe(form: FormData) {\n  const user = form.get('user')\n  if (!user) throw new Error('user required')\n  await db.delete(t).where(eq(t.id, user))\n}\n"}), "next.server-actions")
T.expect("P10 next: ...a 'user' read from the form is the caller's input, not an identity (FAIL)", st == "FAIL", out)
st, out = _pa("check_nextjs.py", dict(_NX, **{"app/a.ts": "'use server'\nimport { auth } from '@clerk/nextjs/server'\nexport async function wipe(id: string) {\n  await auth.protect()\n  await db.delete(t).where(eq(t.id, id))\n}\n"}), "next.server-actions")
T.expect("P10 next: Clerk auth.protect() enforces on its own (PASS)", st == "PASS", out)
_sk = T.fake_key("stripe", 32)
st, out = _pa("check_nextjs.py", dict(_NX, **{".env.production": "NEXT_PUBLIC_BILLING=%s\n" % _sk}), "next.public-env-secrets")
T.expect("P10 next: a key-shaped value under a benign NEXT_PUBLIC_ name in a committed .env FAILs, value unprinted", st == "FAIL" and _sk not in out, "status %s" % st)
st, out = _pa("check_nextjs.py", dict(_NX, **{".env.example": "NEXT_PUBLIC_SENTRY_DSN=\nNEXT_PUBLIC_ALGOLIA_SEARCH_KEY=\n"}), "next.public-env-secrets")
T.expect("P10 next: a vendor's documented browser key (Sentry DSN, Algolia search-only) PASSes", st == "PASS", out)

_GM = json.dumps({"webapp": {"access": "DOMAIN", "executeAs": "USER_ACCESSING"}, "oauthScopes": []})
_HX = "7f3a9c1e5b2d4f6a8c0e1b3d5f7a9c2e"
st, out = _pa("check_gas.py", {"appsscript.json": _GM, "Code.gs": "var FORM_KEY = '%s';\nfunction f() { UrlFetchApp.fetch('https://api.example.com', { headers: { Authorization: 'Bearer ' + FORM_KEY } }); }\n" % _HX}, "gas.keys-in-code")
T.expect("P10 gas: a Drive-word name sent as a bearer is a key, not a Drive id (FAIL)", st == "FAIL", out)
st, out = _pa("check_gas.py", {"appsscript.json": _GM, "Code.gs": "var PROPERTY_FOR_KEY = 'openWeatherApiKey_v2';\nfunction f() { return PropertiesService.getScriptProperties().getProperty(PROPERTY_FOR_KEY); }\n"}, "gas.keys-in-code")
T.expect("P10 gas: a Script Property NAME passed to getProperty is not a value (PASS)", st == "PASS", out)
st, out = _pa("check_gas.py", {".clasp.json": json.dumps({"rootDir": "dist"}), "dist/appsscript.json": _GM, "dist/Code.js": "const MAILGUN_KEY = `%s`;\n" % _HX}, "gas.keys-in-code")
T.expect("P10 gas: a clasp rootDir under dist/ is read, and a backtick literal is a literal (FAIL)", st == "FAIL", out)

_acct = json.loads(json.dumps(GOOD_SNAP))
_z = _acct["zones"][0]
_z["settings"]["security_header"] = {"strict_transport_security": {"enabled": True, "max_age": 300}}
_zid = "cfacct.hsts.%s" % _z["name"].replace(".", "-")
T.expect("P10 account: HSTS max_age 300 is under the 6-month minimum (FAIL)", snap_run(_acct)[1].get(_zid, {}).get("status") == "FAIL")
_z["settings"]["security_header"] = {"strict_transport_security": {"enabled": True, "max_age": "15552000"}}
T.expect("P10 account: a numeric-string max_age is read as its number (PASS)", snap_run(_acct)[1].get(_zid, {}).get("status") == "PASS")
_w = json.loads(json.dumps(GOOD_SNAP))
_w["workers"] = [{"id": "gw", "subdomain": {"enabled": True}, "settings": {"bindings": [{"type": "service", "name": "S", "service": "data"}]}},
                 {"id": "data", "subdomain": {"enabled": False}, "settings": {"bindings": [{"type": "secrets_store_secret", "name": "K", "store_id": "s"}]}}]
T.expect("P10 account: a workers.dev gateway with a service binding to a Worker holding a secret FAILs",
         snap_run(_w)[1].get("cfacct.workers-dev-exposed", {}).get("status") == "FAIL")
_w["workers"][1]["settings"]["bindings"] = [{"type": "plain_text", "name": "APP_ENV", "text": "prod"}]
T.expect("P10 account: ...a service binding to a Worker holding only config PASSes",
         snap_run(_w)[1].get("cfacct.workers-dev-exposed", {}).get("status") == "PASS")
# ---- end Phase 10 platform-a ----

# ---- Phase 10 audit fixes (names) ----
# The connection-string variant rule lives in names.secret_name, so cf.vars-secrets and fly.env-secrets agree.
_wv = lambda name: _pa("check_cloudflare.py", {"wrangler.toml": _W + '[vars]\n%s = "unset"\n' % name, "src/index.ts": _IDX}, "cf.vars-secrets")
_fe = lambda name: _st("check_fly_supabase.py", {"fly.toml": 'app = "a"\n[env]\n  %s = "unset"\n' % name}, "fly.env-secrets")
_c1, _o1 = _wv("DATABASE_URL_UNPOOLED")
_f1, _p1 = _fe("DATABASE_URL_UNPOOLED")
T.expect("P10 names: DATABASE_URL_UNPOOLED FAILs both cf.vars-secrets and fly.env-secrets", _c1 == "FAIL" and _f1 == "FAIL", "cf %s fly %s" % (_c1, _f1))
_c2, _o2 = _wv("APP_URL_UNPOOLED")
_f2, _p2 = _fe("APP_URL_UNPOOLED")
T.expect("P10 names: a lookalike APP_URL_UNPOOLED PASSes both", _c2 == "PASS" and _f2 == "PASS", "cf %s fly %s" % (_c2, _f2))
# ---- end Phase 10 audit fixes (names) ----

T.finish()

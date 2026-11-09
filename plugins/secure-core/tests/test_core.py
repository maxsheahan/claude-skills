#!/usr/bin/env python3
"""secure-core tests: the ledger refuses unmeasured verdicts, UNKNOWN stays
UNKNOWN, and the inventory maps a known surface. Known-bad first."""
import io
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import ledger  # noqa: E402
import testkit as T  # noqa: E402

S = os.path.join(HERE, "..", "scripts")


def rejects(name, r):
    try:
        ledger.validate(r)
        T.expect("ledger rejects " + name, False, "accepted")
    except ledger.LedgerError:
        T.expect("ledger rejects " + name, True)


# --- ledger: known-bad results are refused ---
rejects("an unknown status", ledger.result("x", "t", "WARN", "a:1"))
rejects("a PASS with no evidence", ledger.result("x", "t", "PASS", ""))
rejects("a FAIL with no severity", ledger.result("x", "t", "FAIL", "a:1", fix="f"))
rejects("a FAIL with no fix", ledger.result("x", "t", "FAIL", "a:1", severity="high"))
rejects("an UNKNOWN with no reason", ledger.result("x", "t", "UNKNOWN", "a:1"))
rejects("a credential-shaped value in the text", ledger.result("x", "t", "PASS", "found " + T.fake_key("google")))
# ...and good ones pass.
for r in (ledger.result("x", "t", "PASS", "a:1"), ledger.result("x", "t", "FAIL", "a:1", severity="low", fix="f"),
          ledger.result("x", "t", "UNKNOWN", "a:1", reason="tool missing")):
    try:
        ledger.validate(r)
        T.expect("ledger accepts a well-formed %s" % r["status"], True)
    except ledger.LedgerError as e:
        T.expect("ledger accepts a well-formed %s" % r["status"], False, str(e))

# --- emit exit codes: UNKNOWN is never exit 0 ---
P = ledger.result("p", "t", "PASS", "a:1")
F = ledger.result("f", "t", "FAIL", "a:1", severity="high", fix="x")
U = ledger.result("u", "t", "UNKNOWN", "a:1", reason="r")
T.expect("emit: any FAIL exits 1", ledger.emit([P, F, U], io.StringIO()) == 1)
T.expect("emit: UNKNOWN without FAIL exits 3, not 0", ledger.emit([P, U], io.StringIO()) == 3)
T.expect("emit: no results exits 3 (nothing measured is not a pass)", ledger.emit([], io.StringIO()) == 3)
T.expect("emit: all PASS exits 0", ledger.emit([P], io.StringIO()) == 0)

# --- markdown and counts keep UNKNOWN separate ---
led = ledger.build("/tmp/x", [dict(P), dict(U), dict(F)], ["node"], {})
T.expect("counts keep UNKNOWN on its own", led["counts"] == {"PASS": 1, "FAIL": 1, "UNKNOWN": 1}, str(led["counts"]))
md = ledger.to_markdown(led)
T.expect("markdown has an UNKNOWN section with the reason", "## UNKNOWN (1)" in md and "why unknown: r" in md)

# --- accepted.json: entries need a reason and a date; acceptance never changes status ---
bad_acc = T.tree({"security/accepted.json": json.dumps({"accepted": [{"id": "f"}]})})
try:
    ledger.load_accepted(bad_acc)
    T.expect("accepted.json without reason/date is refused", False)
except ledger.LedgerError:
    T.expect("accepted.json without reason/date is refused", True)
import datetime
_today = datetime.date.today().isoformat()
good_acc = T.tree({"security/accepted.json": json.dumps({"accepted": [{"id": "f", "reason": "ruled", "ruled": _today, "evidence": "a:1"}]})})
led = ledger.build(good_acc, [dict(F)], [], {}, ledger.load_accepted(good_acc))
T.expect("an accepted FAIL is still FAIL, marked accepted", led["results"][0]["status"] == "FAIL" and led["results"][0]["accepted"]["ruled"] == _today)

# --- inventory: a known surface is mapped (known-bad = uncapped paid API, unguarded route) ---
HONO = {
    "package.json": json.dumps({"dependencies": {"hono": "4.6.0"}}),
    "wrangler.toml": 'name = "demo-api"\nmain = "src/index.ts"\n[[d1_databases]]\nbinding = "DB"\n',
    "src/index.ts": (
        "import { Hono } from 'hono'\nconst app = new Hono()\n"
        "app.get('/api/health', (c) => c.text('ok'))\n"
        "app.post('/api/ask', async (c) => {\n  const r = await fetch('https://api.anthropic.com/v1/messages', {headers: {'x-api-key': c.env.ANTHROPIC_API_KEY}})\n  return c.json(await r.json())\n})\n"
        "app.delete('/api/walks/:id', async (c) => {\n  const user = await requireUser(c)\n  await c.env.DB.prepare('delete from walks where id=? and owner_id=?').run()\n  return c.text('ok')\n})\nexport default app\n"),
    "src/index.test.ts": "app.get('/api/only-in-tests', () => 1)\n",
}
bad = T.tree(HONO)
out = T.tree({})
rc = subprocess.run([sys.executable, os.path.join(S, "inventory.py"), bad, "--out", out], capture_output=True, text=True).returncode
inv = json.load(open(os.path.join(out, "inventory.json")))
T.expect("inventory: exits 0", rc == 0)
T.expect("inventory: stack has hono and cloudflare", {"hono", "cloudflare"} <= set(inv["stack"]), str(inv["stack"]))
T.expect("inventory: finds the 3 production routes, not the test-only one", sorted(r["path"] for r in inv["routes"]) == ["/api/ask", "/api/health", "/api/walks/:id"], str(inv["routes"]))
gates = {r["path"]: r["gate"] for r in inv["routes"]}
T.expect("inventory: the owned delete route shows an auth reference", gates["/api/walks/:id"] == "auth reference")
T.expect("inventory: the paid route shows none", gates["/api/ask"] == "none found")
paid = {p["provider"]: p for p in inv["paid_apis"]}
T.expect("inventory: Anthropic found with NO spend cap reference", "Anthropic" in paid and paid["Anthropic"]["spend_cap_reference"] is None, str(paid))
T.expect("inventory: secret name listed, never a value", any(s["name"] == "ANTHROPIC_API_KEY" for s in inv["secrets_read"]))
T.expect("inventory: D1 store and Worker target", any(s["store"] == "D1" for s in inv["data_stores"]) and inv["deploy_targets"][0]["target"] == "Cloudflare Worker")
# known-good: the same app with a daily spend cap next to the call
good_files = dict(HONO)
good_files["src/index.ts"] = good_files["src/index.ts"].replace("  const r = await fetch", "  if (await overDailySpendCap(c)) return c.json({paused: true}, 503)\n  const r = await fetch")
good = T.tree(good_files)
out2 = T.tree({})
subprocess.run([sys.executable, os.path.join(S, "inventory.py"), good, "--out", out2], capture_output=True)
inv2 = json.load(open(os.path.join(out2, "inventory.json")))
cap = [p for p in inv2["paid_apis"] if p["provider"] == "Anthropic"][0]["spend_cap_reference"]
T.expect("inventory: a spend cap next to the call is found", bool(cap), str(cap))
# empty repo: no crash, nothing invented
empty = T.tree({"README.md": "hi"})
out3 = T.tree({})
rc = subprocess.run([sys.executable, os.path.join(S, "inventory.py"), empty, "--out", out3], capture_output=True).returncode
inv3 = json.load(open(os.path.join(out3, "inventory.json")))
T.expect("inventory: empty repo maps nothing and exits 0", rc == 0 and inv3["route_count"] == 0 and inv3["stack"] == [])

# --- walk: agent scratch copies and ignored folders are not the repo's code (Phase 4 defect, a repo's .agents/) ---
import walk  # noqa: E402
scratch = T.git_init(T.tree({".gitignore": "ignored/\n", "src/app.ts": "export const a = 1\n",
                             ".agents/run/inputs/repo/src/app.ts": "app.get('/api/debug/env', x)\n",
                             "ignored/copy/src/app.ts": "app.get('/api/debug/env', x)\n"}))
open(os.path.join(scratch, "src", "new.ts"), "w").write("export const untracked = 1\n")
seen = sorted(walk.rel(scratch, p) for p in walk.files(scratch))
T.expect("walk: reads tracked and untracked-not-ignored source only", seen == ["src/app.ts", "src/new.ts"], str(seen))

# --- node-runtime: the built-code load check applies to code that runs under Node, not to a Worker bundle ---
srv = T.tree({"package.json": json.dumps({"dependencies": {"express": "4"}})})
wk = T.tree({"package.json": json.dumps({"dependencies": {"hono": "4"}}), "wrangler.toml": 'name = "w"\n'})
o1, o2 = T.tree({}), T.tree({})
subprocess.run([sys.executable, os.path.join(S, "inventory.py"), srv, "--out", o1], capture_output=True)
subprocess.run([sys.executable, os.path.join(S, "inventory.py"), wk, "--out", o2], capture_output=True)
T.expect("stack: an express server is node-runtime", "node-runtime" in json.load(open(os.path.join(o1, "inventory.json")))["stack"])
T.expect("stack: a Hono Worker is not", "node-runtime" not in json.load(open(os.path.join(o2, "inventory.json")))["stack"])

# --- Phase 5 audit: the ledger refuses a URL password, an AWS key and an unshaped high-entropy token ---
import random as _r
_al = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
pw = (lambda g: "".join(g.choice(_al) for _ in range(22)))(_r.Random(8))
rejects("a URL carrying a password", ledger.result("x", "t", "PASS", "postgres://admin:%s@db.example.com/app" % pw))
rejects("an AWS access key id", ledger.result("x", "t", "PASS", "AKIA" + (lambda g: "".join(g.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)))(_r.Random(9))))
rejects("an unshaped high-entropy token", ledger.result("x", "t", "PASS", "token " + (lambda g: "".join(g.choice(_al) for _ in range(40)))(_r.Random(10))))
try:
    ledger.validate(ledger.result("x", "t", "PASS", "/var/folders/0b/7x7bxdrj1zyhrxd53h0000gn/T/sl-fixture-abc/src/index.ts:12"))
    T.expect("ledger accepts an ordinary temp path (not a key)", True)
except ledger.LedgerError:
    T.expect("ledger accepts an ordinary temp path (not a key)", False)

# --- Phase 8: stack detection routes nested fly / railway / supabase ---
# A monorepo keeps fly.toml, railway.json and supabase/ one folder down; detect_stack used to read the root only,
# so the adapters never ran (core.route.*-nested bench cases). Decoy: a client folder named supabase is not a project.
def _stack(files):
    d, o = T.tree(files), T.tree({})
    subprocess.run([sys.executable, os.path.join(S, "inventory.py"), d, "--out", o], capture_output=True)
    return set(json.load(open(os.path.join(o, "inventory.json")))["stack"])
T.expect("P8 stack: a fly.toml under services/api/ routes to fly", "fly" in _stack({"services/api/fly.toml": 'app = "api"\n', "README.md": "# m\n"}))
T.expect("P8 stack: a railway.json under services/mcp/ routes to railway", "railway" in _stack({"package.json": json.dumps({"private": True, "workspaces": ["services/*"]}), "services/mcp/railway.json": "{}", "services/mcp/package.json": "{}"}))
T.expect("P8 stack: a railway.toml two levels down routes to railway", "railway" in _stack({"apps/svc/worker/railway.toml": "[deploy]\n", "README.md": "# m\n"}))
T.expect("P8 stack: services/api/supabase/migrations/ routes to supabase", "supabase" in _stack({"services/api/supabase/migrations/0001.sql": "create table public.n (id int);\n", "services/api/main.py": "x = 1\n"}))
T.expect("P8 stack: the Python supabase client (requirements.txt) routes to supabase", "supabase" in _stack({"services/api/requirements.txt": "supabase==2.9.0\nfastapi==0.115.0\n", "services/api/main.py": "x = 1\n"}))
T.expect("P8 stack: `from supabase import create_client` in code routes to supabase", "supabase" in _stack({"bot/db.py": "from supabase import create_client\n"}))
T.expect("P8 stack: a src/lib/supabase/ client folder with no config or migrations is not a Supabase project", "supabase" not in _stack({"src/lib/supabase/client.ts": "export const x = 1\n", "package.json": json.dumps({"dependencies": {"react": "19"}})}))
T.expect("P8 stack: a fly.toml inside node_modules is not the repo's app", "fly" not in _stack({"node_modules/dep/fly.toml": 'app = "dep"\n', "README.md": "# m\n"}))
T.expect("P8 stack: a repo with none of these detects none", not {"fly", "railway", "supabase"} & _stack({"README.md": "# m\n", "package.json": json.dumps({"dependencies": {"hono": "4"}})}))

# --- Phase 9: shared helpers ---
# names.secret_name, surface.import_names / imported / request_names / CALLER_SUPPLIED_RX and walk.block /
# enclosing_block / function_body / decl_src replaced copies in the platform, app and ai scripts (2026-11-01).
# Each former copy's own cases, then every disagreement between copies and the reading the merge keeps.
import names  # noqa: E402
import surface  # noqa: E402
import walk  # noqa: E402

# the cloudflare copy's cases (wrangler [vars] and NEXT_PUBLIC_ names)
for _n, _want in (("STRIPE_SECRET_KEY", True), ("GITHUB_TOKEN", True), ("ANTHROPIC_API_KEY", True), ("DB_PASSWORD", True),
                  ("SUPABASE_SERVICE_ROLE_KEY", True), ("SSH_PRIVATE_KEY", True), ("SENTRY_DSN", True), ("MAPS_KEY", True),
                  ("KEYBOARD_LAYOUT", False), ("MAX_TOKENS", False), ("SESSION_TOKEN_TTL_SECONDS", False), ("TURNSTILE_SITE_KEY", False),
                  ("STRIPE_PUBLISHABLE_KEY", False), ("SUPABASE_ANON_KEY", False), ("PUBLIC_SITE_URL", False), ("MODEL", False)):
    T.expect("P9 names: secret_name(%s) is %s" % (_n, _want), names.secret_name(_n) is _want)
# the fly copy's cases ([env] names and values)
for _n, _want in (("SUPABASE_SERVICE_KEY", True), ("JWT_SECRET", True), ("SUPABASE_URL", False), ("TOKEN_ISSUER", False)):
    T.expect("P9 names: secret_name(%s) is %s" % (_n, _want), names.secret_name(_n) is _want)
T.expect("P9 names: a key-shaped VALUE under an innocent name is a secret", names.secret_name("BILLING_PROVIDER", T.fake_key("stripe", 21)) is True)
T.expect("P9 names: a URL password in the value is a secret", names.secret_name("UPSTREAM", "postgres://app:pw@db.internal/app") is True)
T.expect("P9 names: an innocent name with an innocent value is not", names.secret_name("BILLING_PROVIDER", "stripe") is False)
# disagreements between the copies, and the reading kept
T.expect("P9 names: a setting suffix cancels a strong segment (fly rule): PRIVATE_KEY_PATH", names.secret_name("PRIVATE_KEY_PATH") is False)
T.expect("P9 names: SECRET_KEY_ID and CLIENT_SECRET_FILE are settings about a secret", not names.secret_name("SECRET_KEY_ID") and not names.secret_name("CLIENT_SECRET_FILE"))
T.expect("P9 names: PASSWORD_MIN_LENGTH is a setting", names.secret_name("PASSWORD_MIN_LENGTH") is False)
T.expect("P9 names: a database URL name is a secret everywhere (fly rule): DATABASE_URL, REDIS_URL, PG_DSN", all(names.secret_name(n) for n in ("DATABASE_URL", "REDIS_URL", "PG_DSN", "MONGODB_URI")))
T.expect("P9 names: DATABASE_URL behind a browser prefix is a secret too", names.secret_name("DATABASE_URL", browser=True) is True)
T.expect("P9 names: MAPBOX_TOKEN is public in every config (cloudflare rule)", names.secret_name("MAPBOX_TOKEN") is False and names.secret_name("MAPBOX_TOKEN", browser=True) is False)
T.expect("P9 names: the public allowlist wins over the database rule and the vocabulary", not names.secret_name("PUBLIC_DATABASE_URL") and not names.secret_name("PUBLIC_API_KEY"))
T.expect("P9 names: the fly words PASS, PWD, APIKEY are suffixes: DB_PASS, REDIS_PWD, STRIPE_APIKEY", all(names.secret_name(n) for n in ("DB_PASS", "REDIS_PWD", "STRIPE_APIKEY")))
T.expect("P9 names: weak words count only as a suffix (cloudflare rule): ACCESS_TOKEN_LIFETIME, KEY_VALUE, PRIVATE_NOTES", not any(names.secret_name(n) for n in ("ACCESS_TOKEN_LIFETIME", "KEY_VALUE", "PRIVATE_NOTES", "PASS_THROUGH")))
T.expect("P9 names: strong words count anywhere: SITE_PASSWORD, ALL_SECRETS, PASSWORD_HASH", all(names.secret_name(n) for n in ("SITE_PASSWORD", "ALL_SECRETS", "PASSWORD_HASH")))
T.expect("P9 names: a browser Maps key is public only under a browser prefix", names.secret_name("GOOGLE_MAPS_API_KEY", browser=True) is False and names.secret_name("GOOGLE_MAPS_API_KEY") is True)
T.expect("P9 names: case and whitespace do not matter; an empty name is not a secret", names.secret_name(" stripe_secret_key ") is True and names.secret_name("") is False and names.secret_name("___") is False)

# surface: relative imports
_imp = T.tree({"src/index.ts": "import geo from './geo.js'\nimport { lookup as find, type Opts } from './lib/index'\nconst { reserve } = require('./meter')\nexport { x } from './re'\n",
               "src/geo.ts": "export default async function geo(q) { return fetch('https://maps.googleapis.com/x?q=' + q) }\n",
               "src/lib/index.ts": "export function lookup(a) { return a }\n", "src/meter.js": "exports.reserve = () => {}\n", "src/re.ts": "export const x = 1\n"})
_names = surface.import_names(_imp, "src/index.ts")
T.expect("P9 imports: a default import maps to its LOCAL name (both callers searched the target for it)", _names.get("geo") == ("src/geo.ts", "geo"))
T.expect("P9 imports: './geo.js' resolves to geo.ts (TypeScript ESM names the built file)", _names["geo"][0] == "src/geo.ts")
T.expect("P9 imports: `lookup as find` maps the local name to the exported one, through /index.ts", _names.get("find") == ("src/lib/index.ts", "lookup"))
T.expect("P9 imports: `type Opts` brings no code", "Opts" not in _names)
T.expect("P9 imports: a destructured require resolves too", _names.get("reserve") == ("src/meter.js", "reserve"))
T.expect("P9 imports: imported() lists the file and one level of imports and re-exports", surface.imported(_imp, "src/index.ts") == ["src/index.ts", "src/geo.ts", "src/lib/index.ts", "src/meter.js", "src/re.ts"])
T.expect("P9 imports: an unresolvable specifier is skipped, never guessed", surface.import_names(T.tree({"a.ts": "import z from './missing'\n"}), "a.ts") == {} and surface.resolve_import(_imp, "src/index.ts", "./nope") is None)
T.expect("P9 imports: import_names takes the caller's already-read text", surface.import_names(_imp, "src/index.ts", "import geo from './geo'\n") == {"geo": ("src/geo.ts", "geo")})

# surface: caller input and the names it flows into
_js = """const { model, max_tokens } = await c.req.json()
const input = Schema.parse(await c.req.json())
const q = c.req.query('q')
let page: number = Number(c.req.query('page'))
const { topic } = body
const chosen = ALLOWED.includes(body.model) ? body.model : DEFAULT
const safe = String(model).slice(0, 20)
const res = await fetch(url, { body: JSON.stringify(x) })
const ip = c.req.header('cf-connecting-ip')
const ua = c.req.header('user-agent')
const prompt = `Write about ${safe}`
"""
_rn = surface.request_names(_js)
T.expect("P9 taint: destructured from the body and a schema-parsed whole value are caller input (spend rule)", {"model", "max_tokens", "input", "q"} <= _rn)
T.expect("P9 taint: a bare conventional name (body) at the START of a value binds (spend rule)", "topic" in _rn)
T.expect("P9 taint: a server choice that merely mentions body.model is NOT caller input", "chosen" not in _rn)
T.expect("P9 taint: `body:` inside a fetch option is not the request body", "res" not in _rn)
T.expect("P9 taint: a connecting-address header is never caller input; another header is", "ip" not in _rn and "ua" in _rn)
T.expect("P9 taint: input flows one level through a tainted VALUE (ai rule)", "safe" in _rn and "prompt" in _rn)
T.expect("P9 taint: a typed `let` binding counts", "page" in _rn)
T.expect("P9 taint: an accessor anywhere in the value taints it (ai rule)", "x" in surface.request_names("const x = clean(c.req.query('q')) + '!'\n"))
T.expect("P9 taint: a property named like a tainted variable does not carry taint", "y" not in surface.request_names("const { model } = await c.req.json()\nconst y = cfg.model\n"))
T.expect("P9 taint: Python assignments from the request count", {"data", "topic"} <= surface.request_names("data = request.get_json()\ntopic = request.args.get('t')\nmodel = DEFAULT\n") and "model" not in surface.request_names("model = DEFAULT\n"))
T.expect("P9 taint: nothing bound means an empty set", surface.request_names("const a = 1\nconst b = a + 2\n") == set())
T.expect("P9 taint: the wider CALLER_SUPPLIED reading sees headers and context vars the entry vocabulary does not", surface.CALLER_SUPPLIED_RX.search("c.get('userId')") and surface.CALLER_SUPPLIED_RX.search("c.req.header('x-device')") and not surface.CALLER_INPUT_RX.search("c.get('userId')"))

# walk: brace-balanced blocks and declarations
T.expect("P9 blocks: block() returns the balanced block that opens at or after start", walk.block("x { a { b } c } y", 0) == "{ a { b } c }" and walk.block("f() {\n  if (a) { b }\n}\n", 3) == "{\n  if (a) { b }\n}")
T.expect("P9 blocks: no brace means ''", walk.block("no braces here", 0) == "")
T.expect("P9 blocks: an unbalanced block is read to the cap, never shorter (6000, the larger of the two copies)", len(walk.block("{" + "a" * 7000, 0)) == walk.BLOCK_LIMIT and walk.block("{ ab", 0, limit=3) == "{ a")
T.expect("P9 blocks: block_end gives the index past the matching brace, None when unbalanced", walk.block_end("{ { } }", 0) == 7 and walk.block_end("{ {", 0) is None and walk.block_end("{" + "x" * 10 + "}", 0, limit=5) is None)
_code = "export default {\n  async fetch(req, env) {\n    if (!env.ADMIN_TOKEN) return next()\n  }\n}\n"
_pos = _code.index("return next()")
T.expect("P9 blocks: enclosing_block() is the innermost block around pos, from the strings-blanked view", walk.enclosing_block(_code, _code, _pos) == "{\n    if (!env.ADMIN_TOKEN) return next()\n  }")
T.expect("P9 blocks: enclosing_block() at top level is the whole text", walk.enclosing_block("const a = 1\n", "const a = 1\n", 5) == "const a = 1\n")
T.expect("P9 blocks: function_body() for a declaration and an arrow", walk.function_body("function geo(q) { return q }", "geo") == "{ return q }" and walk.function_body("const geo = async (q) => {\n  return q\n}", "geo") == "{\n  return q\n}")
T.expect("P9 blocks: function_decl() finds let/var too and None when absent", walk.function_decl("let f = () => 1", "f") is not None and walk.function_decl("const g = 1", "f") is None and walk.function_body("x", "f") == "")
T.expect("P9 decl: decl_src() reads a const, a destructuring, a Python assignment, in scope order", walk.decl_src("key", "const key = `ai:${day}`") == "`ai:${day}`" and walk.decl_src("deviceId", "const { deviceId } = await c.req.json()") == "await c.req.json()" and walk.decl_src("n", "n = request.args['n']") == "request.args['n']")
T.expect("P9 decl: the first scope with a binding wins; none means ''", walk.decl_src("k", "const k = inner", "const k = outer") == "inner" and walk.decl_src("k", "const j = 1") == "" and walk.decl_src("k", "if (k == 2) {}") == "")

# --- the version every ledger reports matches the plugin manifest (it sat at 0.3.0 through 0.5.2, found 2026-11-01) ---
_pj = json.load(open(os.path.join(HERE, "..", ".claude-plugin", "plugin.json")))
T.expect("ledger.SUITE_VERSION equals secure-core's plugin.json version", ledger.SUITE_VERSION == _pj["version"], "%s vs %s" % (ledger.SUITE_VERSION, _pj["version"]))

# ---- Phase 10 supply-core-gate ----
# ledger.git_state hashes CONTENT through a throwaway index; the repo's index, HEAD and objects are only read.
import hashlib  # noqa: E402


def _digest(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.exists(path) else None


def _objects(repo):
    return sorted(os.path.relpath(os.path.join(r, n), repo) for r, _, ns in os.walk(os.path.join(repo, ".git", "objects")) for n in ns)


_g = T.git_init(T.tree({"src/a.ts": "export const a = 1\n", ".gitignore": "scratch/\n"}))
open(os.path.join(_g, "src", "a.ts"), "a").write("// dirty at run time\n")
open(os.path.join(_g, "src", "u.ts"), "w").write("export const u = 1\n")
_idx, _head, _objs = _digest(os.path.join(_g, ".git", "index")), T.git(_g, "rev-parse", "HEAD").stdout, _objects(_g)
_s1 = ledger.git_state(_g)
T.expect("P10 git_state: a git repo gives head plus a 40-hex tree hash", _s1 and len(_s1.get("status") or "") == 40 and _s1["head"] == _head.strip(), str(_s1))
T.expect("P10 git_state: the same tree hashes the same", ledger.git_state(_g) == _s1)
T.expect("P10 git_state: the repo's index is byte-identical, HEAD unchanged, no object written",
         _digest(os.path.join(_g, ".git", "index")) == _idx and T.git(_g, "rev-parse", "HEAD").stdout == _head and _objects(_g) == _objs)
T.expect("P10 git_state: ...and the throwaway index left nothing staged in the real one", T.git(_g, "diff", "--cached", "--name-only").stdout.strip() == "")
open(os.path.join(_g, "src", "a.ts"), "a").write("// edited again, same status line\n")
T.expect("P10 git_state: an already-modified tracked file edited again changes the hash", ledger.git_state(_g)["status"] != _s1["status"])
_s2 = ledger.git_state(_g)
open(os.path.join(_g, "src", "u.ts"), "w").write("export const u = 2\n")
T.expect("P10 git_state: an untracked file edited (same `??` line) changes the hash", ledger.git_state(_g)["status"] != _s2["status"])
_s3 = ledger.git_state(_g)
os.makedirs(os.path.join(_g, "scratch")); open(os.path.join(_g, "scratch", "n.ts"), "w").write("x\n")
os.makedirs(os.path.join(_g, "src", "__pycache__")); open(os.path.join(_g, "src", "__pycache__", "m.cpython-312.pyc"), "wb").write(b"\x00\x01")
T.expect("P10 git_state: git-ignored files and __pycache__/*.pyc are left out", ledger.git_state(_g)["status"] == _s3["status"])
# A clean tracked file edited to the same size within the same second as the index refresh is stat-identical
# to its index entry (git compares times to the second here). Copying the repo's index let git trust that stat
# and skip re-reading the file, so the edit passed the gate about 1 run in 6 (audit case F3, measured on 0.6.0,
# 2026-11-09). The edit lands in the refresh's second and the gate runs in the next one, every time.
import time as _time  # noqa: E402
_hit = None
for _try in range(20):
    _r = T.git_init(T.tree({"src/index.ts": "export const x = 1\n"}))
    _p = os.path.join(_r, "src", "index.ts")
    _sec = int(_time.time())
    T.git(_r, "update-index", "--refresh")
    _before = ledger.git_state(_r)
    open(_p, "w").write("export const x = 9\n")  # same byte length
    if int(os.stat(_p).st_mtime) == _sec and int(_time.time()) == _sec:
        while int(_time.time()) == _sec:  # the gate runs in a later second, so its copied index looks newer
            _time.sleep(0.05)
        _hit = ledger.git_state(_r)["status"] != _before["status"]
        break
T.expect("P10 git_state: a same-size edit in the same second as the index refresh still changes the hash (F3)",
         _hit is True, "reached the same second: %s" % (_hit is not None))
open(os.path.join(_g, "src", "__pycache__", "evil.ts"), "w").write("x\n")
T.expect("P10 git_state: ...but any other file under __pycache__/ counts", ledger.git_state(_g)["status"] != _s3["status"])
os.remove(os.path.join(_g, "src", "__pycache__", "evil.ts"))
_led = os.path.join(_g, "out", "findings.json")
os.makedirs(os.path.dirname(_led)); open(_led, "w").write("{}")
_s4 = ledger.git_state(_g, exclude=[_led])
open(_led, "w").write('{"git": "rewritten"}')
T.expect("P10 git_state: an excluded path (the ledger itself) does not count", ledger.git_state(_g, exclude=[_led]) == _s4 and _s4["status"] == _s3["status"])
T.expect("P10 git_state: ...and without the exclusion it does", ledger.git_state(_g)["status"] != _s4["status"])
_env = dict(os.environ, GIT_INDEX_FILE=os.path.join(T.tree({}), "hook-index"))
_r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import ledger, json; print(json.dumps(ledger.git_state(%r, exclude=[%r])))"
                     % (os.path.join(HERE, "..", "lib"), _g, _led)], capture_output=True, text=True, env=_env)
T.expect("P10 git_state: an inherited GIT_INDEX_FILE (a hook's) neither changes the hash nor gets written",
         _r.returncode == 0 and json.loads(_r.stdout) == _s4 and not os.path.exists(_env["GIT_INDEX_FILE"]), _r.stdout + _r.stderr[-300:])
T.expect("P10 git_state: outside git it is None", ledger.git_state(T.tree({"a.txt": "x"})) is None)

# inventory: deploy configs at any depth and under any name, never from sample folders
sys.path.insert(0, S)
import inventory  # noqa: E402
T.expect("P10 inventory: a named fly config (fly.staging.toml) in a service folder is fly",
         "fly" in inventory.detect_stack(T.tree({"svc/api/fly.staging.toml": "app = 'a'\n"}))[0])
T.expect("P10 inventory: ...a fly.toml under examples/ is a sample, not fly",
         "fly" not in inventory.detect_stack(T.tree({"examples/deploy/fly.toml": "app = 'a'\n", "package.json": "{}"}))[0])
T.expect("P10 inventory: railway.toml under a test folder still deploys",
         "railway" in inventory.detect_stack(T.tree({"test/smoke/railway.toml": "[deploy]\n"}))[0])
T.expect("P10 inventory: ...railway.json under docs/ does not",
         "railway" not in inventory.detect_stack(T.tree({"docs/railway.json": "{}"}))[0])
T.expect("P10 inventory: a supabase/ project four folders down is supabase",
         "supabase" in inventory.detect_stack(T.tree({"a/b/c/d/supabase/config.toml": "project_id = 'x'\n"}))[0])
T.expect("P10 inventory: ...a supabase/ under docs/ is a sample",
         "supabase" not in inventory.detect_stack(T.tree({"docs/guide/supabase/migrations/1.sql": "select 1;\n"}))[0])
# Audit 2026-11-07: a hook's inherited GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE must not redirect git_state
# to the hook's repo (it returned repo A's HEAD and tree for repo B with no error).
_ha = T.git_init(T.tree({"a.txt": "repo A\n"}))
_hb = T.git_init(T.tree({"b.txt": "repo B\n"}))
_want_b = ledger.git_state(_hb)
_saved = {k: os.environ.get(k) for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")}
os.environ.update(GIT_DIR=os.path.join(_ha, ".git"), GIT_WORK_TREE=_ha, GIT_INDEX_FILE=os.path.join(_ha, ".git", "index"))
try:
    _got_b = ledger.git_state(_hb)
finally:
    for _k, _v in _saved.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v
T.expect("P10 git_state: an inherited hook GIT_DIR/GIT_WORK_TREE does not redirect it to another repo", _got_b == _want_b and _got_b["head"] != ledger.git_state(_ha)["head"], "%s vs %s" % (_got_b, _want_b))
# ---- end Phase 10 supply-core-gate ----

# ---- Phase 10 platform-a ----
# names.secret_name: camelCase/kebab names split like SNAKE_CASE; plural compound credential words; vendor browser keys.
T.expect("P10 names: camelCase splits into segments (openaiApiKey, stripeSecretKey are secrets)", names.secret_name("openaiApiKey") and names.secret_name("stripeSecretKey"))
T.expect("P10 names: ...and camelCase config stays config (keyboardLayout, sessionTokenTtlSeconds, model)", not any(names.secret_name(n) for n in ("keyboardLayout", "sessionTokenTtlSeconds", "model")))
T.expect("P10 names: a plural compound credential is the credential set (ALLOWED_API_KEYS, SIGNING_KEYS, PASSWORDS)", all(names.secret_name(n) for n in ("ALLOWED_API_KEYS", "SIGNING_KEYS", "PASSWORDS")))
T.expect("P10 names: ...a bare plural weak word is config (MAX_TOKENS, SORT_KEYS)", not names.secret_name("MAX_TOKENS") and not names.secret_name("SORT_KEYS"))
T.expect("P10 names: compounds without the underscore (APITOKEN, ACCESSTOKEN) are secrets", names.secret_name("APITOKEN") and names.secret_name("SHOP_ACCESSTOKEN"))
T.expect("P10 names: vendor browser keys are public only under a browser prefix", not names.secret_name("SENTRY_DSN", browser=True) and not names.secret_name("FIREBASE_API_KEY", browser=True) and names.secret_name("FIREBASE_API_KEY"))
T.expect("P10 names: ...their server twins stay secrets in the browser too (ALGOLIA_ADMIN_KEY)", names.secret_name("ALGOLIA_ADMIN_KEY", browser=True) is True)
# ---- end Phase 10 platform-a ----

# ---- Phase 10 app-auth ----
# surface.names_identity / refusal_condition / worker_methods: a refusal counts as an auth gate by WHO its
# condition is about (operand by operand, not a word anywhere in the text), and a raw Worker's methods are read
# from its own condition or block, never a two-line window.
import surface  # noqa: E402
_h = "const form = await request.json()\nconst row = await db.first(form.slug)\nconst visitor = c.get('visitor')\nconst flag = env.FEATURE_EDITS\n"
T.expect("P10 surface: another object's field and the caller's own data are not identity (row.authored_by !== form.authored_by)",
         not surface.names_identity("(row.authored_by !== form.authored_by)", _h))
T.expect("P10 surface: ...nor a feature flag copied from env (flag)", not surface.names_identity("(!flag)", _h))
T.expect("P10 surface: a name bound to a context read is identity whatever it is called (visitor = c.get(...))", surface.names_identity("(!visitor)", _h))
T.expect("P10 surface: ...an access predicate call is identity (mayEditDoc(...))", surface.names_identity("(!(await mayEditDoc(c, id)))", _h))
T.expect("P10 surface: ...a shared-secret env compare is identity, a flag env is not", surface.names_identity("(given !== env.OPS_KEY)", _h) and not surface.names_identity("(!env.READ_ONLY)", _h))
_c = "if (!acct) {\n  a()\n  b()\n  c()\n  d()\n  return res.status(401).end()\n}\n"
T.expect("P10 surface: the refusal's condition is its enclosing if, however many lines above",
         surface.refusal_condition(_c, _c.index("401")) == "(!acct)")
_p = "def f():\n    if not acct:\n        log()\n        raise HTTPException(401)\n    return 1\n"
T.expect("P10 surface: ...and the Python if over an indented block", (surface.refusal_condition(_p, _p.index("401")) or "").strip() == "not acct")
T.expect("P10 surface: ...None when the refusal sits in no branch", surface.refusal_condition("x()\nreturn deny(403)\n", 14) is None)
def _wm(src, needle):
    code = walk.strip_comments(src, "a.ts", strings=False)
    return surface.worker_methods(src, code, src.index(needle))
T.expect("P10 surface: worker methods come from a switch on the method inside the path block",
         _wm("if (p.startsWith('/v1/docs/')) {\n  switch (req.method) {\n    case 'GET': return a()\n    case 'PUT': return b()\n  }\n}\n", "p.startsWith") == ["GET", "PUT"])
T.expect("P10 surface: ...`method != 'GET'` is a write (ALL)", _wm("if (p.startsWith('/v1/docs/') && req.method != 'GET') { return b() }\n", "p.startsWith") == ["ALL"])
T.expect("P10 surface: ...an enclosing method if counts",
         _wm("if (req.method === 'PATCH') {\n  if (p.startsWith('/v1/docs/')) {\n    return b()\n  }\n}\n", "p.startsWith") == ["PATCH"])
T.expect("P10 surface: ...the next line's method is not borrowed",
         _wm("if (p.startsWith('/static/')) return assets()\nif (p.startsWith('/v1/docs/') && req.method === 'PUT') { return b() }\n", "p.startsWith('/static") == ["ANY"])
# ---- end Phase 10 app-auth ----

# ---- Phase 10 audit fixes (names) ----
# names.secret_name: a connection-string name followed by variant words is the connection string (one home;
# check_fly_supabase.env_secret is gone).
T.expect("P10 names: DATABASE_URL_UNPOOLED and POSTGRES_URL_NON_POOLING are connection strings (FAIL shape)",
         names.secret_name("DATABASE_URL_UNPOOLED") is True and names.secret_name("POSTGRES_URL_NON_POOLING") is True)
T.expect("P10 names: ...a host or a non-database URL with a variant word is not (APP_URL_STAGING, DB_HOST_PRIMARY)",
         names.secret_name("APP_URL_STAGING") is False and names.secret_name("DB_HOST_PRIMARY") is False)
# ---- end Phase 10 audit fixes (names) ----

# ---- Phase 10 audit fixes ----
# surface: one request-input vocabulary (CALLER_INPUT_RX, and DATA_INPUT_RX without headers) and env names
# judged by word segments (secret_env).
T.expect("P10 audit: CALLER_INPUT_RX reads typed c.req.json<T>(), c.req.valid(), req.get() and req.headers[...]",
         all(surface.CALLER_INPUT_RX.search(x) for x in ("await c.req.json<{ a: Array<string> }>()", "c.req.valid('form')", "req.get('x-device')", "req.headers['x-team']", "request.body")))
T.expect("P10 audit: ...not the connecting address, a db.query() call or a cache.json() call",
         not any(surface.CALLER_INPUT_RX.search(x) for x in ("req.headers['x-real-ip']", "request.headers.get('cf-connecting-ip')", "await db.query(sql)", "cache.json()")))
T.expect("P10 audit: DATA_INPUT_RX is caller data without the credential-carrying headers",
         surface.DATA_INPUT_RX.search("await c.req.json<Body>()") and not surface.DATA_INPUT_RX.search("c.req.header('authorization')"))
T.expect("P10 audit: secret_env judges word segments: ADMIN_TOKEN, jwtSecret, PASSCODE are shared secrets",
         all(surface.secret_env(n) for n in ("ADMIN_TOKEN", "jwtSecret", "PASSCODE", "EDITOR_API_KEY")))
T.expect("P10 audit: ...ENABLE_AUTHOR_EDITS, ALLOW_ADMINISTRATION and SESSIONLESS_MODE are flags",
         not any(surface.secret_env(n) for n in ("ENABLE_AUTHOR_EDITS", "ALLOW_ADMINISTRATION", "SESSIONLESS_MODE")))
# ---- end Phase 10 audit fixes ----

T.finish()

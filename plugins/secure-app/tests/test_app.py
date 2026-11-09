#!/usr/bin/env python3
"""secure-app tests: ASVS-lite, outbound fetch, abuse and spend, mutation and
SSRF trap. Known-bad first; the bad fixture is shaped like a map app and
a news-scoring app before their 2026-10-07 repairs."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "secure-core", "lib"))
import testkit as T  # noqa: E402

S = os.path.join(HERE, "..", "scripts")

BAD = {
    "package.json": json.dumps({"dependencies": {"hono": "4.6.0"}}),
    "wrangler.toml": 'name = "maps"\n',
    "src/index.ts": """import { Hono } from 'hono'
import { cors } from 'hono/cors'
const app = new Hono()
app.use('*', cors({ origin: (o) => o, credentials: true }))
app.get('/api/route', async (c) => {
  const from = c.req.query('from')
  const r = await fetch(`https://router.project-osrm.org/route/v1/foot/${from}`)
  return c.json(await r.json())
})
app.get('/api/preview', async (c) => {
  const target = c.req.query('url')
  const r = await fetch(target)
  return c.text(await r.text())
})
app.post('/api/narrate', async (c) => {
  const body = await c.req.json()
  const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', body: JSON.stringify({ model: body.model, max_tokens: body.max_tokens }) })
  return c.json(await r.json())
})
app.delete('/api/walks/:id', async (c) => {
  await c.env.DB.prepare('delete from walks where id = ?').bind(c.req.param('id')).run()
  return c.text('ok')
})
app.get('/api/debug/env', (c) => c.json(Object.keys(c.env)))
app.post('/api/signout', (c) => {
  c.header('Set-Cookie', 'session=; Max-Age=0; Path=/')
  return c.text('bye')
})
app.onError((err, c) => c.json({ message: err.message, stack: err.stack }, 500))
export default app
""",
    "src/budget.ts": "const cap = Number(env.DAILY_SPEND_CAP) || Infinity\n",
    "src/ingest.ts": "export async function pull(feed) {\n  const res = await fetch(feed.link)\n  return res.text()\n}\n",
}
GOOD = {
    "package.json": json.dumps({"dependencies": {"hono": "4.6.0"}}),
    "src/index.ts": """import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { overDailySpendCap } from './spend'
import { safeFetch } from './safeFetch'
const app = new Hono()
app.use('*', cors({ origin: ['https://app.example.com'], credentials: true }))
app.get('/api/route', async (c) => {
  const from = c.req.query('from')
  if (!isInSanFrancisco(from)) return c.json({ error: 'outside the city' }, 400)
  const r = await fetch(`https://router.project-osrm.org/route/v1/foot/${from}`)
  return c.json(await r.json())
})
app.post('/api/narrate', async (c) => {
  const body = await c.req.json()
  if (await overDailySpendCap(c)) return c.json({ paused: true }, 503)
  const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', body: JSON.stringify({ model: 'claude-sonnet-5', max_tokens: 800, messages: [{ role: 'user', content: String(body.text).slice(0, 2000) }] }) })
  return c.json(await r.json())
})
app.delete('/api/walks/:id', async (c) => {
  const user = await requireUser(c)
  await c.env.DB.prepare('delete from walks where id = ? and owner_id = ?').bind(c.req.param('id'), user.id).run()
  return c.text('ok')
})
app.post('/api/signout', async (c) => {
  c.header('Set-Cookie', 'session=; Max-Age=0; Path=/')
  await c.env.DB.prepare('INSERT INTO revoked_sessions (hash, expires_at) VALUES (?, ?)').run()
  return c.text('bye')
})
app.onError((err, c) => { console.error(err.stack); return c.json({ error: 'internal' }, 500) })
export default app
""",
    "src/spend.ts": "export async function overDailySpendCap(c) {\n  const cap = Number(c.env.DAILY_SPEND_CAP)\n  if (!Number.isFinite(cap)) return true // unset cap = paused\n  return false\n}\nconst limiter = new Map()\nexport function allow(ip) { const n = (limiter.get(ip) || 0) + 1; limiter.set(ip, n); return n <= 60 }\n",
    "src/safeFetch.ts": "const BLOCKED = ['169.254.0.0/16']\nexport async function safeFetch(u) { if (isPrivateAddress(u)) throw new Error('blocked'); return fetch(u) }\n",
    "src/ingest.ts": "import { safeFetch } from './safeFetch'\nexport async function pull(feed) {\n  const res = await safeFetch(feed.link)\n  return res.text()\n}\n",
}

bad, good = T.tree(BAD), T.tree(GOOD)

rc, c, out = T.run(os.path.join(S, "check_app.py"), bad)
for cid in ("app.cors", "app.error-leak", "app.debug-routes", "app.signout", "app.object-writes"):
    T.status_is("app bad", c, cid, "FAIL", out)
rc, c, out = T.run(os.path.join(S, "check_app.py"), good)
for cid in ("app.cors", "app.error-leak", "app.debug-routes", "app.signout", "app.object-writes"):
    T.status_is("app good", c, cid, "PASS", out)
mw = T.tree({"src/index.ts": "app.use('/api/*', requireAuth)\napp.delete('/api/walks/:id', async (c) => c.text('x'))\n"})
rc, c, out = T.run(os.path.join(S, "check_app.py"), mw)
T.status_is("auth middleware over the path", c, "app.object-writes", "PASS", out)

rc, c, out = T.run(os.path.join(S, "check_fetch.py"), bad)
T.status_is("fetch bad", c, "fetch.request-url", "FAIL", out)
T.expect("fetch: the request-url FAIL names /api/preview", "/api/preview" in c.get("fetch.request-url", {}).get("evidence", ""))
T.status_is("fetch bad", c, "fetch.data-url", "FAIL", out)
T.expect("fetch: a Worker makes data-url severity low", c.get("fetch.data-url", {}).get("severity") == "low")
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), good)
T.status_is("fetch good", c, "fetch.request-url", "PASS", out)
T.status_is("fetch good", c, "fetch.data-url", "PASS", out)
mixed = dict(GOOD)
mixed["src/other.ts"] = "export async function grab(item) { return fetch(item.image) }\n"
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(mixed))
T.status_is("fetch guard exists but a raw site remains", c, "fetch.data-url", "UNKNOWN", out)

rc, c, out = T.run(os.path.join(S, "check_spend.py"), bad)
for cid in ("spend.cap.anthropic", "spend.unset-cap", "spend.open-proxy", "spend.per-client", "spend.llm-params"):
    T.status_is("spend bad", c, cid, "FAIL", out)
rc, c, out = T.run(os.path.join(S, "check_spend.py"), good)
for cid in ("spend.cap.anthropic", "spend.unset-cap", "spend.open-proxy", "spend.per-client", "spend.llm-params"):
    T.status_is("spend good", c, cid, "PASS", out)

# ---------- mutation_check and ssrf_probe (moved from launch-secure-site) ----------
r = T.git_init(T.tree({"app.py": "def can_edit(owner, user):\n    return owner == user\n",
                       "guarded_test.py": "from app import can_edit\nassert can_edit('a','a')\nassert not can_edit('a','mallory')\n",
                       "weak_test.py": "from app import can_edit\nassert can_edit('a','a')\n"}))
def mut(test, find="owner == user"):
    return subprocess.run([sys.executable, os.path.join(S, "mutation_check.py"), "--repo", r, "--file", "app.py", "--find", find,
                           "--replace", "True", "--test", test], capture_output=True, text=True).returncode
T.expect("mutation: the guarded test DETECTS the removed ownership check (exit 0)", mut("python3 guarded_test.py") == 0)
T.expect("mutation: the weak test lets it SURVIVE (exit 1)", mut("python3 weak_test.py") == 1)
T.expect("mutation: an ambiguous pattern is refused (exit 2)", mut("true", "e") == 2)
T.expect("mutation: the real tree is untouched", "owner == user" in open(os.path.join(r, "app.py")).read())
T.expect("ssrf: the trap server's redirect routes answer", subprocess.run([sys.executable, os.path.join(S, "ssrf_probe.py"), "--self-test"], capture_output=True).returncode == 0)

# ---------- Phase 4 false-positive regressions (real repos, 2026-10-08) ----------
fp = T.tree({
    "wrangler.toml": 'name = "w"\nroutes = [{ pattern = "coach.example.com", custom_domain = true }]\n',
    "src/index.ts": """app.put('/walks/:id', async (c) => {
  const space = await userSpace(c)
  if (!space) return c.json({ error: SIGN_IN_REQUIRED }, 401)
  return c.text('ok')
})
app.get('/geo', async (c) => {
  const url =
    `https://photon.komoot.io/api/?q=${encodeURIComponent(c.req.query('q') ?? '').slice(0, 80)}`
  return fetch(url)
})
export async function cal(env) { return fetch(env.CALENDAR_ICS_URL) }
const SUBSTACK_URL = 'https://example.substack.com'
const FEED_URL = `${SUBSTACK_URL}/feed`
export async function feed() { return fetch(FEED_URL) }
export async function ask(env, params) {
  return fetch('https://api.anthropic.com/v1/messages', { body: JSON.stringify({ model: MODEL, max_tokens: params.maxTokens ?? 1024 }) })
}
const DAILY_SPEND_CAP = 5
""",
    "src/lib/fakeAnthropic.ts": "export function fake(body) { return { model: body.model, max_tokens: body.max_tokens } }\n",
    "scripts/_fal-edit.mjs": "await fetch('https://fal.run/fal-ai/flux')\n",
})
rc, c, out = T.run(os.path.join(S, "check_app.py"), fp)
T.status_is("FP: a handler that answers 401 is gated", c, "app.object-writes", "PASS", out)
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), fp)
T.status_is("FP: multi-line constant, env URL and a template on a constant are not data URLs", c, "fetch.data-url", "PASS", out)
rc, c, out = T.run(os.path.join(S, "check_spend.py"), fp)
T.status_is("FP: an internal params.maxTokens and a test double are not caller-set", c, "spend.llm-params", "PASS", out)
T.expect("FP: local scripts/ are not attacker-reachable spend", "spend.cap.fal" not in c, str(list(c)))
access = T.tree({"README.md": "Live behind Cloudflare Access, gated to one account.\n",
                 "src/index.ts": "app.put('/api/journal/:date/work', async (c) => c.text('x'))\n"})
rc, c, out = T.run(os.path.join(S, "check_app.py"), access)
T.expect("Access-fronted app: still FAIL (no gate in code) but medium, naming Access",
         c.get("app.object-writes", {}).get("status") == "FAIL" and c["app.object-writes"]["severity"] == "medium" and "Cloudflare Access" in c["app.object-writes"]["detail"], out[-300:])

fp2 = T.tree({"src/api.ts": """const BASE = "/api"
export async function get(path) { return fetch(`${BASE}${path}`) }
export async function pay(gate, op, url) { return gate.fetch(op, url, {}) }
export async function stripe(opts) {
  const url = (opts.rewrite ?? ((u) => u))("https://api.stripe.com/v1/checkout/sessions")
  return fetch(url)
}
"""})
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), fp2)
T.status_is("FP: same-origin path, a method named fetch, and a URL built on a fixed literal", c, "fetch.data-url", "PASS", out)
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree({"src/p.ts": "export function photo(photoUrl, key) {\n  const url = photoUrl.replace('{KEY}', key)\n  return fetch(url)\n}\n"}))
T.status_is("a URL from data with no fixed host stays a FAIL", c, "fetch.data-url", "FAIL", out)

cl = T.tree({"src/index.ts": "app.get('/api/route', async (c) => { const f = c.req.query('f'); if (!inBounds(f)) return c.text('no', 400); return fetch(`https://router.example.org/${f}`) })\n",
             "components/Search.tsx": "if (res.status === 429) showBusy()\n"})
rc, c, out = T.run(os.path.join(S, "check_spend.py"), cl)
T.status_is("a 429 handled only in a browser component is not a limiter", c, "spend.per-client", "FAIL", out)

# ---------- Phase 5 audit: bypasses that used to PASS ----------
def st(script, files, cid):
    rc, c, out = T.run(os.path.join(S, script), T.tree(files))
    return c.get(cid, {}).get("status"), out
s, out = st("check_spend.py", {"src/a.ts": "// TODO: add a daily limit before launch\nexport async function f(){ return fetch('https://api.anthropic.com/v1/messages') }\n"}, "spend.cap.anthropic")
T.expect("audit #9: a comment mentioning a limit is not a spend cap", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/a.ts": "app.get('/x', async (c) => { const q = c.req.query('q'); const r = await fetch(`https://api.example.org/?q=${q}`.slice(0, 200)); if (r.status === 429) return c.text('busy'); return c.json(await r.json()) })\n"}, "spend.per-client")
T.expect("audit #9: reading an upstream 429 is not a per-client limiter", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/a.ts": "export async function f(env, spent){ if (env.DAILY_CAP && spent > env.DAILY_CAP) return null; return fetch('https://api.anthropic.com/v1/messages') }\nconst DAILY_SPEND_CAP = 1\n"}, "spend.unset-cap")
T.expect("audit #9: `if (cap && spent > cap)` (unset = unlimited) fails", s == "FAIL", out[-200:])
sdk = {"package.json": json.dumps({"dependencies": {"@anthropic-ai/sdk": "0.50.0", "hono": "4"}}),
       "src/a.ts": "import Anthropic from '@anthropic-ai/sdk'\nconst client = new Anthropic()\napp.post('/ask', async (c) => {\n  const { model, max_tokens, messages } = await c.req.json()\n  return c.json(await client.messages.create({ model, max_tokens, messages }))\n})\n"}
rc, c, out = T.run(os.path.join(S, "check_spend.py"), T.tree(sdk))
T.status_is("audit #8: a paid API called through its SDK is a paid site", c, "spend.cap.anthropic", "FAIL", out)
T.status_is("audit #8: model and max_tokens destructured from the request", c, "spend.llm-params", "FAIL", out)
s, out = st("check_app.py", {"src/a.ts": "app.delete('/walks/:id', async (c) => {\n  // TODO: return Unauthorized\n  await c.env.DB.prepare('delete').run()\n})\n"}, "app.object-writes")
T.expect("audit #9: 'Unauthorized' in a comment is not a gate", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"lib/old/middleware.ts": "export function m(){ return getSession() }\n", "src/a.ts": "app.delete('/walks/:id', async (c) => c.text('x'))\n"}, "app.object-writes")
T.expect("audit #9: a middleware.ts outside the app root does not gate every route", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"app/api/signout/route.ts": "import { cookies } from 'next/headers'\nexport async function POST() { cookies().delete('session'); return Response.json({ok: true}) }\n"}, "app.signout")
T.expect("audit #9: a cookie-only sign-out (cookies().delete) fails", s == "FAIL", out[-200:])
for label, src in (("(o, c) => o", "app.use('*', cors({ origin: (o, c) => o, credentials: true }))\n"),
                   ("origin echoed through a variable", "const origin = c.req.header('Origin')\nc.header('Access-Control-Allow-Origin', origin)\nc.header('Access-Control-Allow-Credentials', 'true')\n")):
    s, out = st("check_app.py", {"src/a.ts": src}, "app.cors")
    T.expect("audit #9: reflected CORS via %s fails" % label, s == "FAIL", out[-200:])
s, out = st("check_app.py", {"src/a.ts": "app.use('*', cors({ origin: (o) => ALLOWED.includes(o) ? o : null, credentials: true }))\n"}, "app.cors")
T.expect("an allow-listed origin function still passes", s == "PASS", out[-200:])
s, out = st("check_fetch.py", {"src/a.ts": "app.post('/p', async (c) => {\n  const { url } = await c.req.json()\n  return fetch(url)\n})\n"}, "fetch.request-url")
T.expect("audit #9: a destructured request URL is caught as request-url", s == "FAIL", out[-200:])
s, out = st("check_fetch.py", {"src/a.ts": "// blocks 169.254.169.254 (todo)\nexport async function g(item) { return fetch(item.link) }\n"}, "fetch.data-url")
T.expect("audit #9: a comment naming 169.254 is not a guard", s == "FAIL", out[-200:])

# ---------- second audit: routes on any router, FastAPI, stripper, CORS, spend ----------
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"express": "4"}}), "src/users.ts": "usersRouter.delete('/:id', async (req, res) => { await db.remove(req.params.id); res.end() })\n"}, "app.object-writes")
T.expect("audit 2: a route on usersRouter is seen and fails", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"requirements.txt": "fastapi\n", "app/main.py": "@app.delete('/users/{user_id}')\ndef delete_user(user_id: int):\n    db.delete(user_id)\n"}, "app.object-writes")
T.expect("audit 2: a FastAPI {id} route without auth fails", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"requirements.txt": "fastapi\n", "app/main.py": "@router.post('/positions/{position_id}/close')\ndef close(position_id: str, user=Depends(verify_supabase_user)):\n    return 1\n"}, "app.object-writes")
T.expect("audit 2: FastAPI Depends(verify_...) counts as auth", s == "PASS", out[-200:])
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"hono": "4"}}), "src/index.ts": "const x = 1\n"}, "app.object-writes")
T.expect("audit 2: a routing framework with no recognised route is UNKNOWN, not PASS", s == "UNKNOWN", out[-200:])
s, out = st("check_app.py", {"src/a.ts": "app.delete('/walks/:id', async (c) => {\n  const s = name.replace(/'/g, '')  // TODO: requireAuth\n  await c.env.DB.prepare('d').run()\n})\n"}, "app.object-writes")
T.expect("audit 2: a regex literal does not turn a comment into code", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"requirements.txt": "flask\n", "app.py": "@app.post('/debug/reset-db')\ndef reset():\n    \"\"\"Call requireAuth and check NODE_ENV first.\"\"\"\n    db.reset()\n"}, "app.debug-routes")
T.expect("audit 2: a docstring is not a guard", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"src/i.ts": "app.use('*', authStub)\napp.delete('/a/:id', (c) => c.text('x'))\nexport const authStub = async (c, next) => { c.set('teacher', c.req.header('X-Teacher-Id')); await next() }\n"}, "app.header-identity")
T.expect("audit 2: identity from X-Teacher-Id fails", s == "FAIL", out[-200:])
for label, src in (("typed arrow", "app.use(cors({ origin: (origin: string) => origin, credentials: true }))"), ("async arrow", "app.use(cors({ origin: async (origin) => origin, credentials: true }))"),
                   ("/.*/", "app.use(cors({ origin: /.*/, credentials: true }))"), ("callback", "app.use(cors({ origin: function (o, cb) { cb(null, true) }, credentials: true }))"),
                   ("express setHeader", "res.setHeader(ACAO, req.headers.origin)\nres.setHeader('Access-Control-Allow-Credentials', 'true')"),
                   ("express header get", "res.header(ACAO, req.get('origin'))\nres.header('Access-Control-Allow-Credentials', 'true')")):
    s, out = st("check_app.py", {"src/a.ts": src + "\n"}, "app.cors")
    T.expect("audit 2: CORS %s fails" % label, s == "FAIL", out[-160:])
s, out = st("check_app.py", {"app.py": "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"}, "app.cors")
T.expect("audit 2: Starlette * with credentials fails", s == "FAIL", out[-160:])
s, out = st("check_spend.py", {"src/a.ts": "class UpstreamLimitError extends Error {}\napp.get('/x', async (c) => { const q = c.req.query('q').slice(0, 9); const r = await fetch(`https://api.example.org/?q=${q}`); if (!r.ok) throw new UpstreamLimitError('x'); return c.json({}) })\n"}, "spend.per-client")
T.expect("audit 2: an error class named *LimitError is not a limiter", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/llm.ts": "export async function ask(){ return fetch('https://api.anthropic.com/v1/messages') }\n", "src/Help.tsx": "import { ask } from './llm'\nexport const H = () => <p>There is no daily spend cap yet</p>\n"}, "spend.cap.anthropic")
T.expect("audit 2: JSX text is not a spend cap", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/a.ts": "const GIFT_LIMITS = { dailyUsdCap: Number.MAX_SAFE_INTEGER }\nexport async function f(){ return fetch('https://api.anthropic.com/v1/messages') }\n"}, "spend.unset-cap")
T.expect("audit 2: a cap set to MAX_SAFE_INTEGER is unlimited", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/generated/assets.ts": 'export const CARD_HTML = "<script>if(!Number.isSafeInteger(s)){issues.push({code:\\"too_big\\",maximum:Number.MAX_SAFE_INTEGER})}</script>";\nexport async function f(){ return fetch(\'https://api.anthropic.com/v1/messages\') }\nconst DAILY_SPEND_CAP = 1\n'}, "spend.unset-cap")
T.expect("2026-10-15: MAX_SAFE_INTEGER inside a string literal (a bundled card) is not a cap", s != "FAIL", out[-200:])
two = {"src/translator.ts": "export async function tr(){ return fetch('https://api.anthropic.com/v1/messages') }\n",
       "src/scorer.ts": "import { DAILY_SPEND_CAP } from './caps'\nexport async function sc(){ return fetch('https://api.anthropic.com/v1/messages') }\n",
       "src/caps.ts": "export const DAILY_SPEND_CAP = 5\n"}
s, out = st("check_spend.py", two, "spend.cap.anthropic")
T.expect("audit 2: one capped call site does not cover an uncapped one", s == "FAIL" and "translator.ts" in out, out[-200:])

s, out = st("check_app.py", {"app.py": "@app.get('/x')\ndef x():\n    try:\n        run()\n    except Exception:\n        return JSONResponse({'error': traceback.format_exc()}, status_code=500)\n"}, "app.error-leak")
T.expect("a Python traceback returned in a response fails", s == "FAIL", out[-200:])

# ---------- cap enforcement must be at the call site (2026-10-09 hand checks: a coaching app, a classroom app, a map app) ----------
llm = "export async function runGeneration(){ return fetch('https://api.anthropic.com/v1/messages') }\n"
mw = {"src/lib/llm.ts": llm,
      "src/index.ts": "import planning from './routes/planning'\napp.use('/api/planning/lessons/generate', requireCaps)\napp.route('/api/planning', planning)\n",
      "src/routes/planning.ts": "import { runGeneration } from '../lib/llm'\nplanning.post('/lessons/generate', async (c) => { return c.json(await runGeneration()) })\nplanning.get('/library', async (c) => c.json([]))\n"}
s, out = st("check_spend.py", mw, "spend.cap.anthropic")
T.expect("a cap middleware mounted over the calling route counts", s == "PASS", out[-200:])
gate_ = {"src/lib/llm.ts": llm, "src/api.ts": "import { runGeneration } from './lib/llm'\napp.post('/x', async (c) => { const g = new SpendGate(c.env.DB); await g.begin(); return c.json(await runGeneration()) })\n"}
s, out = st("check_spend.py", gate_, "spend.cap.anthropic")
T.expect("constructing a spend gate at the call site counts", s == "PASS", out[-200:])
disp = {"src/lib/llm.ts": llm, "src/coach.ts": "export const DAILY_OUTPUT_BUDGET = 1000\nexport function chat(used){ if (used > DAILY_OUTPUT_BUDGET) throw new Error('budget') }\n",
        "src/index.ts": "import { DAILY_OUTPUT_BUDGET } from './coach'\nimport { runGeneration } from './lib/llm'\napp.get('/c', async (c) => { await runGeneration(); return c.json({ budget: DAILY_OUTPUT_BUDGET }) })\n"}
s, out = st("check_spend.py", disp, "spend.cap.anthropic")
T.expect("a budget imported only to display it is not enforcement", s == "FAIL" and "index.ts" in out, out[-200:])
typ = {"src/prose.ts": "import type { Env } from './coach'\nexport async function p(){ return fetch('https://api.anthropic.com/v1/messages') }\n",
       "src/coach.ts": "export type Env = {}\nexport function g(used){ if (used > DAILY_OUTPUT_BUDGET) throw 1 }\n"}
s, out = st("check_spend.py", typ, "spend.cap.anthropic")
T.expect("an `import type` is not a call path to a cap", s == "FAIL", out[-200:])

s, out = st("check_spend.py", {"src/a.ts": "app.get('/t', async (c) => { const q = c.req.query('q').slice(0, 9); return fetch(`https://api.anthropic.com/v1/x?q=${q}`) })\nconst limiter = new ModelCallLimiter(4)\nif (res.status !== 429) retry()\n"}, "spend.per-client")
T.expect("a concurrency limiter and an upstream 429 comparison are not per-client limits", s == "FAIL", out[-200:])

# ---------- auth-gate-check and ai-route-metering (2026-10-13 account audit fixes) ----------
AG = os.path.join(S, "check_auth_gates.py")
MT = os.path.join(S, "check_metering.py")
W_ROUTED = 'name = "w"\nmain = "src/index.ts"\nroutes = [{ pattern = "coach.example.com", custom_domain = true }]\n'
W_PLAIN = 'name = "w"\nmain = "src/index.ts"\n'

def ag(files, cid):
    rc, c, out = T.run(AG, T.tree(files))
    return c.get(cid, {}), out

r, out = ag({"wrangler.toml": W_PLAIN, "src/index.ts": "app.use('/api/*', async (c, next) => {\n  if (!c.env.BETTER_AUTH_SECRET) return next()\n  const s = await getSession(c)\n  if (!s) return c.json({ error: 'unauthorized' }, 401)\n  await next()\n})\n"}, "auth.off-switch")
T.expect("auth: `if (!c.env.SECRET) return next()` is an off-switch (FAIL high)", r.get("status") == "FAIL" and r.get("severity") == "high" and "BETTER_AUTH_SECRET" in r.get("evidence", ""), out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/index.ts": "if (!env.AUTH_SECRET) {\n  return await next()\n}\n"}, "auth.off-switch")
T.expect("auth: the braced, awaited form is an off-switch", r.get("status") == "FAIL", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/turnstile.ts": "export const turnstile = { enabled: !!env.TURNSTILE_SECRET_KEY, verify }\n"}, "auth.off-switch")
T.expect("auth: `enabled: !!env.SECRET` around a verifier is an off-switch", r.get("status") == "FAIL", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/billing.ts": "export async function hook(req, env) {\n  if (env.STRIPE_WEBHOOK_SECRET) {\n    event = stripe.webhooks.constructEvent(body, sig, env.STRIPE_WEBHOOK_SECRET)\n  }\n  grant(event)\n}\n"}, "auth.off-switch")
T.expect("auth: a verification that runs only `if (env.SECRET)` is an off-switch", r.get("status") == "FAIL" and "verification runs only" in r.get("evidence", ""), out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/index.ts": "app.use('/api/*', async (c, next) => {\n  if (!c.env.BETTER_AUTH_SECRET) {\n    if (c.env.NODE_ENV === 'test') return next()\n    return c.json({ error: 'auth not configured' }, 503)\n  }\n  await next()\n})\nif (env.ANTHROPIC_API_KEY) { await fetch('https://api.anthropic.com/v1/messages') }\n"}, "auth.off-switch")
T.expect("auth: 503 on a missing secret (test-env bypass only) passes; a key-gated API call is not an off-switch", r.get("status") == "PASS", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/index.ts": "// if (!c.env.SECRET) return next()\napp.use('*', (c, next) => next())\n"}, "auth.off-switch")
T.expect("auth: an off-switch in a comment does not count", r.get("status") == "PASS", out[-200:])

r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": "export const requireUser = async (c, next) => {\n  const email = c.req.header('cf-access-authenticated-user-email')\n  if (email !== c.env.ALLOWED_EMAIL) return c.json({ error: 'no' }, 403)\n  await next()\n}\n"}, "auth.header-identity")
T.expect("auth: cf-access-authenticated-user-email trusted with no JWT check fails high", r.get("status") == "FAIL" and r.get("severity") == "high", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/auth-stub.ts": "c.set('teacherId', c.req.header('X-Teacher-Id') ?? 'teacher_dev')\n"}, "auth.header-identity")
T.expect("auth: an X-Teacher-Id identity fails", r.get("status") == "FAIL", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/identity.ts": "const u = request.headers.get('x-user-id')\n"}, "auth.header-identity")
T.expect("auth: headers.get('x-user-id') fails", r.get("status") == "FAIL", out[-200:])
COACH = """import { createRemoteJWKSet, jwtVerify } from 'jose'
const ACCESS_TEAM = 'https://team.cloudflareaccess.com'
const JWKS = createRemoteJWKSet(new URL(`${ACCESS_TEAM}/cdn-cgi/access/certs`))
app.use('/api/*', async (c, next) => {
  const token = c.req.header('Cf-Access-Jwt-Assertion')
  if (!token) return c.json({ error: 'unauthorized' }, 401)
  const { payload } = await jwtVerify(token, JWKS, { issuer: ACCESS_TEAM, audience: c.env.ACCESS_AUD, algorithms: ['RS256'] })
  const email = typeof payload.email === 'string' ? payload.email : ''
  if (email !== c.env.ALLOWED_EMAIL) return c.json({ error: 'unauthorized' }, 401)
  await next()
})
"""
r, out = ag({"wrangler.toml": W_ROUTED, "src/index.ts": COACH, "src/legacy.ts": "const e = c.req.header('cf-access-authenticated-user-email')\n"}, "auth.header-identity")
T.expect("auth: a header read with JWT verification in the tree passes (reference, not proof)", r.get("status") == "PASS" and "reference" in r.get("detail", ""), out[-200:])
r, out = ag({"wrangler.toml": W_ROUTED, "src/index.ts": COACH}, "auth.access-jwt")
T.expect("auth: jwtVerify with issuer and audience passes", r.get("status") == "PASS" and "index.ts:7" in r.get("evidence", ""), out[-200:])
r, out = ag({"wrangler.toml": W_ROUTED, "src/index.ts": "app.get('/api/x', (c) => c.json({}))\n"}, "auth.access-jwt")
T.expect("auth: a routed Worker with no assertion reference is UNKNOWN, never PASS", r.get("status") == "UNKNOWN" and "cannot see whether Access fronts this host" in r.get("reason", ""), out[-200:])
rc, c, out = T.run(AG, T.tree({"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n# routes = [{ pattern = "x.example.com" }]\n', "src/index.ts": "app.get('/x', (c) => c.text('x'))\n"}))
T.expect("auth: a wrangler config with no live route (only a commented one) emits no access-jwt check", "auth.access-jwt" not in c, str(sorted(c)))
r, out = ag({"wrangler.toml": W_ROUTED, "src/index.ts": "const token = c.req.header('Cf-Access-Jwt-Assertion')\nif (!token) return c.json({}, 401)\n"}, "auth.access-jwt")
T.expect("auth: an assertion read without jwtVerify fails high", r.get("status") == "FAIL" and r.get("severity") == "high", out[-200:])
r, out = ag({"wrangler.toml": W_ROUTED, "src/index.ts": "import { jwtVerify } from 'jose'\nconst t = c.req.header('Cf-Access-Jwt-Assertion')\nconst { payload } = await jwtVerify(t, JWKS)\n"}, "auth.access-jwt")
T.expect("auth: jwtVerify without issuer and audience fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium", out[-200:])

r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": "import { betterAuth } from 'better-auth'\nexport const auth = betterAuth({\n  emailAndPassword: { enabled: true },\n  database: db,\n})\n"}, "auth.open-signup")
T.expect("auth: better-auth email sign-up with no disableSignUp and no create hook fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": "import { betterAuth } from 'better-auth'\nexport const auth = betterAuth({\n  emailAndPassword: { enabled: true, disableSignUp: true },\n  databaseHooks: { user: { create: { before: async (user) => { if (user.email !== env.ALLOWED_EMAIL) throw new APIError('FORBIDDEN') } } } },\n})\n"}, "auth.open-signup")
T.expect("auth: disableSignUp plus a user.create.before hook passes", r.get("status") == "PASS", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": "import { betterAuth } from 'better-auth'\nexport const auth = betterAuth({ emailAndPassword: { enabled: false } })\n"}, "auth.open-signup")
T.expect("auth: email sign-up disabled emits no open-signup finding", not r, out[-200:])
rc, c, out = T.run(AG, T.tree({"wrangler.toml": W_ROUTED, "src/index.ts": COACH, "src/auth.ts": "import { betterAuth } from 'better-auth'\nexport const auth = betterAuth({ emailAndPassword: { enabled: true, disableSignUp: true } })\n"}))
T.expect("auth clean tree: every check PASS, none UNKNOWN", rc == 0 and c and all(v["status"] == "PASS" for v in c.values()) and {"auth.off-switch", "auth.header-identity", "auth.access-jwt", "auth.open-signup"} <= set(c), out[-300:])

def mt(files, cid):
    rc, c, out = T.run(MT, T.tree(files))
    return c.get(cid, {}), out

RL = 'name = "w"\nmain = "src/index.ts"\n[[ratelimits]]\nname = "AI_LIMITER"\nnamespace_id = "1001"\nsimple = { limit = 20, period = 60 }\n'
NORL = 'name = "w"\nmain = "src/index.ts"\n'
r, out = mt({"wrangler.toml": RL, "src/a.ts": "export async function ask(env, prompt) {\n  const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST' })\n  return r.json()\n}\n"}, "meter.anthropic")
T.expect("meter: a paid call with no counter in its function or its callers fails high", r.get("status") == "FAIL" and r.get("severity") == "high" and "a.ts:2" in r.get("evidence", ""), out[-200:])
r, out = mt({"wrangler.toml": RL, "src/a.ts": "export async function ask(env, prompt) {\n  const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST' })\n  const n = Number(await env.CACHE.get(`ai:count:${today}`)) || 0\n  await env.CACHE.put(`ai:count:${today}`, String(n + 1))\n  return r.json()\n}\n"}, "meter.anthropic")
T.expect("meter: a counter touched only after the call fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium" and "after the call" in r.get("evidence", ""), out[-200:])
r, out = mt({"wrangler.toml": RL, "src/a.ts": "app.post('/gen', async (c) => {\n  const teacherId = c.req.header('x-teacher-id')\n  const used = Number(await c.env.CACHE.get(`usage:${teacherId}`)) || 0\n  if (used >= 50) return c.json({}, 429)\n  await c.env.CACHE.put(`usage:${teacherId}`, String(used + 1))\n  const r = await fetch('https://api.anthropic.com/v1/messages')\n  return c.json(await r.json())\n})\n"}, "meter.anthropic")
T.expect("meter: a counter keyed only on a header-supplied id fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium" and "caller-supplied" in r.get("evidence", ""), out[-200:])
r, out = mt({"wrangler.toml": NORL, "src/a.ts": "export async function ask(env) {\n  await reserveAiBudget(env)\n  return fetch('https://api.anthropic.com/v1/messages')\n}\n"}, "meter.ratelimit-binding")
T.expect("meter: no [[ratelimits]] block fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium", out[-200:])
GOOD_M = {"wrangler.toml": RL,
          "src/lib/ai-guard.ts": "export async function reserveAiBudget(env) {\n  const key = `ai:count:${new Date().toISOString().slice(0, 10)}`\n  const n = Number(await env.CACHE.get(key)) || 0\n  if (n >= 150) throw new BudgetExhaustedError(n, 150)\n  await env.CACHE.put(key, String(n + 1))\n}\n",
          "src/routes/classical.ts": "import { reserveAiBudget } from '../lib/ai-guard'\nasync function callClaudeJson(prompt: string, env: Env): Promise<{ chart?: string; source?: string }> {\n  await reserveAiBudget(env)\n  const res = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST' })\n  return res.json()\n}\n",
          "src/routes/sdk.ts": "import Anthropic from '@anthropic-ai/sdk'\nexport async function feedback(env) {\n  const key = `feedback:count:${day}`\n  const current = Number(await env.STATE.get(key)) || 0\n  if (current >= 40) return null\n  await env.STATE.put(key, String(current + 1))\n  const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY })\n  return client.messages.create({ model: MODEL, max_tokens: 400, messages: [] })\n}\n",
          "src/routes/lookup.ts": "import { reserveDailyBudget } from '../lib/ai-guard'\nasync function llm(env, q) { return fetch('https://api.openai.com/v1/chat/completions') }\napp.get('/lookup', async (c) => {\n  const b = await reserveDailyBudget(c.env, 'lookup', 50)\n  if (!b.ok) return c.json({}, 429)\n  return c.json(await llm(c.env, c.req.query('q')))\n})\n"}
rc, c, out = T.run(MT, T.tree(GOOD_M))
T.expect("meter good: a reservation above the call, an SDK call after a day-keyed KV counter, and a route-level reservation before a helper all PASS",
         c.get("meter.anthropic", {}).get("status") == "PASS" and c.get("meter.openai", {}).get("status") == "PASS", out[-400:])
# Phase 10: GOOD_M declares [[ratelimits]] AI_LIMITER and no code calls .limit() on it. The skill (step 5 and its
# known-bad list) and the bench (meter.ratelimit-binding.declared-never-called) both say a binding nobody calls
# limits nothing: FAIL medium. The fixture stays as written; the counters above are what PASS.
T.expect("meter good: ...but its declared, never-called AI_LIMITER binding is FAIL medium",
         c.get("meter.ratelimit-binding", {}).get("status") == "FAIL" and c.get("meter.ratelimit-binding", {}).get("severity") == "medium", out[-400:])
# the PASS wording is read on GOOD_M with the route calling its binding (GOOD_M itself never calls it)
GOOD_M_RL = dict(GOOD_M, **{"src/routes/lookup.ts": GOOD_M["src/routes/lookup.ts"].replace("  const b = await", "  const { success } = await c.env.AI_LIMITER.limit({ key: c.req.header('cf-connecting-ip') ?? 'anon' })\n  if (!success) return c.json({}, 429)\n  const b = await")})
rc, c, out = T.run(MT, T.tree(GOOD_M_RL))
T.expect("meter good: the ratelimit PASS says the binding is best-effort and the counter is the hard cap", c.get("meter.ratelimit-binding", {}).get("status") == "PASS" and "best-effort" in c.get("meter.ratelimit-binding", {}).get("detail", "") and "hard cap" in c["meter.ratelimit-binding"]["detail"], out[-300:])
r, out = mt({"wrangler.toml": RL, "src/a.ts": "// await reserveAiBudget(env) before the call\nexport async function ask(env) { return fetch('https://api.anthropic.com/v1/messages') }\n"}, "meter.anthropic")
T.expect("meter: a reservation in a comment is not a counter", r.get("status") == "FAIL", out[-200:])
rc, c, out = T.run(MT, T.tree({"wrangler.toml": RL, "src/a.ts": "export async function h() { return fetch('https://example.org/') }\n"}))
T.expect("meter: no paid-model call emits meter.none PASS only", list(c) == ["meter.none"] and c["meter.none"]["status"] == "PASS", str(sorted(c)))
r, out = mt({"wrangler.toml": RL, "package.json": json.dumps({"dependencies": {"openai": "4"}}), "src/a.ts": "import OpenAI from 'openai'\nconst client = new OpenAI()\nexport async function ask(q) { return client.chat.completions.create({ model: 'gpt-5', messages: [{ role: 'user', content: q }] }) }\n"}, "meter.openai")
T.expect("meter: an OpenAI SDK call with no counter fails high", r.get("status") == "FAIL" and r.get("severity") == "high", out[-200:])
r, out = mt({"wrangler.toml": RL, "src/a.ts": "export async function say(env, text) {\n  const used = Number(await env.CACHE.get(`tts:count:${day}`)) || 0\n  if (used >= 20) return null\n  await env.CACHE.put(`tts:count:${day}`, String(used + 1))\n  return fetch('https://api.elevenlabs.io/v1/text-to-speech/x', { method: 'POST', body: text })\n}\n"}, "meter.elevenlabs")
T.expect("meter: an ElevenLabs call after a day-keyed counter passes", r.get("status") == "PASS", out[-200:])

# --- Phase 8: spend / auth / metering regressions ---
# One fixture per former benchmark known miss (bench/cases/secure_app_spend_auth.py, 2026-11-01), in the
# bench case's shape; every new FAIL-capable path is shown FAILing on its bad fixture and quiet on a decoy.
PAID = "export async function ask(env, prompt){ return fetch('https://api.anthropic.com/v1/messages') }\n"
# spend.unset-cap: a string default of "inf" through float()/Number() is an unlimited cap
s, out = st("check_spend.py", {"app/main.py": 'import os\nimport anthropic\nclient = anthropic.Anthropic()\nDAILY_CAP_USD = float(os.environ.get("DAILY_CAP_USD", "inf"))\n'}, "spend.unset-cap")
T.expect("P8 spend: float(os.environ.get(CAP, \"inf\")) is an unlimited fallback", s == "FAIL" and "inf" in out, out[-200:])
s, out = st("check_spend.py", {"src/a.ts": "const limit = Number(env.DAILY_LIMIT ?? 'Infinity')\n" + PAID}, "spend.unset-cap")
T.expect("P8 spend: Number(env.LIMIT ?? 'Infinity') is an unlimited fallback", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"app/main.py": 'import os\nimport anthropic\nPORT = int(os.environ.get("PORT", "8080"))\nDAILY_CAP_USD = float(os.environ.get("DAILY_CAP_USD", "0"))\n'}, "spend.unset-cap")
T.expect("P8 spend: a non-cap env default and a cap defaulting to 0 are not unlimited", s == "PASS", out[-200:])
# spend.unset-cap: NaN passes a "within" guard; the same test before an "over" comparison pauses
s, out = st("check_spend.py", {"src/limits.ts": "export function withinDailyLimit(env, used) {\n  const limit = Number(env.AI_DAILY_LIMIT)\n  return Number.isNaN(limit) || used < limit\n}\n" + PAID}, "spend.unset-cap")
T.expect("P8 spend: `isNaN(limit) || used < limit` lets an unset limit through", s == "FAIL" and "unparseable" in out, out[-200:])
s, out = st("check_spend.py", {"src/spend.ts": "export async function overDailySpendCap(env) {\n  const cap = Number(env.DAILY_SPEND_CAP_USD)\n  if (!Number.isFinite(cap) || cap <= 0) return true\n  return false\n}\n" + PAID}, "spend.unset-cap")
T.expect("P8 spend: `!isFinite(cap) || cap <= 0) return true` pauses and passes", s == "PASS", out[-200:])
# spend.open-proxy: the proxy split across two files, the bound in the helper, and a helper fed no request input
GEO = "export async function reverseGeocode(lat, lng, env) {\n  const r = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${env.MAPS_KEY}`)\n  return r.json()\n}\n"
split = {"src/geo.ts": GEO, "src/index.ts": "import { reverseGeocode } from './geo'\napp.get('/api/reverse', async (c) => c.json(await reverseGeocode(c.req.query('lat') ?? '', c.req.query('lng') ?? '', c.env)))\n"}
s, out = st("check_spend.py", split, "spend.open-proxy")
T.expect("P8 spend: request input handed to an imported helper that fetches a third party is an open proxy", s == "FAIL" and "via src/geo.ts:reverseGeocode" in out, out[-200:])
bounded = dict(split, **{"src/geo.ts": "import { isInServiceArea } from './area'\n" + GEO.replace("  const r =", "  if (!isInServiceArea(Number(lat), Number(lng))) throw new Error('outside the service area')\n  const r =")})
s, out = st("check_spend.py", bounded, "spend.open-proxy")
T.expect("P8 spend: a bound inside the helper covers the split proxy", s == "PASS", out[-200:])
rc, c, out = T.run(os.path.join(S, "check_spend.py"), T.tree({"src/geo.ts": GEO, "src/index.ts": "import { reverseGeocode } from './geo'\napp.get('/api/home', async (c) => { const who = c.req.query('who'); return c.json(await reverseGeocode('10.1', '20.1', c.env)) })\n"}))
T.expect("P8 spend: a helper called with fixed values forwards no request input (no proxy finding)", c.get("spend.open-proxy", {}).get("status") != "FAIL", out[-200:])
# spend.per-client: a limiter keyed on a caller-chosen value is no limiter
s, out = st("check_spend.py", {"wrangler.toml": "[[ratelimits]]\nname = \"AI_LIMITER\"\n", "src/index.ts": "app.post('/api/hint', async (c) => {\n  const { userId, question } = await c.req.json()\n  const { success } = await c.env.AI_LIMITER.limit({ key: String(userId) })\n  if (!success) return c.json({ error: 'slow down' }, 429)\n  return c.json(await fetch('https://api.anthropic.com/v1/messages'))\n})\n"}, "spend.per-client")
T.expect("P8 spend: a limiter keyed on a body userId fails", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/index.ts": "app.post('/api/hint', async (c) => {\n  const uid = c.req.query('userId')\n  if (!limiter.hit(uid)) return c.json({ error: 'slow down' }, 429)\n  return c.json(await fetch('https://api.anthropic.com/v1/messages'))\n})\n"}, "spend.per-client")
T.expect("P8 spend: a limiter keyed on a query userId fails", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/index.ts": "app.post('/api/ask', async (c) => {\n  const clientIp = c.req.header('cf-connecting-ip') ?? 'unknown'\n  if (!allowClient(clientIp)) return c.json({ error: 'too many requests' }, 429)\n  const { q } = await c.req.json()\n  return c.json(await fetch('https://api.anthropic.com/v1/messages'))\n})\n"}, "spend.per-client")
T.expect("P8 spend: a limiter keyed on cf-connecting-ip passes", s == "PASS", out[-200:])
# spend.llm-params: a schema-parsed copy of the request is still the request
zod = {"package.json": json.dumps({"dependencies": {"openai": "4", "zod": "3"}}),
       "src/index.ts": "import OpenAI from 'openai'\nimport { z } from 'zod'\nconst Req = z.object({ model: z.string(), max_tokens: z.number() })\napp.post('/api/draft', async (c) => {\n  const input = Req.parse(await c.req.json())\n  const client = new OpenAI()\n  return c.json(await client.chat.completions.create({ model: input.model, max_tokens: input.max_tokens, messages: [] }))\n})\n"}
s, out = st("check_spend.py", zod, "spend.llm-params")
T.expect("P8 spend: zod-parsed input.model and input.max_tokens are caller-chosen", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/index.ts": "app.post('/api/draft', async (c) => {\n  const parsed = Req.safeParse(await c.req.json())\n  return c.json(await fetch('https://api.anthropic.com/v1/messages', { body: JSON.stringify({ model: 'claude-haiku-4-5', max_tokens: parsed.data.max_tokens }) }))\n})\n"}, "spend.llm-params")
T.expect("P8 spend: safeParse(...).data.max_tokens is caller-chosen", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/index.ts": "const ALLOWED = ['claude-haiku-4-5']\napp.post('/api/chat', async (c) => {\n  const body = await c.req.json()\n  const chosen = ALLOWED.includes(body.model) ? body.model : ALLOWED[0]\n  const budget = Math.min(Number(body.max_tokens) || 512, 1024)\n  return c.json(await fetch('https://api.anthropic.com/v1/messages', { body: JSON.stringify({ model: chosen, max_tokens: budget }) }))\n})\n"}, "spend.llm-params")
T.expect("P8 spend: an allow-listed model and a clamped max_tokens pass", s == "PASS", out[-200:])

# auth.off-switch: the secret destructured or aliased into a local; the guard must be auth-shaped
r, out = ag({"wrangler.toml": W_PLAIN, "src/index.ts": "app.use('/api/admin/*', async (c, next) => {\n  const { ADMIN_TOKEN } = c.env\n  if (!ADMIN_TOKEN) return next()\n  return bearerAuth({ token: ADMIN_TOKEN })(c, next)\n})\n"}, "auth.off-switch")
T.expect("P8 auth: `const { ADMIN_TOKEN } = c.env; if (!ADMIN_TOKEN) return next()` is an off-switch", r.get("status") == "FAIL" and "ADMIN_TOKEN" in r.get("evidence", ""), out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/index.ts": "app.use('/api/*', async (c, next) => {\n  const token = c.env.SESSION_SECRET\n  if (!token) return next()\n  const s = await getSession(c, token)\n  if (!s) return c.json({}, 401)\n  await next()\n})\n"}, "auth.off-switch")
T.expect("P8 auth: an aliased secret (`const token = env.SESSION_SECRET`) is followed", r.get("status") == "FAIL" and "SESSION_SECRET" in r.get("evidence", ""), out[-200:])
BEACON = "export const pageviews = async (c, next) => {\n  if (!c.env.%s) return next()\n  c.executionCtx.waitUntil(fetch('https://plausible.example.net/api/event', { method: 'POST', headers: { authorization: `Bearer ${c.env.%s}` } }))\n  await next()\n}\n"
r, out = ag({"wrangler.toml": W_PLAIN, "src/analytics.ts": BEACON % ("ANALYTICS_TOKEN", "ANALYTICS_TOKEN")}, "auth.off-switch")
T.expect("P8 auth: a skipped analytics beacon is a feature flag, not an auth off-switch", r.get("status") == "PASS", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/analytics.ts": BEACON % ("AUTH_TOKEN", "AUTH_TOKEN")}, "auth.off-switch")
T.expect("P8 auth: the same skip on an auth-named secret still fails", r.get("status") == "FAIL", out[-200:])
# auth.header-identity: the auth-proxy header family
r, out = ag({"package.json": json.dumps({"dependencies": {"express": "4"}}), "lib/user.js": "function currentUser(req) {\n  const email = req.headers['x-forwarded-email']\n  return email ? { email } : null\n}\nmodule.exports = { currentUser }\n"}, "auth.header-identity")
T.expect("P8 auth: identity from x-forwarded-email with no verification fails", r.get("status") == "FAIL" and "x-forwarded-email" in r.get("evidence", ""), out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/id.ts": "const u = request.headers.get('Remote-User')\n"}, "auth.header-identity")
T.expect("P8 auth: identity from Remote-User fails", r.get("status") == "FAIL", out[-200:])
# auth.access-jwt: decodeJwt is not verification; jose imported but never called is not verification; options in a const count
DECODE = "import { decodeJwt } from 'jose'\nconst ACCESS = { issuer: 'https://t.cloudflareaccess.com', audience: 'aud' }\nexport const requireAccess = async (c, next) => {\n  const token = c.req.header('Cf-Access-Jwt-Assertion')\n  if (!token) return c.json({}, 401)\n  const claims = decodeJwt(token)\n  if (claims.iss !== ACCESS.issuer) return c.json({}, 401)\n  await next()\n}\n"
r, out = ag({"wrangler.toml": W_ROUTED, "src/access.ts": DECODE}, "auth.access-jwt")
T.expect("P8 auth: decodeJwt with a hand-compared iss and aud fails high and names decodeJwt", r.get("status") == "FAIL" and r.get("severity") == "high" and "decodeJwt" in r.get("evidence", ""), out[-200:])
r, out = ag({"wrangler.toml": W_ROUTED, "src/access.ts": "import * as jose from 'jose'\nconst token = c.req.header('Cf-Access-Jwt-Assertion')\n"}, "auth.access-jwt")
T.expect("P8 auth: importing jose without a verify call is not verification", r.get("status") == "FAIL" and r.get("severity") == "high", out[-200:])
r, out = ag({"wrangler.toml": W_ROUTED, "src/access.ts": "import { jwtVerify } from 'jose'\nconst opts = { issuer: TEAM, audience: AUD }\nconst t = c.req.header('Cf-Access-Jwt-Assertion')\nconst { payload } = await jwtVerify(t, JWKS, opts)\n"}, "auth.access-jwt")
T.expect("P8 auth: jwtVerify with issuer and audience in an options const passes", r.get("status") == "PASS", out[-200:])
r, out = ag({"wrangler.toml": W_ROUTED, "src/access.ts": "import { jwtVerify } from 'jose'\nconst unrelated = { issuer: 'x', audience: 'y' }\nconst t = c.req.header('Cf-Access-Jwt-Assertion')\nconst { payload } = await jwtVerify(t, JWKS)\n"}, "auth.access-jwt")
T.expect("P8 auth: issuer and audience elsewhere in the file do not count for a bare jwtVerify", r.get("status") == "FAIL" and r.get("severity") == "medium", out[-200:])
# auth.open-signup: a nested option before enabled; a hook built in another file; a Worker-level refusal that fails closed
BA = "import { betterAuth } from 'better-auth'\n%s\nexport const auth = betterAuth({\n  emailAndPassword: {\n    password: { hash: hashPw, verify: verifyPw },\n    enabled: true,\n  },\n%s})\n"
r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": BA % ("", "")}, "auth.open-signup")
T.expect("P8 auth: open sign-up with a nested password: {...} option before enabled: true fails", r.get("status") == "FAIL", out[-200:])
HOOKS = "export function inviteOnlyHooks(env) {\n  return { user: { create: { before: async (user) => { if (!(await invited(env, user.email))) throw new APIError('FORBIDDEN'); return { data: user } } } } }\n}\n"
r, out = ag({"wrangler.toml": W_PLAIN, "src/hooks.ts": HOOKS, "src/auth.ts": BA % ("import { inviteOnlyHooks } from './hooks'", "  databaseHooks: inviteOnlyHooks(env),\n")}, "auth.open-signup")
T.expect("P8 auth: a user.create.before hook built in an imported file closes sign-up", r.get("status") == "PASS", out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/hooks.ts": "export function inviteOnlyHooks(env) {\n  return { session: { create: { after: async () => {} } } }\n}\n", "src/auth.ts": BA % ("import { inviteOnlyHooks } from './hooks'", "  databaseHooks: inviteOnlyHooks(env),\n")}, "auth.open-signup")
T.expect("P8 auth: an imported hook object without user.create.before still fails", r.get("status") == "FAIL", out[-200:])
WORKER = "import { createAuth } from './auth'\nfunction inviteOk(req, env) {\n  if (!env.INVITE_SECRET) return %s\n  return req.headers.get('x-invite-secret') === env.INVITE_SECRET\n}\nexport default {\n  async fetch(req, env) {\n    const path = new URL(req.url).pathname.toLowerCase()\n    if (path.includes('sign-up') && !inviteOk(req, env)) {\n      return Response.json({ error: 'invite only' }, { status: 403 })\n    }\n    return createAuth(env).handler(req)\n  },\n}\n"
BA_FN = "import { betterAuth } from 'better-auth'\nexport function createAuth(env) {\n  return betterAuth({ emailAndPassword: { enabled: true }, secret: env.BETTER_AUTH_SECRET })\n}\n"
r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": BA_FN, "src/worker.ts": WORKER % "false"}, "auth.open-signup")
T.expect("P8 auth: a Worker entry refusing /api/auth/sign-up* (fails closed) passes with a reference detail", r.get("status") == "PASS" and "worker.ts" in r.get("evidence", "") and "reference" in r.get("detail", ""), out[-200:])
r, out = ag({"wrangler.toml": W_PLAIN, "src/auth.ts": BA_FN, "src/worker.ts": WORKER % "true"}, "auth.open-signup")
T.expect("P8 auth: the same refusal whose helper returns true when the secret is unset fails open and FAILs", r.get("status") == "FAIL", out[-200:])

# meter: a name containing Daily is not a counter; a body-destructured key is caller-supplied
r, out = mt({"wrangler.toml": RL, "src/digest.ts": "export function buildDailyDigest(items) { return items.slice(0, 20).join('\\n') }\n",
             "src/index.ts": "import { buildDailyDigest } from './digest'\napp.post('/api/digest', async (c) => {\n  const { items } = await c.req.json()\n  const digest = buildDailyDigest(items)\n  const r = await fetch('https://api.anthropic.com/v1/messages')\n  return c.json(await r.json())\n})\n"}, "meter.anthropic")
T.expect("P8 meter: buildDailyDigest() above the call is not a reservation (FAIL high)", r.get("status") == "FAIL" and r.get("severity") == "high", out[-200:])
r, out = mt({"wrangler.toml": RL, "src/index.ts": "app.post('/api/quiz', async (c) => {\n  const { deviceId, topic } = await c.req.json()\n  const day = new Date().toISOString().slice(0, 10)\n  const used = Number(await c.env.USAGE.get(`quota:${deviceId}:${day}`)) || 0\n  if (used >= 30) return c.json({}, 429)\n  await c.env.USAGE.put(`quota:${deviceId}:${day}`, String(used + 1))\n  const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/x:generateContent')\n  return c.json(await r.json())\n})\n"}, "meter.google-gemini")
T.expect("P8 meter: a counter keyed on a body-destructured deviceId fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium" and "caller-supplied" in r.get("evidence", ""), out[-200:])
# meter: Python defs are functions; a Redis incr or a reserve_* call before the call is a counter
PY_RESERVE = "import datetime\n\nDAILY_CALLS = 400\n\n\ndef reserve_daily_call(r) -> bool:\n    key = \"llm:count:\" + datetime.date.today().isoformat()\n    n = r.incr(key)\n    return n <= DAILY_CALLS\n"
PY_MAIN = "import httpx\nimport redis\nfrom fastapi import FastAPI, HTTPException, Request\nfrom app.meter import reserve_daily_call\n\napp = FastAPI()\nstore = redis.Redis()\n\n\n@app.post(\"/api/summarize\")\nasync def summarize(req: Request):\n%s    body = await req.json()\n    r = httpx.post(\"https://api.openai.com/v1/chat/completions\", json={\"model\": \"gpt-4o-mini\"})\n    return r.json()\n"
r, out = mt({"requirements.txt": "fastapi\nredis\n", "app/meter.py": PY_RESERVE, "app/main.py": PY_MAIN % "    if not reserve_daily_call(store):\n        raise HTTPException(status_code=429)\n"}, "meter.openai")
T.expect("P8 meter: a FastAPI def that reserves a Redis daily counter before the call passes", r.get("status") == "PASS", out[-200:])
r, out = mt({"requirements.txt": "fastapi\nredis\n", "app/main.py": PY_MAIN % "    key = \"llm:count:\" + day\n    if store.incr(key) > 400:\n        raise HTTPException(status_code=429)\n"}, "meter.openai")
T.expect("P8 meter: a Redis incr on a count key inside the def is a counter", r.get("status") == "PASS", out[-200:])
r, out = mt({"requirements.txt": "fastapi\n", "app/main.py": PY_MAIN % ""}, "meter.openai")
T.expect("P8 meter: a Python def with no counter still fails high, naming the def (not 'top level')", r.get("status") == "FAIL" and r.get("severity") == "high" and "summarize" in r.get("evidence", "") and "top level" not in r.get("evidence", ""), out[-200:])
# meter.ratelimit-binding: declared is not called
UNCALLED = "const DAILY = 300\napp.post('/api/tagline', async (c) => {\n  const n = Number(await c.env.USAGE.get(`ai:count:${day}`)) || 0\n  if (n >= DAILY) return c.json({}, 429)\n  await c.env.USAGE.put(`ai:count:${day}`, String(n + 1))\n  return c.json(await fetch('https://api.openai.com/v1/chat/completions'))\n})\n"
r, out = mt({"wrangler.toml": RL, "src/index.ts": UNCALLED}, "meter.ratelimit-binding")
T.expect("P8 meter: a [[ratelimits]] binding declared but never .limit()ed fails medium", r.get("status") == "FAIL" and r.get("severity") == "medium" and "AI_LIMITER" in r.get("evidence", ""), out[-200:])
r, out = mt({"wrangler.jsonc": '{\n  "name": "t",\n  "ratelimits": [{ "name": "AI_LIMITER", "namespace_id": "1001", "simple": { "limit": 20, "period": 60 } }]\n}\n',
             "src/index.ts": UNCALLED.replace("  const n =", "  const { success } = await c.env.AI_LIMITER.limit({ key: c.req.header('cf-connecting-ip') ?? 'anon' })\n  if (!success) return c.json({}, 429)\n  const n =")}, "meter.ratelimit-binding")
T.expect("P8 meter: a jsonc-declared binding that the route calls passes and names the call", r.get("status") == "PASS" and "index.ts" in r.get("evidence", ""), out[-200:])

# --- Phase 8: check_app / check_fetch regressions ---
# Each former benchmark known_miss (bench/cases/secure_app_routes.py, 2026-11-01) as a unit fixture: the bad
# shape FAILs, its safe neighbor PASSes. Shapes follow the bench cases; no key-shaped strings.
HONO_PKG8 = {"package.json": json.dumps({"dependencies": {"hono": "4.6.0"}}), "wrangler.toml": 'name = "notes"\nmain = "src/index.ts"\n'}
NODE_PKG8 = {"package.json": json.dumps({"dependencies": {"express": "4.21.0", "undici": "6.21.0", "@hono/node-server": "1.13.0"}}), "fly.toml": 'app = "x"\n'}

def app8(files, cid):
    return st("check_app.py", dict(HONO_PKG8, **files), cid)

def fetch8(files, cid, base=NODE_PKG8):
    return st("check_fetch.py", dict(base, **files), cid)

# app.debug-routes: the debug word starting a hyphenated segment
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/api/debug-info', (c) => c.json({ bindings: Object.keys(c.env) }))\nexport default app\n"}, "app.debug-routes")
T.expect("p8 debug: /api/debug-info (hyphenated) fails", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/api/seeds', (c) => c.json([]))\napp.get('/api/environments', (c) => c.json([]))\napp.post('/api/password/reset', (c) => c.text('ok'))\nexport default app\n"}, "app.debug-routes")
T.expect("p8 debug: /api/seeds, /api/environments, /api/password/reset are products, PASS", s == "PASS", out[-200:])

# app.signout: an audit-log INSERT is not a revocation; a session-table write is
SIGNOUT8 = "import { Hono } from 'hono'\nimport { deleteCookie } from 'hono/cookie'\nconst app = new Hono()\napp.post('/api/logout', async (c) => {\n  await c.env.DB.prepare('%s').bind(1).run()\n  deleteCookie(c, 'session', { path: '/' })\n  return c.redirect('/')\n})\nexport default app\n"
s, out = app8({"src/index.ts": SIGNOUT8 % "INSERT INTO audit_log (user_id, event) VALUES (?, ?)"}, "app.signout")
T.expect("p8 signout: a .prepare( INSERT into audit_log revokes nothing, FAIL", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": SIGNOUT8 % "INSERT INTO revoked_sessions (hash, expires_at) VALUES (?, ?)"}, "app.signout")
T.expect("p8 signout: an INSERT into revoked_sessions passes", s == "PASS", out[-200:])
s, out = app8({"src/index.ts": SIGNOUT8 % "DELETE FROM sessions WHERE id = ?"}, "app.signout")
T.expect("p8 signout: a DELETE FROM sessions passes", s == "PASS", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.post('/api/logout', async (c) => {\n  // INSERT INTO revoked_sessions happens in a later ticket\n  deleteCookie(c, 'session')\n  return c.redirect('/')\n})\nexport default app\n"}, "app.signout")
T.expect("p8 signout: a session-table write in a comment is not a revocation", s == "FAIL", out[-200:])

# app.object-writes: ownerId from the request body; a 403 whose condition names no identity
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.patch('/api/notes/:id', async (c) => {\n  const { ownerId, body } = await c.req.json()\n  await c.env.DB.prepare('UPDATE notes SET body = ? WHERE id = ? AND owner = ?').bind(body, c.req.param('id'), ownerId).run()\n  return c.json({ ok: true })\n})\nexport default app\n"}, "app.object-writes")
T.expect("p8 object-writes: ownerId destructured from c.req.json() is not an owner check, FAIL", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.patch('/api/notes/:id', async (c) => {\n  const body = await c.req.json()\n  await c.env.DB.prepare('UPDATE notes SET body = ? WHERE id = ? AND owner = ?').bind(body.text, c.req.param('id'), body.ownerId).run()\n  return c.json({ ok: true })\n})\nexport default app\n"}, "app.object-writes")
T.expect("p8 object-writes: body.ownerId is not an owner check, FAIL", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.patch('/api/notes/:id', async (c) => {\n  const user = await requireUser(c)\n  const { ownerId, body } = await c.req.json()\n  await c.env.DB.prepare('UPDATE notes SET body = ? WHERE id = ? AND owner = ?').bind(body, c.req.param('id'), user.id).run()\n  return c.json({ ok: true })\n})\nexport default app\n"}, "app.object-writes")
T.expect("p8 object-writes: a request ownerId beside a real requireUser still passes", s == "PASS", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.put('/api/notes/:id', async (c) => {\n  const note = await c.env.DB.prepare('SELECT locked FROM notes WHERE id = ?').bind(c.req.param('id')).first()\n  if (!note) return c.json({ error: 'not found' }, 404)\n  if (note.locked) return c.json({ error: 'Forbidden' }, 403)\n  await c.env.DB.prepare('UPDATE notes SET body = ?').run()\n  return c.json({ ok: true })\n})\nexport default app\n"}, "app.object-writes")
T.expect("p8 object-writes: a 403 that only refuses locked notes is not a gate, FAIL", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.put('/api/notes/:id', async (c) => {\n  const user = c.get('user')\n  const note = await c.env.DB.prepare('SELECT owner FROM notes WHERE id = ?').bind(c.req.param('id')).first()\n  if (note.owner !== user.id) return c.json({ error: 'Forbidden' }, 403)\n  await c.env.DB.prepare('UPDATE notes SET body = ?').run()\n  return c.json({ ok: true })\n})\nexport default app\n"}, "app.object-writes")
T.expect("p8 object-writes: a 403 whose condition compares the owner to the user passes", s == "PASS", out[-200:])
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"next": "16.0.1"}}), "app/api/notes/[id]/route.ts": "export async function PATCH(req: Request) {\n  const session = await auth()\n  if (!session) return new Response(null, { status: 401 })\n  const { body } = await req.json()\n  await db.note.updateMany({ where: { id: 'x', ownerId: session.user.id }, data: { body } })\n  return Response.json({ ok: true })\n}\n"}, "app.object-writes")
T.expect("p8 object-writes: ownerId from the session with a 401 on no session passes", s == "PASS", out[-200:])

# app.object-writes: a raw Worker fetch handler routed by pathname.startsWith and request.method
WORKER8 = "export default {\n  async fetch(request: Request, env: Env): Promise<Response> {\n    const url = new URL(request.url)\n    if (url.pathname.startsWith('/api/notes/') && request.method === '%s') {\n      const id = url.pathname.split('/').pop()\n      await env.DB.prepare('DELETE FROM notes WHERE id = ?').bind(id).run()\n      return new Response(null, { status: 204 })\n    }\n    return new Response('not found', { status: 404 })\n  },\n}\n"
s, out = st("check_app.py", {"wrangler.toml": 'name = "w"\n', "src/index.ts": WORKER8 % "DELETE"}, "app.object-writes")
T.expect("p8 object-writes: pathname.startsWith('/api/notes/') + method DELETE with no auth fails", s == "FAIL" and "DELETE /api/notes/*" in out, out[-300:])
s, out = st("check_app.py", {"wrangler.toml": 'name = "w"\n', "src/index.ts": WORKER8 % "GET"}, "app.object-writes")
T.expect("p8 object-writes: the same prefix on GET is not a write route", s == "PASS", out[-200:])

# app.header-identity: bracket form, FastAPI Header(), and a response-header WRITE
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"express": "4"}}), "src/identity.js": "export function currentUser(req, res, next) {\n  const id = req.headers['x-user-id']\n  if (!id) return res.status(401).end()\n  req.user = { id: String(id) }\n  next()\n}\n"}, "app.header-identity")
T.expect("p8 header-identity: req.headers['x-user-id'] fails", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"requirements.txt": "fastapi\n", "app/main.py": "from fastapi import FastAPI, Header\napp = FastAPI()\n\n@app.get('/notes')\ndef list_notes(x_user_id: str = Header(...)):\n    return []\n"}, "app.header-identity")
T.expect("p8 header-identity: FastAPI x_user_id: str = Header(...) fails", s == "FAIL", out[-200:])
s, out = st("check_app.py", {"requirements.txt": "flask\n", "app.py": "@app.get('/notes')\ndef notes():\n    uid = request.headers.get('x-user-id', None)\n    return db.notes(uid)\n"}, "app.header-identity")
T.expect("p8 header-identity: a two-argument headers.get('x-user-id', default) READ fails", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/api/me', async (c) => {\n  const user = c.get('user')\n  c.header('X-Tenant-Id', String(user.tenant))\n  return c.json({ id: user.id })\n})\nexport default app\n"}, "app.header-identity")
T.expect("p8 header-identity: c.header('X-Tenant-Id', value) writes a response header, PASS", s == "PASS", out[-200:])

# app.cors: Fastify register(cors, {...})
FASTIFY8 = {"package.json": json.dumps({"dependencies": {"fastify": "5.1.0", "@fastify/cors": "10.0.1"}})}
s, out = st("check_app.py", dict(FASTIFY8, **{"src/server.js": "import Fastify from 'fastify'\nimport cors from '@fastify/cors'\nconst app = Fastify()\nawait app.register(cors, { origin: true, credentials: true })\n"}), "app.cors")
T.expect("p8 cors: app.register(cors, { origin: true, credentials: true }) fails", s == "FAIL", out[-200:])
s, out = st("check_app.py", dict(FASTIFY8, **{"src/server.js": "import Fastify from 'fastify'\nconst app = Fastify()\nawait app.register(require('@fastify/cors'), { credentials: true, origin: (o, cb) => cb(null, true) })\n"}), "app.cors")
T.expect("p8 cors: register(require('@fastify/cors'), approve-all callback) fails", s == "FAIL", out[-200:])
s, out = st("check_app.py", dict(FASTIFY8, **{"src/server.js": "import Fastify from 'fastify'\nimport cors from '@fastify/cors'\nconst app = Fastify()\nawait app.register(cors, { origin: ['https://app.example.com'], credentials: true })\n"}), "app.cors")
T.expect("p8 cors: register(cors) with an origin list passes", s == "PASS", out[-200:])

# app.error-leak: the stack copied into a local first
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.onError((err, c) => {\n  const detail = err.stack\n  return c.json({ error: 'internal', detail }, 500)\n})\nexport default app\n"}, "app.error-leak")
T.expect("p8 error-leak: const detail = err.stack then c.json({ detail }) fails", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.onError((err, c) => {\n  const { stack } = err\n  return new Response(stack, { status: 500 })\n})\nexport default app\n"}, "app.error-leak")
T.expect("p8 error-leak: const { stack } = err then new Response(stack) fails", s == "FAIL", out[-200:])
s, out = app8({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.onError((err, c) => {\n  const detail = err.stack\n  console.error(detail)\n  return c.json({ error: 'internal' }, 500)\n})\nexport default app\n"}, "app.error-leak")
T.expect("p8 error-leak: a stack local that is only logged passes", s == "PASS", out[-200:])

# fetch: undici request(), only where undici is imported
UNDICI8 = "import express from 'express'\nimport { request } from 'undici'\nconst app = express()\napp.get('/api/fetch-title', async (req, res) => {\n  const target = String(req.query.url)\n  const { body } = await request(target, { maxRedirections: 3 })\n  res.json({ n: (await body.text()).length })\n})\n"
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(NODE_PKG8, **{"src/server.js": UNDICI8})))
T.status_is("p8 fetch: undici request(target) from req.query is request-url", c, "fetch.request-url", "FAIL", out)
T.status_is("p8 fetch: undici request(target) is a raw data-URL fetch", c, "fetch.data-url", "FAIL", out)
T.expect("p8 fetch: on a Node host the request-url FAIL is high", c.get("fetch.request-url", {}).get("severity") == "high")
s, out = fetch8({"src/server.js": UNDICI8.replace("import { request } from 'undici'\n", "")}, "fetch.request-url")
T.expect("p8 fetch: request(target) with no client import is some other function, PASS", s == "PASS", out[-200:])

# fetch: the request value handed to a helper in another file
HELPER_APP8 = "import { Hono } from 'hono'\nimport { importFeed } from './lib/feeds'\nconst app = new Hono()\napp.post('/api/feeds', async (c) => {\n  const { url } = await c.req.json()\n  const feed = await importFeed(url)\n  return c.json({ n: feed.length })\n})\n"
s, out = fetch8({"src/index.ts": HELPER_APP8, "src/lib/feeds.ts": "export async function importFeed(feedUrl: string) {\n  const res = await fetch(feedUrl, { headers: { accept: 'application/rss+xml' } })\n  return res.text()\n}\n"}, "fetch.request-url")
T.expect("p8 fetch: a body URL fetched raw by importFeed() in another file fails and names the helper", s == "FAIL" and "via importFeed()" in out and "feeds.ts" in out, out[-300:])
s, out = fetch8({"src/index.ts": HELPER_APP8, "src/lib/feeds.ts": "export async function importFeed(feedUrl: string) {\n  const u = new URL(feedUrl)\n  const res = await fetch(u)\n  return res.text()\n}\n"}, "fetch.request-url")
T.expect("p8 fetch: the helper wrapping the parameter in new URL() still fails", s == "FAIL", out[-200:])
s, out = fetch8({"src/index.ts": HELPER_APP8, "src/lib/feeds.ts": "export async function importFeed(feedUrl: string) {\n  return pull(feedUrl)\n}\nasync function pull(target: string) {\n  return (await fetch(target)).text()\n}\n"}, "fetch.request-url")
T.expect("p8 fetch: two helper hops deep still fails", s == "FAIL", out[-200:])
s, out = fetch8({"src/index.ts": HELPER_APP8, "src/lib/feeds.ts": "import { safeFetch } from './safeFetch'\nexport async function importFeed(feedUrl: string) {\n  return (await safeFetch(feedUrl)).text()\n}\n",
                 "src/lib/safeFetch.ts": "import ipaddr from 'ipaddr.js'\nexport async function safeFetch(input: string) {\n  const u = new URL(input)\n  if (ipaddr.parse(await resolve(u.hostname)).range() !== 'unicast') throw new Error('blocked')\n  return fetch(u)\n}\n"}, "fetch.request-url")
T.expect("p8 fetch: a helper that goes through safeFetch passes", s == "PASS", out[-200:])

# fetch: destructured searchParams, and a caller-chosen host inside a template
s, out = fetch8({"app/api/img/route.ts": "export async function GET(req: Request) {\n  const { searchParams } = new URL(req.url)\n  const image = searchParams.get('image')\n  const upstream = await fetch(image)\n  return new Response(upstream.body)\n}\n"}, "fetch.request-url", base={"package.json": json.dumps({"dependencies": {"next": "16.0.1"}})})
T.expect("p8 fetch: const { searchParams } = new URL(req.url) feeding fetch fails", s == "FAIL", out[-200:])
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(NODE_PKG8, **{"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/api/status', async (c) => {\n  const host = c.req.query('host')\n  const r = await fetch(`https://${host}/health`)\n  return c.json({ up: r.ok })\n})\n"})))
T.status_is("p8 fetch: `https://${host}/health` with host from the query is request-url", c, "fetch.request-url", "FAIL", out)
T.status_is("p8 fetch: a variable host is a raw data-URL fetch", c, "fetch.data-url", "FAIL", out)
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(NODE_PKG8, **{"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.get('/api/w', async (c) => {\n  const city = c.req.query('city')\n  const r = await fetch(`https://api.weather.example/v1?city=${encodeURIComponent(city)}`)\n  return c.json(await r.json())\n})\n"})))
T.status_is("p8 fetch: a fixed host with the request value in the query string passes request-url", c, "fetch.request-url", "PASS", out)
T.status_is("p8 fetch: ...and data-url", c, "fetch.data-url", "PASS", out)

# fetch: a request KEY into a constant allowlist map
MAP_APP8 = "import { Hono } from 'hono'\nconst SOURCES: Record<string, { url: string }> = {\n  city: { url: 'https://news.example.org/city.rss' },\n  sports: { url: 'https://news.example.org/sports.rss' },\n}\nconst app = new Hono()\napp.get('/api/feed', async (c) => {\n  const src = SOURCES[c.req.query('feed') ?? '']\n  if (!src) return c.json({ error: 'unknown feed' }, 400)\n  const r = await fetch(src.url)\n  return c.text(await r.text())\n})\n"
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(HONO_PKG8, **{"src/index.ts": MAP_APP8})))
T.status_is("p8 fetch: SOURCES[c.req.query('feed')].url is an allowlisted URL, request-url PASS", c, "fetch.request-url", "PASS", out)
T.status_is("p8 fetch: ...and data-url PASS", c, "fetch.data-url", "PASS", out)
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(HONO_PKG8, **{"src/index.ts": MAP_APP8.replace("'https://news.example.org/sports.rss'", "`https://${c.env.FEED_HOST}/sports.rss`")})))
T.status_is("p8 fetch: a map whose URLs are not all fixed-host literals is not an allowlist, request-url FAIL", c, "fetch.request-url", "FAIL", out)

# fetch: new Request(storedUrl) is the stored URL, not the incoming request
s, out = fetch8({"src/deliver.ts": "export async function deliverPending(env: Env) {\n  const { results } = await env.DB.prepare('SELECT url, payload FROM webhook_jobs').all()\n  for (const hook of results) {\n    const request = new Request(hook.url, { method: 'POST', body: hook.payload })\n    const res = await fetch(request)\n    await env.DB.prepare('UPDATE webhook_jobs SET status = ?').bind(res.status).run()\n  }\n}\n"}, "fetch.data-url", base={"wrangler.toml": 'name = "w"\n[triggers]\ncrons = ["*/5 * * * *"]\n'})
T.expect("p8 fetch: fetch(request) where request = new Request(hook.url) is a raw data-URL fetch (Worker: low)", s == "FAIL", out[-300:])
s, out = fetch8({"src/index.ts": "export default {\n  fetch(request: Request, env: Env) {\n    if (new URL(request.url).pathname.startsWith('/assets')) return env.ASSETS.fetch(request)\n    return fetch(request)\n  },\n}\n"}, "fetch.data-url", base={"wrangler.toml": 'name = "w"\n'})
T.expect("p8 fetch: proxying the incoming Request still passes", s == "PASS", out[-200:])
s, out = fetch8({"src/jobs/avatars.ts": "// const request = new Request(hook.url)\n// fetch(request)\nexport async function noop() { return 1 }\n"}, "fetch.data-url")
T.expect("p8 fetch: a commented-out new Request/fetch pair is nothing", s == "PASS", out[-200:])

# fetch: browser-only React code is not a server fetch site
VITE8 = {"package.json": json.dumps({"dependencies": {"react": "19.0.0", "vite": "6.0.0"}})}
s, out = fetch8({"src/hooks/useJson.ts": "import { useEffect, useState } from 'react'\nexport function useJson<T>(url: string) {\n  const [data, setData] = useState<T | null>(null)\n  useEffect(() => { fetch(url).then((r) => r.json()).then(setData) }, [url])\n  return data\n}\n"}, "fetch.data-url", base=VITE8)
T.expect("p8 fetch: fetch(url) inside a React hook runs in the browser, PASS", s == "PASS", out[-200:])
s, out = fetch8({"app/Widget.tsx": "'use client'\nimport React from 'react'\nexport function Widget({ src }: { src: string }) {\n  React.useEffect(() => { fetch(src) }, [src])\n  return null\n}\n"}, "fetch.data-url", base=VITE8)
T.expect("p8 fetch: a 'use client' component passes", s == "PASS", out[-200:])
s, out = fetch8({"src/hooks/useJson.ts": "import { useEffect, useState } from 'react'\nexport function useJson(url) { useEffect(() => { fetch(url) }, [url]) }\n", "src/jobs/ingest.ts": "export async function pull(item: { link: string }) { return (await fetch(item.link)).text() }\n"}, "fetch.data-url", base=VITE8)
T.expect("p8 fetch: a server-side raw fetch in the same repo still fails (the hook file alone is skipped)", s == "FAIL" and "1 browser-only file(s) skipped" in out and "ingest.ts" in out, out[-300:])

# fetch: a guard function exists but a raw site does not call it (FAIL); a guard installed below the call sites (UNKNOWN)
GUARDED8 = {"src/lib/safeFetch.ts": "import ipaddr from 'ipaddr.js'\nimport { lookup } from 'node:dns/promises'\nexport async function safeFetch(input: string) {\n  const u = new URL(input)\n  const { address } = await lookup(u.hostname)\n  if (ipaddr.parse(address).range() !== 'unicast') throw new Error('blocked')\n  return fetch(u, { redirect: 'error' })\n}\n",
            "src/jobs/feeds.ts": "import { safeFetch } from '../lib/safeFetch'\nexport async function pull(item: { link: string }) { return (await safeFetch(item.link)).text() }\n",
            "src/jobs/avatars.ts": "export async function importAvatar(profile: { avatarUrl: string }) {\n  const res = await fetch(profile.avatarUrl)\n  return new Uint8Array(await res.arrayBuffer())\n}\n"}
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(NODE_PKG8, **GUARDED8)))
T.status_is("p8 fetch: safeFetch exists but avatars.ts fetches raw: FAIL, not UNKNOWN", c, "fetch.data-url", "FAIL", out)
T.expect("p8 fetch: that FAIL is high on Node and names the raw site", c.get("fetch.data-url", {}).get("severity") == "high" and "avatars.ts" in c["fetch.data-url"]["evidence"], out[-300:])
rc, c, out = T.run(os.path.join(S, "check_fetch.py"), T.tree(dict(NODE_PKG8, **dict(GUARDED8, **{"src/net.ts": "import { Agent, setGlobalDispatcher } from 'undici'\nsetGlobalDispatcher(new Agent({ connect: { lookup: publicOnlyLookup } }))\n"}))))
T.status_is("p8 fetch: a global dispatcher guard below the call sites keeps the raw site UNKNOWN", c, "fetch.data-url", "UNKNOWN", out)

# --- check_mcp: authorization inside MCP tools (built 2026-11-01) ---
MCP_PKG = json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.20.0", "agents": "0.2.0", "zod": "3.23.8"}})
MCP_HEAD = """import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import * as q from './queries'
export function createServer(deps) {
  const server = new McpServer({ name: 'notes', version: '1.0.0' })
  const viewer = deps.user.id
"""
MCP_TAIL = "  return server\n}\n"
READ_TOOL = """  server.registerTool('read_note', { inputSchema: { note_id: z.string() } }, async ({ note_id }) => {
    const n = await q.getNote(deps.db, viewer, note_id)
    return { content: [{ type: 'text', text: n?.body ?? 'none' }] }
  })
"""
SYNC_GATED = """  server.registerTool('sync', { inputSchema: { space_id: z.string() } }, async ({ space_id }) => {
    if (!deps.user.owner) return { content: [{ type: 'text', text: 'Only an owner can run sync.' }] }
    await q.syncSpace(deps.db, space_id)
    return { content: [{ type: 'text', text: 'ok' }] }
  })
"""
Q_SCOPED = """export async function getNote(db, viewer, id) {
  return db.prepare(`SELECT body FROM notes WHERE id = ? AND owner_id = ?`).bind(id, viewer).first()
}
export async function syncSpace(db, space) {
  await db.prepare(`DELETE FROM notes WHERE space_id = ?`).bind(space).run()
}
"""
def mcp(server, queries, extra=None):
    f = {"package.json": MCP_PKG, "src/server.ts": MCP_HEAD + server + MCP_TAIL, "src/queries.ts": queries}
    f.update(extra or {})
    return T.tree(f)

def mcp_run(repo):
    return T.run(os.path.join(S, "check_mcp.py"), repo)

# known-bad first: every FAIL-capable id seen FAIL
rc, c, out = mcp_run(mcp(READ_TOOL, Q_SCOPED.replace(" AND owner_id = ?", "").replace(".bind(id, viewer)", ".bind(id)")))
T.status_is("mcp: a tool read keyed only on the caller's note id", c, "mcp.tool-scope", "FAIL", out)
T.expect("mcp: that FAIL is high and names queries.ts:2", c.get("mcp.tool-scope", {}).get("severity") == "high" and "src/queries.ts:2" in c["mcp.tool-scope"]["evidence"], out[-300:])
rc, c, out = mcp_run(mcp(READ_TOOL.replace("{ note_id: z.string() }", "{ note_id: z.string(), user_id: z.string() }"), Q_SCOPED))
T.status_is("mcp: a tool taking user_id as an argument", c, "mcp.identity-from-args", "FAIL", out)
rc, c, out = mcp_run(mcp(READ_TOOL + SYNC_GATED.replace("    if (!deps.user.owner) return { content: [{ type: 'text', text: 'Only an owner can run sync.' }] }\n", ""), Q_SCOPED))
T.status_is("mcp: a sync tool with no owner check", c, "mcp.privileged-tools", "FAIL", out)
T.status_is("mcp: the ungated sync's unscoped DELETE is now reachable and FAILs scope too", c, "mcp.tool-scope", "FAIL", out)
NESTED = Q_SCOPED.replace("`SELECT body FROM notes WHERE id = ? AND owner_id = ?`",
                          "`SELECT body FROM notes WHERE owner_id = ? AND created_at < (SELECT created_at FROM notes WHERE id = ?)`").replace(".bind(id, viewer)", ".bind(viewer, id)")
rc, c, out = mcp_run(mcp(READ_TOOL, NESTED))
T.status_is("mcp: a scoped read with an unscoped nested lookup", c, "mcp.tool-scope", "FAIL", out)
T.expect("mcp: that FAIL is low (it leaks a timestamp, not rows)", c.get("mcp.tool-scope", {}).get("severity") == "low", out[-300:])
HELPER_SQL = Q_SCOPED.replace("return db.prepare(`SELECT body FROM notes WHERE id = ? AND owner_id = ?`).bind(id, viewer).first()",
                              "return rows(db, `SELECT body FROM notes WHERE id = ?`, id)")
rc, c, out = mcp_run(mcp(READ_TOOL, HELPER_SQL))
T.status_is("mcp: SQL passed through the app's own rows() helper is read too", c, "mcp.tool-scope", "FAIL", out)
PY = {"requirements.txt": "fastmcp==2.3.0\n", "server.py": """from fastmcp import FastMCP
mcp = FastMCP("notes")

@mcp.tool()
def read_note(note_id: str) -> str:
    row = db.execute("SELECT body FROM notes WHERE id = ?", (note_id,)).fetchone()
    return row[0]
"""}
rc, c, out = mcp_run(T.tree(PY))
T.status_is("mcp: a FastMCP tool keyed only on the caller's id", c, "mcp.tool-scope", "FAIL", out)

# known-good: the same shapes, safe
rc, c, out = mcp_run(mcp(READ_TOOL + SYNC_GATED, Q_SCOPED))
for cid in ("mcp.tool-scope", "mcp.identity-from-args", "mcp.privileged-tools"):
    T.status_is("mcp good: owner-scoped read and an owner-gated sync", c, cid, "PASS", out)
VIS = """const visible = (col) => `${col} IN (SELECT channel_id FROM visible_channels WHERE user_id = ?)`
export async function getNote(db, viewer, id) {
  return db.prepare(`SELECT body FROM notes WHERE id = ? AND ${visible("channel_id")}`).bind(id, viewer).first()
}
export async function syncSpace(db, space) {
  await db.prepare(`DELETE FROM notes WHERE space_id = ?`).bind(space).run()
}
"""
rc, c, out = mcp_run(mcp(READ_TOOL + SYNC_GATED, VIS))
T.status_is("mcp good: scoped through a visible() helper interpolated into the SQL", c, "mcp.tool-scope", "PASS", out)
DERIVED = """export async function getNote(db, viewer, id) {
  const hit = await db.prepare(`SELECT channel_id, created_at FROM notes WHERE id = ? AND owner_id = ?`).bind(id, viewer).first()
  if (!hit) return null
  return db.prepare(`SELECT body FROM notes WHERE channel_id = ? AND created_at > ?`).bind(hit.channel_id, hit.created_at).all()
}
export async function syncSpace(db, space) {}
"""
rc, c, out = mcp_run(mcp(READ_TOOL, DERIVED))
T.status_is("mcp good: neighbors read by a channel id taken from a scoped lookup", c, "mcp.tool-scope", "PASS", out)
CONST = """export async function getNote(db, viewer, id) {
  const mine = `SELECT s.id FROM spaces s JOIN members m ON m.space_id = s.id AND m.user_id = ?1`
  return db.prepare(`SELECT body FROM notes WHERE id = ?2 AND space_id IN (${mine})`).bind(viewer, id).first()
}
export async function syncSpace(db, space) {}
"""
rc, c, out = mcp_run(mcp(READ_TOOL, CONST))
T.status_is("mcp good: scoped by a membership subquery held in a const", c, "mcp.tool-scope", "PASS", out)
rc, c, out = mcp_run(T.tree({"package.json": json.dumps({"dependencies": {"hono": "4.6.0"}}), "src/index.ts": "export default { fetch: () => new Response('hi') }\n"}))
T.status_is("mcp: a repo with no MCP server", c, "mcp.none", "PASS", out)
rc, c, out = mcp_run(T.tree({"package.json": MCP_PKG, "src/server.ts": "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'\nexport const s = new McpServer({ name: 'x', version: '1' })\nregisterAll(s)\n"}))
T.status_is("mcp: an MCP import with no tool the check can recognize is UNKNOWN, never PASS", c, "mcp.tool-scope", "UNKNOWN", out)

# --- check_mcp Phase 11: the shapes a real review found (scope grain, model-visible writes, open registration, typed params, app tools) ---
import importlib.util as _ilu


def _bench_cases(name):
    """The bench's case list, or [] with a visible note where bench/ is absent (an installed or exported copy ships
    the plugin folder only). Absent bench is a skipped section, never a pass: the source repo always has it."""
    path = os.path.join(HERE, "..", "..", "bench", "cases", name)
    if not os.path.exists(path):
        print("SKIPPED: bench/cases/%s not present in this copy; its MCP cases run in the source repo" % name)
        return []
    spec = _ilu.spec_from_file_location(name[:-3], path)
    mod = _ilu.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod.CASES


for case in _bench_cases("secure_app_mcp.py"):
    rc, c, out = mcp_run(T.tree(case["files"]))
    for cid, want in case["expect"].items():
        T.status_is("mcp p11 %s" % case["id"], c, cid, want, out)

# --- check_mcp: tool-description poisoning (OWASP MCP03), from the bench file so the two never drift ---
for case in _bench_cases("secure_app_mcp_descriptions.py"):
    rc, c, out = mcp_run(T.tree(case["files"]))
    for cid, want in case["expect"].items():
        T.status_is("mcp desc %s" % case["id"], c, cid, want, out)

# ---- Phase 10 app-auth ----
# One FAIL and one PASS per mechanism added in Phase 10 to check_app.py and check_auth_gates.py (the audit's own
# fixtures become bench cases later; these are written fresh).
def _h(src):
    return {"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\n" + src + "\nexport default app\n"}
# auth_ref, operand by operand
s, out = app8(_h("app.put('/api/docs/:id', async (c) => {\n  const form = await c.req.json()\n  const doc = await c.env.DB.prepare('SELECT * FROM docs WHERE id = ?').bind(c.req.param('id')).first()\n  if (doc.authored_by !== form.authored_by) return c.json({}, 403)\n  return c.json({ ok: 1 })\n})"), "app.object-writes")
T.expect("P10 app: a 403 comparing a row field to the caller's own body field is no gate", s == "FAIL", out[-300:])
s, out = app8(_h("app.put('/api/docs/:id', async (c) => {\n  const visitor = c.get('visitor')\n  if (!visitor) {\n    log('x')\n    log('y')\n    log('z')\n    return c.json(\n      {},\n      401,\n    )\n  }\n  return c.json({ ok: 1 })\n})"), "app.object-writes")
T.expect("P10 app: ...a wrapped 401 under `if (!visitor)` five lines up, visitor from c.get(), is a gate", s == "PASS", out[-300:])
# raw Worker methods
_w = lambda body: {"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\n', "src/index.ts": "export default {\n  async fetch(req, env) {\n    const u = new URL(req.url)\n" + body + "\n    return new Response('', { status: 404 })\n  },\n}\n"}
s, out = st("check_app.py", _w("    if (u.pathname.startsWith('/v1/docs')) {\n      switch (req.method) {\n        case 'GET': return Response.json({})\n        case 'PATCH': await env.DB.prepare('UPDATE docs SET x = 1').run(); return new Response('')\n      }\n    }"), "app.object-writes")
T.expect("P10 app: a Worker switch on req.method under startsWith('/v1/docs') is an object write", s == "FAIL", out[-300:])
s, out = st("check_app.py", _w("    if (u.pathname.startsWith('/static/')) return env.ASSETS.fetch(req)\n    if (u.pathname.startsWith('/v1/docs/') && req.method === 'PATCH') {\n      const sess = await getSession(req, env)\n      if (!sess) return new Response('', { status: 401 })\n      return new Response('')\n    }"), "app.object-writes")
T.expect("P10 app: ...a GET asset route does not borrow the next line's PATCH", s == "PASS", out[-300:])
# debug words: strong with any continuation, soft only with a debug-shaped tail
s, out = app8(_h("app.get('/ops/dumpEnv', (c) => c.json(c.env))"), "app.debug-routes")
T.expect("P10 app: /ops/dumpEnv is a debug route", s == "FAIL", out[-300:])
s, out = app8(_h("app.get('/api/seed-varieties', (c) => c.json([]))\napp.get('/api/env-banner', (c) => c.json({}))"), "app.debug-routes")
T.expect("P10 app: .../api/seed-varieties and /api/env-banner are product routes", s == "PASS", out[-300:])
# sign-out SQL: a session row by its id, or a revocation column, on any table
s, out = app8(_h("app.post('/api/logout', async (c) => {\n  await c.env.DB.prepare('UPDATE accounts SET token_epoch = token_epoch + 1 WHERE id = ?').bind(1).run()\n  return c.json({})\n})"), "app.signout")
T.expect("P10 app: bumping a token_epoch column revokes the session", s == "PASS", out[-300:])
s, out = app8(_h("app.post('/api/logout', async (c) => {\n  await c.env.DB.prepare('UPDATE accounts SET last_ip = ? WHERE id = ?').bind('x', 1).run()\n  return c.json({})\n})"), "app.signout")
T.expect("P10 app: ...updating last_ip revokes nothing", s == "FAIL", out[-300:])
# error leak: a stack inside an object literal local; a `stack:` key elsewhere is not the local
s, out = app8(_h("app.onError((e, c) => {\n  const info = { msg: e.message, trace: e.stack }\n  return c.json(info, 500)\n})"), "app.error-leak")
T.expect("P10 app: a stack copied into an object literal and sent leaks", s == "FAIL", out[-300:])
s, out = app8(_h("app.onError((e, c) => {\n  const trace = e.stack\n  console.error(trace)\n  return c.json({ error: 'oops' }, 500)\n})\napp.get('/api/about', (c) => c.json({ trace: 'none' }))"), "app.error-leak")
T.expect("P10 app: ...a logged local and a later `trace:` key leak nothing", s == "PASS", out[-300:])
# header identity: Django META, destructuring; an assignment is a write
s, out = st("check_app.py", {"requirements.txt": "django==5.1\n", "app/views.py": "def me(request):\n    acct = request.META.get('HTTP_X_ACCOUNT_ID')\n    return acct\n"}, "app.header-identity")
T.expect("P10 app: request.META.get('HTTP_X_ACCOUNT_ID') is identity from a header", s == "FAIL", out[-300:])
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"express": "4.21.0"}}), "src/gw.js": "export function fwd(req, res, next) {\n  req.headers['x-member-id'] = String(res.locals.verified.id)\n  next()\n}\n"}, "app.header-identity")
T.expect("P10 app: ...assigning headers['x-member-id'] is a write, not a read", s == "PASS", out[-300:])
# CORS: the callback handing the origin back; a function returning a fixed origin after a compare is not reflection
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"express": "4.21.0", "cors": "2.8.5"}}), "src/s.js": "app.use(cors({ origin: function (o, done) { done(null, o) }, credentials: true }))\n"}, "app.cors")
T.expect("P10 app: origin: function (o, done) { done(null, o) } reflects", s == "FAIL", out[-300:])
s, out = st("check_app.py", {"package.json": json.dumps({"dependencies": {"koa": "2.15.0", "@koa/cors": "5.0.0"}}), "src/s.js": "app.use(cors({ origin: (ctx) => ctx.get('Origin') === 'https://a.example.org' ? 'https://a.example.org' : '', credentials: true }))\n"}, "app.cors")
T.expect("P10 app: ...comparing the Origin to one fixed value is not reflection", s == "PASS", out[-300:])
# auth.off-switch: aliases with a default, env names read word by word, the Authorization header READ
r, out = ag(_h("app.use('/ops/*', async (c, next) => {\n  const key = c.env.OPS_ADMIN_KEY || ''\n  if (!key) return next()\n  return bearerAuth({ token: key })(c, next)\n})"), "auth.off-switch")
T.expect("P10 gates: `const key = c.env.X || ''` then `if (!key) return next()` is an off-switch", r.get("status") == "FAIL", out[-300:])
r, out = ag(_h("app.use('*', async (c, next) => {\n  if (!c.env.PASSTHROUGH_MODE) return next()\n  c.header('x-mode', 'pt')\n  await next()\n})"), "auth.off-switch")
T.expect("P10 gates: ...PASSTHROUGH_MODE has no PASS word", r.get("status") == "PASS", out[-300:])
r, out = ag(_h("app.use('*', async (c, next) => {\n  if (!c.env.METRICS_TOKEN) return next()\n  await fetch('https://m.example.net', { headers: { \"authorization\": c.env.METRICS_TOKEN } })\n  await next()\n})"), "auth.off-switch")
T.expect("P10 gates: ...sending an Authorization header is not reading one", r.get("status") == "PASS", out[-300:])
r, out = ag(_h("app.use('*', async (c, next) => {\n  if (!c.env.METRICS_TOKEN) return next()\n  if (c.req.header('Authorization') !== c.env.METRICS_TOKEN) return c.redirect('/')\n  await next()\n})"), "auth.off-switch")
T.expect("P10 gates: ...reading it is a guard", r.get("status") == "FAIL", out[-300:])
# auth.access-jwt: jsonwebtoken, options imported from another file, a bare verify from hono/jwt
_aj = lambda files: dict({"wrangler.toml": W_ROUTED}, **files)
r, out = ag(_aj({"src/a.ts": "import jwt from 'jsonwebtoken'\nimport { OPTS } from './opts'\nexport const gate = (c) => jwt.verify(c.req.header('Cf-Access-Jwt-Assertion'), KEY, OPTS)\n", "src/opts.ts": "export const OPTS = { issuer: 'https://t.cloudflareaccess.com', audience: 'aud' }\n"}), "auth.access-jwt")
T.expect("P10 gates: jwt.verify with options imported from another file is verification with issuer and audience", r.get("status") == "PASS", out[-300:])
r, out = ag(_aj({"src/a.ts": "import { verify as check } from 'hono/jwt'\nexport const gate = (c) => check(c.req.header('Cf-Access-Jwt-Assertion'), KEY, 'RS256')\n"}), "auth.access-jwt")
T.expect("P10 gates: ...a hono/jwt verify without issuer and audience FAILs medium", r.get("status") == "FAIL" and r.get("severity") == "medium", out[-300:])
# auth.open-signup: the refusal must reach the sign-up API (positive path test, not a GET-only page)
_ba = {"package.json": json.dumps({"dependencies": {"better-auth": "1.3.4"}}), "lib/auth.ts": "import { betterAuth } from 'better-auth'\nexport const auth = betterAuth({ emailAndPassword: { enabled: true } })\n"}
r, out = ag(dict(_ba, **{"src/edge.ts": "export function gate(path, user) {\n  if (!path.includes('/sign-up') && !user) { return new Response('', { status: 401 }) }\n}\n"}), "auth.open-signup")
T.expect("P10 gates: a public-path list that exempts sign-up is no refusal", r.get("status") == "FAIL", out[-300:])
r, out = ag(dict(_ba, **{"src/edge.ts": "export function gate(path) {\n  if (path.startsWith('/api/auth/sign-up')) { return new Response('', { status: 403 }) }\n}\n"}), "auth.open-signup")
T.expect("P10 gates: ...refusing every /api/auth/sign-up path is", r.get("status") == "PASS", out[-300:])
# ---- end Phase 10 app-auth ----


# ---- Phase 10 app-spend ----
# One FAIL and one PASS fixture per mechanism added in Phase 10 (check_fetch, check_spend, check_metering, walk).
_FN = {"package.json": json.dumps({"dependencies": {"hono": "4.6.0", "express": "4.21.0"}}), "fly.toml": 'app = "x"\n'}

def f10(files, cid):
    return st("check_fetch.py", dict(_FN, **files), cid)

_RESOLVING = "import ipaddr from 'ipaddr.js'\nimport { lookup } from 'node:dns/promises'\nexport async function ensurePublic(u: URL) {\n  const { address } = await lookup(u.hostname)\n  if (ipaddr.parse(address).range() !== 'unicast') throw new Error('blocked')\n}\n"
# fetch.data-url: a guard that resolves and checks the address, beside a raw site, is FAIL; called on the URL first, PASS
s, out = f10({"src/net.ts": _RESOLVING, "src/a.ts": "export async function grab(p) { return fetch(p.avatarUrl) }\n"}, "fetch.data-url")
T.expect("P10 fetch: a resolving guard the raw site does not call is FAIL", s == "FAIL", out[-300:])
s, out = f10({"src/net.ts": _RESOLVING, "src/a.ts": "import { ensurePublic } from './net'\nexport async function grab(p) {\n  const u = new URL(p.avatarUrl)\n  await ensurePublic(u)\n  return fetch(u)\n}\n"}, "fetch.data-url")
T.expect("P10 fetch: the guard called on the same URL before the fetch is PASS", s == "PASS", out[-300:])
s, out = f10({"src/net.ts": _RESOLVING, "src/a.ts": "import { ensurePublic } from './net'\nexport async function grab(p) {\n  await ensurePublic(new URL(p.homepage))\n  return fetch(p.avatarUrl)\n}\n"}, "fetch.data-url")
T.expect("P10 fetch: the guard called on a different value does not guard the fetch", s == "FAIL", out[-300:])
# fetch.data-url: an agent below the call sites counts only when it does its own lookup
s, out = f10({"src/net.ts": _RESOLVING, "src/agent.ts": "import https from 'node:https'\nexport const agent = new https.Agent({ keepAlive: true })\n", "src/a.ts": "export async function grab(p) { return fetch(p.avatarUrl) }\n"}, "fetch.data-url")
T.expect("P10 fetch: a keep-alive agent is not a guard below the call sites (FAIL)", s == "FAIL", out[-300:])
s, out = f10({"src/net.ts": _RESOLVING, "src/agent.ts": "import { Agent, setGlobalDispatcher } from 'undici'\nsetGlobalDispatcher(new Agent({ connect: { lookup: publicOnlyLookup } }))\n", "src/a.ts": "export async function grab(p) { return fetch(p.avatarUrl) }\n"}, "fetch.data-url")
T.expect("P10 fetch: a global dispatcher with its own lookup makes the raw site UNKNOWN", s == "UNKNOWN", out[-300:])
# fetch: an SSRF-filter agent handed to the call guards it
_SRF = "import axios from 'axios'\nimport { useAgent } from 'request-filtering-agent'\napp.get('/api/p', async (req, res) => {\n  const t = String(req.query.url)\n  const r = await axios.get(t%s)\n  res.json({ n: 1 })\n})\n"
s, out = f10({"src/s.js": _SRF % ", { httpAgent: useAgent(t), httpsAgent: useAgent(t) }"}, "fetch.request-url")
T.expect("P10 fetch: request-filtering-agent on the call is a guard (request-url PASS)", s == "PASS", out[-300:])
s, out = f10({"src/s.js": _SRF % ""}, "fetch.request-url")
T.expect("P10 fetch: ...the same call without the agent is FAIL", s == "FAIL", out[-300:])
# fetch: constant URLs are judged per branch and across modules
s, out = f10({"src/a.ts": "export async function pull(item) {\n  const u = item.link ?? 'https://fallback.example.org/feed.xml'\n  return fetch(u)\n}\n"}, "fetch.data-url")
T.expect("P10 fetch: `data ?? 'https://literal'` is not constant (FAIL)", s == "FAIL", out[-300:])
s, out = f10({"src/a.ts": "export async function pull(cfg) {\n  const u = cfg.backup ? 'https://b.example.org/x' : 'https://a.example.org/x'\n  return fetch(u)\n}\n"}, "fetch.data-url")
T.expect("P10 fetch: a ternary of two owner literals is constant (PASS)", s == "PASS", out[-300:])
s, out = f10({"src/config.ts": "export const endpoints = { weather: 'https://api.weather.example/v1' } as const\nexport const STATUS = 'https://status.example.com/x'\n",
              "src/a.ts": "import { endpoints, STATUS } from './config'\nexport async function a() { return fetch(endpoints.weather) }\nexport async function b() { return fetch(STATUS) }\n"}, "fetch.data-url")
T.expect("P10 fetch: a constant or constant map imported from another module is constant (PASS)", s == "PASS", out[-300:])
s, out = f10({"src/a.ts": "export async function a(id) { return fetch('https://api.example.com' + id) }\n"}, "fetch.data-url")
T.expect("P10 fetch: a literal host with no `/` after it does not fix the host ('@evil' appends to it): FAIL", s == "FAIL", out[-300:])
# fetch: server entries in a module with React hooks are server code
_RR = "import { useState } from 'react'\nexport async function %s({ request }) {\n  const r = await fetch(new URL(request.url).searchParams.get('u') ?? '')\n  return { t: await r.text() }\n}\nexport default function P() { const [o] = useState(false); return o }\n"
s, out = f10({"app/routes/p.tsx": _RR % "loader"}, "fetch.data-url")
T.expect("P10 fetch: a loader beside a hooks component is a server fetch (FAIL)", s == "FAIL", out[-300:])
s, out = f10({"app/routes/p.tsx": _RR % "clientLoader"}, "fetch.data-url")
T.expect("P10 fetch: a clientLoader runs in the browser (PASS)", s == "PASS", out[-300:])
# fetch.request-url: request accessors, locals and config objects
s, out = f10({"src/s.js": "app.post('/api/h', async (request, reply) => {\n  const target = 'https://' + request.body.host + '/x'\n  const r = await axios({ method: 'POST', url: target.trim() })\n  return {}\n})\n"}, "fetch.request-url")
T.expect("P10 fetch: request.body into a concatenated local into an axios config url is FAIL", s == "FAIL", out[-300:])
s, out = f10({"src/s.js": "app.post('/api/h', async (request, reply) => {\n  const id = request.body.id\n  const r = await axios({ method: 'GET', url: `https://api.example.com/items/${id}` })\n  return {}\n})\n"}, "fetch.request-url")
T.expect("P10 fetch: ...a request value only in the path of a fixed host is PASS", s == "PASS", out[-300:])
s, out = f10({"src/index.ts": "const SOURCES = { a: 'https://n.example.org/a.rss' }\napp.get('/api/f', async (c) => {\n  const t = SOURCES[c.req.query('f') ?? ''] ?? c.req.query('url')\n  return c.text(await (await fetch(t)).text())\n})\n"}, "fetch.request-url")
T.expect("P10 fetch: an allowlist lookup with a raw request fallback is FAIL", s == "FAIL", out[-300:])
s, out = f10({"src/index.ts": "import { safeFetch } from './sf'\napp.get('/api/f', async (c) => {\n  await safeFetch('https://status.example.com')\n  return c.text(await (await fetch(c.req.query('url'))).text())\n})\n"}, "fetch.request-url")
T.expect("P10 fetch: a guard call elsewhere in the handler does not guard a raw fetch (FAIL)", s == "FAIL", out[-300:])
s, out = f10({"requirements.txt": "fastapi\nrequests\n", "app/main.py": "import requests\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n\n@app.get('/api/p')\ndef p(url: str, request: Request):\n    return requests.get(url, timeout=5).text\n"}, "fetch.request-url")
T.expect("P10 fetch: a FastAPI parameter fetched with requests is FAIL", s == "FAIL", out[-300:])
s, out = f10({"requirements.txt": "fastapi\nrequests\n", "app/main.py": "import requests\nfrom fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/api/p')\ndef p(city: str):\n    return requests.get('https://api.weather.example/v1', params={'q': city}).text\n"}, "fetch.request-url")
T.expect("P10 fetch: a FastAPI parameter sent as a query to a fixed host is PASS", s == "PASS", out[-300:])

# spend.unset-cap: a cap binding that can be unlimited on any branch; a NaN branch that proceeds
_PAID10 = "export async function ask(){ return fetch('https://api.anthropic.com/v1/messages') }\n"
s, out = st("check_spend.py", {"src/a.ts": "const cap = env.CAP ? Number(env.CAP) : Infinity\n" + _PAID10}, "spend.unset-cap")
T.expect("P10 spend: `cond ? Number(env.CAP) : Infinity` is an unlimited cap (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"app/s.py": "import math\nimport anthropic\nclass Settings:\n    daily_cap_usd: float = math.inf\n"}, "spend.unset-cap")
T.expect("P10 spend: a typed field defaulting to math.inf is an unlimited cap (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"app/s.py": "import anthropic\n\"\"\"Never write DAILY_CAP_USD: float = float('inf') or float(os.environ.get('DAILY_CAP_USD', 'inf')).\"\"\"\nDAILY_CAP_USD = 0.0\n"}, "spend.unset-cap")
T.expect("P10 spend: the same text inside a docstring is prose (PASS)", s == "PASS", out[-200:])
s, out = st("check_spend.py", {"src/a.ts": "export function within(env, used) {\n  const limit = Number(env.LIMIT)\n  if (Number.isNaN(limit)) return true\n  return used < limit\n}\n" + _PAID10}, "spend.unset-cap")
T.expect("P10 spend: `if (isNaN(limit)) return true` before `return used < limit` proceeds (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/a.ts": "export function over(env, used) {\n  const limit = Number(env.LIMIT)\n  if (Number.isNaN(limit)) return true\n  return used >= limit\n}\n" + _PAID10}, "spend.unset-cap")
T.expect("P10 spend: ...before `return used >= limit` (an over check) it refuses (PASS)", s == "PASS", out[-200:])
# spend.per-client: a header the caller sets is not a client key; the connecting address is
_PC = "const limiter = makeLimiter()\napp.post('/api/h', async (req, res) => {\n  const userId = %s\n  if (!(await limiter.check(userId))) return res.status(429).end()\n  res.json(await fetch('https://api.anthropic.com/v1/messages'))\n})\n"
s, out = st("check_spend.py", dict(_FN, **{"src/s.js": _PC % "req.get('x-user-id')"}), "spend.per-client")
T.expect("P10 spend: a limiter keyed on req.get('x-user-id') limits nothing (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", dict(_FN, **{"src/s.js": _PC % "req.get('cf-connecting-ip')"}), "spend.per-client")
T.expect("P10 spend: ...keyed on req.get('cf-connecting-ip') it is per client (PASS)", s == "PASS", out[-200:])
# spend.llm-params: wrappers, Next req.json(), schema copies judged by their schema, Python kwargs
s, out = st("check_spend.py", {"src/i.ts": "app.post('/c', async (c) => {\n  const body = await c.req.json()\n  return fetch('https://api.anthropic.com/v1/messages', { body: JSON.stringify({ max_tokens: Number(body.maxTokens) }) })\n})\n"}, "spend.llm-params")
T.expect("P10 spend: max_tokens: Number(body.maxTokens) is caller-set (FAIL)", s == "FAIL", out[-200:])
_ZOD = "import { z } from 'zod'\nconst Req = z.object({ model: %s, max_tokens: %s })\napp.post('/c', async (c) => {\n  const input = Req.parse(await c.req.json())\n  return fetch('https://api.openai.com/v1/chat/completions', { body: JSON.stringify({ model: input.model, max_tokens: input.max_tokens }) })\n})\n"
s, out = st("check_spend.py", {"src/i.ts": _ZOD % ("z.string()", "z.number()")}, "spend.llm-params")
T.expect("P10 spend: a schema copy with an open model string is caller-set (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"src/i.ts": _ZOD % ("z.enum(['gpt-4o-mini'])", "z.number().int().max(1024)")}, "spend.llm-params")
T.expect("P10 spend: ...with z.enum and .max(1024) the server chose (PASS)", s == "PASS", out[-200:])
s, out = st("check_spend.py", {"app/m.py": "import anthropic\nclient = anthropic.Anthropic()\nasync def chat(req):\n    body = await req.json()\n    return client.messages.create(model=body['model'], max_tokens=400)\n"}, "spend.llm-params")
T.expect("P10 spend: Python model=body['model'] is caller-set (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"app/m.py": "import anthropic\nclient = anthropic.Anthropic()\nasync def chat(req):\n    body = await req.json()\n    return client.messages.create(model='claude-haiku-4-5', max_tokens=400, messages=body['messages'])\n"}, "spend.llm-params")
T.expect("P10 spend: ...a fixed Python model is PASS", s == "PASS", out[-200:])
# spend.open-proxy: namespace and path-alias imports of the forwarding helper (walk.import_bindings)
_GEO = "export async function rev(lat: string, lng: string) {\n  %sconst r = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}`)\n  return r.json()\n}\n"
_NS = "import * as geo from './geo'\napp.get('/api/rev', async (c) => c.json(await geo.rev(c.req.query('lat') ?? '', c.req.query('lng') ?? '')))\n"
s, out = st("check_spend.py", {"wrangler.toml": 'name = "w"\n', "src/geo.ts": _GEO % "", "src/index.ts": _NS}, "spend.open-proxy")
T.expect("P10 spend: geo.rev(query) through `import * as geo` is an open proxy (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"wrangler.toml": 'name = "w"\n', "src/geo.ts": _GEO % "if (!inBounds(lat, lng)) throw new Error('outside')\n  ", "src/index.ts": _NS}, "spend.open-proxy")
T.expect("P10 spend: ...with a bounds check in the helper it is PASS", s == "PASS", out[-200:])
s, out = st("check_spend.py", {"package.json": json.dumps({"dependencies": {"next": "16.0.1"}}), "lib/geo.ts": _GEO % "",
                               "app/api/rev/route.ts": "import { rev } from '@/lib/geo'\nexport async function GET(req) {\n  const lat = req.nextUrl.searchParams.get('lat') ?? ''\n  return Response.json(await rev(lat, '0'))\n}\n"}, "spend.open-proxy")
T.expect("P10 spend: a helper imported through the @/ alias is followed (FAIL)", s == "FAIL", out[-200:])
s, out = st("check_spend.py", {"wrangler.toml": 'name = "w"\n', "src/geo.ts": _GEO % "if (!Number.isFinite(Number(lat))) throw new Error('bad')\n  ", "src/index.ts": _NS}, "spend.open-proxy")
T.expect("P10 spend: an isFinite number check is not an area bound (FAIL)", s == "FAIL", out[-200:])

# meter: a called helper is judged by its body; SQL drivers; routes behind middleware; binding aliases and parameters
_KV = "export async function %s(env) {\n  const key = `ai:count:${day}`\n  const n = Number(await env.USAGE.get(key)) || 0\n  if (n >= 300) return false\n  await env.USAGE.put(key, String(n + 1))\n  return true\n}\n"
_RT = "import { %s } from './g'\napp.post('/api/t', async (c) => {\n  if (!(await %s(c.env))) return c.json({}, 429)\n  return c.json(await fetch('https://api.openai.com/v1/chat/completions'))\n})\n"
r, out = mt({"wrangler.toml": RL, "src/g.ts": _KV % "allowCall", "src/index.ts": _RT % ("allowCall", "allowCall")}, "meter.openai")
T.expect("P10 meter: a helper of any name whose body reserves a day-keyed KV count is a counter (PASS)", r.get("status") == "PASS", out[-300:])
r, out = mt({"wrangler.toml": RL, "src/g.ts": "export async function reserveSeat(env) { await env.DB.prepare('UPDATE seats SET held = 1').run() }\n", "src/index.ts": _RT % ("reserveSeat", "reserveSeat")}, "meter.openai")
T.expect("P10 meter: a helper named reserve* whose body touches no counter is not one (FAIL)", r.get("status") == "FAIL", out[-300:])
r, out = mt({"requirements.txt": "fastapi\n", "app/m.py": "import httpx\n\nasync def s(db):\n    n = await db.fetchval('UPDATE llm_usage SET calls = calls + 1 WHERE day = current_date RETURNING calls')\n    if n > 400:\n        raise RuntimeError('cap')\n    return httpx.post('https://api.openai.com/v1/chat/completions')\n"}, "meter.openai")
T.expect("P10 meter: an UPDATE of a usage row through any SQL driver before the call is a counter (PASS)", r.get("status") == "PASS", out[-300:])
r, out = mt({"requirements.txt": "fastapi\n", "app/m.py": "import httpx\n\nasync def s(db):\n    await db.fetchval('UPDATE profiles SET seen = now()')\n    return httpx.post('https://api.openai.com/v1/chat/completions')\n"}, "meter.openai")
T.expect("P10 meter: ...an UPDATE of an unrelated row is not (FAIL)", r.get("status") == "FAIL", out[-300:])
_MW = "import { reserveAiCall } from './g'\napp.post('/api/t', requireAuth, zValidator('json', z.object({ p: z.string() })), async (c) => {\n  %s\n  return c.json(await fetch('https://api.openai.com/v1/chat/completions'))\n})\n"
r, out = mt({"wrangler.toml": RL, "src/g.ts": _KV % "reserveAiCall", "src/index.ts": _MW % "if (!(await reserveAiCall(c.env))) return c.json({}, 429)"}, "meter.openai")
T.expect("P10 meter: a route behind middleware arguments is a function with its reservation (PASS)", r.get("status") == "PASS", out[-300:])
r, out = mt({"wrangler.toml": RL, "src/g.ts": _KV % "reserveAiCall", "src/index.ts": _MW % "const x = 1"}, "meter.openai")
T.expect("P10 meter: ...the same route without one is FAIL", r.get("status") == "FAIL", out[-300:])
_BRT = "app.post('/api/t', async (c) => {\n  %s\n  return c.json(await fetch('https://api.openai.com/v1/chat/completions'))\n})\n"
r, out = mt({"wrangler.toml": RL, "src/index.ts": _BRT % "const limiter = c.env.AI_LIMITER\n  const { success } = await limiter.limit({ key: 'k' })"}, "meter.ratelimit-binding")
T.expect("P10 meter: an alias of the binding calling .limit() is a call (PASS)", r.get("status") == "PASS", out[-300:])
r, out = mt({"wrangler.toml": RL, "src/rl.ts": "export async function perIp(binding, c) { return (await binding.limit({ key: 'k' })).success }\n", "src/index.ts": "import { perIp } from './rl'\n" + _BRT % "await perIp(c.env.AI_LIMITER, c)"}, "meter.ratelimit-binding")
T.expect("P10 meter: the binding passed to a helper that calls .limit() on that parameter is a call (PASS)", r.get("status") == "PASS", out[-300:])
r, out = mt({"wrangler.toml": RL, "src/rl.ts": "export async function perIp(binding, c) { return true }\n", "src/index.ts": "import { perIp } from './rl'\n" + _BRT % "await perIp(c.env.AI_LIMITER, c)"}, "meter.ratelimit-binding")
T.expect("P10 meter: ...a helper that never calls .limit() on it is not (FAIL)", r.get("status") == "FAIL", out[-300:])
# ---- end Phase 10 app-spend ----

# ---- Phase 10 audit fixes ----
# One FAIL and one PASS per mechanism the Phase 10 audit fixes add (check_app.sql_revokes, check_fetch
# implements_guard and same-value guard calls, surface.secret_env, the typed c.req.json<T>() accessor).
_hx = lambda src: {"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\n" + src + "\nexport default app\n"}
# sign-out: a revocation column is judged by its word segments; a timestamp revokes nothing
s, out = app8(_hx("app.post('/auth/logout', async (c) => {\n  await c.env.DB.prepare('UPDATE members SET last_token_seen_at = CURRENT_TIMESTAMP WHERE id = ?').bind(1).run()\n  c.header('Set-Cookie', 'm=; Max-Age=0')\n  return c.json({})\n})"), "app.signout")
T.expect("P10 audit: a sign-out that only stamps last_token_seen_at revokes nothing (FAIL)", s == "FAIL", out[-300:])
s, out = app8(_hx("app.post('/auth/logout', async (c) => {\n  await c.env.DB.prepare('UPDATE members SET session_generation = session_generation + 1 WHERE id = ?').bind(1).run()\n  return c.json({})\n})"), "app.signout")
T.expect("P10 audit: ...bumping session_generation does (PASS)", s == "PASS", out[-300:])
# env names by word segments: a flag holding AUTH or ADMIN as a substring is not a shared secret
s, out = app8(_hx("app.patch('/api/pages/:id', async (c) => {\n  if (!c.env.ALLOW_ADMINISTRATION_TOOLS) return c.json({}, 403)\n  await c.env.DB.prepare('UPDATE pages SET t = 1 WHERE id = ?').bind(c.req.param('id')).run()\n  return c.json({})\n})"), "app.object-writes")
T.expect("P10 audit: a 403 on env.ALLOW_ADMINISTRATION_TOOLS is a feature flag, not a gate (FAIL)", s == "FAIL", out[-300:])
s, out = app8(_hx("app.patch('/api/pages/:id', async (c) => {\n  if (c.req.query('k') !== c.env.EDITOR_API_KEY) return c.json({}, 403)\n  await c.env.DB.prepare('UPDATE pages SET t = 1 WHERE id = ?').bind(c.req.param('id')).run()\n  return c.json({})\n})"), "app.object-writes")
T.expect("P10 audit: ...a 403 against env.EDITOR_API_KEY is a shared-secret gate (PASS)", s == "PASS", out[-300:])
# Hono's typed c.req.json<T>() is caller input
s, out = app8(_hx("app.patch('/api/pages/:id', async (c) => {\n  const form = await c.req.json<{ account: string }>()\n  if (!form.account) return c.json({}, 401)\n  await c.env.DB.prepare('UPDATE pages SET t = 1 WHERE id = ?').bind(c.req.param('id')).run()\n  return c.json({})\n})"), "app.object-writes")
T.expect("P10 audit: a 401 on a field of c.req.json<T>() is the caller's own data (FAIL)", s == "FAIL", out[-300:])
s, out = app8(_hx("app.patch('/api/pages/:id', async (c) => {\n  const form = await c.req.json<{ t: string }>()\n  const acct = c.var.acct\n  if (!acct) return c.json({}, 401)\n  await c.env.DB.prepare('UPDATE pages SET t = ? WHERE id = ?').bind(form.t, c.req.param('id')).run()\n  return c.json({})\n})"), "app.object-writes")
T.expect("P10 audit: ...a 401 on c.var.acct beside a typed body read is a gate (PASS)", s == "PASS", out[-300:])
s, out = f10({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\napp.post('/api/peek', async (c) => {\n  const { page: where } = await c.req.json<{ page: string }>()\n  return c.json({ s: (await fetch(where)).status })\n})\nexport default app\n"}, "fetch.request-url")
T.expect("P10 audit: a URL destructured from c.req.json<T>() reaches fetch (FAIL)", s == "FAIL", out[-300:])
s, out = f10({"src/index.ts": "import { Hono } from 'hono'\nconst app = new Hono()\nconst SITES = { a: 'https://a.example.org/' }\napp.post('/api/peek', async (c) => {\n  const { page } = await c.req.json<{ page: string }>()\n  return c.json({ s: (await fetch(SITES.a)).status, page })\n})\nexport default app\n"}, "fetch.request-url")
T.expect("P10 audit: ...a fixed URL beside a typed body read is not caller-chosen (PASS)", s == "PASS", out[-300:])
# guards: a string never counts, and a guard call counts only on the value fetched
s, out = f10({"src/net.ts": _RESOLVING, "src/feeds.ts": "export async function pull(job: { feedUrl: string }) {\n  if (!job.feedUrl) throw new Error('ensurePublic(): no feed url given')\n  return (await fetch(job.feedUrl)).text()\n}\n"}, "fetch.data-url")
T.expect("P10 audit: a guard name inside an error message guards nothing (FAIL)", s == "FAIL", out[-300:])
s, out = f10({"src/net.ts": _RESOLVING, "src/feeds.ts": "import { ensurePublic } from './net'\nasync function vetted(raw: string) {\n  await ensurePublic(new URL(raw))\n  return raw\n}\nexport async function pull(job: { feedUrl: string, iconUrl: string }) {\n  await vetted(job.feedUrl)\n  return (await fetch(job.feedUrl)).text()\n}\n"}, "fetch.data-url")
T.expect("P10 audit: ...a repo helper that calls the guard, called on the fetched value, is a check (PASS)", s == "PASS", out[-300:])
s, out = f10({"src/net.ts": _RESOLVING, "src/feeds.ts": "import { ensurePublic } from './net'\nasync function vetted(raw: string) {\n  await ensurePublic(new URL(raw))\n  return raw\n}\nexport async function pull(job: { feedUrl: string, iconUrl: string }) {\n  await vetted(job.iconUrl)\n  return (await fetch(job.feedUrl)).text()\n}\n"}, "fetch.data-url")
T.expect("P10 audit: ...the same helper called on a different value is not (FAIL)", s == "FAIL", out[-300:])
# ---- end Phase 10 audit fixes ----

T.finish()

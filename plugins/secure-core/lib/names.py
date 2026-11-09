"""names.py - is this env var NAME a credential? One answer for every adapter.

Phase 9 (2026-11-01) merged two copies: check_cloudflare.secret_name (whole-segment
and suffix vocabulary, public-by-design allowlists, the `browser` flag, shared with
check_nextjs) and check_fly_supabase.secret_name (word list, setting suffixes,
database URL names, value shapes). Where the copies disagreed, the merge keeps the
reading that both plugins' unit tests and the full bench accept:

- A SETTING SUFFIX cancels the name (fly rule, now everywhere): PRIVATE_KEY_PATH,
  SECRET_KEY_ID, PASSWORD_MIN_LENGTH, CLIENT_SECRET_FILE name a setting ABOUT a secret,
  not the secret. The cloudflare copy said True to these because a strong segment
  (PRIVATE_KEY, SECRET) appeared anywhere.
- A DATABASE URL name is a secret (fly rule, now everywhere): DATABASE_URL, REDIS_URL,
  PG_DSN carry a password in the value, so one in wrangler [vars] or behind a browser
  prefix is a leak. The cloudflare copy had no such rule.
- PUBLIC-BY-DESIGN names are public in every config (cloudflare rule, now everywhere):
  MAPBOX_TOKEN and *_ANON_KEY / *_SITE_KEY / *_PUBLISHABLE_KEY / *_PUBLIC_KEY, plus a
  PUBLIC or PUBLISHABLE segment anywhere. The fly copy called MAPBOX_TOKEN a secret and
  only let ANON/SITE/PUBLIC/PUBLISHABLE cancel the word right after them.
- The public allowlist is tested BEFORE the database rule and the secret vocabulary: an
  author who writes PUBLIC_ in a name has declared it public.
- Weak words are suffixes, never substrings and never middle segments (cloudflare rule):
  KEY, TOKEN, SALT, PRIVATE, API_KEY, ACCESS_KEY, AUTH_TOKEN, ACCESS_TOKEN as the last
  segment or the last pair. The fly copy counted KEY, TOKEN, PRIVATE anywhere unless a
  listed setting suffix followed (ACCESS_TOKEN_LIFETIME, KEY_VALUE, PRIVATE_NOTES were
  secrets there). The fly words PASS, PWD and APIKEY join the suffix set (DB_PASS,
  REDIS_PWD, STRIPE_APIKEY), so nothing the fly copy's tests caught is lost.
- Strong words count anywhere as a whole segment or pair (cloudflare rule, kept): SECRET,
  SECRETS, PASSWORD, PASSWD, PASSCODE, CREDENTIAL(S), DSN, PRIVATE_KEY, SERVICE_ROLE,
  CLIENT_SECRET, SIGNING_KEY, SECRET_KEY.
- Phase 10 (2026-11-07): a camelCase or kebab name is split into the same segments as its
  SNAKE_CASE twin before any rule runs (openaiApiKey reads as OPENAI_API_KEY; a JSON config
  writes names that way), the compound words written without the underscore are in the
  vocabulary (APITOKEN, ACCESSTOKEN, SECRETKEY, PRIVATEKEY), and the PLURAL of a compound
  credential word is a credential (ALLOWED_API_KEYS is the accepted bearer set, PASSWORDS,
  SIGNING_KEYS). A bare plural weak word stays config: MAX_TOKENS, SORT_KEYS.
  Under `browser=True` the vendor keys documented as browser-safe are public too (Sentry DSN,
  Firebase web API key, PostHog project key, Algolia search-only key), like Mapbox and Maps.
- Phase 10 audit (2026-11-07): a CONNECTION-STRING name followed by variant words is still the
  connection string. Neon's DATABASE_URL_UNPOOLED, Vercel's POSTGRES_URL_NON_POOLING and
  REDIS_URL_REPLICA carry the same password as the bare name. The trailing words in
  CONN_VARIANT (pooling mode, replica role, environment, migration or owner role) are
  stripped and the database URL rule asks again; nothing else is stripped, so
  APP_URL_STAGING and DB_HOST_PRIMARY stay settings and API_KEY_PROD keeps its old answer.
  This rule used to live in check_fly_supabase.env_secret, so `[vars] DATABASE_URL_UNPOOLED`
  PASSed cf.vars-secrets while fly.env-secrets FAILed it; one home now.
- `browser=True` (a name a bundler ships, prefix already stripped) treats Google's
  referrer-restricted Maps key names as public; the same name in wrangler [vars] or fly
  [env] is a server key and stays a secret (cloudflare rule, kept).
- `value` (fly rule, kept) is read only to recognize a key shape or a URL password; it is
  never returned, printed or stored. The cloudflare callers pass no value.

Never reads a value for any other purpose. KEYBOARD_LAYOUT, MAX_TOKENS and
SESSION_TOKEN_TTL_SECONDS are config, not credentials (bench decoys 2026-11-01).
"""
import re

import ledger

# Strong: a credential wherever the segment (or adjacent pair) appears.
SECRET_SEGMENTS = {"SECRET", "SECRETS", "PASSWORD", "PASSWD", "PASSCODE", "CREDENTIAL", "CREDENTIALS", "DSN",
                   "PRIVATE_KEY", "SERVICE_ROLE", "CLIENT_SECRET", "SIGNING_KEY", "SECRET_KEY",
                   "SECRETKEY", "PRIVATEKEY", "CLIENTSECRET", "SIGNINGKEY"}
# Weak: a credential only as the last segment or the last pair.
SECRET_SUFFIXES = {"KEY", "TOKEN", "SALT", "API_KEY", "ACCESS_KEY", "AUTH_TOKEN", "ACCESS_TOKEN", "PRIVATE",
                   "PASS", "PWD", "APIKEY", "APITOKEN", "ACCESSTOKEN", "AUTHTOKEN", "ACCESSKEY",
                   "API_TOKEN", "BEARER_TOKEN", "REFRESH_TOKEN", "CLIENT_KEY"}
# The single weak words: their plural (MAX_TOKENS, SORT_KEYS) is config, not a credential set.
BARE_WEAK = {"KEY", "TOKEN", "SALT", "PRIVATE", "PASS", "PWD"}
# Public by design: the provider documents the browser as the value's home and
# restricts it by domain or scope server-side. A publishable/site/anon key or a
# PUBLIC_ segment is meant to ship; Mapbox's public token (pk., URL-restricted)
# is named NEXT_PUBLIC_MAPBOX_TOKEN in Mapbox's own Next.js guide.
PUBLIC_SUFFIXES = {"SITE_KEY", "ANON_KEY", "PUBLISHABLE_KEY", "PUBLIC_KEY"}
PUBLIC_SEGMENTS = {"PUBLIC", "PUBLISHABLE"}
PUBLIC_NAMES = {"MAPBOX_TOKEN", "MAPBOX_ACCESS_TOKEN"}
# Public only under a browser prefix (NEXT_PUBLIC_, VITE_): Google documents browser Maps keys as public and
# referrer-restricted, while the same name in wrangler [vars] or fly [env] is a server key and stays a secret
# (Phase 8, 2026-11-01).
BROWSER_PUBLIC_NAMES = {"GOOGLE_MAPS_API_KEY", "GOOGLE_MAPS_KEY", "MAPS_API_KEY", "MAPS_KEY"}
# Vendor keys whose own docs put them in the browser (Phase 10, 2026-11-07): a Sentry DSN only accepts
# events, a Firebase web apiKey identifies the project (security rules guard the data), a PostHog
# project key (phc_) only ingests, an Algolia search-only key only searches. Matched as the whole name
# or its tail after an app prefix (SHOP_SENTRY_DSN). Their server twins (ALGOLIA_ADMIN_KEY,
# POSTHOG_PERSONAL_API_KEY, FIREBASE_PRIVATE_KEY) do not match and stay secrets.
BROWSER_PUBLIC_VENDOR = re.compile(r"(?:^|_)(?:SENTRY_DSN|FIREBASE_(?:WEB_)?API_KEY|POSTHOG_(?:PROJECT_)?(?:API_)?KEY"
                                   r"|ALGOLIA_SEARCH(?:_ONLY)?(?:_API)?_KEY)$")
# A name ending in one of these holds a setting ABOUT a secret, not the secret.
SETTING_SUFFIX = {"ISSUER", "URL", "URI", "ENDPOINT", "HOST", "ID", "NAME", "PREFIX", "SUFFIX", "TTL", "SECONDS", "MS", "MINUTES", "HOURS", "DAYS",
                  "LENGTH", "LEN", "SIZE", "COUNT", "LIMIT", "MAX", "MIN", "HEADER", "AUDIENCE", "AUD", "ALGORITHM", "ALG", "PATH", "FILE", "DIR",
                  "EXPIRY", "EXPIRES", "EXPIRATION", "ENABLED", "REQUIRED", "TYPE", "MODE", "VERSION", "PROPERTY", "LAYOUT", "FORMAT", "SCHEME",
                  "REGION", "BUCKET", "TABLE", "ROTATION", "POLICY", "HINT", "LABEL", "FIELD", "PARAM", "COOKIE", "STORE", "PROVIDER", "KID"}
# A connection string carries its password: DATABASE_URL, REDIS_URL, PG_DSN, MONGODB_URI.
DB_URL = re.compile(r"(?:^|_)(?:DATABASE|DB|POSTGRES|POSTGRESQL|PG|MYSQL|MONGO|MONGODB|REDIS|AMQP|RABBITMQ|KAFKA|NEON|CONNECTION)_?(?:URL|URI|DSN|STRING)$")
# Words a provider appends to a connection-string name for a variant of the same database (Phase 10 audit).
CONN_VARIANT = {"UNPOOLED", "POOLED", "POOLER", "NON", "POOLING", "DIRECT", "PRIMARY", "REPLICA", "READONLY", "RO", "RW",
                "PROD", "PRODUCTION", "STAGING", "DEV", "TEST", "SHADOW", "MIGRATE", "MIGRATION", "MIGRATIONS", "ADMIN",
                "OWNER", "SESSION", "TRANSACTION", "PRISMA", "INTERNAL", "EXTERNAL"}
URL_PASSWORD = re.compile(r"://[^/\s:@'\"]+:[^@\s/'\"]+@")
# camelCase / PascalCase boundaries: aB, a1B, and the end of an acronym run (APIKey -> API_Key).
CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _segments(name):
    """SNAKE segments of a name in any case convention: openaiApiKey, openai-api-key and
    OPENAI_API_KEY all give [OPENAI, API, KEY]. An all-lowercase or all-caps run is not split."""
    n = CAMEL.sub("_", name.strip()).replace("-", "_").replace(".", "_").upper()
    return [s for s in n.split("_") if s]


def _singular(segs):
    """The same segments with the last one de-pluralized (KEYS -> KEY), or None when it is not plural."""
    last = segs[-1]
    if len(last) > 3 and last.endswith("S") and not last.endswith("SS"):
        return segs[:-1] + [last[:-1]]
    return None


def secret_name(name, value=None, browser=False):
    """True when an env/var NAME is shaped like a credential (see the module docstring for the rules).
    `value`, when given, is read only to recognize a key shape or a URL password and is never returned.
    `browser=True` judges a name a bundler ships to the browser (the prefix already stripped)."""
    if value and (any(p.search(value) for p in ledger.SECRET_SHAPES) or URL_PASSWORD.search(value)):
        return True
    segs = _segments(name)
    if not segs:
        return False
    n = "_".join(segs)
    if browser and (n in BROWSER_PUBLIC_NAMES or BROWSER_PUBLIC_VENDOR.search(n)):
        return False
    if n in PUBLIC_NAMES or set(segs) & PUBLIC_SEGMENTS or any(n == s or n.endswith("_" + s) for s in PUBLIC_SUFFIXES):
        return False
    core = segs
    while len(core) > 1 and core[-1] in CONN_VARIANT:
        core = core[:-1]
    if DB_URL.search("_".join(core)):
        return True
    if segs[-1] in SETTING_SUFFIX:
        return False
    pairs = {"_".join(segs[i:i + 2]) for i in range(len(segs) - 1)}
    if set(segs) & SECRET_SEGMENTS or pairs & SECRET_SEGMENTS:
        return True
    if segs[-1] in SECRET_SUFFIXES or "_".join(segs[-2:]) in SECRET_SUFFIXES:
        return True
    # A plural compound credential word (API_KEYS, SIGNING_KEYS, PASSWORDS, APITOKENS) is the credential set;
    # a bare plural weak word (MAX_TOKENS, SORT_KEYS) is config.
    one = _singular(segs)
    if one is None:
        return False
    last, pair = one[-1], "_".join(one[-2:])
    return (last in SECRET_SEGMENTS or (last in SECRET_SUFFIXES and last not in BARE_WEAK)
            or (len(one) > 1 and (pair in SECRET_SUFFIXES or pair in SECRET_SEGMENTS)))

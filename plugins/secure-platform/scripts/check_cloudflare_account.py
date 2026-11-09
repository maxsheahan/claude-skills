#!/usr/bin/env python3
"""check_cloudflare_account.py - the Cloudflare ACCOUNT, read through the API or
from a snapshot, judged the way the 2026-10-13 audit judged it (findings Z-1 to Z-6).

  check_cloudflare_account.py --snapshot account.json          offline: judge a saved snapshot
  check_cloudflare_account.py fetch --out account.json         read-only GETs with $CLOUDFLARE_API_TOKEN,
                                                               write the snapshot, print which calls
                                                               were unauthorized (the token is never printed)
  check_cloudflare_account.py                                  fetch into a temp snapshot, then judge it

Per zone (cfacct.<check>.<zone>):
  ssl       `strict` (Full strict), else FAIL medium: Full accepts an unvalidated origin certificate.
  tls       min_tls_version >= 1.2, else FAIL low.
  https     always_use_https on, else FAIL medium: plain http serves the site.
  hsts      HSTS enabled with a max_age of at least 15552000 (6 months, the repo-side minimum;
            a numeric string is read as its number) on zones that serve content, else FAIL
            low (enabled with max_age 0 tells browsers to forget HSTS); a zone with
            zero DNS records serves nothing and is reported as PASS with an info detail.
  dnssec    status active, else FAIL low.
Account-wide:
  cfacct.dangling-cname     a *.pages.dev CNAME target whose project is absent from the
                            Pages project list FAILs high (subdomain takeover).
  cfacct.members-2fa        a member with two_factor_authentication_enabled false FAILs high;
                            a member whose response carries no such field (a pending invitation)
                            is UNKNOWN, never folded into PASS.
  cfacct.pages-preview-secrets  a Pages preview env carrying a secret_text that production
                            also carries FAILs medium (a preview deploy runs with production money).
  cfacct.kv-orphans         KV namespaces bound by no Worker and no Pages project: FAIL info.
  cfacct.workers-dev-exposed  a Worker with workers.dev enabled, no route or custom domain, and
                            a data binding (D1, KV, R2, Hyperdrive, Vectorize, a queue, a secret,
                            a Secrets Store secret, a Durable Object, a plain_text var named or
                            shaped like a credential, or a service binding to a Worker holding
                            any of these) FAILs medium (zone rules cannot reach it).
Every check whose data a call could not read (9109 / 10000) is UNKNOWN naming the permission.

Snapshot shape (the same objects the API returns, grouped):
  {"account_id", "zones": [{"id","name","settings": {id: value},"dnssec": {...},"dns_records": [...],
   "worker_routes": [...]}], "pages_projects": [...], "members": [...], "kv_namespaces": [...],
   "workers": [{"id","subdomain": {...},"settings": {"bindings": [...]}}], "worker_domains": [...],
   "errors": [{"call", "code", "message"}]}
"""
import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
from ledger import result  # noqa: E402
from names import secret_name  # noqa: E402  (a plain_text binding named like a credential is a secret in the clear)

API = "https://api.cloudflare.com/client/v4"
AUTH_CODES = (9109, 10000)
# call key -> the token permission that lets it run (names from the Cloudflare permissions reference)
PERMISSION = {
    "accounts": "Account Settings: Read",
    "zones": "Zone: Read",
    "zone_settings": "Zone Settings: Read",
    "dnssec": "DNS: Read",
    "dns_records": "DNS: Read",
    "worker_routes": "Workers Routes: Read",
    "pages_projects": "Cloudflare Pages: Read",
    "members": "Account Settings: Read",
    "kv_namespaces": "Workers KV Storage: Read",
    "workers": "Workers Scripts: Read",
    "worker_subdomain": "Workers Scripts: Read",
    "worker_settings": "Workers Scripts: Read",
    "worker_domains": "Workers Scripts: Read",
}
# The same minimum as the repo-side cf.headers.hsts check (Phase 10: max_age 300 passed here, failed there).
HSTS_MIN_AGE = 15552000


def _max_age(v):
    """max_age as a number: the API returns an int, a snapshot writer may store "15552000"."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


DATA_BINDINGS = {"d1", "kv_namespace", "r2_bucket", "secret_text", "durable_object_namespace", "hyperdrive", "vectorize", "queue",
                 "secrets_store_secret"}


def allowed_base(base):
    """The token only ever goes to Cloudflare or a local test server: never another host, never file://."""
    b = base.rstrip("/")
    return b == API.rstrip("/") or re.match(r"^http://127\.0\.0\.1:\d+(/|$)", b) is not None


class Api:
    def __init__(self, token, base=API):
        self.token = token
        self.base = base.rstrip("/")
        self.errors = []

    def get(self, call, path, paginate=False):
        """GET one endpoint; a list endpoint follows `page` until result_info says done.
        Any error is recorded as {call, code, message} and None is returned. The token
        never appears in anything this script prints or writes."""
        items, page = [], 1
        while True:
            url = "%s%s" % (self.base, path)
            if paginate:
                url += ("&" if "?" in url else "?") + "page=%d&per_page=50" % page
            req = urllib.request.Request(url, headers={"Authorization": "Bearer %s" % self.token, "Accept": "application/json"})
            try:
                        # self.base passed allowed_base(): Cloudflare's own https host or a 127.0.0.1 test server.
                with urllib.request.urlopen(req, timeout=30) as r:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    data = json.loads(r.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as e:
                try:
                    data = json.loads(e.read().decode("utf-8", "replace"))
                except ValueError:
                    data = {"success": False, "errors": [{"code": e.code, "message": "HTTP %d" % e.code}]}
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.errors.append({"call": call, "code": 0, "message": "network: %s" % type(e).__name__})
                return None
            if not data.get("success"):
                err = (data.get("errors") or [{"code": 0, "message": "unknown"}])[0]
                self.errors.append({"call": call, "code": err.get("code", 0), "message": str(err.get("message", ""))[:120]})
                return None
            res = data.get("result")
            if not paginate:
                return res
            items += res or []
            info = data.get("result_info") or {}
            if not res or page >= int(info.get("total_pages") or 1):
                return items
            page += 1


def fetch_snapshot(token, account=None, base=API):
    api = Api(token, base)
    snap = {"errors": api.errors}
    if not account:
        accts = api.get("accounts", "/accounts", paginate=True)
        account = (accts or [{}])[0].get("id") if accts else None
    snap["account_id"] = account
    zones = api.get("zones", "/zones", paginate=True) or []
    snap["zones"] = []
    for z in zones:
        zid = z.get("id")
        row = {"id": zid, "name": z.get("name")}
        settings = api.get("zone_settings:%s" % z.get("name"), "/zones/%s/settings" % zid)
        row["settings"] = {s.get("id"): s.get("value") for s in settings} if settings is not None else None
        row["dnssec"] = api.get("dnssec:%s" % z.get("name"), "/zones/%s/dnssec" % zid)
        row["dns_records"] = api.get("dns_records:%s" % z.get("name"), "/zones/%s/dns_records" % zid, paginate=True)
        row["worker_routes"] = api.get("worker_routes:%s" % z.get("name"), "/zones/%s/workers/routes" % zid)
        snap["zones"].append(row)
    if account:
        a = "/accounts/%s" % account
        snap["pages_projects"] = api.get("pages_projects", a + "/pages/projects", paginate=True)
        snap["members"] = api.get("members", a + "/members", paginate=True)
        snap["kv_namespaces"] = api.get("kv_namespaces", a + "/storage/kv/namespaces", paginate=True)
        scripts = api.get("workers", a + "/workers/scripts")
        snap["workers"] = None
        if scripts is not None:
            snap["workers"] = []
            for s in scripts:
                name = s.get("id")
                snap["workers"].append({
                    "id": name,
                    "subdomain": api.get("worker_subdomain:%s" % name, a + "/workers/scripts/%s/subdomain" % urllib.parse.quote(name, safe="")),
                    "settings": api.get("worker_settings:%s" % name, a + "/workers/scripts/%s/settings" % urllib.parse.quote(name, safe="")),
                })
        snap["worker_domains"] = api.get("worker_domains", a + "/workers/domains")
    else:
        for k in ("pages_projects", "members", "kv_namespaces", "workers", "worker_domains"):
            snap[k] = None
    return snap


def _unauth(snap, call_prefix):
    """The error record for a call (or any call with that prefix), or None."""
    for e in snap.get("errors") or []:
        c = str(e.get("call", ""))
        if c == call_prefix or c.startswith(call_prefix + ":"):
            return e
    return None


def _unknown(cid, title, snap, call, evidence=None):
    e = _unauth(snap, call) or {"code": 0, "message": "not in snapshot"}
    perm = PERMISSION.get(call.split(":")[0], "the matching read permission")
    code = e.get("code", 0)
    if code in AUTH_CODES:
        reason = "GET %s returned %s %s; the token needs %s" % (call, code, e.get("message", ""), perm)
    else:
        reason = "GET %s did not run (%s %s); the token needs %s" % (call, code, e.get("message", ""), perm)
    return result(cid, title, "UNKNOWN", evidence or "%s absent from the snapshot" % call, reason=reason)


def _slug(name):
    return re.sub(r"[^a-z0-9]+", "-", (name or "zone").lower()).strip("-")


def judge(snap):
    res = []
    zones = snap.get("zones")
    if zones is None:
        res.append(_unknown("cfacct.zones", "Zone settings", snap, "zones"))
        zones = []
    pages = snap.get("pages_projects")
    project_names = {p.get("name") for p in pages} if pages is not None else None
    for z in zones:
        zname, zs = z.get("name"), _slug(z.get("name"))
        settings = z.get("settings")
        if settings is None:
            for k, title in (("ssl", "SSL mode is Full (strict)"), ("tls", "Minimum TLS is 1.2"), ("https", "Always Use HTTPS is on"), ("hsts", "HSTS is on")):
                res.append(_unknown("cfacct.%s.%s" % (k, zs), "%s: %s" % (zname, title), snap, "zone_settings:%s" % zname))
        else:
            ssl = settings.get("ssl")
            if ssl == "strict":
                res.append(result("cfacct.ssl.%s" % zs, "%s: SSL mode is Full (strict)" % zname, "PASS", "GET /zones/%s/settings: ssl = strict" % zname))
            else:
                res.append(result("cfacct.ssl.%s" % zs, "%s: SSL mode is Full (strict)" % zname, "FAIL", "GET /zones/%s/settings: ssl = %s" % (zname, ssl), severity="medium",
                                  fix="set SSL/TLS encryption mode to Full (strict); every Pages and Workers origin presents a valid certificate"))
            tls = str(settings.get("min_tls_version") or "")
            try:
                ok_tls = float(tls) >= 1.2
            except ValueError:
                ok_tls = False
            if ok_tls:
                res.append(result("cfacct.tls.%s" % zs, "%s: Minimum TLS is 1.2" % zname, "PASS", "GET /zones/%s/settings: min_tls_version = %s" % (zname, tls)))
            else:
                res.append(result("cfacct.tls.%s" % zs, "%s: Minimum TLS is 1.2" % zname, "FAIL", "GET /zones/%s/settings: min_tls_version = %s" % (zname, tls or "unset"), severity="low",
                                  fix="set Minimum TLS Version to 1.2 (SSL/TLS > Edge Certificates)"))
            auh = settings.get("always_use_https")
            if auh == "on":
                res.append(result("cfacct.https.%s" % zs, "%s: Always Use HTTPS is on" % zname, "PASS", "GET /zones/%s/settings: always_use_https = on" % zname))
            else:
                res.append(result("cfacct.https.%s" % zs, "%s: Always Use HTTPS is on" % zname, "FAIL", "GET /zones/%s/settings: always_use_https = %s" % (zname, auh), severity="medium",
                                  fix="turn on Always Use HTTPS (SSL/TLS > Edge Certificates) so plain http is redirected at the edge"))
            sh = settings.get("security_header") or {}
            hsts = (sh.get("strict_transport_security") or {}) if isinstance(sh, dict) else {}
            recs = z.get("dns_records")
            if recs is not None and len(recs) == 0:
                res.append(result("cfacct.hsts.%s" % zs, "%s: HSTS is on" % zname, "PASS", "zone has 0 DNS records: nothing is served, HSTS not judged",
                                  detail="info: an empty zone; revisit when a record is added"))
            elif hsts.get("enabled") is True and hsts.get("max_age") is not None and not (_max_age(hsts["max_age"]) or 0) >= HSTS_MIN_AGE:
                age = _max_age(hsts["max_age"])
                why = "browsers forget HSTS at max-age 0" if not age else "under %d (6 months), the repo-side minimum: a browser that stays away that long is back on http" % HSTS_MIN_AGE
                res.append(result("cfacct.hsts.%s" % zs, "%s: HSTS is on" % zname, "FAIL", "GET /zones/%s/settings: security_header.strict_transport_security.enabled = true but max_age = %s (%s)" % (zname, hsts.get("max_age"), why),
                                  severity="low", fix="set the HSTS max-age to 6 months (15552000) once every host on the zone answers https; max-age 0 is HSTS switched off"))
            elif hsts.get("enabled") is True:
                res.append(result("cfacct.hsts.%s" % zs, "%s: HSTS is on" % zname, "PASS", "GET /zones/%s/settings: security_header.strict_transport_security.enabled = true, max_age = %s" % (zname, hsts.get("max_age", "not reported"))))
            else:
                res.append(result("cfacct.hsts.%s" % zs, "%s: HSTS is on" % zname, "FAIL", "GET /zones/%s/settings: security_header.strict_transport_security.enabled = %s (%s DNS record(s))" % (zname, hsts.get("enabled"), "?" if recs is None else len(recs)),
                                  severity="low", fix="enable HSTS at the zone (max-age 6 months, no preload) once every host on the zone answers https"))
        dnssec = z.get("dnssec")
        if dnssec is None:
            res.append(_unknown("cfacct.dnssec.%s" % zs, "%s: DNSSEC is active" % zname, snap, "dnssec:%s" % zname))
        elif dnssec.get("status") == "active":
            res.append(result("cfacct.dnssec.%s" % zs, "%s: DNSSEC is active" % zname, "PASS", "GET /zones/%s/dnssec: status = active" % zname))
        else:
            res.append(result("cfacct.dnssec.%s" % zs, "%s: DNSSEC is active" % zname, "FAIL", "GET /zones/%s/dnssec: status = %s" % (zname, dnssec.get("status")), severity="low",
                              fix="enable DNSSEC (DNS > Settings) and add the DS record at the registrar"))

    # dangling CNAME to a deleted Pages project
    cname_rows, dangling, unread = [], [], []
    for z in zones:
        recs = z.get("dns_records")
        if recs is None:
            unread.append(z.get("name"))
            continue
        for r in recs:
            tgt = str(r.get("content") or "")
            if r.get("type") == "CNAME" and tgt.endswith(".pages.dev"):
                project = tgt[: -len(".pages.dev")].split(".")[-1]
                cname_rows.append((r.get("name"), tgt, project))
    if unread and not cname_rows:
        res.append(_unknown("cfacct.dangling-cname", "No CNAME points at a missing Pages project", snap, "dns_records:%s" % unread[0]))
    elif project_names is None and cname_rows:
        res.append(_unknown("cfacct.dangling-cname", "No CNAME points at a missing Pages project", snap, "pages_projects",
                            evidence="%d pages.dev CNAME(s) found; the Pages project list could not be read" % len(cname_rows)))
    else:
        for name, tgt, project in cname_rows:
            if project not in project_names:
                dangling.append("%s -> %s (no Pages project named %s)" % (name, tgt, project))
        if dangling:
            res.append(result("cfacct.dangling-cname", "No CNAME points at a missing Pages project", "FAIL", ledger.join_hits(dangling, 4, "; "), severity="high",
                              fix="delete the record or repoint it; a pages.dev name anyone can create is a hostname anyone can claim",
                              detail="%s zone(s) unread" % len(unread) if unread else None))
        else:
            res.append(result("cfacct.dangling-cname", "No CNAME points at a missing Pages project", "PASS",
                              "%d pages.dev CNAME(s) across %d zone(s), each matching a live Pages project" % (len(cname_rows), len(zones) - len(unread)),
                              detail="%s zone(s) unread" % len(unread) if unread else None))

    members = snap.get("members")
    if members is None:
        res.append(_unknown("cfacct.members-2fa", "Every account member has two-factor authentication", snap, "members"))
    else:
        label = lambda m: str((m.get("user") or {}).get("email") or m.get("id") or "?")
        no2fa = [label(m) for m in members if (m.get("user") or {}).get("two_factor_authentication_enabled") is False]
        unread = [label(m) for m in members if (m.get("user") or {}).get("two_factor_authentication_enabled") is None]
        if no2fa:
            res.append(result("cfacct.members-2fa", "Every account member has two-factor authentication", "FAIL", ledger.join_hits(no2fa, 4, ", "), severity="high",
                              fix="turn on 2FA for each member at dash.cloudflare.com/profile and enforce it for the account (Manage Account > Members)",
                              detail="the dashboard is ground truth if it shows 2FA on; the API field is what was read" + ("; %d member(s) with no 2FA field (pending invitation)" % len(unread) if unread else "")))
        elif unread:
            res.append(result("cfacct.members-2fa", "Every account member has two-factor authentication", "UNKNOWN",
                              "GET /accounts/<id>/members: %d member(s), %d with no two_factor_authentication_enabled field: %s" % (len(members), len(unread), ledger.join_hits(unread, 4, ", ")),
                              reason="a pending invitation carries no 2FA state until the invitee accepts; re-check after acceptance or read Manage Account > Members"))
        else:
            res.append(result("cfacct.members-2fa", "Every account member has two-factor authentication", "PASS", "GET /accounts/<id>/members: %d member(s), two_factor_authentication_enabled true on each" % len(members)))

    if pages is None:
        res.append(_unknown("cfacct.pages-preview-secrets", "Pages previews do not carry production secrets", snap, "pages_projects"))
    else:
        shared = []
        for p in pages:
            cfg = p.get("deployment_configs") or {}
            prod = (cfg.get("production") or {}).get("env_vars") or {}
            prev = (cfg.get("preview") or {}).get("env_vars") or {}
            names = sorted(k for k, v in prev.items() if isinstance(v, dict) and v.get("type") == "secret_text" and k in prod)
            if names:
                shared.append("%s: %s" % (p.get("name"), ", ".join(names)))
        if shared:
            res.append(result("cfacct.pages-preview-secrets", "Pages previews do not carry production secrets", "FAIL", ledger.join_hits(shared, 4, "; "), severity="medium",
                              fix="give the preview environment test keys of its own (or no secret at all); a preview branch deploy otherwise runs with production money"))
        else:
            res.append(result("cfacct.pages-preview-secrets", "Pages previews do not carry production secrets", "PASS", "GET /accounts/<id>/pages/projects: %d project(s), no preview secret_text shared with production" % len(pages)))

    kv = snap.get("kv_namespaces")
    workers = snap.get("workers")
    if kv is None:
        res.append(_unknown("cfacct.kv-orphans", "Every KV namespace is bound by something", snap, "kv_namespaces"))
    elif workers is None or pages is None:
        res.append(_unknown("cfacct.kv-orphans", "Every KV namespace is bound by something", snap, "workers" if workers is None else "pages_projects",
                            evidence="%d namespace(s) listed; the binding owners could not all be read" % len(kv)))
    else:
        bound = set()
        for w in workers:
            for b in ((w.get("settings") or {}).get("bindings") or []):
                if b.get("type") == "kv_namespace" and b.get("namespace_id"):
                    bound.add(b["namespace_id"])
        for p in pages:
            for env in ((p.get("deployment_configs") or {}).values()):
                for b in ((env or {}).get("kv_namespaces") or {}).values():
                    if isinstance(b, dict) and b.get("namespace_id"):
                        bound.add(b["namespace_id"])
        orphans = [str(n.get("title") or n.get("id")) for n in kv if n.get("id") not in bound]
        if orphans:
            res.append(result("cfacct.kv-orphans", "Every KV namespace is bound by something", "FAIL", ledger.join_hits(orphans, 6, ", "), severity="info",
                              fix="delete the unbound namespaces on the owner's word (wrangler dev leaves *_preview twins behind)"))
        else:
            res.append(result("cfacct.kv-orphans", "Every KV namespace is bound by something", "PASS", "%d namespace(s), each bound by a Worker or a Pages project" % len(kv)))

    if workers is None:
        res.append(_unknown("cfacct.workers-dev-exposed", "No Worker holding data or secrets is reachable only on workers.dev", snap, "workers"))
    else:
        routed = set()
        for z in zones:
            for r in (z.get("worker_routes") or []):
                if r.get("script"):
                    routed.add(r["script"])
        for d in (snap.get("worker_domains") or []):
            if d.get("service"):
                routed.add(d["service"])
        exposed, partial = [], []
        # What each Worker holds: a data binding, a secret, a plain_text var whose name or value is a
        # credential (names.secret_name: it is a secret stored in the clear), or a service binding to a
        # Worker that holds data (reachable through this one). Followed to a fixed point (Phase 10).
        holds = {}
        for w in workers:
            st = w.get("settings") or {}
            kinds = set()
            for b in (st.get("bindings") or []):
                t = b.get("type")
                if t in DATA_BINDINGS:
                    kinds.add(t)
                elif t == "plain_text" and secret_name(b.get("name") or "", b.get("text") if isinstance(b.get("text"), str) else None):
                    kinds.add("plain_text secret %s" % b.get("name"))
            holds[w.get("id")] = kinds
        changed = True
        while changed:
            changed = False
            for w in workers:
                for b in ((w.get("settings") or {}).get("bindings") or []):
                    target = b.get("service")
                    if b.get("type") == "service" and holds.get(target) and target != w.get("id"):
                        tag = "service %s" % target
                        if tag not in holds[w.get("id")]:
                            holds[w.get("id")].add(tag)
                            changed = True
        for w in workers:
            name = w.get("id")
            sub, st = w.get("subdomain"), w.get("settings")
            if sub is None or st is None:
                partial.append(name)
                continue
            kinds = sorted(holds.get(name) or ())
            if sub.get("enabled") and name not in routed and kinds:
                exposed.append("%s (%s)" % (name, ", ".join(kinds)))
        if exposed:
            res.append(result("cfacct.workers-dev-exposed", "No Worker holding data or secrets is reachable only on workers.dev", "FAIL", ledger.join_hits(exposed, 6, "; "), severity="medium",
                              fix="set workers_dev = false and serve it on a zone route or custom domain (zone rules and Access cannot reach *.workers.dev), or delete the Worker",
                              detail="%d Worker(s) partially read" % len(partial) if partial else None))
        else:
            res.append(result("cfacct.workers-dev-exposed", "No Worker holding data or secrets is reachable only on workers.dev", "PASS",
                              "%d Worker(s): none with workers.dev on, no route, and a data or secret binding" % len(workers),
                              detail="%d Worker(s) partially read" % len(partial) if partial else None))
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", choices=["fetch", "check"], default="check")
    ap.add_argument("--snapshot", help="judge this saved snapshot instead of reading the API")
    ap.add_argument("--out", help="fetch: where to write the snapshot")
    ap.add_argument("--account", help="account id (default: the first account the token can list)")
    ap.add_argument("--api-base", default=os.environ.get("CLOUDFLARE_API_BASE", API), help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.snapshot and a.mode == "check":
        try:
            snap = json.load(open(a.snapshot, encoding="utf-8"))
        except (OSError, ValueError) as e:
            return ledger.emit([result("cfacct.snapshot", "Account snapshot", "UNKNOWN", a.snapshot, reason="snapshot unreadable: %s" % e)])
    else:
        token = os.environ.get("CLOUDFLARE_API_TOKEN")
        if not token:
            return ledger.emit([result("cfacct.token", "Cloudflare account read", "UNKNOWN", "CLOUDFLARE_API_TOKEN unset and no --snapshot given",
                                      reason="no token: export CLOUDFLARE_API_TOKEN (read-only scopes) or pass --snapshot account.json")])
        if not allowed_base(a.api_base):
            print("refused: the API base must be %s or a http://127.0.0.1 test server" % API, file=sys.stderr)
            return 2
        snap = fetch_snapshot(token, a.account, a.api_base)
        out = a.out or (tempfile.mkstemp(prefix="cf-account-", suffix=".json")[1] if a.mode == "fetch" else None)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(snap, fh, indent=1)
        if a.mode == "fetch":
            unauth = [e for e in snap["errors"] if e.get("code") in AUTH_CODES]
            print("snapshot written to %s (%d zone(s), %s Worker(s), %s Pages project(s))" % (
                out, len(snap.get("zones") or []), "?" if snap.get("workers") is None else len(snap["workers"]), "?" if snap.get("pages_projects") is None else len(snap["pages_projects"])))
            for e in unauth:
                print("unauthorized: %s (%s %s) needs %s" % (e["call"], e["code"], e["message"], PERMISSION.get(e["call"].split(":")[0], "?")))
            for e in snap["errors"]:
                if e.get("code") not in AUTH_CODES:
                    print("failed: %s (%s %s)" % (e["call"], e["code"], e["message"]))
            return 3 if unauth else 0
    cannot = [
        "Cloudflare Access policies and their members (Zero Trust dashboard): the Access app list is not read here",
        "API token inventory (scopes, expiry, last used): needs User API Tokens: Read on a user token",
        "Deployed Worker script content: the content endpoint; this check reads settings and bindings only",
        "KV, D1 and R2 contents: never read",
    ]
    return ledger.emit(judge(snap), cannot_see=cannot)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""check_gas.py - Google Apps Script adapter.

  check_gas.py REPO

  gas.webapp-access  appsscript.json webapp.access ANYONE_ANONYMOUS FAILs high
                     (critical when executeAs is USER_DEPLOYING: strangers run
                     code as the deployer); ANYONE (any Google account) FAILs low;
                     DOMAIN, MYSELF and no web app PASS.
  gas.scopes         explicit oauthScopes with a full-access scope where a
                     narrow one exists (drive, gmail full, mail.google.com,
                     spreadsheets) FAIL low; no oauthScopes: UNKNOWN (scopes
                     are auto-detected and not reviewable from the repo).
  gas.keys-in-code   a key-shaped value or an apiKey literal in .gs/.html/.js/.ts
                     (clasp transpiles .ts on push) FAILs high: use
                     PropertiesService. A name containing "key" is not enough on
                     its own: a Drive object id (SPREADSHEET_KEY passed to
                     openById) is an identifier, not a credential, unless it is
                     sent to a third party as one (an Authorization header, a
                     key= parameter); a Script Property NAME passed to
                     getProperty is not a value. A clasp rootDir under dist/ or
                     build/ is read too.
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

BROAD = {
    "https://www.googleapis.com/auth/drive": "drive.file or drive.readonly",
    "https://mail.google.com/": "gmail.send or gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify": "gmail.send or gmail.readonly",
    "https://www.googleapis.com/auth/spreadsheets": "spreadsheets.currentonly",
    "https://www.googleapis.com/auth/documents": "documents.currentonly",
}
# Quoted with ', " or a backtick (V8 template literal, Phase 10); a template with ${...} is not a literal.
KEY_LITERAL = re.compile(r"""(\w*(?:key|pass|password|passwd|secret|token|credential)\w*)['"]?\s*[:=]\s*(['"`])([^'"`\s]{16,})\2""", re.I)
SCAN_EXT = (".gs", ".html", ".js", ".ts")
# Apps Script code calls Drive object ids "keys" (SpreadsheetApp.openById(SPREADSHEET_KEY)); an id is not a credential.
DRIVE_OBJECT = re.compile(r"(?:^|_)(?:SPREADSHEET|SHEET|DOC|DOCUMENT|FOLDER|FILE|FORM|PRESENTATION|SLIDE|SLIDES|CALENDAR|SCRIPT|DEPLOYMENT|TEMPLATE|DRIVE)(?:_|$)", re.I)
DRIVE_ID = re.compile(r"^[A-Za-z0-9_\-]{20,70}$")


# A line that hands a value to a third party as a credential: an Authorization header, a bearer or
# basic scheme, a key/token/appid query parameter, an api-key header.
SENT_AS_CREDENTIAL = re.compile(r"""Authorization|\bBearer\b|\bBasic\b|[?&][\w-]*(?:key|token|appid|secret)[\w-]*=|['"][\w-]*(?:api[-_]?key|token)['"]\s*:""", re.I)


def _uses(name, text):
    """The lines that use `name` after its declaration (word-bounded, the declaration line excluded)."""
    lines = text.splitlines()
    rx = re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])")
    hits = [i for i, line in enumerate(lines) if rx.search(line)]
    return [lines[i] for i in hits[1:]]


def _drive_id(name, value, text):
    """A Drive/Sheets/Docs id: the value has an id shape (no symbols) AND the variable is passed to
    an openById/getFileById call, or the name says a Drive object and the value is never handed to
    a third party as a credential (Phase 10: TEMPLATE_KEY sent as `?api_key=` and FORM_KEY sent as
    a bearer were excused by the Drive word in the name alone)."""
    if not DRIVE_ID.match(value):
        return False
    if re.search(r"ById\(\s*" + re.escape(name) + r"\s*\)", text):
        return True
    return bool(DRIVE_OBJECT.search(name)) and not any(SENT_AS_CREDENTIAL.search(line) for line in _uses(name, text))


def _property_name(name, text):
    """The literal is the NAME of a Script Property, not its value: the variable is passed to
    getProperty / setProperty / deleteProperty (the pattern this check recommends)."""
    return bool(re.search(r"\.(?:get|set|delete)Property\(\s*" + re.escape(name) + r"\s*[,)]", text))


def _scan_roots(repo, manifests):
    """The repo, plus each manifest's folder that walk.files would skip (clasp rootDir `dist` or
    `build`: the pushed code lives there, Phase 10)."""
    roots = [repo]
    for mp in manifests:
        d = os.path.dirname(mp)
        parts = walk.rel(repo, d).split("/")
        if any(x in walk.SKIP_DIRS for x in parts) and d not in roots:
            roots.append(d)
    return roots


def _entropy(s):
    import math
    from collections import Counter
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def main():
    repo = os.path.abspath(sys.argv[1])
    manifests = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git") and not d.startswith(".")]
        manifests += [os.path.join(root, n) for n in names if n == "appsscript.json"]
    res = []
    for mp in manifests[:6]:
        rel = walk.rel(repo, mp)
        tag = "" if len(manifests) == 1 else "." + re.sub(r"[^A-Za-z0-9]+", "_", os.path.dirname(rel) or "root")
        try:
            m = json.load(open(mp))
        except ValueError:
            res.append(result("gas.manifest" + tag, "appsscript.json readable", "UNKNOWN", rel, reason="unparseable JSON"))
            continue
        wa = m.get("webapp")
        if not wa:
            res.append(result("gas.webapp-access" + tag, "Web app access is limited", "PASS", "%s: no webapp section (not deployed as a web app)" % rel))
        else:
            acc, ex = wa.get("access", ""), wa.get("executeAs", "")
            if acc == "ANYONE_ANONYMOUS":
                sev = "critical" if ex == "USER_DEPLOYING" else "high"
                res.append(result("gas.webapp-access" + tag, "Web app access is limited", "FAIL", "%s: access %s, executeAs %s" % (rel, acc, ex), severity=sev,
                                  fix="DOMAIN for one school's staff, or ANYONE (signed-in Google users) with an allow-list; never anonymous while executing as the deployer"))
            elif acc == "ANYONE":
                res.append(result("gas.webapp-access" + tag, "Web app access is limited", "FAIL", "%s: access ANYONE (any Google account)" % rel, severity="low",
                                  fix="DOMAIN if the audience is one organization; if it must be ANYONE, check Session.getActiveUser() against an allow-list"))
            else:
                res.append(result("gas.webapp-access" + tag, "Web app access is limited", "PASS", "%s: access %s" % (rel, acc or "default (MYSELF)")))
        scopes = m.get("oauthScopes")
        if scopes is None:
            res.append(result("gas.scopes" + tag, "OAuth scopes are narrow", "UNKNOWN", rel, reason="no oauthScopes: auto-detected at authorization, not reviewable here; list them explicitly"))
        else:
            broad = ["%s (use %s)" % (s.rsplit("/", 1)[-1] or s, BROAD[s]) for s in scopes if s in BROAD]
            if broad:
                res.append(result("gas.scopes" + tag, "OAuth scopes are narrow", "FAIL", "%s: %s" % (rel, "; ".join(broad)), severity="low",
                                  fix="replace each full-access scope with the narrow one the code needs"))
            else:
                res.append(result("gas.scopes" + tag, "OAuth scopes are narrow", "PASS", "%s: %d explicit scope(s), none full-access" % (rel, len(scopes))))
    if manifests:
        hits, seen = [], set()
        for p in (p for root in _scan_roots(repo, manifests) for p in walk.files(root, exts=SCAN_EXT, tests=False)):
            if p in seen:
                continue
            seen.add(p)
            t = walk.read(p)
            for rx in ledger.SECRET_SHAPES:
                for m in rx.finditer(t):
                    hits.append("%s:%d" % (walk.rel(repo, p), walk.line_of(t, m.start())))
            for m in KEY_LITERAL.finditer(t):
                name, v = m.group(1), m.group(3)
                if "${" in v:
                    continue
                if _entropy(v) >= 3.5 and not re.match(r"^(?:https?://|/|\.|[A-Z_]+$)", v) and not _drive_id(name, v, t) and not _property_name(name, t):
                    hits.append("%s:%d" % (walk.rel(repo, p), walk.line_of(t, m.start())))
        if hits:
            res.append(result("gas.keys-in-code", "No keys in Apps Script code", "FAIL", ledger.join_hits(sorted(set(hits)), 6, ", "), severity="high",
                              fix="store it with PropertiesService.getScriptProperties(), remove it from the file, rotate it"))
        else:
            res.append(result("gas.keys-in-code", "No keys in Apps Script code", "PASS", "no key-shaped value or key literal in %s" % "/".join(SCAN_EXT)))
    return ledger.emit(res, cannot_see=["The deployed version's access setting can differ from appsscript.json until a new deployment is made (clasp deploy)",
                                        "Script Properties contents: Apps Script editor, Project Settings (names only)"])


if __name__ == "__main__":
    sys.exit(main())

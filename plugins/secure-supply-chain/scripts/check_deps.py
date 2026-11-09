#!/usr/bin/env python3
"""check_deps.py - production dependency advisories, with reachability triage.

  check_deps.py REPO [--audit-json FILE]   (--audit-json: parse a saved `npm audit --json`, for tests)

Per package folder with a lockfile (root plus workspaces, never node_modules):
  - deps.lockfile.<dir>: a package.json with no lockfile FAILs (each install
    resolves different versions). Inside a git repo a lockfile counts only when
    git would ship it: one that exists on disk but is git-ignored FAILs, since
    CI and production never see it. A workspace member (a folder matched by the
    root package.json `workspaces` globs or pnpm-workspace.yaml `packages`, block
    or flow style, `./` prefixes allowed, `!` exclusions honored) is
    locked by the root lockfile and PASSes naming it; its audit is the root's.
  - deps.audit.<dir>.<package>: one result per high or critical production
    advisory. FAIL unless security/advisory-triage.json records it as not
    reachable with a reason and a review date, which makes it PASS with that
    reasoning shown. Reachable or untriaged stays FAIL. A parent flagged only
    through a child (npm lists the child's name in `via`) carries the child's
    advisories: triaged unreachable there means PASS here, untriaged means FAIL
    naming the child.
  - deps.audit.<dir>.moderate: moderate and low advisories, one result.
Reports: npm 7+ (per-package map), pnpm and npm 6 (advisories keyed by id) and
yarn classic (`yarn audit --json`, one JSON object per line) and yarn berry
(`yarn npm audit --json`, {value, children} per line) are all read; a yarn
line whose resolution is dev-only is left out, as --omit=dev would. Every
package folder gets its lockfile check; at most 12 lockfiled folders are
audited, the rest are UNKNOWN (never silently skipped).
A major-version fix is named as such; nothing is ever installed or bumped.
npm missing, offline, or an unparseable audit: UNKNOWN with the reason.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

LOCKS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn", "bun.lockb": "bun", "bun.lock": "bun"}


def triage(repo):
    p = os.path.join(repo, "security", "advisory-triage.json")
    if not os.path.exists(p):
        return {}
    try:
        data = json.load(open(p))
    except ValueError:
        return {}
    # Keyed by advisory (GHSA id, URL or npm source number), never by package alone: a new advisory
    # in an already-triaged package is untriaged (Phase 5 audit #13).
    out = {}
    for a in data.get("advisories", []):
        if a.get("package") and a.get("advisory") and a.get("reason") and a.get("reviewed") and "reachable" in a:
            out.setdefault(a["package"], {})[str(a["advisory"])] = a
    return out


def advisories(v, vulns=None, pkg=None, _seen=None):
    """One (owner package, alias set) per advisory npm attaches to a package: {GHSA id, its URL,
    npm source number}. pnpm's folded entries carry a single advisory_id. A `via` that is a bare
    package name is a child the parent is flagged through: its advisories are the parent's too,
    owned by the child, so the child's triage decides for the parent."""
    out = []
    seen = _seen if _seen is not None else set()
    if pkg is not None:
        seen.add(pkg)
    for via in v.get("via") or []:
        if isinstance(via, dict):
            al = set()
            if via.get("url"):
                al |= {via["url"], via["url"].rstrip("/").rsplit("/", 1)[-1]}
            if via.get("source") is not None:
                al.add(str(via["source"]))
            if al:
                out.append((pkg, al))
        elif isinstance(via, str) and vulns and via in vulns and via not in seen:
            out += advisories(vulns[via], vulns, via, seen)
    if v.get("advisory_id"):
        out.append((pkg, {str(v["advisory_id"])}))
    return out


def triage_state(tri, pkg, v, vulns=None):
    """('unreachable', entries) when every advisory is triaged unreachable; ('reachable', entries) when
    any triaged one is reachable; ('untriaged', missing ids) otherwise, including no advisory id at all.
    Advisories reached through a child package are looked up under the child's triage entries."""
    advs = advisories(v, vulns, pkg)
    if not advs:
        return "untriaged", ["(no advisory id in the report)"]
    hits, missing = [], []
    for owner, al in advs:
        entries = tri.get(owner or pkg, {})
        e = next((entries[a] for a in al if a in entries), None)
        if e is None:
            short = sorted((x for x in al if not x.startswith("http")), key=lambda x: (not x.startswith("GHSA"), x)) or sorted(al)
            missing.append(short[0] if owner in (None, pkg) else "%s (via %s)" % (short[0], owner))
        else:
            hits.append(e)
    if missing:
        return "untriaged", missing
    if any(h.get("reachable") is not False for h in hits):
        return "reachable", hits
    return "unreachable", hits


def through(v):
    """The child package names a parent is flagged through (npm's string entries in `via`)."""
    return [x for x in (v.get("via") or []) if isinstance(x, str)]


def _yaml_list(text, key):
    """The string items of a top-level YAML key, block style (`key:` then `- item` lines) or flow style
    (`key: ['a', "b"]`, possibly over several lines). Enough YAML for pnpm-workspace.yaml."""
    items, block, flow = [], False, None
    for line in text.splitlines():
        s = line.split(" #", 1)[0].rstrip() if not line.lstrip().startswith("#") else ""
        st = s.strip()
        if flow is not None:
            flow += " " + st
            if "]" in st:
                break
            continue
        if not st:
            continue
        if not line.startswith((" ", "\t", "-")):
            block = False
            m = re.match(r"%s\s*:\s*(.*)$" % re.escape(key), st)
            if m:
                rest = m.group(1).strip()
                if rest.startswith("["):
                    flow = rest
                    if "]" in rest:
                        break
                else:
                    block = True
            continue
        if block and st.startswith("- "):
            items.append(st[2:].strip())
    if flow is not None:
        items = [x.strip() for x in flow.strip().lstrip("[").split("]", 1)[0].split(",")]
    return [x.strip().strip("'\"") for x in items if x.strip().strip("'\"")]


def _norm_glob(g):
    g = g.strip()
    neg = g.startswith("!")
    g = g[1:] if neg else g
    while g.startswith("./"):
        g = g[2:]
    return neg, g.rstrip("/")


def workspace_globs(folder):
    """Workspace member globs declared in this folder: package.json `workspaces` (npm, yarn, bun;
    a list or {"packages": [...]}) and pnpm-workspace.yaml `packages:` (block or flow style).
    Returns (include, exclude): a leading `./` is dropped, a leading `!` is an exclusion."""
    globs = []
    pkg = walk.package_json(folder) or {}
    ws = pkg.get("workspaces")
    if isinstance(ws, dict):
        ws = ws.get("packages")
    if isinstance(ws, list):
        globs += [g for g in ws if isinstance(g, str)]
    globs += _yaml_list(walk.read(os.path.join(folder, "pnpm-workspace.yaml")), "packages")
    inc, exc = [], []
    for g in globs:
        neg, n = _norm_glob(g)
        if n:
            (exc if neg else inc).append(n)
    return inc, exc


def is_member(rel, globs):
    """A folder is a workspace member when an include glob matches it and no exclusion does."""
    inc, exc = globs
    return any(glob_match(rel, g) for g in inc) and not any(glob_match(rel, g) for g in exc)


def glob_match(rel, pattern):
    """A workspace glob against a repo-relative folder: `*` stays inside one path segment, `**` crosses."""
    rx = "".join(".*" if part == "**" else re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
                 for part in re.split(r"(\*\*)", pattern))
    return re.fullmatch(rx, rel) is not None


def lockfile_present(repo, folder, name):
    """A lockfile counts when it exists AND, inside a git repo, when git would ship it (tracked or
    untracked-but-not-ignored). Returns 'present', 'ignored' or None."""
    p = os.path.join(folder, name)
    if not os.path.exists(p):
        return None
    allowed = walk.git_files(repo)
    if allowed is None or walk.rel(repo, p) in allowed:
        return "present"
    return "ignored"


def parse_report(text):
    """One JSON document (npm, pnpm), or yarn classic's NDJSON (one object per line) folded into the
    advisories-by-id shape pnpm uses. (data, None) or (None, reason) when nothing can be read."""
    objs = []
    try:
        whole = json.loads(text)
        if not (isinstance(whole, dict) and "vulnerabilities" not in whole and (("type" in whole and "data" in whole) or _berry(whole))):
            return whole, None
        objs = [whole]  # a one-line yarn report (summary only, or one berry advisory) is still yarn's shape
    except ValueError:
        pass
    for line in [] if objs else text.splitlines():
        line = line.strip()
        if line:
            try:
                objs.append(json.loads(line))
            except ValueError:
                return None, "not JSON, not one JSON object per line"
    if not objs:
        return None, "empty report"
    advs, summary, errs = {}, None, []
    for o in objs:
        if not isinstance(o, dict):
            continue
        kind, data = o.get("type"), o.get("data")
        if kind == "auditAdvisory" and isinstance(data, dict):
            adv, res = data.get("advisory") or {}, data.get("resolution") or {}
            if res.get("dev") is True:
                continue  # a dev-only path: not production, as --omit=dev would leave it out
            key = str(adv.get("id") or res.get("id") or len(advs) + 1)
            advs[key] = adv
        elif _berry(o):
            # yarn berry `yarn npm audit --json`: {"value": package, "children": {"ID", "URL", "Severity", ...}}
            ch = o["children"]
            key = str(ch.get("ID") or ch.get("URL") or len(advs) + 1)
            advs[key] = {"id": ch.get("ID") or key, "module_name": o["value"], "severity": str(ch.get("Severity") or "low").lower(),
                         "url": ch.get("URL") or "", "patched_versions": ch.get("Patched Versions") or ""}
        elif kind == "auditSummary" and isinstance(data, dict):
            summary = data
        elif kind == "error":
            errs.append(str(data))
    if summary is None and not advs:
        return None, ("yarn: " + errs[-1][:160]) if errs else "one JSON object per line, but no auditSummary and no auditAdvisory"
    return {"advisories": advs, "metadata": summary or {}}, None


def _berry(o):
    return isinstance(o, dict) and isinstance(o.get("value"), str) and isinstance(o.get("children"), dict)


def yarn_berry(folder):
    """yarn 2+ (berry): a .yarnrc.yml, or a yarn.lock with a __metadata block."""
    return os.path.exists(os.path.join(folder, ".yarnrc.yml")) or "__metadata:" in walk.read(os.path.join(folder, "yarn.lock"))[:2000]


def package_dirs(repo):
    dirs = []
    for p in walk.files(repo, exts=("package.json",), tests=False):
        d = os.path.dirname(p)
        if d not in dirs:
            dirs.append(d)
    return dirs  # every folder gets its lockfile check; only the audits are capped (MAX_AUDITS)


MAX_AUDITS = 12  # each live audit is a registry call of up to 180 s


def audit(folder, tool, saved):
    if saved:
        data, why = parse_report(walk.read(saved))
        if data is None:
            return None, "saved audit could not be read: %s" % why
        return _validated(data, "saved audit")
    if tool != "npm":
        if not shutil.which(tool):
            return None, "%s lockfile but %s is not installed" % (tool, tool)
        if tool == "bun":
            return None, "bun has no audit command"
    if not shutil.which("npm"):
        return None, "npm not installed"
    if tool == "npm":
        cmd = ["npm", "audit", "--omit=dev", "--json"]
    elif tool == "yarn" and yarn_berry(folder):
        cmd = ["yarn", "npm", "audit", "--environment", "production", "--recursive", "--json"]
    else:
        cmd = [tool, "audit", "--prod", "--json"]
    try:
        r = subprocess.run(cmd, cwd=folder, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return None, "%s audit timed out" % tool
    data, why = parse_report(r.stdout)
    if data is None:
        return None, "%s audit gave no JSON (offline?): %s" % (tool, (r.stderr.strip().splitlines() or [why])[-1][:160])
    return _validated(data, "%s audit" % tool)


SEV_RANK = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


def _from_advisories(data):
    """pnpm (and npm 6) report advisories keyed by id; fold them into npm 7's per-package map,
    keeping every advisory id and the highest severity."""
    out = {}
    for key, adv in (data.get("advisories") or {}).items():
        name, sev = adv.get("module_name"), adv.get("severity", "low")
        if not name:
            continue
        entry = out.setdefault(name, {"severity": sev, "fixAvailable": False, "via": []})
        if SEV_RANK.get(sev, 0) > SEV_RANK.get(entry["severity"], 0):
            entry["severity"] = sev
        patched = adv.get("patched_versions") or ""
        entry["fixAvailable"] = entry["fixAvailable"] or (bool(patched) and patched != "<0.0.0")
        entry["via"].append({"source": adv.get("id", key), "url": adv.get("url") or ""})
    return out


def _validated(data, label):
    """An audit report without a vulnerabilities map measured nothing: never read it as clean."""
    if isinstance(data, dict) and "vulnerabilities" not in data and isinstance(data.get("advisories"), dict):
        data = dict(data, vulnerabilities=_from_advisories(data))
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict):
        err = data.get("error") if isinstance(data, dict) else None
        detail = str(err.get("summary", err) if isinstance(err, dict) else err or "no vulnerabilities map in the report")
        return None, "%s did not measure anything: %s" % (label, detail[:160])
    return data, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--audit-json")
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    tri = triage(repo)
    res = []
    dirs = package_dirs(repo)
    # Workspace roots: a folder with a committed lockfile that declares member globs locks its members.
    roots = []
    for d in dirs:
        lock = next((f for f in LOCKS if lockfile_present(repo, d, f) == "present"), None)
        globs = workspace_globs(d) if lock else ([], [])
        if globs[0]:
            roots.append((d, lock, globs))
    audited = 0
    for d in dirs:
        rel = walk.rel(repo, d) if d != repo else "."
        tag = "root" if rel == "." else rel.replace("/", "_")
        states = {f: lockfile_present(repo, d, f) for f in LOCKS}
        locks = [f for f, s in states.items() if s == "present"]
        if not locks:
            owner = next(((r, lock) for r, lock, globs in roots if r != d and d.startswith(r + os.sep)
                          and is_member(walk.rel(r, d), globs)), None)
            if owner:
                rrel = walk.rel(repo, owner[0]) if owner[0] != repo else "."
                res.append(result("deps.lockfile.%s" % tag, "Lockfile present in %s" % rel, "PASS",
                                  "%s/%s locks workspace member %s" % (rrel, owner[1], rel)))
                continue  # the root audit covers its members
            ignored = [f for f, s in states.items() if s == "ignored"]
            if ignored:
                res.append(result("deps.lockfile.%s" % tag, "Lockfile present in %s" % rel, "FAIL",
                                  "%s/%s exists on disk but is git-ignored: not committed, so CI and production resolve fresh versions" % (rel, ignored[0]),
                                  severity="medium", fix="remove the lockfile from .gitignore, commit it and install with npm ci"))
            else:
                res.append(result("deps.lockfile.%s" % tag, "Lockfile present in %s" % rel, "FAIL", "%s/package.json with no lockfile" % rel,
                                  severity="medium", fix="commit a lockfile and install with npm ci so every build resolves the same versions"))
            continue
        res.append(result("deps.lockfile.%s" % tag, "Lockfile present in %s" % rel, "PASS", "%s/%s" % (rel, locks[0])))
        audited += 1
        if audited > MAX_AUDITS:
            res.append(result("deps.audit.%s" % tag, "Production advisories in %s" % rel, "UNKNOWN", "%s/%s" % (rel, locks[0]),
                              reason="not audited: more than %d folders with their own lockfile; run the audit in this folder by hand" % MAX_AUDITS))
            continue
        data, why = audit(d, LOCKS[locks[0]], a.audit_json)
        if data is None:
            res.append(result("deps.audit.%s" % tag, "Production advisories in %s" % rel, "UNKNOWN", "%s/%s" % (rel, locks[0]), reason=why))
            continue
        vulns = data.get("vulnerabilities") or {}
        minor = []
        for pkg, v in sorted(vulns.items()):
            sev = v.get("severity", "low")
            fix = v.get("fixAvailable")
            major = isinstance(fix, dict) and fix.get("isSemVerMajor")
            fixtxt = ("fix is a MAJOR bump to %s %s: a separate decision, never auto-applied" % (fix.get("name"), fix.get("version"))) if major \
                else ("compatible fix available: npm audit fix (review the lockfile diff)" if fix else "no fix published: triage reachability")
            if sev in ("high", "critical"):
                cid = "deps.audit.%s.%s" % (tag, pkg)
                state, info = triage_state(tri, pkg, v, vulns)
                via = through(v)
                if state == "unreachable":
                    res.append(result(cid, "%s advisories in %s are unreachable" % (pkg, rel), "PASS",
                                      "security/advisory-triage.json (reviewed %s)" % info[0]["reviewed"],
                                      detail=("flagged only through %s; " % ", ".join(via) if via else "") + "triaged per advisory: " + "; ".join(e["reason"] for e in info)))
                else:
                    res.append(result(cid, "No %s advisory in production dependency %s" % (sev, pkg), "FAIL", "%s/%s: %s audit, production deps" % (rel, locks[0], LOCKS[locks[0]]),
                                      severity="critical" if sev == "critical" else "high", fix=fixtxt,
                                      detail=("triaged REACHABLE: " + info[0]["reason"]) if state == "reachable"
                                      else "untriaged advisory %s: record reachability per advisory id in security/advisory-triage.json" % ledger.join_hits(info, 3, ", ")))
            else:
                minor.append("%s (%s%s)" % (pkg, sev, ", major fix" if major else ""))
        untriaged_minor = [m for m in minor if triage_state(tri, m.split(" ")[0], vulns.get(m.split(" ")[0], {}), vulns)[0] != "unreachable"]
        if untriaged_minor:
            res.append(result("deps.audit.%s.moderate" % tag, "No untriaged moderate/low advisories in %s" % rel, "FAIL", "%s: %s" % (rel, ledger.join_hits(untriaged_minor, 8, ", ")),
                              severity="low", fix="triage each in security/advisory-triage.json (reachable or not, with the reason); take compatible fixes"))
        else:
            res.append(result("deps.audit.%s.moderate" % tag, "No untriaged moderate/low advisories in %s" % rel, "PASS",
                              "%s: npm audit --omit=dev, %d moderate/low, all triaged unreachable" % (rel, len(minor)) if minor else "%s: npm audit --omit=dev found none" % rel))
    if os.path.exists(os.path.join(repo, "requirements.txt")):
        if shutil.which("pip-audit"):
            r = subprocess.run(["pip-audit", "-r", "requirements.txt"], cwd=repo, capture_output=True, text=True, timeout=300)
            if r.returncode == 0:
                res.append(result("deps.python", "No Python advisories", "PASS", "pip-audit -r requirements.txt"))
            else:
                res.append(result("deps.python", "No Python advisories", "FAIL", "pip-audit -r requirements.txt", severity="medium",
                                  fix="upgrade or triage each pip-audit finding"))
        else:
            res.append(result("deps.python", "No Python advisories", "UNKNOWN", "requirements.txt", reason="pip-audit not installed (uv tool install pip-audit)"))
    elif os.path.exists(os.path.join(repo, "pyproject.toml")):
        res.append(result("deps.python", "No Python advisories", "UNKNOWN", "pyproject.toml",
                          reason="pyproject without requirements.txt: run pip-audit inside the project's environment"))
    if not res:
        res.append(result("deps.none", "Dependency audit", "UNKNOWN", repo, reason="no package.json or Python manifest found"))
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

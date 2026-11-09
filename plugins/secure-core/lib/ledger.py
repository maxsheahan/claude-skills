"""ledger.py - the one findings format every secure-launch check speaks.

A check result is PASS, FAIL or UNKNOWN. There is no fourth state and no
default: a result with any other status, a PASS without evidence, a FAIL
without a severity or a fix, or an UNKNOWN without a reason is rejected, so a
check cannot report a verdict it did not measure.

UNKNOWN means "not run, or could not run". It is counted on its own line
everywhere and is never folded into PASS or FAIL. `security/accepted.json` can
mark a specific check id as accepted (with a reason and a ruling date); an
accepted result keeps its status and stays in the report, it only stops the
gate from refusing on it.

Check scripts call `emit(results)` and print one JSON object on stdout.
"""
import datetime
import json
import os
import re
import sys

STATUSES = ("PASS", "FAIL", "UNKNOWN")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SUITE_VERSION = "0.6.1"

# Values that look like credentials. Used to refuse writing them anywhere: a
# check must report a location, never a value. Patterns match key SHAPES only.
SECRET_SHAPES = [
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"sk-ant-[0-9A-Za-z_\-]{20,}"),
    re.compile(r"sk-(?:proj-)?[0-9A-Za-z_\-]{32,}"),
    re.compile(r"[sr]k_(?:live|test)_[0-9A-Za-z]{16,}"),
    re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"),
    re.compile(r"github_pat_[0-9A-Za-z_]{40,}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    re.compile(r"eyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@'\"]+:[^@\s/'\"]{6,}@"),   # URL with a password
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]
_TOKEN = re.compile(r"[A-Za-z0-9+_\-]{32,}")  # no "/": paths are not keys


def _high_entropy(text):
    """A 32+ char run mixing upper, lower and digits with high entropy: a key with no known shape."""
    import math
    from collections import Counter
    for m in _TOKEN.finditer(text or ""):
        s = m.group(0)
        if not (any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)):
            continue
        c = Counter(s)
        if -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) > 4.3:
            return True
    return False


class LedgerError(ValueError):
    pass


def result(id, title, status, evidence, severity=None, fix=None, reason=None, detail=None):
    """Build one check result. Validation happens in validate()."""
    r = {"id": id, "title": title, "status": status, "evidence": evidence}
    if severity:
        r["severity"] = severity
    if fix:
        r["fix"] = fix
    if reason:
        r["reason"] = reason
    if detail:
        r["detail"] = detail
    return r


_PYC_RX = re.compile(r"(^|/)__pycache__/[^/]+\.py[co]$")
# Every GIT_* variable is dropped, not only the index and object ones: a hook exports GIT_DIR and
# GIT_WORK_TREE, and under them `git -C repo` hashes the HOOK's repo with no error (audit 2026-11-07).


def git_state(repo, exclude=()):
    """HEAD plus a hash of the working tree's CONTENT, shared by the orchestrator and the gate.

    The tree is hashed by staging every non-ignored file into a throwaway index (seeded from HEAD's
    tree with no stat data, so every file is re-read) and running `git write-tree` on it, with new
    objects written to a throwaway object directory that borrows the repo's store as an alternate.
    The repo's own index, HEAD and object store are never written. The old fingerprint hashed
    `git status --porcelain` lines and missed a file edited after the run whenever its status line
    stayed the same (an untracked or already-modified file; Phase 10 audit F4, F5, F6).

    Left out: git-ignored files (`git add -A` honors .gitignore and info/exclude); Python bytecode,
    only paths matching `(^|/)__pycache__/<name>.pyc|.pyo` (running vendored scripts writes it inside a
    committed .secure-launch/, which changed the tree between ledger and gate on the first real CI run,
    a coaching app's PR, 2026-10-09); and the paths in `exclude`, meant for the ledger file itself,
    which carries this binding and so cannot be part of what it hashes.

    Returns None outside a git repo, and {"head", "status": None, "error"} when the tree could not be
    hashed (the gate refuses that)."""
    import shutil
    import subprocess
    import tempfile
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

    def git(where, *args, tenv=None, stdin=None):
        return subprocess.run(["git", "-C", where] + list(args), capture_output=True, text=True,
                              env=tenv or env, input=stdin)

    def last(r):
        return (r.stderr.strip().splitlines()[-1:] or [""])[0][:200]

    head = git(repo, "rev-parse", "HEAD")
    if head.returncode != 0:
        return None
    state = {"head": head.stdout.strip(), "status": None}
    top = git(repo, "rev-parse", "--show-toplevel").stdout.strip()
    index = git(repo, "rev-parse", "--git-path", "index").stdout.strip()
    objects = git(repo, "rev-parse", "--git-path", "objects").stdout.strip()
    if not (top and index and objects):
        state["error"] = "git rev-parse could not name the work tree, index or object store"
        return state
    index, objects = (os.path.normpath(os.path.join(repo, x)) for x in (index, objects))  # relative to -C repo
    tmp = tempfile.mkdtemp(prefix="sl-gitstate-")
    try:
        tidx = os.path.join(tmp, "index")
        os.makedirs(os.path.join(tmp, "objects"))
        tenv = dict(env, GIT_INDEX_FILE=tidx, GIT_OBJECT_DIRECTORY=os.path.join(tmp, "objects"),
                    GIT_ALTERNATE_OBJECT_DIRECTORIES=objects)
        # The throwaway index starts from HEAD's tree with no cached stat data, so `git add -A` re-reads
        # every file. A copy of the repo's index carried stat data that git trusted once the copy looked
        # newer than the file: a same-size edit in the second of the last index write then passed the gate
        # (audit case F3, about 1 run in 6 on 0.6.0, 2026-11-09).
        seed = git(top, "read-tree", "HEAD", tenv=tenv)
        if seed.returncode != 0:
            state["error"] = "git read-tree into a throwaway index failed: %s" % last(seed)
            return state
        add = git(top, "add", "-A", "--", ".", tenv=tenv)
        if add.returncode != 0:
            state["error"] = "git add into a throwaway index failed: %s" % last(add)
            return state
        listed = set(p for p in git(top, "ls-files", "-z", "--cached", tenv=tenv).stdout.split("\0") if p)
        real_top = os.path.realpath(top)
        drop = {p for p in listed if _PYC_RX.search(p)}
        for e in exclude or ():
            rel = os.path.relpath(os.path.realpath(e), real_top).replace(os.sep, "/")
            if rel in listed:
                drop.add(rel)
        if drop:
            rm = git(top, "update-index", "--force-remove", "-z", "--stdin", tenv=tenv, stdin="\0".join(sorted(drop)) + "\0")
            if rm.returncode != 0:
                state["error"] = "git update-index on the throwaway index failed: %s" % last(rm)
                return state
        tree = git(top, "write-tree", tenv=tenv)
        if tree.returncode != 0 or not tree.stdout.strip():
            state["error"] = "git write-tree on the throwaway index failed: %s" % last(tree)
            return state
        state["status"] = tree.stdout.strip()
        return state
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def join_hits(hits, n=6, sep="; "):
    """Evidence for a list of hits. When truncated it ends with the total and a
    fingerprint of the FULL list, so an acceptance bound to this evidence stops
    matching the moment a new hit appears (Phase 5 audit, second pass)."""
    import hashlib
    hits = [str(h) for h in hits]
    shown = sep.join(hits[:n])
    if len(hits) <= n:
        return shown
    # A display fingerprint so a reader sees the hidden list changed, never a security check.
    fp = hashlib.sha1("\n".join(sorted(hits)).encode(), usedforsecurity=False).hexdigest()[:10]  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return "%s (+%d more; %d total, fingerprint %s)" % (shown, len(hits) - n, len(hits), fp)


def contains_secret_shape(text):
    return any(p.search(text or "") for p in SECRET_SHAPES) or _high_entropy(text)


def validate(r):
    if not isinstance(r, dict):
        raise LedgerError("result is not an object: %r" % (r,))
    for k in ("id", "title", "status", "evidence"):
        if not r.get(k):
            raise LedgerError("%s: missing %s" % (r.get("id", "?"), k))
    st = r["status"]
    if st not in STATUSES:
        raise LedgerError("%s: status %r is not PASS, FAIL or UNKNOWN" % (r["id"], st))
    if st == "FAIL":
        if r.get("severity") not in SEVERITIES:
            raise LedgerError("%s: FAIL needs a severity in %s" % (r["id"], SEVERITIES))
        if not r.get("fix"):
            raise LedgerError("%s: FAIL needs a one-line fix" % r["id"])
    if st == "UNKNOWN" and not r.get("reason"):
        raise LedgerError("%s: UNKNOWN needs the reason it could not run" % r["id"])
    blob = json.dumps(r)
    if contains_secret_shape(blob):
        raise LedgerError("%s: result text contains a credential-shaped value; report the location only" % r["id"])
    return r


def emit(results, out=sys.stdout, cannot_see=None):
    """Validate and print one JSON object for the orchestrator. Exit code: 0
    all PASS, 1 any FAIL, 3 no FAIL but some UNKNOWN (so a caller that only
    reads exit codes still cannot mistake UNKNOWN for PASS)."""
    for r in results:
        validate(r)
    payload = {"checks": results}
    if cannot_see:
        payload["cannot_see"] = list(cannot_see)
    json.dump(payload, out, indent=1)
    out.write("\n")
    statuses = {r["status"] for r in results}
    if "FAIL" in statuses:
        return 1
    if "UNKNOWN" in statuses or not results:
        return 3
    return 0


ACCEPT_DAYS = 90


def load_accepted(repo, today=None):
    """security/accepted.json: {"accepted": [{"id", "reason", "ruled": "YYYY-MM-DD",
    "evidence": <the exact evidence string ruled on>, "expires"?: "YYYY-MM-DD"}]}.
    An acceptance covers ONE result: same id AND same evidence, so a new leak
    under the same id is not covered. It expires (default 90 days after the
    ruling). Expired entries are dropped, never honored."""
    p = os.path.join(repo, "security", "accepted.json")
    if not os.path.exists(p):
        return {}
    try:
        data = json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LedgerError("security/accepted.json unreadable: %s" % exc)
    today = today or datetime.date.today()
    out = {}
    for a in data.get("accepted", []):
        if not (a.get("id") and a.get("reason") and a.get("ruled") and a.get("evidence")):
            raise LedgerError("accepted entry needs id, reason, ruled (YYYY-MM-DD) and the evidence it was ruled on: %r" % (a.get("id"),))
        try:
            ruled = datetime.date.fromisoformat(a["ruled"])
            expires = datetime.date.fromisoformat(a["expires"]) if a.get("expires") else ruled + datetime.timedelta(days=ACCEPT_DAYS)
        except ValueError:
            raise LedgerError("accepted %s: ruled/expires must be YYYY-MM-DD" % a["id"])
        if ruled > today:
            raise LedgerError("accepted %s: ruled %s is in the future" % (a["id"], a["ruled"]))
        expires = min(expires, ruled + datetime.timedelta(days=ACCEPT_DAYS))  # never longer than 90 days
        if expires < today:
            continue
        a = dict(a, expires=expires.isoformat())
        out[(a["id"], a["evidence"])] = a
    return out


def acceptance(accepted, r):
    """The acceptance covering this exact result, or None. Critical FAILs are never acceptable."""
    if r["status"] == "FAIL" and r.get("severity") == "critical":
        return None
    return accepted.get((r["id"], r["evidence"]))


def counts(results):
    c = {s: 0 for s in STATUSES}
    for r in results:
        c[r["status"]] += 1
    return c


def build(repo, results, stack, adapters, accepted=None, cannot_see=None):
    accepted = accepted or {}
    for r in results:
        validate(r)
        a = acceptance(accepted, r)
        if a:
            r["accepted"] = {"reason": a["reason"], "ruled": a["ruled"], "expires": a["expires"]}
    return {
        "suite_version": SUITE_VERSION,
        "repo": os.path.realpath(repo),
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "stack": stack,
        "adapters": adapters,
        "counts": counts(results),
        "results": results,
        "cannot_see": sorted(set(cannot_see or [])),
    }


SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def to_markdown(ledger):
    c = ledger["counts"]
    lines = [
        "# Security findings: %s" % os.path.basename(ledger["repo"]),
        "",
        "Generated %s by secure-launch %s. **%d FAIL, %d UNKNOWN, %d PASS.** UNKNOWN means not run or could not run; it is not a pass."
        % (ledger["generated_at"], ledger["suite_version"], c["FAIL"], c["UNKNOWN"], c["PASS"]),
        "",
        "Stack detected: %s" % (", ".join(ledger["stack"]) or "nothing recognised"),
        "",
    ]
    for status in ("FAIL", "UNKNOWN", "PASS"):
        rows = [r for r in ledger["results"] if r["status"] == status]
        if not rows:
            continue
        rows.sort(key=lambda r: (SEV_ORDER.get(r.get("severity", "info"), 9), r["id"]))
        lines += ["## %s (%d)" % (status, len(rows)), ""]
        for r in rows:
            head = "- **%s** `%s`" % (r["title"], r["id"])
            if status == "FAIL":
                head += " [%s]" % r["severity"]
            if r.get("accepted"):
                head += " (accepted %s: %s)" % (r["accepted"]["ruled"], r["accepted"]["reason"])
            lines.append(head)
            lines.append("  - evidence: %s" % r["evidence"])
            if r.get("reason"):
                lines.append("  - why unknown: %s" % r["reason"])
            if r.get("fix") and status != "PASS":
                lines.append("  - fix: %s" % r["fix"])
            if r.get("detail"):
                lines.append("  - %s" % r["detail"])
        lines.append("")
    if ledger.get("cannot_see"):
        lines += ["## What this run cannot see", "", "Not checks, so not counted. Each needs a human look (dashboard, live data) before calling the repo covered.", ""]
        lines += ["- %s" % s for s in ledger["cannot_see"]] + [""]
    lines += ["## Adapters", ""] + ["- %s: %s" % (k, v) for k, v in sorted(ledger["adapters"].items())]
    return "\n".join(lines) + "\n"

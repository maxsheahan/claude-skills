#!/usr/bin/env python3
"""scan_captures.py - find secret values in captured session transcripts
without printing them.

  scan_captures.py [DIR ...] [--json]

Default DIRs: four capture folders under the notes root in VAULT below;
pass DIRs explicitly to scan anywhere else.
Runs gitleaks over plain files with the value fully redacted, after proving
the detector on planted fake keys. Prints RULE  path:line, never the match.
JSON captures (.jsonl, .json) are also scanned DECODED: every string value is
written, unescaped, to a private temp mirror, so a key whose closing quote is
JSON-escaped (a backslash before it) or whose letters are unicode-escaped
still meets the provider rule; a mirror hit is reported at the original file
and line.

Exit: 0 clean, 1 findings, 2 detector not proven or not installed (report
"not run", never "clean").

STAGED: nothing schedules this. Wiring it into an automated commit is a
standing change for the owner; the steps are in the secure-launch README.
"""
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile

# Folders to scan when none are passed: SECURE_CAPTURE_DIRS, separated like PATH.
CAPTURE_DIRS_ENV = "SECURE_CAPTURE_DIRS"


def gitleaks(path, report):
    empty = os.path.join(os.path.dirname(report), "noignore")
    os.makedirs(empty, exist_ok=True)
    subprocess.run(["gitleaks", "dir", path, "-c", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gitleaks-suite.toml"),
                    "-i", empty, "--ignore-gitleaks-allow", "--redact=100", "--no-banner", "-f", "json", "-r", report],
                   capture_output=True, text=True)
    try:
        return json.load(open(report))
    except (OSError, ValueError):
        return None


def decoded_mirror(src, dst):
    """Write every string value of each JSON line (.jsonl) or document (.json) under src,
    JSON-unescaped, to the same relative path under dst. Returns {mirror path: [original line
    for each mirror line]}. Unparseable lines are skipped; the originals are scanned anyway."""
    lines_of = {}
    for root, dirs, names in os.walk(src):
        dirs[:] = [d for d in dirs if d != ".git"]
        for n in names:
            if not n.endswith((".jsonl", ".json")):
                continue
            path = os.path.join(root, n)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(50_000_000)
            except OSError:
                continue
            docs = list(enumerate(text.splitlines(), 1)) if n.endswith(".jsonl") else [(1, text)]
            out, origin = [], []
            for lineno, chunk in docs:
                try:
                    doc = json.loads(chunk)
                except ValueError:
                    continue
                stack = [doc]
                while stack:
                    v = stack.pop()
                    if isinstance(v, str):
                        for piece in v.splitlines() or [""]:
                            out.append(piece)
                            origin.append(lineno)
                    elif isinstance(v, dict):
                        stack.extend(v.values())
                    elif isinstance(v, list):
                        stack.extend(v)
            if out:
                mp = os.path.join(dst, os.path.relpath(path, src))
                os.makedirs(os.path.dirname(mp), exist_ok=True)
                with open(mp, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(out) + "\n")
                lines_of[mp] = origin
    return lines_of


def prove(work):
    r = random.Random(11)
    al = string.ascii_letters + string.digits
    canary = os.path.join(work, "canary")
    os.makedirs(canary)
    with open(os.path.join(canary, "session.md"), "w") as fh:
        fh.write("Ran the command and it printed:\n")
        fh.write("GOOGLE_MAPS_KEY=AIza" + "".join(r.choice(al + "-_") for _ in range(35)) + "\n")
        fh.write("stripe " + "sk_" + "live_" + "".join(r.choice(al) for _ in range(40)) + "\n")
    got = gitleaks(canary, os.path.join(work, "canary.json"))
    return got is not None and len(got) >= 2


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not shutil.which("gitleaks"):
        print("gitleaks not installed (brew install gitleaks): capture scan NOT RUN")
        return 2
    dirs = args or [os.path.expanduser(d) for d in os.environ.get(CAPTURE_DIRS_ENV, "").split(os.pathsep) if d]
    if not dirs:
        print("no capture folders: pass them as arguments or set %s; capture scan NOT RUN" % CAPTURE_DIRS_ENV)
        return 2
    work = tempfile.mkdtemp(prefix="capscan-")
    try:
        if not prove(work):
            print("DETECTOR NOT PROVEN on planted keys: capture scan NOT RUN")
            return 2
        findings, scanned = [], []
        for i, d in enumerate(dirs):
            if not os.path.isdir(d):
                print("skipped (not found): %s" % d)
                continue
            got = gitleaks(d, os.path.join(work, "r%d.json" % i))
            if got is None:
                print("SCAN FAILED on %s: capture scan NOT RUN" % d)
                return 2
            scanned.append(d)
            seen = set()
            for f in got:
                seen.add((f.get("RuleID"), f.get("File"), f.get("StartLine")))
                findings.append({"rule": f.get("RuleID"), "file": f.get("File"), "line": f.get("StartLine")})
            mirror = os.path.join(work, "decoded%d" % i)
            lines_of = decoded_mirror(d, mirror)
            if lines_of:
                dec = gitleaks(mirror, os.path.join(work, "d%d.json" % i))
                if dec is None:
                    print("SCAN FAILED on the decoded JSON of %s: capture scan NOT RUN" % d)
                    return 2
                for f in dec:
                    mp = os.path.join(mirror, os.path.relpath(f.get("File") or "", mirror)) if not os.path.isabs(f.get("File") or "") else f.get("File")
                    origin = lines_of.get(mp) or lines_of.get(os.path.realpath(mp)) or []
                    ln = f.get("StartLine") or 0
                    orig_line = origin[ln - 1] if 0 < ln <= len(origin) else None
                    key = (f.get("RuleID"), os.path.join(d, os.path.relpath(mp, mirror)), orig_line)
                    if key in seen or (key[0], os.path.relpath(key[1]), key[2]) in seen:
                        continue
                    seen.add(key)
                    findings.append({"rule": f.get("RuleID"), "file": key[1], "line": orig_line})
        if as_json:
            print(json.dumps({"scanned": scanned, "findings": findings}, indent=1))
        else:
            print("detector proven; scanned %d folder(s); %d finding(s)" % (len(scanned), len(findings)))
            for f in findings:
                print("  %s  %s:%s" % (f["rule"], f["file"], f["line"]))
        return 1 if findings else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

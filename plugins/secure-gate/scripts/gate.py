#!/usr/bin/env python3
"""gate.py - turn a secure-launch ledger into a ship / do-not-ship decision.

  gate.py LEDGER [--repo R] [--tests-from security/gate.json] [--max-age-hours N]

Refuses (exit 1) on any FAIL and on any UNKNOWN, unless that exact check id is
listed in R/security/accepted.json with a reason and a ruling date. Accepted
items are still printed. An empty ledger refuses: nothing measured is not a
pass, and a passing test command never stands in for a scan. A malformed or
internally inconsistent ledger is exit 2: counts that do not match the
results, a repo field that is missing or relative (a ledger that does not
name the absolute checkout it judged is not bound to this one), no git
binding while R is a git repo, a binding to another commit or working tree (the
binding is a hash of every non-ignored file's content, see ledger.git_state),
a generated_at with no time zone or more than five minutes in the future.

--tests-from: a JSON file {"test_command": "npm run test:api"} naming the
repo's mutation-proven security tests. The command runs after the ledger is
found usable and non-empty; a failure refuses. A missing file becomes UNKNOWN
gate.tests (refused unless accepted).

What the gate cannot see: a well-formed, fresh ledger whose rows were edited
with the counts recomputed. The ledger carries no signature, so the control
for that is CI writing the ledger in-job, outside the checkout (the
templates do), never trusting one found in the tree.

In GitHub Actions it writes ::error / ::warning annotations and a step summary.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402

GHA = os.environ.get("GITHUB_ACTIONS") == "true"
FUTURE_SKEW_SECONDS = 5 * 60  # a generated_at further ahead of this clock than this is not a timestamp, it is an edit


def note(kind, msg):
    if GHA:
        print("::%s::%s" % (kind, msg.replace("\n", " ")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ledger")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tests-from")
    ap.add_argument("--max-age-hours", type=float, default=6.0, help="refuse an older ledger (default 6 h); 0 or less never turns the check off")
    a = ap.parse_args()
    try:
        led = json.load(open(a.ledger))
        results = led["results"]
        for r in results:
            ledger.validate(r)
    except (OSError, ValueError, KeyError, TypeError, ledger.LedgerError) as exc:
        print("GATE ERROR: ledger unusable: %s" % exc)
        return 2
    if ledger.counts(results) != led.get("counts"):
        print("GATE ERROR: ledger counts do not match its results (edited by hand?)")
        return 2
    here = os.path.realpath(a.repo)
    named = led.get("repo")
    if not isinstance(named, str) or not os.path.isabs(named):
        # "" and "." would resolve to the gate's working directory, which IS the repo in CI and in the
        # hook: a ledger that names no absolute checkout would match wherever it is copied or cloned.
        print("GATE ERROR: ledger names no absolute repo (%r); a ledger that does not say which checkout it judged is not bound to this one" % (named,))
        return 2
    if os.path.realpath(named) != here:
        print("GATE ERROR: ledger is for %s, not %s (a committed or copied ledger is never trusted)" % (named, here))
        return 2
    ran = {k: v for k, v in (led.get("adapters") or {}).items() if str(v).startswith("ran")}
    if not ran:
        print("GATE ERROR: ledger records no adapter that ran")
        return 2
    g = led.get("git")
    now = ledger.git_state(a.repo, exclude=[os.path.abspath(a.ledger)])  # the ledger cannot hash itself; the orchestrator leaves it out too
    if now is not None and not now.get("status"):
        print("GATE ERROR: cannot hash the working tree of %s (%s), so the ledger cannot be bound to it" % (here, now.get("error", "no tree hash")))
        return 2
    if g is not None and not isinstance(g, dict):
        print("GATE ERROR: ledger git binding is not an object (%r)" % (g,))
        return 2
    if g is None and now is not None:
        print("GATE ERROR: %s is a git repo but the ledger has no git binding (it does not say which commit it judged); re-run secure-launch" % here)
        return 2
    if g is not None:
        now = now or {}
        if now.get("head") != g.get("head") or now.get("status") != g.get("status"):
            print("GATE ERROR: ledger was made at another commit or working tree (%s); re-run secure-launch" % (str(g.get("head", ""))[:10]))
            return 2
    if led.get("complete") is not True:
        print("GATE ERROR: ledger is not marked complete (the run did not finish)")
        return 2
    try:
        made = datetime.datetime.fromisoformat(led["generated_at"])
    except (KeyError, ValueError, TypeError):
        print("GATE ERROR: ledger has no usable generated_at")
        return 2
    if made.tzinfo is None or made.utcoffset() is None:
        print("GATE ERROR: ledger generated_at %r carries no time zone, so its age cannot be judged" % led["generated_at"])
        return 2
    age = datetime.datetime.now().astimezone() - made
    if age.total_seconds() < -FUTURE_SKEW_SECONDS:
        print("GATE ERROR: ledger generated_at is %.1f h in the future (more than %d min of clock skew); a timestamp from the future is not usable"
              % (-age.total_seconds() / 3600, FUTURE_SKEW_SECONDS // 60))
        return 2
    if age.total_seconds() > a.max_age_hours * 3600:  # no value switches the age check off: 0 refuses any ledger older than now
        print("GATE REFUSED: ledger is %.1f h old (limit %.1f h); re-run secure-launch" % (age.total_seconds() / 3600, a.max_age_hours))
        return 1
    try:
        accepted = ledger.load_accepted(a.repo)
    except ledger.LedgerError as exc:
        print("GATE ERROR: %s" % exc)
        return 2
    results = list(results)
    if not results:
        # Before the test command: a ledger that measured nothing refuses even when the repo's tests pass.
        print("GATE REFUSED: the ledger holds no results (nothing measured)")
        note("error", "secure-launch ledger is empty")
        return 1
    if a.tests_from is not None:
        p = a.tests_from if os.path.isabs(a.tests_from) else os.path.join(a.repo, a.tests_from)
        cmd = None
        if os.path.exists(p):
            try:
                cmd = json.load(open(p)).get("test_command")
            except ValueError:
                cmd = None
        if not cmd:
            results.append(ledger.result("gate.tests", "Mutation-proven security tests ran", "UNKNOWN", a.tests_from,
                                         reason="no test_command declared in %s" % a.tests_from))
        else:
            print("running security tests: %s" % cmd)
            # A shell on purpose: test_command is the repo owner's own command line (npm run x && y), read from the
            # repo's security/gate.json. Whoever can edit that file can already edit the tests it runs, so the shell
            # adds no new trust boundary. Treat gate.json as code in review.
            rc = subprocess.run(cmd, shell=True, cwd=a.repo).returncode  # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
            if rc == 0:
                results.append(ledger.result("gate.tests", "Mutation-proven security tests ran", "PASS", "%s exited 0" % cmd))
            else:
                results.append(ledger.result("gate.tests", "Mutation-proven security tests ran", "FAIL", "%s exited %d" % (cmd, rc),
                                             severity="high", fix="fix the failing security test; never weaken it to pass"))
    blocking, shown = [], []
    for r in results:
        if r["status"] == "PASS":
            continue
        acc = ledger.acceptance(accepted, r)
        tag = "%s %s [%s] %s" % (r["status"], r["id"], r.get("severity", "-"), r.get("reason") or r.get("fix") or "")
        if acc:
            shown.append("ACCEPTED (%s, until %s, %s) %s" % (acc["ruled"], acc["expires"], acc["reason"], tag))
            note("warning", "accepted %s: %s" % (r["id"], acc["reason"]))
        else:
            blocking.append(tag + "  <- " + r["evidence"][:160])
            note("error" if r["status"] == "FAIL" else "warning", "%s %s: %s" % (r["status"], r["id"], r.get("reason") or r.get("fix", "")))
    c = ledger.counts(results)
    head = "secure-launch gate: %d FAIL, %d UNKNOWN, %d PASS (%d accepted)" % (c["FAIL"], c["UNKNOWN"], c["PASS"], len(shown))
    print(head)
    for s in shown:
        print("  " + s)
    for b in blocking:
        print("  BLOCKING " + b)
    if GHA and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write("## %s\n\n" % head)
            fh.write("UNKNOWN is not a pass: each blocks until it runs or is accepted in security/accepted.json.\n\n")
            for b in blocking:
                fh.write("- BLOCKING %s\n" % b.replace("|", "/"))
            for s in shown:
                fh.write("- %s\n" % s.replace("|", "/"))
    if blocking:
        print("GATE REFUSED: %d blocking item(s)" % len(blocking))
        return 1
    print("GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

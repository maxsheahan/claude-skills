#!/usr/bin/env python3
"""secure_launch.py - detect the stack, map the surface, run every applicable
check across the suite's plugins, and write ONE findings ledger.

  secure_launch.py REPO [--out DIR] [--url https://host/ ...] [--extra-dir out ...]
                        [--only PLUGIN] [--timeout 300]

Writes DIR/findings.json, DIR/findings.md, DIR/inventory.json, DIR/inventory.md
(default DIR: REPO/security). Read-only on REPO otherwise. Network: npm audit
(registry read) and, only with --url, one HEAD per URL plus one plain-http GET
per host. Never a burst, a form, a cookie or a credential.

A check that cannot run (plugin missing, tool missing, crashed, bad output) is
recorded as UNKNOWN with the reason. It is never dropped and never a pass.
Exit: 0 all PASS, 1 any FAIL, 3 no FAIL but some UNKNOWN, 2 usage error,
4 the orchestrator itself crashed (no ledger written).
"""
import argparse
import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import inventory  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)


def plugin_scripts(name):
    """Scripts dir of a sibling plugin in the marketplace or installed-cache layout."""
    cands = [os.path.join(CORE, "..", name, "scripts")]
    cands += sorted(glob.glob(os.path.join(CORE, "..", "..", name, "*", "scripts")), reverse=True)
    for c in cands:
        if os.path.isdir(c):
            return os.path.abspath(c)
    return None


# (plugin, script, applies(stack) -> bool or reason-string-when-skipped, extra args builder)
REGISTRY = [
    ("secure-secrets", "check_secrets.py", lambda s: True),
    ("secure-supply-chain", "check_deps.py", lambda s: bool({"node", "python"} & set(s)) or "no package.json or Python manifest"),
    ("secure-supply-chain", "check_pinning.py", lambda s: True),
    ("secure-supply-chain", "load_built.py", lambda s: "node-runtime" in s or "no code that runs under Node itself (no server dependency or node start script); a Worker or browser bundle is not judged by Node"),
    ("secure-app", "check_app.py", lambda s: True),
    ("secure-app", "check_fetch.py", lambda s: True),
    ("secure-app", "check_spend.py", lambda s: True),
    ("secure-app", "check_auth_gates.py", lambda s: True),
    ("secure-app", "check_metering.py", lambda s: True),
    ("secure-app", "check_mcp.py", lambda s: True),
    ("secure-ai", "check_ai.py", lambda s: True),
    ("secure-platform", "check_cloudflare.py", lambda s: "cloudflare" in s or "no wrangler config, _headers or functions/"),
    ("secure-platform", "check_nextjs.py", lambda s: "nextjs" in s or "no next dependency"),
    ("secure-platform", "check_fly_supabase.py", lambda s: bool({"fly", "supabase"} & set(s)) or "no fly.toml or Supabase"),
    ("secure-platform", "check_gas.py", lambda s: "google-apps-script" in s or "no appsscript.json or .clasp.json"),
    ("secure-platform", "check_railway.py", lambda s: "railway" in s or "no railway.json or railway.toml"),
]


def unknown(id, title, reason, evidence):
    return ledger.result(id, title, "UNKNOWN", evidence, reason=reason[:400])


def run_check(plugin, script, repo, extra, timeout, blind):
    label = "%s/%s" % (plugin, script)
    sdir = plugin_scripts(plugin)
    if not sdir or not os.path.exists(os.path.join(sdir, script)):
        return [unknown("%s.%s.run" % (plugin, script[:-3]), "%s did not run" % label,
                        "plugin %s (or its %s) not found next to secure-core" % (plugin, script), label)]
    argv = [sys.executable, os.path.join(sdir, script), repo] + extra
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [unknown("%s.%s.run" % (plugin, script[:-3]), "%s did not finish" % label, "timed out after %ds" % timeout, label)]
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    if r.returncode not in (0, 1, 3):
        return [unknown("%s.%s.run" % (plugin, script[:-3]), "%s crashed" % label,
                        "exit %d: %s" % (r.returncode, _scrub(tail[0])), label)]
    try:
        data = json.loads(r.stdout)
        checks = data["checks"]
        blind += ["%s: %s" % (plugin, s) for s in data.get("cannot_see", [])]
        for c in checks:
            ledger.validate(c)
            c["plugin"] = plugin
        if not checks:
            return [unknown("%s.%s.empty" % (plugin, script[:-3]), "%s returned nothing" % label,
                            "the adapter applies to this repo but produced no result", label)]
        return checks
    except (ValueError, KeyError, TypeError, ledger.LedgerError) as exc:
        return [unknown("%s.%s.run" % (plugin, script[:-3]), "%s gave unusable output" % label, _scrub(str(exc)), label)]


def _git_state(repo, exclude=()):
    """HEAD and a hash of the working tree's content, so the gate can refuse a ledger from another commit or tree."""
    return ledger.git_state(repo, exclude)


def _scrub(text):
    out = text
    for rx in ledger.SECRET_SHAPES:
        out = rx.sub("<redacted>", out)
    return out[:300]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--out")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--extra-dir", action="append", default=[], help="build output or untracked folders for the secret scan")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--timeout", type=int, default=300)
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    if not os.path.isdir(repo):
        print("not a directory: %s" % repo, file=sys.stderr)
        return 2
    out = os.path.abspath(a.out or os.path.join(repo, "security"))
    os.makedirs(out, exist_ok=True)

    inv = inventory.build(repo)
    json.dump(inv, open(os.path.join(out, "inventory.json"), "w"), indent=1)
    open(os.path.join(out, "inventory.md"), "w").write(inventory.markdown(inv))
    stack = inv["stack"]

    results, adapters, blind = [], {}, []
    for plugin, script, applies in REGISTRY:
        if a.only and plugin not in a.only:
            continue
        ok = applies(stack)
        name = "%s/%s" % (plugin, script)
        if ok is not True:
            adapters[name] = "not applicable: %s" % ok
            continue
        extra = []
        if script == "check_secrets.py":
            for d in a.extra_dir:
                extra += ["--extra-dir", d]
        got = run_check(plugin, script, repo, extra, a.timeout, blind)
        adapters[name] = "ran: %d checks" % len(got)
        results += got
    if a.url:
        extra = []
        for u in a.url:
            extra += ["--url", u]
        got = run_check("secure-platform", "check_live_headers.py", repo, extra, a.timeout, blind)
        adapters["secure-platform/check_live_headers.py"] = "ran: %d checks" % len(got)
        results += got
    else:
        adapters["secure-platform/check_live_headers.py"] = "not run: no --url given"

    accepted = ledger.load_accepted(repo)
    led = ledger.build(repo, results, stack, adapters, accepted, blind)
    led["complete"] = True
    json.dump(led, open(os.path.join(out, "findings.json"), "w"), indent=1)
    open(os.path.join(out, "findings.md"), "w").write(ledger.to_markdown(led))
    # Taken AFTER every output file exists, so a default in-repo run (DIR inside REPO) hashes the tree the gate will
    # see; findings.json itself is left out (it carries the binding), and the gate leaves out the ledger it reads.
    led["git"] = _git_state(repo, exclude=[os.path.join(out, "findings.json")])
    json.dump(led, open(os.path.join(out, "findings.json"), "w"), indent=1)
    c = led["counts"]
    print("%s: %d FAIL, %d UNKNOWN, %d PASS -> %s" % (os.path.basename(repo), c["FAIL"], c["UNKNOWN"], c["PASS"], os.path.join(out, "findings.md")))
    if c["FAIL"]:
        return 1
    if c["UNKNOWN"] or not results:
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # a crash is never a FAIL or a PASS: exit 4, no ledger
        print("secure-launch crashed: %s: %s" % (type(exc).__name__, _scrub(str(exc))), file=sys.stderr)
        sys.exit(4)

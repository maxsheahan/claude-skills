#!/usr/bin/env python3
"""mutation_check.py - prove a test catches the removal of one protection.

Applies ONE exact text replacement (a protection removed) in a throwaway git
worktree of REPO at HEAD, runs the test command there, and reports whether the
tests noticed. The real tree is never touched.

  mutation_check.py --repo R --file F --find OLD --replace NEW --test "CMD"
                    [--label NAME] [--link node_modules]

--find must occur exactly once in F at HEAD (otherwise the mutation is
ambiguous and is refused). --link symlinks a heavy directory (node_modules)
from the repo into the worktree so the test command runs.

Exit: 0 DETECTED (the tests failed), 1 SURVIVED (tests still pass: the
protection is unguarded), 2 setup error. Run it twice per protection when
asked whether an EXISTING suite guards it: once with the new test command,
once with the old one (a SURVIVED there is the finding).
"""
import argparse, os, shutil, subprocess, sys, tempfile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--file", required=True, help="path relative to the repo")
    ap.add_argument("--find", required=True)
    ap.add_argument("--replace", required=True)
    ap.add_argument("--test", required=True, help="shell command run in the worktree")
    ap.add_argument("--label", default="")
    ap.add_argument("--link", action="append", default=[])
    a = ap.parse_args()
    label = a.label or f"{a.file}: {a.find[:50]!r}"
    repo = os.path.abspath(a.repo)
    tmp = tempfile.mkdtemp(prefix="mutation-")
    wt = os.path.join(tmp, "wt")
    try:
        r = subprocess.run(["git", "-C", repo, "worktree", "add", "--detach", wt, "HEAD"], capture_output=True, text=True)
        if r.returncode:
            print(f"SETUP ERROR {label}: {r.stderr.strip()}")
            return 2
        for d in a.link:
            src = os.path.join(repo, d)
            if os.path.exists(src):
                os.symlink(src, os.path.join(wt, d))
        target = os.path.join(wt, a.file)
        try:
            text = open(target, encoding="utf-8").read()
        except OSError as e:
            print(f"SETUP ERROR {label}: {e}")
            return 2
        n = text.count(a.find)
        if n != 1:
            print(f"SETUP ERROR {label}: --find occurs {n} times in {a.file} at HEAD (must be exactly 1)")
            return 2
        open(target, "w", encoding="utf-8").write(text.replace(a.find, a.replace))
        # A shell on purpose: --test is the operator's own command line, typed by the person running this check.
        t = subprocess.run(a.test, shell=True, cwd=wt, capture_output=True, text=True)  # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
        if t.returncode != 0:
            print(f"DETECTED {label}: the tests failed with the protection removed")
            return 0
        print(f"SURVIVED {label}: the tests still pass with the protection removed")
        return 1
    finally:
        subprocess.run(["git", "-C", repo, "worktree", "remove", "--force", wt], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

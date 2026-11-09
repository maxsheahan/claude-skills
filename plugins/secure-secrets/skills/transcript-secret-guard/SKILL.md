---
name: transcript-secret-guard
description: "Keep secret values out of captured Claude sessions, which are git-tracked and pushed: a staged PreToolUse hook that blocks Bash commands known to print secrets (cat .dev.vars, printenv, railway variables without a count, gh auth token, wrangler auth token, a read of ~/.wrangler/config, echo $KEY, a key pasted into a command) and names the count-only form, plus a scanner that reports file:line for secrets already in the session capture folders without printing them. Use when the user says 'a key got into the transcript', 'scan the captures for keys', 'block commands that print secrets', or after any exposure. Do NOT use it to rotate the key (secret-rotation) or to scan a code repo (secret-scan)."
metadata:
  workflow: true
allowed-tools:
  - Bash
  - Read
---

# transcript-secret-guard

Secrets reached captured sessions at least three times since September: Railway variable prefixes (2026-09-04), a Google Maps key (2026-10-03), a project's `.dev.vars` key (2026-09-21). The capture folders were committed and pushed by an automatic sync.

## Trigger

A secret value appeared, or might have appeared, in a session; or the owner wants the guard installed; or a periodic check of the capture folders.

## Inputs

- For a scan: the capture folders (pass them as arguments).
- For the guard: nothing; it reads the hook JSON.

## Prerequisites

- `gitleaks` for the scanner.
- The guard is STAGED at `secure-secrets/staged/secret_print_guard.py`. It runs only after the owner approves the settings.json entry in the suite README. Installing the plugin does NOT register it (the plugin ships no `hooks/hooks.json` on purpose).

## Procedure

1. **Scan:** `python3 <base>/../../scripts/scan_captures.py DIR [DIR ...]` (or set `SECURE_CAPTURE_DIRS`). Exit 2 means the detector was not proven or gitleaks is missing: report "not run", never "clean". Each hit is `RULE path:line`.
2. **For each hit:** do not open the line. Read the file with the matched span masked if you must classify it (`sed -E 's/[A-Za-z0-9_\-]{20,}/<R>/g'` on that line). A real key: rotate it first (`secret-rotation`), because the transcript is already pushed; scrubbing the file afterwards does not unpublish it.
3. **Scrubbing a capture** is a change to the capture store and a history question (a sync may already have pushed it): propose it to the owner with the file list; never rewrite pushed history on your own.
4. **Guard install** (on the owner's word only): the exact settings.json block is in the suite README under "Install steps". After installing, it is live in the NEXT session, not this one; prove it then with one blocked and one allowed command.

## Outputs

The hit list (rule, file, line), the classification of each, which keys need rotation, and, if installed, the guard's blocked/allowed proof.

## Failure handling

- The guard blocks a command that prints no value: prefix it with `SECRET_GUARD_ALLOW=1` (visible in the transcript) and add the pattern to the guard's allow cases plus a test.
- The guard cannot see the Read tool. Reading `.dev.vars` with Read puts the values in the session too; the rule is behavioral (never Read a secrets file) until a Read-matcher hook is approved.

## Verification

`bash <base>/../../tests/run_tests.sh`

Allow-list design: any command naming a secrets file (globs included) is blocked unless it is a names-only, count, presence or load form. 48 secret-printing commands are blocked (including the 24 bypasses a 2026-10-08 audit found: `cut -f1-`, `tee`, `base64`, `git show HEAD:.dev.vars`, `env -0`, herestrings) and 28 value-free ones are allowed (source .env then npm test, node --env-file=, grep -n .dev.vars .gitignore); bad input fails open. The scanner finds a planted key at its line without printing it, passes a clean folder, and refuses to call anything clean without gitleaks.

## Rules

1. Never print, quote or paste the matched value, including a fragment.
2. The hook and any autosync wiring are standing changes: staged here, installed only on the owner's word naming them.
3. When the owner rules that this skill should not do something, add that rule here in the same turn.

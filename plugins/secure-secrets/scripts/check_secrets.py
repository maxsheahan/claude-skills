#!/usr/bin/env python3
"""check_secrets.py - the ledger form of the secret scan.

  check_secrets.py REPO [--extra-dir DIR ...]

Runs scan_secrets.sh (gitleaks, proven on planted fake keys first, values
redacted) over the git history (or the files, outside git) and each extra
folder, and checks that secrets files are ignored and untracked. Prints the
ledger JSON. Never prints anything from a secrets file.

Secrets files by name: .dev.vars, .env and every dotted variant
(.env.production.local), *.pem, *.key, *.p12, *.pfx, ssh id_* files (suffixed
too, never the .pub half), credentials.json, service-account*.json, .netrc;
templates (.example and friends) and dotenv-vault's encrypted .env.vault are
not secrets files. Config files committed by design (.envrc, .npmrc,
secrets.yml, appsettings*.json) are secrets files when they assign a literal
value to a credential-named key; their text is read in-process for that.
Generic-rule hits are classified in-process with the value never shown: a
value that is lowercase words is an identifier; so is a hex or UUID value
whose VARIABLE ends in an identifier noun (cacheKey, idempotency_key,
CACHE_KEY) and a pk_ value under a publishable name. A name that also says
api, auth, secret, token or password, or a value of any other shape, is kept.
Hex and UUID values under any other name are kept (Heroku and Postmark keys
look like that). A repo-side allowlist is .gitleaksignore, .gitleaks.toml, a
gitleaks config TOML under any name that carries an allowlist, or a
gitleaks:allow comment on the same line as code (before or after it) in any
text file; prose that mentions the word is not one.
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
from ledger import result  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
# Secrets files by NAME: .dev.vars, .env with any number of dotted suffixes (.env.production.local),
# key material (*.pem, *.key, *.p12, *.pfx, ssh id_* files with or without a suffix, never the
# .pub half), credential JSON, .netrc.
SECRET_FILES = re.compile(r"^(\.dev\.vars|\.env(\.[A-Za-z0-9_-]+)*|.*\.(pem|key|p12|pfx)|id_(rsa|dsa|ecdsa|ed25519)([._-][A-Za-z0-9._-]+)?"
                          r"|credentials\.json|service-account.*\.json|[._]netrc)$")
# Config files that are committed BY DESIGN and become secrets files only when they hold a literal
# credential: direnv's .envrc (often just `use flake`), .npmrc (save-exact, or an ${NPM_TOKEN}
# reference), Rails' config/secrets.yml (ENV references), .NET appsettings*.json. Their text is read
# in-process to decide; nothing from it is ever printed.
CONFIG_SECRET_FILES = re.compile(r"^(\.envrc|\.npmrc|secrets\.ya?ml|appsettings(\.[A-Za-z0-9_-]+)*\.json)$")
TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults)$")
# Names that match SECRET_FILES but are designed to be committed: dotenv-vault's .env.vault is the
# ENCRYPTED artifact (the DOTENV_KEY that opens it lives elsewhere).
NOT_SECRET_FILES = {".env.vault"}
# KEY = value or KEY: value, one assignment at a time (export lines, ini, YAML, JSON pairs and
# connection-string parts like Password=...;). A value is a REFERENCE when it starts with $, ${,
# <%, {{ or %(, or names an env lookup; a reference is never a literal credential.
KV = re.compile(r"([A-Za-z0-9_.@/:\-]+?)[\"']?[ \t]*(?:=|:[ \t])[ \t]*[\"']?([^\s\"';,]*)")
REFERENCE = re.compile(r"^(\$|<%|\{\{|%\(|ENV\b|process\.env|env\(|os\.environ)")
CRED_WORDS = {"password", "passwd", "pwd", "pass", "secret", "token", "credential", "credentials", "apikey", "auth"}
CRED_PAIRS = {("api", "key"), ("access", "key"), ("private", "key"), ("key", "base"), ("secret", "key"), ("client", "secret")}


def name_words(name):
    """CF_CACHE_PURGE_API_KEY, config.cache.apiKey, _authToken -> lowercase words."""
    out = []
    for part in re.split(r"[^A-Za-z0-9]+", name or ""):
        out += [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", part)]
    return out


def credential_key(key):
    """A config key that names a credential: its last path segment holds a credential word."""
    words = name_words(re.split(r"[/:]", key)[-1])
    if not words:
        return False
    if any(w in CRED_WORDS for w in words if w != "auth") or words[-1] == "auth":
        return True
    return any(pair in CRED_PAIRS for pair in zip(words, words[1:]))


def literal_credential(text):
    """True when some line assigns a literal value (not a reference) to a credential-named key."""
    for line in (text or "").splitlines():
        if line.lstrip().startswith(("#", ";")):  # shell, ini and YAML comments (// starts an .npmrc registry line)
            continue
        for m in KV.finditer(line):
            key, val = m.group(1), m.group(2)
            if len(val) >= 4 and credential_key(key) and not REFERENCE.match(val):
                return True
    return False


def _read(repo, rel, tracked):
    """The text of a tracked file as committed (the index), or the working file; empty if unreadable."""
    if tracked:
        r = subprocess.run(["git", "-C", repo, "show", ":" + rel], capture_output=True)
        if r.returncode == 0:
            return r.stdout[:1_000_000].decode("utf-8", errors="replace")
    try:
        with open(os.path.join(repo, rel), "rb") as fh:
            return fh.read(1_000_000).decode("utf-8", errors="replace")
    except OSError:
        return ""


def is_secret_file(path, repo=None, tracked=False):
    """True when the basename says secrets file and is not a template, a committed-by-design
    artifact or the public half of an ssh key. A committed-by-design config name (.envrc, .npmrc,
    secrets.yml, appsettings*.json) counts only when it holds a literal credential."""
    name = os.path.basename(path)
    if TEMPLATE.search(name) or name in NOT_SECRET_FILES or name.endswith(".pub"):
        return False
    if SECRET_FILES.match(name):
        return True
    if CONFIG_SECRET_FILES.match(name):
        return repo is not None and literal_credential(_read(repo, path, tracked))
    return False


SUMMARY = re.compile(r"^(git history of|files in) (.+?): (\d+) finding\(s\)$")



def _dir_tag(repo, where):
    """A distinct, readable id per scanned folder: dist and app/dist never share one."""
    import hashlib
    where = where.rstrip("/")
    if where.startswith(repo + os.sep):
        return os.path.relpath(where, repo).replace("/", "_").lstrip(".")
    # A short folder id for a file name, never a security check.
    return "%s-%s" % (os.path.basename(where).lstrip("."), hashlib.sha1(where.encode(), usedforsecurity=False).hexdigest()[:6])  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1


def scan(repo, extra):
    r = subprocess.run(["bash", os.path.join(HERE, "scan_secrets.sh"), repo] + extra, capture_output=True, text=True)
    out = r.stdout
    if r.returncode == 2 or "DETECTOR NOT PROVEN" in out or "not installed" in out:
        reason = (out.strip().splitlines() or ["scan could not run"])[-1]
        return [result("secrets.scan", "Secret scan", "UNKNOWN", "secure-secrets/scripts/scan_secrets.sh",
                       reason=reason + " (brew install gitleaks)")]
    res, block = [], None
    for line in out.splitlines():
        m = SUMMARY.match(line)
        if m:
            where = m.group(2)
            cid = "secrets.history" if (m.group(1) == "git history of" or where == repo) else "secrets.files." + _dir_tag(repo, where)
            block = {"id": cid, "where": where, "n": int(m.group(3)), "rows": []}
            res.append(block)
        elif block is not None and line.startswith("  "):
            block["rows"].append(line.strip())
    out_results = []
    for b in res:
        title = "No secrets in %s" % ("git history" if b["id"] == "secrets.history" else b["where"])
        if b["n"] == 0:
            out_results.append(result(b["id"], title, "PASS", "gitleaks (detector proven on planted keys): 0 findings in %s" % b["where"]))
            continue
        kept, dismissed = classify(repo, b)
        if kept is None:  # the classification pass did not run: report the raw count, never fewer
            kept, dismissed = b["rows"], 0
        if not kept:
            out_results.append(result(b["id"], title, "PASS", "gitleaks: %d hit(s), all generic-rule identifiers" % dismissed,
                                      detail="%d generic-api-key hit(s) dismissed as identifiers (lowercase words with no key-like character mix, or a variable named identifier/cache/idempotency/publishable holding a value with no provider prefix); classified in-process, no value shown" % dismissed))
        else:
            out_results.append(result(b["id"], title, "FAIL", ledger.join_hits(kept, 8, "; "), severity="high",
                                      fix="classify each hit with the value masked; rotate any real one (secret-rotation skill) and purge it from history",
                                      detail="%d finding(s) kept, %d generic-rule identifier(s) dismissed; rule and file shown, values never printed" % (len(kept), dismissed)))
    if not out_results:
        out_results.append(result("secrets.scan", "Secret scan", "UNKNOWN", "scan_secrets.sh", reason="scan produced no summary line"))
    return out_results


IDENT = re.compile(r"[a-z0-9]+(?:[._\-][a-z0-9]+)+")


HEXISH = re.compile(r"[0-9a-fA-F\-.]+")

# The variable the generic rule matched on: the identifier that precedes the separator in
# gitleaks' Match text (idempotencyKey": "..., cacheKey: '..., STRIPE_PUBLISHABLE_KEY = '...).
MATCH_NAME = re.compile(r"^\s*[\"'`]?([A-Za-z_][A-Za-z0-9_.-]*)")
# A name says identifier when its LAST meaningful word is an identifier noun, followed by nothing
# but key/id/hash (cacheKey, idempotency_key, CACHE_KEY, STRIPE_PUBLISHABLE_KEY). A name holding
# a credential word anywhere (CF_CACHE_PURGE_API_KEY, REDIS_CACHE_AUTH_KEY, cache_secret) never is.
IDENTIFIER_WORDS = ("idempoten", "cache", "publishable", "identifier")
IDENTIFIER_TAIL = {"key", "id", "hash"}
NOT_IDENTIFIER_WORDS = {"secret", "token", "password", "passwd", "pwd", "pass", "private", "credential", "credentials",
                        "api", "apikey", "auth", "access", "client", "signing", "master"}
# Provider prefixes: a value carrying one is a key whatever its variable is called.
# pk_ (Stripe publishable) is deliberately absent: Stripe designs it to be public.
PROVIDER_PREFIX = re.compile(r"^(sk[-_]|rk_|whsec_|AIza|gh[pousr]_|github_pat_|xox[baprs]-|AKIA|ASIA|npm_|glpat-|eyJ|hf_|r8_|SG\.|re_|shp(at|ss)_|dop_v1_|sq0|-----BEGIN)")
# The value shapes an identifier-named variable may hold: a hex digest or UUID; under a publishable
# name, a publishable-key prefix. A random mixed-class token is a credential whatever it is called.
PUBLISHABLE_VALUE = re.compile(r"^(pk_(live|test)_|sb_publishable_)[A-Za-z0-9_]+$")


def identifier_shaped(s):
    """A generic-rule match that cannot be a credential by its VALUE alone: dotted or
    kebab lowercase words (radius.prefs.v1), or letters and underscores with no digit
    and no mixed case. Never a hex or UUID shape, never more than two digits. Real keys
    mix classes; provider-specific rules are never dismissed."""
    digits = sum(c.isdigit() for c in s)
    if HEXISH.fullmatch(s) or digits > 2:
        return False  # UUIDs and hex tokens are real key formats (Heroku, Postmark): never dismissed by value
    if IDENT.fullmatch(s):
        return True
    has_digit = digits > 0
    mixed = any(c.islower() for c in s) and any(c.isupper() for c in s)
    return not has_digit and not mixed


def identifier_named(match, secret):
    """A generic-rule hit whose VARIABLE ends in an identifier noun (idempotencyKey, cacheKey,
    STRIPE_PUBLISHABLE_KEY) and whose VALUE has an identifier's shape: a hex digest or UUID, or a
    pk_ key under a publishable name. A name that also says api/auth/secret/token/password, a
    random mixed-class value, and a value that starts like a real key (sk_live_ in the publishable
    slot) are kept."""
    m = MATCH_NAME.match(match or "")
    if not m or not secret or PROVIDER_PREFIX.match(secret):
        return False
    words = name_words(m.group(1))
    if not words or any(w in NOT_IDENTIFIER_WORDS for w in words):
        return False
    hit = [i for i, w in enumerate(words) if w.startswith(IDENTIFIER_WORDS)]
    if not hit or not set(words[hit[-1] + 1:]) <= IDENTIFIER_TAIL:
        return False
    if words[hit[-1]] == "publishable":
        return bool(PUBLISHABLE_VALUE.match(secret))
    return bool(HEXISH.fullmatch(secret)) and sum(c.isalnum() for c in secret) >= 16


def classify(repo, block):
    """Re-run gitleaks for one scope WITHOUT redaction into a private temp dir,
    decide each generic-api-key hit in-process, delete the report. Returns
    (kept rows as 'RULE  FILE  xN', number dismissed), or (None, 0) if it could
    not run. Never prints or returns a value."""
    import collections, json, shutil, tempfile
    work = tempfile.mkdtemp(prefix="sl-classify-")
    # Owner-only on purpose: the unredacted report lands here. Stricter than the rule wants, so the finding is a false alarm.
    os.chmod(work, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    try:
        rep = os.path.join(work, "r.json")
        mode = ["git"] if block["id"] == "secrets.history" and subprocess.run(["git", "-C", repo, "rev-parse", "--git-dir"], capture_output=True).returncode == 0 else ["dir"]
        os.makedirs(os.path.join(work, "noignore"))
        src = block["where"]
        if mode == ["git"] and os.path.exists(os.path.join(src, ".gitleaksignore")):
            # gitleaks honors the source's own .gitleaksignore whatever -i says: scan a clone without it
            subprocess.run(["git", "clone", "-q", "--no-hardlinks", src, os.path.join(work, "clone")], capture_output=True)
            if os.path.isdir(os.path.join(work, "clone")):
                try:
                    os.remove(os.path.join(work, "clone", ".gitleaksignore"))
                except OSError:
                    pass
                src = os.path.join(work, "clone")
        subprocess.run(["gitleaks"] + mode + [src, "-c", os.path.join(HERE, "gitleaks-suite.toml"), "-i", os.path.join(work, "noignore"),
                        "--ignore-gitleaks-allow", "--redact=0", "--no-banner", "-f", "json", "-r", rep], capture_output=True)
        try:
            found = json.load(open(rep))
        except (OSError, ValueError):
            return None, 0
        finally:
            if os.path.exists(rep):
                os.remove(rep)
        kept, dismissed = collections.Counter(), 0
        for f in found:
            if f.get("RuleID") == "generic-api-key" and (identifier_shaped(f.get("Secret") or "")
                                                         or identifier_named(f.get("Match"), f.get("Secret"))):
                dismissed += 1
            else:
                kept[(f.get("RuleID"), f.get("File"))] += 1
        return ["%s  %s  x%d" % (r, fl, n) for (r, fl), n in kept.most_common(40)], dismissed
    finally:
        shutil.rmtree(work, ignore_errors=True)


def ignored(repo):
    if subprocess.run(["git", "-C", repo, "rev-parse", "--git-dir"], capture_output=True).returncode != 0:
        return [result("secrets.ignored", "Secrets files are git-ignored", "UNKNOWN", repo, reason="not a git repo")]
    tracked = subprocess.run(["git", "-C", repo, "ls-files"], capture_output=True, text=True).stdout.splitlines()
    bad_tracked = [p for p in tracked if is_secret_file(p, repo, tracked=True)]
    present = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".backups", ".wrangler", ".next", ".open-next")]
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), repo)
            if is_secret_file(rel, repo):
                present.append(rel)
    not_ignored = []
    for p in present:
        if p in bad_tracked:
            continue
        if subprocess.run(["git", "-C", repo, "check-ignore", "-q", p], capture_output=True).returncode != 0:
            not_ignored.append(p)
    out = []
    if bad_tracked:
        out.append(result("secrets.tracked", "No secrets file is committed", "FAIL", ledger.join_hits(bad_tracked, 6, ", "), severity="critical",
                          fix="git rm --cached the file, add it to .gitignore, rotate every key it held, purge history"))
    else:
        out.append(result("secrets.tracked", "No secrets file is committed", "PASS", "git ls-files: none of .dev.vars/.env*/pem/key/p12/id_rsa/.netrc/credentials tracked, and no .envrc/.npmrc/secrets.yml/appsettings holding a literal credential"))
    if not_ignored:
        out.append(result("secrets.ignored", "Secrets files are git-ignored", "FAIL", ledger.join_hits(not_ignored, 6, ", "), severity="high",
                          fix="add the file name to .gitignore before the next git add"))
    else:
        out.append(result("secrets.ignored", "Secrets files are git-ignored", "PASS",
                          "git check-ignore: %s" % (ledger.join_hits(present, 6, ", ") + " ignored" if present else "no secrets file present")))
    return out



# gitleaks honors gitleaks:allow anywhere on the LINE of a finding. An inline allow is a comment
# holding the word on a line that also holds code: code before it (`key = "..." # gitleaks:allow`),
# or, for a block comment, code after it closes (`/* gitleaks:allow */ const key = ...`). A line
# that is only the comment, or prose that quotes the word (`gitleaks:allow` in CONTRIBUTING.md),
# silences nothing.
ALLOW_MARKER = re.compile(r"(#|//|/\*|--|<!--|;)\s*gitleaks:allow\b")
BLOCK_CLOSE = {"/*": "*/", "<!--": "-->"}


def inline_allow(text):
    """True when some line carries code and a gitleaks:allow comment."""
    for line in text.splitlines():
        if "gitleaks:allow" not in line:
            continue
        for m in ALLOW_MARKER.finditer(line):
            if line[:m.start()].strip():
                return True
            close = BLOCK_CLOSE.get(m.group(1))
            if close:
                end = line.find(close, m.end())
                if end >= 0 and line[end + len(close):].strip():
                    return True
    return False


# A gitleaks config under any file name (gitleaks.toml, ci/gitleaks-rules.toml) that the repo's own
# scanner can be pointed at with --config: a TOML with an allowlist table and a gitleaks marker
# ([extend], useDefault, [[rules]] or gitleaks in its name). pyproject's [tool.x.allowlist] is not one.
TOML_ALLOWLIST = re.compile(r"(?m)^\s*\[\[?\s*(?:rules\.)?allowlists?\s*\]\]?\s*$")
GITLEAKS_TOML = re.compile(r"(?m)^\s*(?:\[extend\]|useDefault\s*=|\[\[rules\]\])")


def gitleaks_config_allowlist(name, text):
    return name.endswith(".toml") and bool(TOML_ALLOWLIST.search(text)) and ("gitleaks" in name.lower() or bool(GITLEAKS_TOML.search(text)))


def allowlists(repo):
    """A repo's own gitleaks allowlists hide hits from any scanner that honors them.
    The suite ignores them; this result says they exist so a human reads them.
    Every text file is read (.tf, .go, .rb, .vue included); binaries are skipped."""
    found = [f for f in (".gitleaksignore", ".gitleaks.toml", ".gitleaks.yml") if os.path.exists(os.path.join(repo, f))]
    for root, dirs, names in os.walk(repo):
        # The suite's own ledger (security/findings.md and friends) quotes this check's wording, so a repo that keeps
        # its ledger would match itself; the output folder is never an allowlist.
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git") and not d.startswith(".") and not (root == repo and d == "security")]
        for n in names:
            p = os.path.join(root, n)
            try:
                with open(p, "rb") as fh:
                    raw = fh.read(1_000_000)
            except OSError:
                continue
            if b"\x00" in raw[:8192]:
                continue
            rel = os.path.relpath(p, repo)
            if rel not in found and gitleaks_config_allowlist(n, raw.decode("utf-8", errors="replace")):
                found.append(rel)
            if b"gitleaks:allow" in raw and inline_allow(raw.decode("utf-8", errors="replace")):
                found.append("%s (gitleaks:allow)" % rel)
        if len(found) > 20:
            break
    if found:
        return [result("secrets.allowlist", "No repo-side gitleaks allowlist", "FAIL", ledger.join_hits(found, 6, ", "), severity="low",
                       fix="read each allowlisted hit with the value masked; the suite scans past them, other scanners do not",
                       detail="the suite ignores these (own config, empty ignore path, --ignore-gitleaks-allow)")]
    return [result("secrets.allowlist", "No repo-side gitleaks allowlist", "PASS", "no .gitleaksignore, .gitleaks.toml or gitleaks:allow comment")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("--extra-dir", action="append", default=[])
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    extra = [os.path.join(repo, d) if not os.path.isabs(d) else d for d in a.extra_dir]
    return ledger.emit(scan(repo, extra) + ignored(repo) + allowlists(repo))


if __name__ == "__main__":
    sys.exit(main())

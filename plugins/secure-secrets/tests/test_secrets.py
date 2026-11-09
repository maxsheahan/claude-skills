#!/usr/bin/env python3
"""secure-secrets tests. Known-bad first; no key-shaped string is stored in this file."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "secure-core", "lib"))
import testkit as T  # noqa: E402

S = os.path.join(HERE, "..", "scripts")
GUARD = os.path.join(HERE, "..", "staged", "secret_print_guard.py")
GKEY = T.fake_key("google", 5)
SKEY = T.fake_key("stripe", 6)

# ---------- check_secrets ----------
bad = T.git_init(T.tree({"src/app.js": "const k = '%s';\n" % GKEY, ".gitignore": "node_modules\n", ".dev.vars": "X=1\n"}))
subprocess.run(["git", "-C", bad, "add", "-f", ".dev.vars"], capture_output=True)
subprocess.run(["git", "-C", bad, "commit", "-qm", "oops"], capture_output=True)
open(os.path.join(bad, ".env"), "w").write("Y=2\n")
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), bad)
T.status_is("bad repo", c, "secrets.history", "FAIL", out)
T.status_is("bad repo", c, "secrets.tracked", "FAIL", out)
T.status_is("bad repo", c, "secrets.ignored", "FAIL", out)
T.expect("check_secrets: the key value is never printed", GKEY not in out)
T.expect("check_secrets: bad repo exits 1", rc == 1)

good = T.git_init(T.tree({"src/app.js": "const k = env.MAPS_KEY;\n", ".gitignore": ".dev.vars\n.env\n", ".dev.vars.example": "MAPS_KEY=\n"}))
open(os.path.join(good, ".dev.vars"), "w").write("MAPS_KEY=x\n")
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), good)
for cid in ("secrets.history", "secrets.tracked", "secrets.ignored"):
    T.status_is("good repo", c, cid, "PASS", out)
T.expect("check_secrets: good repo exits 0", rc == 0, out[-300:])

build = T.tree({"bundle.js": "x='%s'" % SKEY})
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), good, "--extra-dir", build)
T.expect("check_secrets: build output folder is scanned and fails", any(k.startswith("secrets.files.") and v["status"] == "FAIL" for k, v in c.items()), str(list(c)))

clean_build = T.tree({"bundle.js": "console.log('no keys here')\n"})
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), good, "--extra-dir", clean_build)
T.expect("check_secrets: a clean build output folder PASSes", any(k.startswith("secrets.files.") and v["status"] == "PASS" for k, v in c.items()), str({k: v["status"] for k, v in c.items()}))

env = dict(os.environ, PATH="/usr/bin:/bin")
r = subprocess.run([sys.executable, os.path.join(S, "check_secrets.py"), good], capture_output=True, text=True, env=env)
cc = {x["id"]: x for x in json.loads(r.stdout)["checks"]}
T.status_is("no gitleaks", cc, "secrets.scan", "UNKNOWN", r.stdout)
T.expect("check_secrets: missing detector is never a PASS (exit 3, not 0)", r.returncode == 3, str(r.returncode))

# ---------- check_secret_shape ----------
vars_bad = T.tree({".dev.vars": "ELEVENLABS_API_KEY=ELEVENLABS_API_KEY=abcdef0123456789\nANTHROPIC_API_KEY=%s\nSTRIPE_SECRET_KEY=\"%s\nMAPS_KEY=your-key-here\nOTHER=fine \n" % (GKEY, SKEY)})
rc, c, out = T.run(os.path.join(S, "check_secret_shape.py"), os.path.join(vars_bad, ".dev.vars"))
T.status_is("shape bad", c, "shape.ELEVENLABS_API_KEY", "FAIL", out)
T.expect("shape: the NAME= prefix is named", "NAME= prefix" in c.get("shape.ELEVENLABS_API_KEY", {}).get("detail", ""))
T.status_is("shape bad", c, "shape.ANTHROPIC_API_KEY", "FAIL", out)
T.status_is("shape bad", c, "shape.STRIPE_SECRET_KEY", "FAIL", out)
T.status_is("shape bad", c, "shape.MAPS_KEY", "FAIL", out)
T.status_is("shape bad", c, "shape.OTHER", "FAIL", out)
T.expect("shape: no value or fragment printed", GKEY not in out and SKEY not in out and "abcdef0123" not in out and SKEY[-6:] not in out)
vars_good = T.tree({".dev.vars": "# comment\nMAPS_KEY=%s\nSTRIPE_SECRET_KEY='%s'\nPLAIN=hello\n" % (GKEY, SKEY)})
rc, c, out = T.run(os.path.join(S, "check_secret_shape.py"), os.path.join(vars_good, ".dev.vars"))
T.expect("shape: well-formed file all PASS", rc == 0 and len(c) == 3 and all(v["status"] == "PASS" for v in c.values()), out[-400:])

# ---------- secret_print_guard (staged hook) ----------
def guard(cmd):
    r = subprocess.run([sys.executable, GUARD], input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}), capture_output=True, text=True)
    return r.returncode, r.stderr

BLOCK = [
    "cat .dev.vars", "cat ~/My\\ App/.dev.vars", "head -5 .env.local", "cat .env", "less .env.production",
    "printenv", "env", "env | sort", "printenv ANTHROPIC_API_KEY", "echo $ANTHROPIC_API_KEY", "echo \"${STRIPE_SECRET_KEY}\"",
    "railway variables", "railway variables --kv", "gh auth token", "gh auth status --show-token",
    "gcloud auth print-access-token", "security find-generic-password -s x -w",
    "node -e \"console.log(process.env.OPENAI_API_KEY)\"", "python3 -c 'import os; print(os.environ[\"MAPS_API_KEY\"])'",
    "echo hi && cat .dev.vars", "grep MAPS .dev.vars", "supabase status", "curl -H 'x-api-key: %s' https://x" % T.fake_key("anthropic"),
    "echo abc | npx wrangler pages secret put KEY",
    "wrangler auth token", "npx wrangler auth token --json",
    "cd ~/.wrangler/config && cat default.toml", "cd ~/Library/Preferences/.wrangler/config; grep oauth work.toml",
    "cd ~/.wrangler/config && /bin/cat default.toml", "cd ~/.wrangler/config && command cat default.toml", "cd ~/.wrangler/config && env X=1 cat default.toml",
    "cd ~/.wrangler/config && cut -d= -f2 default.toml", "cd ~/.wrangler/config && python3 -c \"print(open('default.toml').read())\"",
    "cd ~/.wrangler/config && while read l; do echo $l; done < default.toml",
    "cd ~/.wrangler/config && cd .. && cat config/default.toml", "cd ~/.wrangler/config && popd && cat default.toml",
    "cd ~/.wrangler && cd /tmp && cd ~/.wrangler && cat config/default.toml", "cd ~/.wrangler; cd /; cd ~/.wrangler/config; cat default.toml", "cd /tmp && cd ~/.wrangler/config && cat default.toml", "cd ~/.wrangler/config && ls & cat default.toml", "cd ~/.wrangler/config && ls &cat default.toml",
    "cd ~/.wrangler/config && ls && cat default.toml", "cd ~/.wrangler/config; ls; cat default.toml", "pushd ~/.wrangler/config && cat default.toml", "cd ~/.wrangler && cat config/default.toml",
    "npx wrangler@latest auth token", "npx wrangler@3 auth token", "pnpm dlx wrangler@latest auth token", "bunx wrangler@4.1.0 auth token",
    "echo abc | npx wrangler@latest pages secret put KEY", 'curl -H "Authorization: Bearer $(wrangler auth token)" https://api.cloudflare.com/client/v4/user',
    "cat ~/.wrangler/config/default.toml", "grep oauth_token ~/.wrangler/config/work.toml", "less ~/Library/Preferences/.wrangler/config/default.toml",
    "cat ~/.wrangler/config/*.toml",
]
ALLOW = [
    "cut -d= -f1 .dev.vars", "cat .dev.vars | cut -d= -f1", "grep -c . .dev.vars", "grep -q '^MAPS_KEY=' .dev.vars && echo present",
    "env | cut -d= -f1", "railway variables --kv | grep -c .", "railway variables --kv | cut -d= -f1", "gh auth status",
    "git check-ignore -v .dev.vars", "ls -la .env.example", "cat .env.example", "cat .dev.vars.example", "set -euo pipefail",
    "[ -n \"$ANTHROPIC_API_KEY\" ] && echo set", "npx wrangler pages secret list", "pbpaste | npx wrangler pages secret put MAPS_KEY",
    "npm test", "env NODE_ENV=test npm test", "SECRET_GUARD_ALLOW=1 cat .dev.vars", "supabase status -o env | cut -d= -f1",
    "git status", "cat README.md",
    "cd ~/.wrangler/config && ls -la", "cd ~/.wrangler && ls config", "cd ~/.wrangler && ls config; cd ~/proj; cat README.md", "cd ~/.wrangler/config && ls -la && pwd", "cd ~/.wrangler/config && cd .. && ls", "cd ~/.wrangler && cd && cat notes.txt", "cd ~/proj && cat README.md", "wrangler whoami", "wrangler whoami --cwd ~/.config/cf-profiles/work", "wrangler auth list", "wrangler auth activate work ~/.config/cf-profiles/work",
    "ls -la ~/.wrangler/config/", "ls -la ~/.wrangler/config/default.toml", "cut -d= -f1 ~/.wrangler/config/work.toml", "grep -c . ~/.wrangler/config/default.toml",
]
for cmd in BLOCK:
    rc, err = guard(cmd)
    T.expect("guard blocks: %s" % cmd[:60], rc == 2 and "Instead:" in err, "rc=%d" % rc)
for cmd in ALLOW:
    rc, err = guard(cmd)
    T.expect("guard allows: %s" % cmd[:60], rc == 0, err.strip()[:160])
r = subprocess.run([sys.executable, GUARD], input="not json", capture_output=True, text=True)
T.expect("guard fails open on unreadable input", r.returncode == 0)
r = subprocess.run([sys.executable, GUARD], input=json.dumps({"tool_name": "Read", "tool_input": {"file_path": ".dev.vars"}}), capture_output=True, text=True)
T.expect("guard ignores non-Bash tools (Read is a separate gap, see README)", r.returncode == 0)

# ---------- Phase 5 audit: guard bypasses now blocked, false blocks now allowed ----------
AUDIT_BLOCK = [
    "cut -d= -f1- .dev.vars", "cut -d= -f1,2 .dev.vars", "cat .dev.vars | tee /dev/stderr | wc -l", "grep -c x .dev.vars | cat .dev.vars",
    "cat .dev*", "cat .dev.var?", "base64 .dev.vars", "paste .dev.vars", "rev .dev.vars", "column -t .dev.vars", "fold .dev.vars",
    "dd if=.dev.vars", "diff .dev.vars /dev/null", "tr a b < .dev.vars", "cp .dev.vars /tmp/x && cat /tmp/x",
    "git show HEAD:.dev.vars", "git log -p -- .env", "env -0", "declare -x", "python3 -c 'import os;print(os.environ)'",
    "echo $DATABASE_URL", "echo \"$GH_PAT\"", "cat <<< \"$OPENAI_API_KEY\"", "security find-generic-password -s x -g",
]
AUDIT_ALLOW = ["source .env && npm test", "grep -n .dev.vars .gitignore", "node --env-file=.dev.vars server.js", "echo $KEY_COUNT",
               ". ./.env && npm run build", "echo ${#ANTHROPIC_API_KEY}"]
for cmd in AUDIT_BLOCK:
    rc, err = guard(cmd)
    T.expect("guard (audit) blocks: %s" % cmd[:60], rc == 2, "rc=%d" % rc)
for cmd in AUDIT_ALLOW:
    rc, err = guard(cmd)
    T.expect("guard (audit) allows: %s" % cmd[:60], rc == 0, err.strip()[:160])
# a false block found live once the hook was registered: a jq filter is not a dotfile glob
for cmd in ["gh run list --limit 1 --json conclusion --jq '.[0]'", "jq '.items[0].name' data.json", "ls -la .github/",
            "for i in $(seq 1 3); do gh pr checks 1 --json name --jq '.[0].name'; done"]:
    rc, err = guard(cmd)
    T.expect("guard (live false block) allows: %s" % cmd[:60], rc == 0, err.strip()[:160])
# a second live false block: text that only NAMES a secrets file is not a read
for cmd in ['git commit -qm "hook blocks cat .dev.vars and allows cut -d= -f1"', "printf '%s\\n' 'the guard blocks cat .dev.vars' >> notes.md",
            'gh pr create --title "x" --body "never cat .env in CI"', "echo 'do not run cat .dev.vars'",
            "cat > notes.md <<'EOF'\nnever run cat .dev.vars\nEOF"]:
    rc, err = guard(cmd)
    T.expect("guard (message text) allows: %s" % cmd[:60].replace("\n", " "), rc == 0, err.strip()[:160])
for cmd in ['echo "$(cat .dev.vars)"', "python3 -c 'print(open(\".dev.vars\").read())'", "sh -c 'cat .dev.vars'",
            "python3 - <<'PY'\nprint(open('.dev.vars').read())\nPY", 'git commit -m "$(cat .dev.vars)"']:
    rc, err = guard(cmd)
    T.expect("guard still blocks code or substitution: %s" % cmd[:60].replace("\n", " "), rc == 2, "rc=%d" % rc)
for cmd in ["cat .*", "cat .??*", "head .e*", "cat .[e]nv"]:
    rc, err = guard(cmd)
    T.expect("guard still blocks dotfile globs: %s" % cmd, rc == 2, "rc=%d" % rc)

# ---------- Phase 8 (2026-11-01): five false blocks found live in one day ----------
LIVE_ALLOW = [
    # a STATE.md edit whose heredoc PROSE names secrets files
    "cd ~/suite && python3 - <<'EOF'\np='STATE.md'; s=open(p).read()\ns += 'more file shapes: .env.production.local, *.key, id_rsa, .envrc; .env.vault excluded'\nopen(p,'w').write(s)\nEOF\ngrep -c Phase STATE.md",
    # a filtered copy of the environment, nothing printed
    "python3 - <<'EOF'\nimport os\nclean = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}\nimport subprocess; subprocess.run(['git', 'status'], env=clean)\nEOF",
    # a grep whose PATTERN contains env, piped
    "grep -rn 'process.env' src | head -20",
    "grep -c env file.ts",
    # a GraphQL call carrying ids=
    "gh api graphql -f query='{ nodes(ids: [\"x\"]) { id } }' -F ids=abc",
    # the Dreamer session's four, verbatim shapes (no value in any of them)
    """cd ~ && which gitleaks || echo "NO gitleaks"; echo "=== six laptop-only ==="; for d in midterm-2026 intent-keys "LinkedIn Gate" Secure-Launch duckalos two-pane-demo; do [ -d "$d/.git" ] || { echo "$d: NOT A REPO (ls: $(ls -d ~/$d* 2>/dev/null | head -2))"; continue; }; echo "--- $d"; git -C "$d" branch --show-current; echo "dirty: $(git -C "$d" status --porcelain | wc -l | tr -d ' ')  commits: $(git -C "$d" rev-list --count HEAD)  size: $(du -sh "$d/.git" | cut -f1)"; echo "tracked env/keys: $(git -C "$d" ls-files | grep -iE '(^|/)\\.env|secret|credential|\\.pem$|service-account' | head -3 | tr '\\n' ' ')"; echo "gitignore: $([ -f "$d/.gitignore" ] && grep -cE 'node_modules|\\.env' "$d/.gitignore" || echo none)"; done""",
    """cd ~ && SECRET_GUARD_ALLOW=1 bash -c 'which gitleaks || echo "NO gitleaks"; for d in a b; do echo "$d"; done'""",
    """ids=$(gh api graphql -f query='{ a:repository(owner:"blueandyellow44",name:"midterm-2026"){id} }' -q '[.data.a.id] | @json'); gh api graphql -f query="mutation { updateUserPinnedItems(input:{itemIds:$ids}) { user { pinnedItems(first:6){ nodes { ... on Repository { name } } } } } }" -q '.data.updateUserPinnedItems.user.pinnedItems.nodes[].name' | tr '\\n' ' '""",
    """gh api graphql -f query='{ user(login:"blueandyellow44"){ pinnedItems(first:6){ nodes { ... on Repository { name } } } } }' -q '.data.user.pinnedItems.nodes[].name' | tr '\\n' ' '""",
    # a commit helper whose message only mentions the word env (reported live 2026-11-01 ~17:15)
    'c(){ msg="$1"; shift; git add -- "$@" && git commit -q -m "$msg"; }; c "chore(config): tidy. Gitleaks clean; env holds only two feature flags." settings.json CLAUDE.md',
    # a multi-line message passed to a shell function: "; env" sits inside the quotes (live 2026-11-01, second report)
    'c(){ msg="$1"; shift; git add -- "$@" && git commit -q -m "$msg"; }\nc "chore(config): record the live settings\n\nCLAUDE.md: ROE count now 19, lessons size. Gitleaks clean; env\nholds only two feature flags." settings.json',
    'git commit -q -m "chore(config): record the live settings\nCLAUDE.md: ROE count now 19, lessons size. Gitleaks clean; env\nholds only two feature flags." settings.json',
    # the override after a cd
    "cd ~/suite && SECRET_GUARD_ALLOW=1 cat .dev.vars",
    "cd ~/suite && for f in a b; do echo $f; done; SECRET_GUARD_ALLOW=1 python3 x.py",
]
LIVE_BLOCK = [
    "python3 - <<'PY'\nimport os\nprint(dict(os.environ))\nPY",
    "python3 - <<'PY'\nimport os\nfor k, v in os.environ.items(): print(k, v)\nPY",
    "python3 - <<'PY'\nprint(open('.env').read())\nPY",
    "node - <<'JS'\nconsole.log(JSON.stringify(process.env))\nJS",
    "cd ~/suite && cat .dev.vars",
    "bash -c \"true; env\"",
    "sh -c 'printenv'",
    "eval \"cat .dev.vars\"",
    "echo hi\nenv",
    "cd x; env",
    "grep -iE 'x' .env",
    "grep '' .dev.vars",
    "jq '.' .dev.vars",
    "echo \"$(grep -v '^#' .dev.vars)\"",
    "grep -rn x . ; env",
    "env | sort",
]
for cmd in LIVE_ALLOW:
    rc, err = guard(cmd)
    T.expect("guard (live 2026-11-01) allows: %s" % cmd[:70].replace("\n", " "), rc == 0, err.strip()[:200])
for cmd in LIVE_BLOCK:
    rc, err = guard(cmd)
    T.expect("guard (live 2026-11-01) still blocks: %s" % cmd[:70].replace("\n", " "), rc == 2, "rc=%d" % rc)

# ---------- scan_captures ----------
caps = T.tree({"2026/10/session-a.md": "user ran it and got MAPS=%s\n" % GKEY, "2026/10/session-b.md": "nothing here\n"})
r = subprocess.run([sys.executable, os.path.join(S, "scan_captures.py"), caps], capture_output=True, text=True)
T.expect("captures: a planted key in a transcript is found (exit 1)", r.returncode == 1 and "session-a.md:1" in r.stdout, r.stdout[-300:])
T.expect("captures: the value is never printed", GKEY not in r.stdout + r.stderr)
clean = T.tree({"2026/10/session.md": "a clean session\n"})
r = subprocess.run([sys.executable, os.path.join(S, "scan_captures.py"), clean], capture_output=True, text=True)
T.expect("captures: clean folder exits 0", r.returncode == 0, r.stdout)
r = subprocess.run([sys.executable, os.path.join(S, "scan_captures.py"), clean], capture_output=True, text=True, env=dict(os.environ, PATH="/usr/bin:/bin"))
T.expect("captures: no gitleaks is NOT RUN (exit 2), never clean", r.returncode == 2 and "NOT RUN" in r.stdout)

# ---------- store_secret + verify_secret (rotation helpers) ----------
import http.server, threading
d = T.tree({".dev.vars": "A=1\nELEVEN=old\n"})
f = os.path.join(d, ".dev.vars")
def store(val, name="ELEVEN"):
    return subprocess.run([sys.executable, os.path.join(S, "store_secret.py"), f, name], input=val, capture_output=True, text=True)
r = store("ELEVEN=" + GKEY + "\n")
T.expect("store: a value carrying NAME= is refused", r.returncode == 2 and "NAME=" in r.stderr)
r = store("")
T.expect("store: empty stdin is refused", r.returncode == 2)
r = store(GKEY + "\n")
body = open(f).read()
T.expect("store: replaces the line, keeps the others, prints no value", r.returncode == 0 and body == "A=1\nELEVEN=%s\n" % GKEY and GKEY not in r.stdout + r.stderr, r.stdout)
T.expect("store: file is 0600", oct(os.stat(f).st_mode & 0o777) == "0o600")

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.headers.get("xi-api-key") == GKEY else 401)
        self.end_headers()
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d" % srv.server_address[1]
def verify(name):
    return subprocess.run([sys.executable, os.path.join(S, "verify_secret.py"), "elevenlabs", "--file", f, "--name", name, "--base-url", base], capture_output=True, text=True)
open(f, "w").write("ELEVEN=wrong-value-here\nGOOD=%s\n" % GKEY)
r = verify("ELEVEN")
T.expect("verify: a wrong key exits 1 (refused), value not printed", r.returncode == 1 and "HTTP 401" in r.stdout and "wrong-value" not in r.stdout)
r = verify("GOOD")
T.expect("verify: the right key exits 0 with only the status", r.returncode == 0 and "HTTP 200" in r.stdout and GKEY not in r.stdout)
r = verify("MISSING")
T.expect("verify: an unset name exits 3 (could not tell), never 0", r.returncode == 3)
srv.shutdown()
r = subprocess.run([sys.executable, os.path.join(S, "verify_secret.py"), "elevenlabs", "--file", f, "--name", "GOOD", "--base-url", "http://evil.example/"], capture_output=True, text=True)
T.expect("verify: refuses to send a key to any other host", r.returncode == 2)

# ---------- generic-rule identifiers are classified without showing them (Phase 4) ----------
import random, string
rr = random.Random(31)
mixed = "".join(rr.choice(string.ascii_letters + string.digits) for _ in range(32))
# The shape gitleaks really flags in a news-scoring app (prefs.ts, 2026-10-08): a storage key name.
# The neutral stand-in must clear gitleaks' entropy floor and stopword list, as the original did.
ident_repo = T.git_init(T.tree({"src/prefs.ts": 'const KEY = "radius.prefs.v1";\nconst STORAGE_KEY = "radius.prefs.v1";\n'}))
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), ident_repo)
T.expect("generic identifiers: dismissed, PASS, and said so", c.get("secrets.history", {}).get("status") == "PASS" and "dismissed" in c["secrets.history"].get("detail", ""), out[-400:])
real_repo = T.git_init(T.tree({"src/k.ts": 'const API_KEY = "%s";\n' % mixed}))
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), real_repo)
T.status_is("generic but key-shaped: kept", c, "secrets.history", "FAIL", out)
T.expect("generic: no value printed either way", mixed not in out and "radius.prefs" not in out)

# ---------- Phase 5 audit: the repo cannot switch off its own scan; UUID/hex keys are never dismissed ----------
import uuid
GK2 = T.fake_key("google", 41)
for label, extra_files in (("a .gitleaksignore", None), ("a .gitleaks.toml allowlist", {".gitleaks.toml": '[extend]\nuseDefault = true\n[allowlist]\npaths = ["src/.*"]\n'}),
                           ("an inline gitleaks:allow", "inline")):
    files = {"src/a.ts": "const k = '%s'%s\n" % (GK2, " // gitleaks:allow" if extra_files == "inline" else "")}
    if isinstance(extra_files, dict):
        files.update(extra_files)
    rp = T.git_init(T.tree(files))
    if extra_files is None:  # fingerprint-based ignore file, as gitleaks writes it
        sha = subprocess.run(["git", "-C", rp, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        open(os.path.join(rp, ".gitleaksignore"), "w").write("%s:src/a.ts:gcp-api-key:1\nsrc/a.ts:gcp-api-key:1\n" % sha)
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("audit #3: %s does not hide the key" % label, c, "secrets.history", "FAIL", out)
    T.status_is("audit #3: %s is reported" % label, c, "secrets.allowlist", "FAIL", out)
    T.expect("audit #3: value not printed (%s)" % label, GK2 not in out)
for label, val in (("a UUID", str(uuid.UUID(int=random.Random(5).getrandbits(128)))), ("dash-joined hex", "-".join("%08x" % random.Random(i).getrandbits(32) for i in range(4)))):
    rp = T.git_init(T.tree({"src/k.ts": 'const api_key = "%s";\nconst secret_token = "%s";\n' % (val, val)}))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    hits = c.get("secrets.history", {})
    T.expect("audit #4: %s is never dismissed as an identifier" % label, hits.get("status") == "FAIL" or (hits.get("status") == "PASS" and "dismissed" not in hits.get("detail", "")), str(hits)[:200])
    T.expect("audit #4: value not printed (%s)" % label, val not in out)

# ---------- second audit (2026-10-09): guard bypasses ----------
AUDIT2_BLOCK = ["ls .dev.vars | xargs cat", "node --env-file=.dev.vars -p process.env.X", "cat .dev.va*", "ls -la .dev.vars $(cat .dev.vars)",
                "stat .dev.vars `cat .dev.vars`", "git check-ignore .dev.vars | xargs cat", "cat .d*.vars", "cat .[d]ev.vars", "cat ?dev.vars",
                "cat .en?", "cat .e?v", "cat .dev.v''ars", 'cat ".dev".vars', "f=.dev; cat ${f}.vars", "find . -name '.dev.v*' -exec cat {} +",
                "for f in .dev.v*; do cat $f; done", "git show HEAD:./.dev.v*",
                "source .dev.vars && node -e 'console.log(JSON.stringify(process.env))'",
                "source .dev.vars && python3 -c 'import os;[print(v) for v in os.environ.values()]'", "source .dev.vars && sh -c printenv"]
for cmd in AUDIT2_BLOCK:
    rc, err = guard(cmd)
    T.expect("guard (audit 2) blocks: %s" % cmd[:60], rc == 2, "rc=%d" % rc)
for cmd in ["node --env-file=.dev.vars server.js", "node --env-file=.dev.vars --watch src/server.ts", "source .env && npm test", "ls -la .dev.vars", "git check-ignore -v .dev.vars"]:
    rc, err = guard(cmd)
    T.expect("guard (audit 2) still allows: %s" % cmd[:60], rc == 0, err.strip()[:160])

# ---------- Phase 8 (2026-11-01): the 14 benchmark known misses, each as FAIL-side and PASS-side fixtures ----------
import json as _json, re
P8 = random.Random(808)
_al = string.ascii_letters + string.digits
_pick = lambda a, n: "".join(P8.choice(a) for _ in range(n))
_uuid = lambda: str(uuid.UUID(int=P8.getrandbits(128)))
_hex64 = lambda: _pick("0123456789abcdef", 64)
_pem = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(_pick(_al + "+/", 64) for _ in range(6)) + "\n-----END PRIVATE KEY-----\n"
ANT = T.fake_key("anthropic", 81)
GH8 = T.fake_key("github", 82)
SK8 = T.fake_key("stripe", 83)

# secrets.tracked: every secrets-file NAME, templates and the encrypted .env.vault excluded
for label, name, want in (("two-suffix .env.production.local", ".env.production.local", "FAIL"), ("certs/server.key", "certs/server.key", "FAIL"),
                          ("ssh id_rsa", "deploy/id_rsa", "FAIL"), ("a PKCS12 bundle", "certs/client.p12", "FAIL"),
                          ("dotenv-vault .env.vault (encrypted, meant to be committed)", ".env.vault", "PASS"), ("a template .env.production.local.example", ".env.production.local.example", "PASS")):
    body = _pem if name.endswith((".key", "id_rsa", ".p12")) else "SESSION_SECRET=committed-value\n"
    rp = T.git_init(T.tree({"app.py": "print('x')\n", name: body}))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("tracked (%s)" % label, c, "secrets.tracked", want, out)

# secrets.ignored: direnv's .envrc is a secrets file
rp = T.git_init(T.tree({"app.py": "import os\nK = os.environ['OPENAI_API_KEY']\n", ".gitignore": "__pycache__\n"}))
open(os.path.join(rp, ".envrc"), "w").write("export OPENAI_API_KEY=set-locally\n")
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
T.status_is("ignored (.envrc present, not ignored)", c, "secrets.ignored", "FAIL", out)
rp = T.git_init(T.tree({"app.py": "print('x')\n", ".gitignore": ".envrc\n"}))
open(os.path.join(rp, ".envrc"), "w").write("export OPENAI_API_KEY=set-locally\n")
rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
T.status_is("ignored (.envrc ignored)", c, "secrets.ignored", "PASS", out)

# secrets.allowlist: gitleaks:allow is read in every text file, only as a comment after code
AWS8 = "AK" + "IA" + _pick(string.ascii_uppercase + "234567", 16)
for label, files, want in (("inline allow in Terraform", {"main.tf": 'provider "aws" {\n  access_key = "%s" # gitleaks:allow\n}\n' % AWS8}, "FAIL"),
                           ("inline allow in Go", {"cfg.go": 'package cfg\n\nconst awsKey = "%s" // gitleaks:allow\n' % AWS8}, "FAIL"),
                           ("prose mention in CONTRIBUTING.md", {"CONTRIBUTING.md": "# Contributing\n\nNever add a `gitleaks:allow` comment to get CI green; rotate the key instead.\n"}, "PASS"),
                           ("a comment-only line above the value silences nothing", {"main.tf": '# gitleaks:allow\naccess_key = "%s"\n' % AWS8}, "PASS")):
    rp = T.git_init(T.tree(dict({"README.md": "# x\n"}, **files)))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("allowlist (%s)" % label, c, "secrets.allowlist", want, out)
    if "AK" + "IA" in str(files):
        T.status_is("allowlist (%s): the key itself is still found" % label, c, "secrets.history", "FAIL", out)
    T.expect("allowlist (%s): value not printed" % label, AWS8 not in out)

# secrets.history: identifier-NAMED hex/UUID/pk_ values are dismissed; the same shapes under any other name are kept
HIST = [("idempotencyKey UUIDs in a fixture", {"test/orders.json": _json.dumps([{"id": _uuid(), "idempotencyKey": _uuid()} for _ in range(3)], indent=2)}, "PASS"),
        ("a sha256 cacheKey", {"src/assets.ts": "export const assets = { styles: { path: '/styles.css', cacheKey: '%s' } }\n" % _hex64()}, "PASS"),
        ("a Stripe publishable pk_live_ key", {"app/stripe.ts": "const STRIPE_PUBLISHABLE_KEY = '%s'\n" % ("pk" + "_live_" + _pick(_al, 40))}, "PASS"),
        ("a Stripe SECRET key in the publishable slot", {"app/stripe.ts": "const STRIPE_PUBLISHABLE_KEY = '%s'\n" % SK8}, "FAIL"),
        ("a UUID under a cache_secret name", {"src/c.ts": "const cache_secret = '%s'\n" % _uuid()}, "FAIL"),
        ("a UUID Heroku key", {"deploy.sh": "export HEROKU_API_KEY=%s\n" % _uuid().upper()}, "FAIL"),
        ("a hex api_key", {"src/k.py": "api_key = '%s'\n" % _hex64()}, "FAIL")]
for label, files, want in HIST:
    rp = T.git_init(T.tree(dict({"package.json": "{}\n"}, **files)))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("history (%s)" % label, c, "secrets.history", want, out)
    if want == "PASS":
        T.expect("history (%s): dismissed, and said so" % label, "dismissed" in c.get("secrets.history", {}).get("detail", ""), str(c.get("secrets.history"))[:200])
    for v in files.values():
        for tok in re.findall(r"[A-Za-z0-9_-]{32,}", v):
            T.expect("history (%s): value not printed" % label, tok not in out)

# check_secret_shape: specific rule wins, provider-mismatch, prefixed placeholder, = padding, placeholder words by name
SHAPE = [("sk-ant- key in the OPENAI slot", "OPENAI_API_KEY=%s\n" % ANT, "shape.OPENAI_API_KEY", "FAIL"),
         ("an sk-proj- key in the OPENAI slot", "OPENAI_API_KEY=%s\n" % ("sk-" + "proj-" + _pick(_al, 48)), "shape.OPENAI_API_KEY", "PASS"),
         ("ghp_ followed by x's", "GITHUB_TOKEN=%s\n" % ("gh" + "p_" + "x" * 36), "shape.GITHUB_TOKEN", "FAIL"),
         ("a real-shaped GitHub token", "GITHUB_TOKEN=%s\n" % GH8, "shape.GITHUB_TOKEN", "PASS"),
         ("whsec_ under STRIPE_WEBHOOK_SECRET (webhook rule beats STRIPE.*SECRET)", "STRIPE_WEBHOOK_SECRET=whsec_%s\n" % _pick(_al, 32), "shape.STRIPE_WEBHOOK_SECRET", "PASS"),
         ("a secret key in the webhook slot", "STRIPE_WEBHOOK_SECRET=%s\n" % SK8, "shape.STRIPE_WEBHOOK_SECRET", "FAIL"),
         ("pk_live_ in STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY=%s\n" % ("pk" + "_live_" + _pick(_al, 40)), "shape.STRIPE_SECRET_KEY", "FAIL"),
         ("base64 with = padding", "SESSION_SECRET=%s=\n" % _pick(_al, 43), "shape.SESSION_SECRET", "PASS"),
         ("base64 with == padding", "SESSION_SECRET=%s==\n" % _pick(_al, 42), "shape.SESSION_SECRET", "PASS"),
         ("NAME= followed by more value", "SESSION_SECRET=SESSION_SECRET=%s\n" % _pick(_al, 32), "shape.SESSION_SECRET", "FAIL"),
         ("APP_ENV=test is a setting", "APP_ENV=test\n", "shape.APP_ENV", "PASS"),
         ("API_KEY=test is a placeholder", "API_KEY=test\n", "shape.API_KEY", "FAIL"),
         ("xxxx under any name", "REGION=xxxx\n", "shape.REGION", "FAIL")]
for label, body, cid, want in SHAPE:
    d8 = T.tree({".env": body})
    rc, c, out = T.run(os.path.join(S, "check_secret_shape.py"), os.path.join(d8, ".env"))
    T.status_is("shape (%s)" % label, c, cid, want, out)
    val = body.split("=", 1)[1].strip()
    T.expect("shape (%s): value not printed" % label, len(val) < 8 or val not in out)

# ---- Phase 10 secrets-ai ----
# One FAIL and one PASS fixture per mechanism introduced in Phase 10; values built at run time, never printed.
P10 = random.Random(1010)
_r10 = lambda n: "Q" + "".join(P10.choice(_al) for _ in range(n - 3)) + "7z"
NPM10 = "np" + "m_" + "".join(P10.choice(string.ascii_lowercase + string.digits) for _ in range(36))
# config files committed by design: a secrets file only when a credential key holds a literal value
for label, name, body, want in ((".envrc that only says use flake", ".envrc", "use flake\ndotenv_if_exists\n", "PASS"),
                                (".envrc exporting a literal key", ".envrc", "export STRIPE_SECRET_KEY=%s\n" % _r10(30), "FAIL"),
                                (".npmrc with an ${NPM_TOKEN} reference", ".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", "PASS"),
                                (".npmrc with a literal token", ".npmrc", "//registry.npmjs.org/:_authToken=%s\n" % NPM10, "FAIL"),
                                ("secrets.yml with an ENV reference", "config/secrets.yml", "production:\n  secret_key_base: <%= ENV[\"SECRET_KEY_BASE\"] %>\n", "PASS"),
                                ("appsettings with a connection-string password", "appsettings.Production.json", '{"Db": "Server=db;Password=%s;"}\n' % _r10(20), "FAIL"),
                                (".netrc", ".netrc", "machine example.com login a password %s\n" % _r10(20), "FAIL"),
                                ("suffixed deploy key id_rsa_ci", "deploy/id_rsa_ci", _pem, "FAIL"),
                                ("the public half id_rsa_ci.pub", "deploy/id_rsa_ci.pub", "ssh-ed25519 AAAA%s ci\n" % _r10(40), "PASS")):
    rp = T.git_init(T.tree({"app.py": "print('x')\n", name: body}))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("p10 tracked (%s)" % label, c, "secrets.tracked", want, out)
    T.expect("p10 tracked (%s): value not printed" % label, not any(tok in out for tok in re.findall(r"[A-Za-z0-9_]{20,}", body)))
# identifier-named generic hits: dismissed only for an identifier-shaped value under a name with no credential word
for label, files, want in (("a random token under CACHE_KEY", {"src/c.ts": "const CACHE_KEY = '%s'\n" % _r10(40)}, "FAIL"),
                           ("a hex value under CACHE_API_KEY", {"src/c.ts": "const CACHE_API_KEY = '%s'\n" % _hex64()}, "FAIL"),
                           ("a hex value under CACHE_KEY", {"src/c.ts": "const CACHE_KEY = '%s'\n" % _hex64()}, "PASS")):
    rp = T.git_init(T.tree(dict({"package.json": "{}\n"}, **files)))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("p10 history (%s)" % label, c, "secrets.history", want, out)
# allowlists: a block comment BEFORE the code on the same line; a gitleaks config TOML under another name
AWS10 = "AK" + "IA" + "".join(P10.choice(string.ascii_uppercase + "234567") for _ in range(16))
for label, files, want in (("/* gitleaks:allow */ before the code", {"src/a.ts": "/* gitleaks:allow */ export const k = '%s'\n" % AWS10}, "FAIL"),
                           ("a block comment alone on its line", {"src/a.ts": "/* gitleaks:allow */\nexport const n = 1\n"}, "PASS"),
                           ("gitleaks.toml (no dot) with an allowlist", {"gitleaks.toml": "[extend]\nuseDefault = true\n[allowlist]\npaths = ['src/.*']\n"}, "FAIL"),
                           ("pyproject [tool.x.allowlist] is not a gitleaks config", {"pyproject.toml": "[tool.lint]\nx = 1\n[tool.lint.allowlist]\nnames = ['a']\n"}, "PASS")):
    rp = T.git_init(T.tree(dict({"README.md": "# x\n"}, **files)))
    rc, c, out = T.run(os.path.join(S, "check_secrets.py"), rp)
    T.status_is("p10 allowlist (%s)" % label, c, "secrets.allowlist", want, out)
# check_secret_shape: placeholder words compared without separators; names read by words; x-filled bodies after a fixed head
GK10 = T.fake_key("google", 1010)
for label, body, cid, want in (("change-me under DB_PASS", "DB_PASS=change-me\n", "shape.DB_PASS", "FAIL"),
                               ("a real-looking password under DB_PASS", "DB_PASS=%s\n" % _r10(24), "shape.DB_PASS", "PASS"),
                               ("AUTH_MODE=test is a setting", "AUTH_MODE=test\n", "shape.AUTH_MODE", "PASS"),
                               ("AUTH_TOKEN=test is a placeholder", "AUTH_TOKEN=test\n", "shape.AUTH_TOKEN", "FAIL"),
                               ("ANTHROPIC_BASE_URL is a URL, not a key", "ANTHROPIC_BASE_URL=https://gw.example.com/a\n", "shape.ANTHROPIC_BASE_URL", "PASS"),
                               ("ANTHROPIC_API_KEY holding a URL", "ANTHROPIC_API_KEY=https://gw.example.com/a\n", "shape.ANTHROPIC_API_KEY", "FAIL"),
                               ("AIzaSy then x's", "GOOGLE_MAPS_API_KEY=AIzaSy%s\n" % ("X" * 33), "shape.GOOGLE_MAPS_API_KEY", "FAIL"),
                               ("a real-shaped AIza key", "GOOGLE_MAPS_API_KEY=%s\n" % GK10, "shape.GOOGLE_MAPS_API_KEY", "PASS"),
                               ("NAME= pasted with nothing after", "MY_SVC_API_TOKEN=MY_SVC_API_TOKEN=\n", "shape.MY_SVC_API_TOKEN", "FAIL")):
    d10 = T.tree({".env": body})
    rc, c, out = T.run(os.path.join(S, "check_secret_shape.py"), os.path.join(d10, ".env"))
    T.status_is("p10 shape (%s)" % label, c, cid, want, out)
# scan_captures: JSON string values are scanned decoded (an escaped closing quote no longer hides a key)
ANT10 = "sk-" + "ant-api03-" + "".join(P10.choice(_al + "-_") for _ in range(93)) + "AA"
for label, body, want in (("an Anthropic key before an escaped quote", _json.dumps({"content": "{\"ANTHROPIC_API_KEY\": \"%s\"}" % ANT10}) + "\n", 1),
                          ("only a masked key", _json.dumps({"content": "{\"ANTHROPIC_API_KEY\": \"sk-ant-...4f2a\"}"}) + "\n", 0)):
    d10 = T.tree({"raw/x.jsonl": body})
    r = subprocess.run([sys.executable, os.path.join(S, "scan_captures.py"), d10], capture_output=True, text=True)
    T.expect("p10 captures (%s): exit %d" % (label, want), r.returncode == want, r.stdout[-300:].replace(ANT10, "<KEY>"))
    T.expect("p10 captures (%s): value not printed" % label, ANT10 not in r.stdout + r.stderr)
# ---- end Phase 10 secrets-ai ----

T.finish()

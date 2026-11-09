#!/usr/bin/env python3
"""secret_print_guard.py - PreToolUse hook (Bash) that stops commands which
print secret VALUES into the session, because captured sessions are
git-tracked and pushed.

STAGED, NOT REGISTERED. Install steps are in the secure-launch README; this
file does nothing until a settings.json PreToolUse entry points at it.

Why: values reached captured transcripts at least three times (Railway
variable prefixes 2026-09-04, a Google Maps key 2026-10-03, a project's .dev.vars
key 2026-09-21).

Contract: reads the hook JSON on stdin. Exit 2 with a message on stderr blocks
the call and tells Claude the count-only or redacted form. Exit 0 allows.
Malformed input fails OPEN (exit 0, warning on stderr): a guard that crashes
must not take every Bash call down with it.

Override, visible in the transcript: start the command (or the command after a
`cd ... &&`) with SECRET_GUARD_ALLOW=1 (read from the command string; a hook
cannot see env vars set inline on the command it gates, found 2026-06-13).
2026-11-01: five false blocks in one day (prose naming a secrets file inside a
heredoc, a filtered os.environ copy, a grep pattern containing env, the prefix
after a cd) made the guard judge sinks and read primitives, not words.
2026-11-07: wrangler's credential store (~/.wrangler/config/<profile>.toml) and
`wrangler auth token` both passed unseen while a Cloudflare login skill was
graded; the store is a secrets file now and the token print is refused like gh's.
"""
import json
import re
import sys

SECRETISH = r"[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSCODE|PRIVATE|CREDENTIAL|DSN|SALT|PAT|_URL|DATABASE|CONN)[A-Za-z0-9_]*"
SAFE_VAR_SUFFIX = re.compile(r"_(?:COUNT|LEN|LENGTH|SET|PATH|FILE|DIR|NAME|NAMES|ID)$")
# Any token that names a secrets file, including globs (.dev*, .env*, .dev.var?).
SECRET_FILE_TOKEN = re.compile(r"""(?:^|[\s'"=<>|;&(:/])(?:\.dev\.vars|\.dev[*?\[]|\.dev\.var[*?\[]|\.env(?:\.(?!example\b|sample\b|template\b)[\w*?\[\]-]+|[*?\[])?|[\w.*?-]*\.pem|id_rsa|id_ed25519|credentials\.json|service-account[\w.*?-]*\.json|\.netrc|\.npmrc|hosts\.yml|\.wrangler/config/[\w.*?\[\]-]+)(?=$|[\s'"|;&<>)])""")
# The only forms allowed to name a secrets file: they show names, counts or presence, or load it into a process.
ALLOWED_WITH_SECRET_FILE = [
    re.compile(r"""^cut\s+-d\s*['"]?=['"]?\s+-f\s*1\s+\S+$"""),                          # cut -d= -f1 FILE (exactly field 1)
    re.compile(r"""^cut\s+-f\s*1\s+-d\s*['"]?=['"]?\s+\S+$"""),
    re.compile(r"""^awk\s+-F\s*['"]?=['"]?\s+['"]\{\s*print\s+\$1\s*\}['"]\s+\S+$"""),
    re.compile(r"""^sed\s+-E?\s*['"]s/=\.\*//['"]\s+\S+$"""),
    re.compile(r"""^grep\s+-[a-zA-Z]*[cqlL][a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*(?:'[^']*'|"[^"]*"|\S+)\s+\S+$"""),  # grep -c/-q/-l PATTERN FILE
    re.compile(r"""^wc(?:\s+-[lcw]+)?\s+\S+$"""),
    re.compile(r"""^(?:ls|stat|file)(?:\s+-[a-zA-Z]+)*(?:\s+[\w./~-]+)+$"""),
    re.compile(r"""^(?:test|\[)\s+-[efsr]\s+\S+(?:\s+\])?$"""),
    re.compile(r"""^git\s+(?:check-ignore|ls-files|rm\s+--cached)(?:\s+-[-a-zA-Z]+)*(?:\s+[\w./-]+)+$"""),
    re.compile(r"""^chmod\s+\d+\s+\S+$"""),
    re.compile(r"""^(?:source|\.)\s+\S+$"""),                                               # loads, prints nothing (checked with the rest of the command)
    re.compile(r"""^(?:node|bun|tsx)\s+(?:--(?!eval|print)[\w-]+(?:=\S+)?\s+)*--env-file=\S+\s+(?:--(?!eval|print)[\w-]+(?:=\S+)?\s+)*[\w./-]+\.(?:m?[jt]s|cjs|mjs)(?:\s+[\w./=:-]+)*$"""),  # a script path, never -e/-p
    re.compile(r"""^set\s+-a$|^set\s+\+a$"""),
]
# Pipelines allowed to READ a secrets file: one reader, then exactly one names-only/count stage.
READER = r"(?:cat|bat|head|tail)(?:\s+-[a-zA-Z0-9]+)*\s+\S+"
NAMES_OR_COUNT = r"""(?:cut\s+-d\s*['"]?=['"]?\s+-f\s*1|cut\s+-f\s*1\s+-d\s*['"]?=['"]?|awk\s+-F\s*['"]?=['"]?\s+['"]\{\s*print\s+\$1\s*\}['"]|sed\s+-E?\s*['"]s/=\.\*//['"]|wc(?:\s+-[lcw]+)?|grep\s+-[a-zA-Z]*[cqlL][a-zA-Z]*(?:\s+(?:'[^']*'|"[^"]*"|\S+))?)"""
ALLOWED_PIPELINE = re.compile(r"^" + READER + r"\s*\|\s*" + NAMES_OR_COUNT + r"\s*$")

SHAPES = [
    r"AIza[0-9A-Za-z_\-]{35}", r"sk-ant-[0-9A-Za-z_\-]{20,}", r"sk-(?:proj-)?[0-9A-Za-z_\-]{32,}",
    r"[sr]k_(?:live|test)_[0-9A-Za-z]{16,}", r"gh[pousr]_[0-9A-Za-z]{30,}", r"github_pat_[0-9A-Za-z_]{40,}",
    r"xox[baprs]-[0-9A-Za-z\-]{10,}", r"eyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}",
    r"[a-z][a-z0-9+.\-]*://[^/\s:@'\"]+:[^@\s/'\"]{6,}@",
]

HINT_FILE = "show names only: `cut -d= -f1 .dev.vars`, count: `grep -c . .dev.vars`, presence: `grep -q '^NAME=' .dev.vars && echo present`"
OTHER_RULES = [
    ("prints the environment", re.compile(r"(?:^|\|)\s*(?:printenv(?:\s+[A-Za-z_]\w*)?|env(?:\s+-0|\s+--null)?|export\s+-p|declare\s+-[a-zA-Z]*[xp][a-zA-Z]*|typeset\s+-x|set)\s*(?:$|[|;&>])"),
     "list names only: `env | cut -d= -f1`, or test one: `[ -n \"$NAME\" ] && echo set`"),
    ("prints the environment from code", re.compile(r"(?:print|console\.log|puts|pp|p)\s*\(?\s*(?:dict\()?\s*(?:os\.environ|process\.env|ENV)\s*\)?\s*\)?\s*(?:$|[;\n'\"])"),
     "print the names only: `print(sorted(os.environ))`"),
    ("prints a secret variable", re.compile(r"(?:\b(?:echo|printf|print)\b|\bcat\s*<<<)[^|;&]*\$\{?(" + SECRETISH + r")"),
     "test presence instead: `[ -n \"$NAME\" ] && echo set`, or length: `echo ${#NAME}`"),
    ("prints a secret from code", re.compile(r"(?:console\.log|print|puts|System\.out)\s*\(?[^;|&]*(?:process\.env|os\.environ|ENV\[|getenv)[^;|&]*" + SECRETISH, re.I),
     "print presence or length, never the value: `console.log(!!process.env.NAME, (process.env.NAME||'').length)`"),
    ("Railway variables", re.compile(r"\brailway\s+(?:variables|vars)\b"),
     "`railway variables --kv | cut -d= -f1` for names, `railway variables --kv | grep -c .` for a count"),
    ("GitHub token", re.compile(r"\bgh\s+auth\s+(?:token|status\b[^|;&]*(?:-t\b|--show-token))"),
     "`gh auth status` (without -t) shows the account and scopes without the token"),
    # Any runner prefix (npx, pnpm dlx, bunx) and any version pin (wrangler@latest, @3) still names wrangler (Claude review, PR #8).
    ("Wrangler OAuth token", re.compile(r"\bwrangler(?:@[\w.^~-]+)?\s+auth\s+token\b"),
     "`wrangler whoami` shows the login, accounts and scopes without the token; route the command with `--profile` and `CLOUDFLARE_ACCOUNT_ID` instead of extracting it (the OAuth token is not reusable for direct API calls anyway)"),
    ("cloud token print", re.compile(r"\bgcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token\b|\baws\s+configure\s+get\s+\S*secret|\bsecurity\s+find-(?:generic|internet)-password\b[^|;&]*\s-[wg]\b|\bop\s+read\b|\bpass\s+show\b"),
     "pipe the token straight into the command that needs it (`$(gcloud auth print-access-token)` inside a curl), never to the terminal"),
    ("Wrangler secret value", re.compile(r"\b(?:echo|printf)\b[^|]*\|\s*(?:(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+(?:--yes\s+|-y\s+)?)?wrangler(?:@[\w.^~-]+)?\s+(?:pages\s+)?secret\s+put\b"),
     "pipe from the clipboard or a file without echoing: `pbpaste | npx wrangler pages secret put NAME` (secret-handling skill)"),
    ("Supabase keys", re.compile(r"\bsupabase\s+status\b"),
     "`supabase status -o env | cut -d= -f1` for names"),
]
# Changing into wrangler's folder (cd or pushd, ~/.wrangler or deeper) lets any command read the store by a bare
# name. A list of reader names is never complete (/bin/cat, command cat, cut, python -c, a while-read loop all
# slipped past one; Claude reviews, PR #8), so this is an allowlist: after the cd, only listing commands may run
# until the command changes directory again. Judged on the whole command.
WRANGLER_CD = re.compile(r"""(?:^|&&|;|\|\||\()\s*(?:cd|pushd)\s+["']?[^;&|"']*\.wrangler\b""")
WRANGLER_LISTING = re.compile(r"""^(?:ls|stat|file|pwd|du|true)(?:\s+[^<>`$&;|()]*)?$""")
# Only a cd to a home or absolute path outside .wrangler (or a bare cd) leaves the folder; a relative cd, or a
# popd to wherever the stack pointed, may stay inside, so it is treated as still inside.
WRANGLER_LEAVE = re.compile(r"""^(?:cd\s*$|(?:cd|pushd)\s+["']?(?:~/?|/)(?![^;&|"']*\.wrangler)[^;&|]*$)""")
WRANGLER_STAY = re.compile(r"""^(?:cd|pushd)\s+["']?(?!~|/)[^;&|]*$""")


def _wrangler_cd_read(cmd):
    """True when, at any point inside a .wrangler folder, a command other than listing runs. Every segment is
    walked, so leaving and re-entering (a decoy first cd) is caught too (Claude review, PR #8)."""
    if not WRANGLER_CD.search(cmd):
        return False
    inside = False
    for part in re.split(r"&&|\|\||;|\||&|\n|\(|\)", cmd):  # a lone & (background) separates commands too
        seg = part.strip()
        if not seg:
            continue
        if re.match(r"""(?:cd|pushd)\s+["']?[^;&|"']*\.wrangler\b""", seg):
            inside = True
            continue
        if not inside:
            continue
        if WRANGLER_LEAVE.match(seg):
            inside = False
            continue
        if WRANGLER_STAY.match(seg) or seg == "popd":
            continue  # a relative cd or popd may stay inside, so the folder still counts as entered
        if not WRANGLER_LISTING.match(seg):
            return True
    return False


ALLOWED_OTHER = [
    re.compile(r"""^railway\s+(?:variables|vars)\s+--kv\s*\|\s*""" + NAMES_OR_COUNT + r"""\s*$"""),
    re.compile(r"""^supabase\s+status\s+-o\s+env\s*\|\s*""" + NAMES_OR_COUNT + r"""\s*$"""),
    re.compile(r"""^env\s*\|\s*""" + NAMES_OR_COUNT + r"""\s*$"""),
]


def _segments(cmd):
    """Split on && || ; and newlines OUTSIDE quotes, keeping pipelines whole. A `;` or a line break inside a
    quoted argument is text: a commit message passed to a shell function, "...Gitleaks clean; env\nholds...",
    once split into a bare `env` command (false block found live, 2026-11-01). What a quote hands to an
    interpreter (sh -c, bash -c, eval) is judged separately by _interpreter_payloads."""
    out, cur, q, i, n = [], [], None, 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if q:
            cur.append(ch)
            if ch == "\\" and q == '"' and i + 1 < n:
                cur.append(cmd[i + 1]); i += 2; continue
            if ch == q:
                q = None
            i += 1; continue
        if ch in "'\"":
            q = ch; cur.append(ch); i += 1; continue
        if ch == "\\" and i + 1 < n:
            cur.append(ch); cur.append(cmd[i + 1]); i += 2; continue
        two = cmd[i:i + 2]
        if two in ("&&", "||"):
            out.append("".join(cur)); cur = []; i += 2; continue
        if ch in ";\n":
            out.append("".join(cur)); cur = []; i += 1; continue
        cur.append(ch); i += 1
    out.append("".join(cur))
    return [x.strip() for x in out if x.strip()]


INTERP_PAYLOAD = re.compile(r"""(?:\b(?:sh|bash|zsh|dash|ksh)\s+(?:-[a-zA-Z]*c[a-zA-Z]*)|\beval)\s+('(?:[^']*)'|"(?:[^"\\]|\\.)*")""")


def _interpreter_payloads(cmd):
    """Script text a quote hands to a shell (bash -c '...', eval "..."): judged as a command of its own."""
    return [m.group(1)[1:-1] for m in INTERP_PAYLOAD.finditer(cmd)]


def _secret_var_named(seg):
    for m in re.finditer(r"\$\{?#?(" + SECRETISH + r")", seg):
        if seg[m.start():m.start() + 3] == "${#":
            continue  # a length, not a value
        if not SAFE_VAR_SUFFIX.search(m.group(1)):
            return True
    return False


def _grep_pattern_only(seg):
    """`grep -n .dev.vars .gitignore`: the secrets name is the PATTERN, the file read is not a secrets file."""
    if "|" in seg or not re.match(r"^(?:grep|rg|egrep)\s", seg):
        return False
    import shlex
    try:
        toks = shlex.split(seg)[1:]
    except ValueError:
        return False
    args = [x for x in toks if not x.startswith("-")]
    return len(args) >= 2 and not any(SECRET_FILE_TOKEN.search(" " + f) for f in args[1:])


RUNS_OTHER = re.compile(r"\$\(|`|\bxargs\b|-exec\b|\bfor\s+\w+\s+in\b|\bwhile\b|\beval\b|\bsh\s+-c\b|\bbash\s+-c\b|\bzsh\s+-c\b")
# A glob that can expand to a secrets dotfile: .d*/.e* with a wildcard, a class holding d or e (.[d]ev),
# a bare .* or .??, or ?dev/?env. Not a jq filter like '.[0]' (a false block found live, 2026-10-09).
DOT_GLOB = re.compile(r"""(?:^|[\s/:'"=])(?:\.(?:[de][\w.-]*[*?\[]|\[[^\]]*[de][^\]]*\])[\w.*?\[\]-]*|\.[*?]+(?=$|[\s'"|;&)])|\?[\w.*?\[\]-]*(?:dev|env)[\w.*?\[\]-]*)""")
SECRET_ASSIGN = re.compile(r"""(?<![-\w])[A-Za-z_]\w*=['"]?\.?(?:\.dev|\.env|dev\.vars|\.d\b|\.e\b)""")  # f=.dev; not --env-file=
ENV_DUMP_SHELL = re.compile(r"\bprintenv\b|(?:^|\|)\s*env\s*(?:$|\|)")
# A whole-environment expression in code is a dump only when a sink prints, logs, writes or returns it on
# the same line; `{k: v for k, v in os.environ.items() if ...}` builds a filtered copy and prints nothing
# (false block found live, 2026-11-01).
ENV_DUMP_CODE = re.compile(r"JSON\.stringify\(\s*process\.env|Object\.(?:values|entries)\(\s*process\.env|os\.environ\.(?:values|items|copy)\(|dict\(\s*os\.environ|for\s+\w+\s*(?:,\s*\w+)?\s+in\s+os\.environ")
PRINT_SINK = re.compile(r"\b(?:print|console\.(?:log|error|info|dir)|puts|pp|sys\.std(?:out|err)\.write|json\.dumps?|JSON\.stringify|write|return|echo|process\.stdout\.write)\b|>>?\s*\S")
# A secrets-file name inside a script body is a READ only beside a read primitive on the same line; a
# docstring, a comment or a string written to a notes file is text (false block found live, 2026-11-01).
READ_PRIM = re.compile(r"\bopen\s*\(|\bread(?:File|FileSync|_text|lines)?\s*\(|\bPath\s*\(|\bsubprocess\b|\bexec\w*\s*\(|\bspawn\w*\s*\(|\bfs\.|\brequire\(\s*['\"]fs|\bcat\s|\bhead\s|\btail\s|\bless\s|\bsource\s|\bdotenv\b|load_dotenv|\bwith\s+open")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n(.*?)\n\2(?=$|\n)", re.S)


def _env_dump(text):
    """True when text dumps the whole environment: a shell env/printenv, or a code form beside a sink."""
    if ENV_DUMP_SHELL.search(text):
        return True
    return any(ENV_DUMP_CODE.search(line) and PRINT_SINK.search(line) for line in text.split("\n"))


def _code_body_hit(body):
    """Judge a script body (a heredoc fed to an interpreter, or a -c/-e script) line by line."""
    for line in body.split("\n"):
        if (SECRET_FILE_TOKEN.search(" " + line) or DOT_GLOB.search(" " + line)) and READ_PRIM.search(line):
            return ("reads a secrets file from code", HINT_FILE)
        if ENV_DUMP_CODE.search(line) and PRINT_SINK.search(line):
            return ("prints the environment from code", "print the names only: `print(sorted(os.environ))`")
        if re.search(r"(?:print|console\.log|puts)\s*\(?[^\n]*(?:os\.environ|process\.env|ENV\[|getenv)[^\n]*" + SECRETISH, line, re.I):
            return ("prints a secret from code", "print presence or length, never the value")
        for sh in SHAPES:
            if re.search(sh, line):
                return ("contains a credential-shaped value", "never paste a key into a command")
    return None


def _normalize(cmd):
    """Undo the quoting tricks that split a filename: .dev.v''ars, ".dev".vars, .dev\\.vars."""
    return re.sub(r"(?<=\w|\.)(?:''|\"\")(?=\w|\.)", "", cmd).replace('"', "").replace("\\", "")


_QUOTED = r"""'[^']*'|"(?:[^"\\$`]|\\.)*\""""   # a double-quoted string with no $ or backtick expands nothing


def _strip_messages(cmd):
    """Blank text that is only printed or stored, never run: echo/printf arguments, commit and PR
    messages (-m, --message, --body, --title), and a quoted heredoc written to a file with cat/tee.
    A commit message that NAMES .dev.vars reads nothing (false block found live, 2026-10-09).
    Script arguments (python -c, sh -c, node -e) are left alone and still judged."""
    out = re.sub(r"""(?m)((?:^|[;&|]\s*)(?:cat|tee)\s+(?:-a\s+)?>{0,2}\s*\S+\s*<<-?\s*'(\w+)'\n)(.*?)(\n\2$)""",
                 lambda m: m.group(1) + "" + m.group(4), cmd, flags=re.S)
    out = re.sub(r"""((?:\s|^)(?:-[a-zA-Z]*m|--message|--body|--title|-t|-b)(?:\s+|=))(""" + _QUOTED + r")", lambda m: m.group(1) + "''", out)

    def blank_echo(m):
        return re.sub(_QUOTED, "''", m.group(0))
    out = re.sub(r"""(?:^|(?<=[;&|]))\s*(?:echo|printf)\b[^;&|\n]*""", blank_echo, out)
    # A grep PATTERN or a jq FILTER is matched against text, never read as a file: a grep for
    # `(^|/)\.env|secret` and `--jq '.data.nodes[].name'` both blocked live on 2026-11-01 (the second as
    # a dotfile glob, the same class as the `.[0]` false block of 2026-10-09). Only the quoted argument is blanked.
    out = re.sub(r"""(\b(?:grep|rg|egrep|fgrep)\b(?:\s+-{1,2}[A-Za-z-]+(?:=\S+)?)*\s+)('[^']*'|"(?:[^"\\$`]|\\.)*")""", lambda m: m.group(1) + "''", out)
    out = re.sub(r"""((?:--jq|-q|\bjq)(?:\s+-[a-zA-Z]+)*\s+)('[^']*'|"(?:[^"\\$`]|\\.)*")""", lambda m: m.group(1) + "''", out)
    return out


def check(cmd):
    """Return (rule, suggestion) for a command that would print a secret, else None."""
    # The override is honored where a top-level command starts: at the front, or after a `cd ... &&`
    # (found live 2026-11-01: the prefix after a cd was ignored). It stays visible in the transcript.
    if re.search(r"(?:^|&&|;)\s*SECRET_GUARD_ALLOW=1\b", cmd):
        return None
    raw = cmd
    cmd = _normalize(_strip_messages(cmd))
    # Script bodies fed to an interpreter are judged as code, line by line, then taken out of the
    # shell-level pass (a prose line naming .dev.vars inside a heredoc is text, not a read).
    for m in list(HEREDOC.finditer(cmd)):
        hit = _code_body_hit(m.group(3))
        if hit:
            return hit
    cmd = HEREDOC.sub(lambda m: m.group(0)[: m.start(3) - m.start()] + "\n" + m.group(2), cmd)
    # Split on the text as typed (quotes intact), then normalize each piece: _normalize drops every double quote,
    # which would make a quoted `;` look like a command separator.
    typed = HEREDOC.sub(lambda m: m.group(0)[: m.start(3) - m.start()] + "\n" + m.group(2), _strip_messages(raw))
    if SECRET_ASSIGN.search(cmd):
        return ("builds a secrets filename in a variable", HINT_FILE)
    loads = bool(re.search(r"(?:^|&&|;|\|\|)\s*(?:source|\.)\s+\S*(?:\.env|\.dev\.vars)|--env-file=", cmd))
    if loads and _env_dump(cmd.split("--env-file=", 1)[-1] if "--env-file=" in cmd else re.split(r"(?:source|\.)\s+\S*(?:\.env|\.dev\.vars)\S*", cmd, 1)[-1]):
        return ("loads a secrets file, then dumps the environment", "after loading, never print the environment; check one name with `[ -n \"$NAME\" ]`")
    if _env_dump(cmd) and not re.search(r"\|\s*" + NAMES_OR_COUNT + r"\s*$", cmd):
        return ("prints the environment", "list names only: `env | cut -d= -f1`")
    for s in SHAPES:
        if re.search(s, cmd):
            return ("contains a credential-shaped value", "never paste a key into a command; read it from the clipboard or a file inside the command (secret-handling skill)")
    if _wrangler_cd_read(cmd):
        return ("reads wrangler's credential store after a cd", "`ls -la ~/.wrangler/config/` names the profiles; `wrangler whoami` shows the login without reading the file")
    if re.search(r"\bgit\s+(?:show|log\s+[^|;&]*-p|diff|blame|cat-file|grep)\b[^|;&]*(?:\.dev\.vars|\.env\b|\.pem)", cmd):
        return ("prints a secrets file from git history", HINT_FILE)
    for payload in _interpreter_payloads(typed):
        if payload.strip() and not re.match(r"\s*SECRET_GUARD_ALLOW=1\b", payload):
            hit = check(payload)
            if hit:
                return hit
    for seg in (_normalize(x) for x in _segments(typed)):
        names_secret = SECRET_FILE_TOKEN.search(" " + seg) or DOT_GLOB.search(" " + seg)
        if names_secret and RUNS_OTHER.search(seg):
            return ("names a secrets file and runs another command on it", HINT_FILE)
        if names_secret:
            if _grep_pattern_only(seg):
                continue
            if not (any(rx.match(seg) for rx in ALLOWED_WITH_SECRET_FILE) or ALLOWED_PIPELINE.match(seg)):
                return ("names a secrets file in a form that can print it", HINT_FILE)
            continue
        if any(rx.match(seg) for rx in ALLOWED_OTHER):
            continue
        for name, rx, hint in OTHER_RULES:
            if rx.search(seg):
                if name == "prints a secret variable" and not _secret_var_named(seg):
                    continue
                return (name, hint)
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        print("secret_print_guard: unreadable hook input; allowing", file=sys.stderr)
        return 0
    if data.get("tool_name") != "Bash":
        return 0
    cmd = (data.get("tool_input") or {}).get("command") or ""
    hit = check(cmd)
    if not hit:
        return 0
    print("Blocked by secret_print_guard: this command %s, and its output would land in a captured, pushed transcript. "
          "Instead: %s. If the output is truly value-free, prefix the command with SECRET_GUARD_ALLOW=1." % hit, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

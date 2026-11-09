#!/usr/bin/env python3
"""check_railway.py - Railway adapter.

  check_railway.py REPO

Railway keeps variables and networking in the dashboard, so most of what
matters is under cannot_see with the count-only command to read it.

  railway.env-dump  code that logs or returns the whole environment FAILs high:
                    every variable lands in Railway's logs or a response. The
                    whole environment is process.env, os.environ (also
                    .items() / .values() / .copy()), Bun.env, c.env,
                    Deno.env.toObject(), a name bound to one of them (`const
                    env = process.env`, a Worker's fetch(request, env)), or a
                    spread or dict() of them, appearing as ANY argument of a
                    log, print, render or response call (chains such as
                    res.status(200).json(...) count), inside an f-string or
                    template-literal interpolation, as a Koa `ctx.body =`, or
                    as a return value. Object.keys(process.env),
                    len(os.environ), `in os.environ`, process.env.NAME and a
                    bare `env` bound to anything else (process.env.NODE_ENV, a
                    Jinja Environment) are not the whole environment. String
                    text and comments never match.
  railway.config    railway.json/railway.toml parses; a start command that
                    runs a dev server (npm run dev, next dev, --reload, --watch,
                    --hot, nodemon, react-scripts start, ng serve, manage.py
                    runserver, fastapi dev, ...) FAILs low. The command is split
                    on && ; || |, env assignments and `cd X` are followed, and
                    `npm start`, `npm run X`, `yarn X`, `pnpm X` and `bun run X`
                    are resolved through the nearest package.json scripts (two
                    levels). With no startCommand, what the builder runs is
                    read: a Dockerfile's ENTRYPOINT + CMD (builder DOCKERFILE,
                    or a Dockerfile present), nixpacks.toml [start] cmd,
                    railpack.json, then the Procfile web process. Every railway config in the repo is read (one
                    service per folder); with several, the id carries the folder.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

# A log, print or response call. A response is often reached through a chain
# (res.status(200).json(...), reply.code(200).send(...)) and a template render hands its
# context to a page that prints it (res.render('debug', { env: process.env })).
SINK = re.compile(r"\b(?:console\.(?:log|info|debug|warn|error|table|dir|trace)|logger\.\w+|logging\.\w+|log\.(?:info|debug|warn|warning|error|trace|fatal)|"
                  r"print|pprint|JSON\.stringify|jsonify|Response\.json|new\s+Response|render_template|TemplateResponse|"
                  r"(?:res|reply|response|resp|ctx|c)(?:\s*\.\s*\w+\s*\([^()\n]*\))*\s*\.\s*(?:json|jsonp|send|end|write|render|html|text|body)|"
                  r"[\w$]+(?:\s*\.\s*(?:status|code|type|header|headers|set|setHeader|cookie|vary|contentType)\s*\([^()\n]*\))+\s*\.\s*(?:json|jsonp|send|end|write|render))\s*\(")
# Koa and friends answer by assignment: ctx.body = process.env
BODY_ASSIGN = re.compile(r"\b(?:ctx|this|context|res|response)\s*\.\s*body\s*=(?!=)\s*([^\n;]+)")
RETURN = re.compile(r"\breturn\s+([^\n;]+)")
# The whole environment as a value. A Python mapping read whole through .items() / .values() / .copy()
# is still whole. Not followed by any other member access, an index or a call.
BASE_ENV = (r"process\.env", r"os\.environ", r"Bun\.env", r"Deno\.env\.toObject\(\)", r"c\.env")
# a returned value: only the unmistakable forms (a helper that returns its own `env` object is not a dump)
STRICT_ENV = (r"process\.env", r"os\.environ", r"Bun\.env", r"Deno\.env\.toObject\(\)")
WHOLE_SUFFIX = r"(\.(?:items|values|copy)\(\))?"
# wrappers that read names or counts only, never values
SAFE_WRAP = re.compile(r"(?:Object\.keys|Object\.getOwnPropertyNames|Reflect\.ownKeys|len|sorted|list|set|keys|tuple)\s*\(\s*$|\bin\s+$|\bnot\s+in\s+$")
COUNT_WRAP = re.compile(r"\blen\s*\(\s*$")
# A name bound to the whole environment: `const env = process.env`, `env = dict(os.environ)`, and a
# Worker handler's env parameter (fetch(request, env, ctx)). Bare `env` is NOT the environment by
# itself (`const env = process.env.NODE_ENV`, a Jinja `env = Environment()`).
ASSIGN = re.compile(r"(?:^|[;{(\s])(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]+?)?\s*=(?![=>])\s*([^\n;]+)", re.M)
WORKER_PARAM = re.compile(r"\b(?:fetch|scheduled|queue|email|tail|trace)\s*\(\s*[\w$]+\s*(?::\s*[\w.<>\[\]]+)?\s*,\s*([A-Za-z_$][\w$]*)")
DEV = re.compile(r"npm run dev|\b(?:next|nuxt|nuxi|astro|remix|svelte-kit|react-router|wrangler)\s+dev\b|gatsby develop|"
                 r"\bvite(?!\s+(?:build|preview|optimize)\b)(?=\s|$)|nodemon|--reload\b|--watch(?![\w-])|--hot\b|flask\s+(?:[^\n&;|]*\s)?run\b|"
                 r"ts-node-dev|tsx\s+watch|react-scripts\s+start|\bng\s+serve\b|vue-cli-service\s+serve|webpack(?:-cli)?\s+serve|webpack-dev-server|"
                 r"manage\.py\s+runserver|\bfastapi\s+dev\b|\bember\s+serve\b|\bparcel(?!\s+build\b)\s+\S|artisan\s+serve|\bhugo\s+server\b|\bjekyll\s+serve\b")
SCRIPT_CALL = re.compile(r"^\s*(?:npm\s+(?:run(?:-script)?\s+)?|yarn\s+(?:run\s+)?|pnpm\s+(?:run\s+)?|bun\s+(?:run\s+)?|npx\s+)?([\w:.-]+)")
ENV_PREFIX = re.compile(r"^\s*(?:env\s+)?(?:[A-Za-z_]\w*=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)+|^\s*exec\s+")


def _args(text, open_idx):
    """The text inside the parentheses opening at open_idx (balanced), or None."""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:j]
    return None


def _env_rx(names):
    # not a member of something else (x.process.env), but a spread ({...process.env}) is the whole value
    return re.compile(r"(?<![\w$])(?:(?<=\.\.\.)|(?<!\.))(?:" + "|".join(names) + r")" + WHOLE_SUFFIX + r"(?![\w$.\[(])")


def dumps_env(expr, rx):
    """True when EXPR (an argument list or a returned value) carries the whole environment."""
    for m in rx.finditer(expr):
        before = expr[max(0, m.start() - 40):m.start()]
        if (COUNT_WRAP if m.group(1) and not m.group(1).startswith(".copy") else SAFE_WRAP).search(before):
            continue
        return True
    return False


def env_aliases(t):
    """Names this file binds to the whole environment (two passes, so an alias of an alias counts)."""
    names = set(m.group(1) for m in WORKER_PARAM.finditer(t))
    for _ in range(2):
        rx = _env_rx(list(STRICT_ENV) + [re.escape(n) for n in names])
        for m in ASSIGN.finditer(t):
            rhs = m.group(2).strip()
            if dumps_env(rhs, rx):
                names.add(m.group(1))
    return names


INTERP_JS = re.compile(r"\$\{([^{}]+)\}")
FSTRING = re.compile(r"""(?<![\w])[fF][rR]?("|')(.*?)(?<!\\)\1""")
INTERP_PY = re.compile(r"\{([^{}]+?)(?:![rsa])?(?::[^{}]*)?\}")


def _interpolations(raw, py):
    """The expressions interpolated into f-strings or template literals of RAW (string contents kept)."""
    if py:
        return [e for f in FSTRING.finditer(raw) for e in INTERP_PY.findall(f.group(2))]
    return INTERP_JS.findall(raw)


def env_dumps(repo):
    hits = []
    for p in walk.files(repo, tests=False):
        t = walk.read_code(p, strings=False)
        raw = walk.read_code(p, strings=True)  # same length: only string contents differ
        if len(raw) != len(t):
            raw = t
        py = p.endswith(".py")
        rel = walk.rel(repo, p)
        aliases = env_aliases(t)
        wide = _env_rx(list(BASE_ENV) + [re.escape(n) for n in aliases])
        strict = _env_rx(list(STRICT_ENV) + [re.escape(n) for n in aliases])
        for m in SINK.finditer(t):
            a = _args(t, m.end() - 1)
            if a is None:
                continue
            span = raw[m.end():m.end() + len(a)]
            if dumps_env(a, wide) or any(dumps_env(e, wide) for e in _interpolations(span, py)):
                hits.append("%s:%d" % (rel, walk.line_of(t, m.start())))
        for rx_, m_iter in ((strict, RETURN.finditer(t)), (wide, BODY_ASSIGN.finditer(t))):
            for m in m_iter:
                if dumps_env(m.group(1), rx_):
                    hits.append("%s:%d" % (rel, walk.line_of(t, m.start())))
    return sorted(set(hits))


def _segments(cmd):
    """A shell command split on && || ; and |, each segment with its env assignments and exec stripped."""
    return [ENV_PREFIX.sub("", s).strip() for s in re.split(r"&&|\|\||;|\|", cmd or "") if s.strip()]


def expand(cmd, cwd, repo, depth=0):
    """[(command_text, via)] for every segment of CMD, with `cd X` followed and `npm start` /
    `npm run X` / `yarn X` / `pnpm X` / `bun run X` resolved through the nearest package.json
    scripts (two levels deep). `via` names the script a segment resolved through, or None."""
    out = []
    for seg in _segments(cmd):
        cd = re.match(r"^cd\s+(\"[^\"]+\"|'[^']+'|\S+)$", seg)
        if cd:
            cwd = os.path.normpath(os.path.join(cwd, cd.group(1).strip("\"'")))
            continue
        resolved = _resolve_script(seg, cwd, repo, depth)
        if resolved is None:
            out.append((seg, None))
        else:
            target, pj_dir, via = resolved
            inner = expand(target, pj_dir, repo, depth + 1)
            out += [(txt, via if v is None else "%s -> %s" % (via, v)) for txt, v in inner] or [(target, via)]
    return out


def _resolve_script(seg, cwd, repo, depth):
    """(script_text, package_dir, via) when SEG runs a package.json script, else None."""
    m = SCRIPT_CALL.match(seg)
    if not m or depth > 2:
        return None
    head = seg.split()[0]
    if head not in ("npm", "yarn", "pnpm", "bun"):
        return None
    name = m.group(1)
    if name in ("install", "ci", "i", "exec", "x", "dlx", "--version"):
        return None
    if head == "bun" and not re.match(r"^bun\s+run\s", seg) and re.search(r"\.[cm]?[jt]sx?$", name):
        return None  # `bun src/index.ts` runs a file, not a script
    d = cwd
    while True:
        pj = os.path.join(d, "package.json")
        if os.path.isfile(pj):
            try:
                scripts = (json.load(open(pj, encoding="utf-8")) or {}).get("scripts") or {}
            except (OSError, ValueError, AttributeError):
                return None
            target = scripts.get(name) if isinstance(scripts, dict) else None
            if not isinstance(target, str):
                return None
            return target, d, "%s script %r" % (walk.rel(repo, pj), name)
        if os.path.abspath(d) == os.path.abspath(repo) or not os.path.abspath(d).startswith(os.path.abspath(repo)):
            return None
        d = os.path.dirname(d)


def _dockerfile_cmd(path):
    """ENTRYPOINT plus CMD of a Dockerfile's last stage, as one command line ('' when none)."""
    text = re.sub(r"\\\n", " ", walk.read(path))
    parts = {}
    for m in re.finditer(r"^\s*(CMD|ENTRYPOINT)\s+(.+)$", text, re.M | re.I):
        val = m.group(2).strip()
        if val.startswith("["):
            try:
                val = " ".join(json.loads(val))
            except ValueError:
                pass
        parts[m.group(1).upper()] = val
    return " ".join(x for x in (parts.get("ENTRYPOINT"), parts.get("CMD")) if x)


def default_start(cfg_dir, builder, dockerfile):
    """(command, source label) a Railway builder runs when the config has no startCommand."""
    df = os.path.join(cfg_dir, dockerfile or "Dockerfile")
    if builder == "DOCKERFILE" or (not builder and os.path.isfile(df)):
        cmd = _dockerfile_cmd(df)
        if cmd:
            return cmd, "%s CMD" % os.path.basename(df)
    nix = walk.read(os.path.join(cfg_dir, "nixpacks.toml"))
    m = re.search(r"^\s*\[start\]\s*$[^\[]*?^\s*cmd\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", nix, re.M)
    if m:
        return m.group(1) if m.group(1) is not None else m.group(2), "nixpacks.toml [start] cmd"
    try:
        rp = json.loads(walk.read(os.path.join(cfg_dir, "railpack.json")) or "{}")
        rp_cmd = ((rp.get("deploy") or {}).get("startCommand") or "") if isinstance(rp, dict) else ""
    except ValueError:
        rp_cmd = ""
    if rp_cmd:
        return rp_cmd, "railpack.json deploy.startCommand"
    procs = re.findall(r"^\s*([\w-]+)\s*:\s*(.+)$", walk.read(os.path.join(cfg_dir, "Procfile")), re.M)
    for name, cmd in sorted(procs, key=lambda x: x[0] != "web"):
        return cmd.strip(), "Procfile %s" % name
    return "", None


def config_checks(repo, cfgs):
    res = []
    for cp in cfgs:
        rel = walk.rel(repo, cp)
        tag = "" if len(cfgs) == 1 else "." + re.sub(r"[^A-Za-z0-9]+", "_", os.path.dirname(rel) or "root")
        t = walk.read(cp)
        start, builder, dockerfile = "", "", ""
        if cp.endswith(".json"):
            try:
                d = json.loads(t)
                if not isinstance(d, dict):
                    raise ValueError("not an object")
                start = (d.get("deploy") or {}).get("startCommand", "") or ""
                builder = str((d.get("build") or {}).get("builder") or "").upper()
                dockerfile = (d.get("build") or {}).get("dockerfilePath") or ""
            except (ValueError, AttributeError):
                res.append(result("railway.config" + tag, "Railway config runs a production server", "UNKNOWN", rel, reason="unparseable JSON"))
                continue
        else:
            m = re.search(r"""startCommand\s*=\s*(?:"([^"]*)"|'([^']*)')""", t)
            start = (m.group(1) if m and m.group(1) is not None else (m.group(2) if m else "")) or ""
            b = re.search(r"""\bbuilder\s*=\s*["']([^"']*)["']""", t)
            builder = (b.group(1) if b else "").upper()
            df = re.search(r"""\bdockerfilePath\s*=\s*["']([^"']*)["']""", t)
            dockerfile = df.group(1) if df else ""
        source = "startCommand"
        cfg_dir = os.path.dirname(cp)
        if not start:
            start, source = default_start(cfg_dir, builder, dockerfile)
        dev, via = None, None
        for txt, v in expand(start, cfg_dir, repo):
            dev = DEV.search(txt)
            if dev:
                via = v
                break
        if start and dev:
            res.append(result("railway.config" + tag, "Railway config runs a production server", "FAIL",
                              "%s %s runs a dev server (%s)%s" % (rel, source, dev.group(0), " via %s" % via if via else ""), severity="low",
                              fix="start the built production server (node dist/..., next start, gunicorn), not a dev server; if the start command is `npm start`, the start script must not run one either (the start command, a Dockerfile CMD, nixpacks.toml [start] or a Procfile all count)"))
        else:
            vias = [v for _, v in expand(start, cfg_dir, repo) if v]
            res.append(result("railway.config" + tag, "Railway config runs a production server", "PASS",
                              "%s %s: no dev server%s" % (rel, "startCommand" if not source or source == "startCommand" else source, "" if start else " (builder default)") + (" (resolved via %s)" % vias[0] if vias else "")))
    return res


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    dumps = env_dumps(repo)
    if dumps:
        res.append(result("railway.env-dump", "The environment is never logged or returned whole", "FAIL", ledger.join_hits(dumps, 6, ", "), severity="high",
                          fix="log or return only the names you need (Object.keys(process.env) at most); rotate anything already in the logs"))
    else:
        res.append(result("railway.env-dump", "The environment is never logged or returned whole", "PASS", "production source: no whole-environment log, response or return"))
    cfgs = sorted(walk.files(repo, exts=("railway.json", "railway.toml")))
    for f in ("railway.json", "railway.toml"):
        p = os.path.join(repo, f)
        if os.path.isfile(p) and p not in cfgs:
            cfgs.append(p)
    res += config_checks(repo, cfgs)
    return ledger.emit(res, cannot_see=[
        "Railway variables: read count-only, `railway variables --kv | grep -c .` and names with `railway variables --kv | cut -d= -f1`; never plain `railway variables`",
        "Public networking (generated domain, TCP proxy) on or off: service Settings, Networking",
    ])


if __name__ == "__main__":
    sys.exit(main())

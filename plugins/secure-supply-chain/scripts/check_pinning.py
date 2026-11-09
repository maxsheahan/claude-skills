#!/usr/bin/env python3
"""check_pinning.py - CI and build tooling that can change under you.

  check_pinning.py REPO

  - actions.pinned: every `uses: owner/repo@ref` in .github/workflows (block
    steps, flow-style `- { uses: x@v1 }` steps, job-level reusable workflows,
    local composite actions) pinned to a full 40-character commit SHA.
    Third-party actions on a tag FAIL medium; GitHub's own (actions/*,
    github/*) FAIL low. YAML comments are blanked first: a commented-out step
    is not a step.
    A `uses:` inside a block scalar (a `run: |` heredoc) is text, not a step.
    A `docker://` action FAILs unless it names an image digest (@sha256:...).
  - actions.secret-scope: any reference to the secrets context (`${{ secrets.X }}`,
    `${{secrets.X}}`, `${{ secrets['X'] }}`, `${{ toJSON(secrets) }}`) in a
    workflow-level, job-level or job-container (`jobs.<id>.container.env`)
    `env:` FAILs medium: every step of the job, including third-party actions,
    can read it. So does `secrets: inherit` on a reusable-workflow call. The
    scoped pattern gives each secret only to its step.
  - tooling.wrangler: a deploy that runs wrangler through a one-off runner
    (`npx`, `npm exec`, `npm x`, `pnpm dlx`, `pnpx`, `bunx`, `bun x`,
    `yarn dlx`, with any flags, `--`, or `-p wrangler`) with no wrangler in
    package.json, a version that is not exact (`@latest`, `@beta`, `@4`,
    `@^4.0.0`), a registry-fetching runner (`pnpm dlx`, `pnpx`, `yarn dlx`)
    with no exact version, a `latest`/`*` range in package.json, or the
    wrangler action without an exact `wranglerVersion` in that step (whatever
    order its keys take, blank lines allowed) FAILs low (a new wrangler can
    change a deploy with no commit). Only emitted when wrangler is used.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

# `uses:` as a mapping key: at a line start (after an optional dash) or inside a flow mapping (`{ uses: x }`, `, uses: x`).
USES = re.compile(r"(?:^|[\s{,])uses:\s*['\"]?([^'\"\s#,}]+)", re.M)
SHA = re.compile(r"@[0-9a-f]{40}$")
# Any read of the secrets context inside an expression: member (`secrets.X`), index (`secrets['X']`),
# or the whole context (`toJSON(secrets)`), with or without spaces inside `${{ }}`.
SECRET_REF = re.compile(r"\$\{\{[^}]*(?<![\w.])secrets(?![\w])")
# wrangler run through a one-off package runner, which downloads whatever version is current. Any flags may
# sit between the runner and the package (`-y`, `--bun`, `--`), and npm's `-p/--package wrangler[@v]` names it
# before the command. Group 1: the runner; group 2: a version on -p; group 3: a version on the command.
RUNNER_WRANGLER = re.compile(
    r"(\bnpx|\bnpm\s+(?:exec|x)|\bpnpm\s+dlx|\bpnpx|\bbunx|\bbun\s+x|\byarn\s+dlx)"
    r"(?:\s+(?:-p|--package)(?:=|\s+)wrangler(?:@([^\s'\"]+))?(?=\s)|\s+--?[A-Za-z][\w-]*(?:=[^\s'\"]+)?|\s+--(?=\s))*"
    r"\s+wrangler(?![\w.\-])(?:@([^\s'\"]+))?")
# Runners that always fetch from the registry, never the project's installed copy.
FETCHING_RUNNER = re.compile(r"^(?:pnpm\s+dlx|pnpx|yarn\s+dlx)$")
EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$")
# A docker:// action is pinned only by an image digest.
DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def yaml_code(text):
    """The workflow with its comments blanked (same length, same line breaks): a `#` at a line start
    or after whitespace, outside quotes, opens a comment. A commented-out step or secret is not one."""
    out = []
    for line in text.split("\n"):
        q, res = None, []
        for i, ch in enumerate(line):
            if q:
                if ch == q:
                    q = None
                res.append(ch)
            elif ch in "'\"":
                q = ch
                res.append(ch)
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                res.append(" " * (len(line) - i))
                break
            else:
                res.append(ch)
        out.append("".join(res))
    return "\n".join(out)


def blank_block_scalars(text):
    """The workflow with the BODY of every block scalar (`run: |`, `script: >-`, any `key: |`) blanked, same
    length and line breaks: a `uses:` written inside a heredoc is text, not a step. Used for the uses: scan
    only; the wrangler scan reads run: bodies, which is where commands live."""
    lines = text.split("\n")
    out, body_ind = [], None
    for l in lines:
        ind = len(l) - len(l.lstrip())
        if body_ind is not None:
            if not l.strip() or ind > body_ind:
                out.append(" " * len(l))
                continue
            body_ind = None
        out.append(l)
        if re.search(r":\s*[|>][+\-0-9]*\s*$", l):
            body_ind = ind if not l.lstrip().startswith("- ") else ind + 2
    return "\n".join(out)


def step_block(lines, i):
    """The whole step that owns line i (a `uses:` line): from its `- ` dash line to the line before the
    next step or a shallower key, so `name:`/`uses:`/`with:` are read together in any order. A line with
    no dash at its key indent (a job-level `uses:`, a flow mapping) falls back to the line plus its block."""
    key_ind = len(lines[i]) - len(lines[i].lstrip())
    line = lines[i].lstrip()
    if line.startswith("- "):
        key_ind += 2
    dash_ind = key_ind - 2
    start = i
    while start > 0 and not re.match(r"^\s{%d}- " % dash_ind, lines[start]):
        ind = len(lines[start]) - len(lines[start].lstrip())
        if lines[start].strip() and ind < key_ind:
            break
        start -= 1  # a blank line inside the step does not end it
    if not re.match(r"^\s{%d}- " % dash_ind, lines[start]):
        return lines[i] + "\n" + block(lines, i)
    out = [lines[start]]
    for l in lines[start + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= dash_ind:
            break
        out.append(l)
    return "\n".join(out)


def workflows(repo):
    """Workflows plus local composite actions (.github/actions/*/action.yml), which run third-party actions too."""
    out = []
    d = os.path.join(repo, ".github", "workflows")
    if os.path.isdir(d):
        out += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith((".yml", ".yaml"))]
    ad = os.path.join(repo, ".github", "actions")
    for root, _, names in os.walk(ad):
        out += [os.path.join(root, n) for n in sorted(names) if n in ("action.yml", "action.yaml")]
    return out


def env_level(lines, i):
    """Who can read an `env:` at line i: 'workflow', 'job', 'job container' (jobs.<id>.container.env, read by
    every step that runs in the container) or 'step' (a step, or a service container, which gets only its own).
    Worked out from the chain of parent keys, nearest first."""
    ind = len(lines[i]) - len(lines[i].lstrip())
    if ind == 0:
        return "workflow"
    chain, cur = [], ind
    for j in range(i - 1, -1, -1):
        l = lines[j]
        if not l.strip():
            continue
        jind = len(l) - len(l.lstrip())
        if jind < cur:
            st = l.strip()
            if st.startswith("- "):
                return "step"
            chain.append(st.split(":", 1)[0].strip().strip("'\""))
            cur = jind
            if jind == 0:
                break
    chain.reverse()  # top-level key first
    if not chain or chain[0] != "jobs":
        return "step"  # a composite action's runs:, or nothing a whole job reads
    if len(chain) == 2:
        return "job"
    if len(chain) == 3 and chain[2] == "container":
        return "job container"
    return "step"


def block(lines, i):
    ind = len(lines[i]) - len(lines[i].lstrip())
    out = []
    for l in lines[i + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= ind:
            break
        out.append(l)
    return "\n".join(out)


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    wfs = workflows(repo)
    unpinned, broad = [], []
    for p in wfs:
        t = yaml_code(walk.read(p))
        r = walk.rel(repo, p)
        for m in USES.finditer(blank_block_scalars(t)):
            u = m.group(1)
            if u.startswith("docker://"):
                if not DOCKER_DIGEST.search(u):  # a tag (or none) is a mutable image
                    unpinned.append((False, "%s:%d %s" % (r, walk.line_of(t, m.start()), u)))
                continue
            if u.startswith("./") or "@" not in u:
                continue
            if not SHA.search(u):
                first = u.split("/")[0] in ("actions", "github")
                unpinned.append((first, "%s:%d %s" % (r, walk.line_of(t, m.start()), u)))
        lines = t.split("\n")
        for i, l in enumerate(lines):
            inline = re.match(r"^\s*env:\s*\{", l) and SECRET_REF.search(l)
            if inline or (re.match(r"^\s*env:\s*$", l) and SECRET_REF.search(block(lines, i))):
                lvl = env_level(lines, i)
                if lvl != "step":
                    broad.append("%s:%d (%s-level env)" % (r, i + 1, lvl))
            if re.match(r"^\s*secrets:\s*['\"]?inherit['\"]?\s*$", l):
                # a job calling a reusable workflow hands it EVERY secret of the repo
                broad.append("%s:%d (secrets: inherit hands every secret to the called workflow)" % (r, i + 1))
    if not wfs:
        res.append(result("actions.pinned", "GitHub Actions pinned to commit SHAs", "PASS", "no .github/workflows in the repo"))
    elif unpinned:
        third = [u for f, u in unpinned if not f]
        res.append(result("actions.pinned", "GitHub Actions pinned to commit SHAs", "FAIL", ledger.join_hits([u for _, u in unpinned], 8, "; "),
                          severity="medium" if third else "low",
                          fix="pin each to its full commit SHA with the tag in a comment (uses: owner/action@<sha> # v4.2.0)",
                          detail="%d unpinned (%d third-party)" % (len(unpinned), len(third))))
    else:
        res.append(result("actions.pinned", "GitHub Actions pinned to commit SHAs", "PASS", "%d workflow(s), every uses: on a 40-char SHA" % len(wfs)))
    if wfs:
        if broad:
            res.append(result("actions.secret-scope", "Secrets scoped to the step that uses them", "FAIL", ledger.join_hits(broad, 8, "; "), severity="medium",
                              fix="move each secrets.X from the workflow/job env: into the env: of the one step that needs it"))
        else:
            res.append(result("actions.secret-scope", "Secrets scoped to the step that uses them", "PASS", "%d workflow(s): no secrets in workflow- or job-level env" % len(wfs)))

    pkgs = {}
    for p in walk.all_package_jsons(repo):
        try:
            import json
            pkgs[walk.rel(repo, p)] = walk.deps(json.load(open(p)))
        except (OSError, ValueError):
            pass
    pinned_in_pkg = {k: v["wrangler"] for k, v in pkgs.items() if "wrangler" in v}
    problems, uses_wrangler = [], bool(pinned_in_pkg)
    locked = {}
    for k, v in pinned_in_pkg.items():
        lock = os.path.join(repo, os.path.dirname(k), "package-lock.json")
        try:
            import json as _j
            lv = ((_j.load(open(lock)).get("packages") or {}).get("node_modules/wrangler") or {}).get("version")
        except (OSError, ValueError):
            lv = None
        if not lv:  # pnpm and yarn lockfiles name the resolved version too
            base = os.path.join(repo, os.path.dirname(k))
            for lf, rx in (("pnpm-lock.yaml", r"(?m)^\s+wrangler:\s*\n\s+specifier:[^\n]*\n\s+version:\s*'?(\d+\.\d+\.\d+)|/wrangler@(\d+\.\d+\.\d+)|^\s{2}wrangler@(\d+\.\d+\.\d+)"),
                           ("yarn.lock", r'(?m)^"?wrangler@[^\n]*:\n\s+version "?(\d+\.\d+\.\d+)')):
                m = re.search(rx, walk.read(os.path.join(base, lf)))
                if m:
                    lv = next(g for g in m.groups() if g)
                    break
        if lv:
            locked[k] = lv
        elif v.strip() in ("latest", "*", "") or v.startswith(("http", "git")) or not re.match(r"^\d+\.\d+\.\d+$", v.strip()):
            problems.append("%s: wrangler %r with no package-lock.json pinning it" % (k, v))
    for p in wfs:
        t = yaml_code(walk.read(p))
        r = walk.rel(repo, p)
        for m in RUNNER_WRANGLER.finditer(t):
            uses_wrangler = True
            runner, ver = " ".join(m.group(1).split()), m.group(2) or m.group(3)
            where = "%s:%d %s" % (r, walk.line_of(t, m.start()), " ".join(m.group(0).split()))
            if ver:
                if not EXACT.match(ver.strip("'\"")):  # latest, a dist-tag, a major, a ^/~ range
                    problems.append("%s (wrangler@%s is not an exact version)" % (where, ver))
            elif FETCHING_RUNNER.match(runner):
                problems.append("%s (%s always downloads the current wrangler, whatever package.json pins)" % (where, runner))
            elif not pinned_in_pkg:
                problems.append("%s (no pinned version)" % where)
        for m in re.finditer(r"uses:\s*['\"]?cloudflare/wrangler-action@[^'\"\s,}]+", t):
            uses_wrangler = True
            step = step_block(t.split("\n"), walk.line_of(t, m.start()) - 1)
            vm = re.search(r"(?m)(?:^|[\s{,])wranglerVersion:\s*['\"]?([^'\"\s,}]*)", step)
            if not vm:
                problems.append("%s:%d wrangler-action without wranglerVersion" % (r, walk.line_of(t, m.start())))
            elif not EXACT.match(vm.group(1)):
                problems.append("%s:%d wrangler-action wranglerVersion %r is not an exact version" % (r, walk.line_of(t, m.start()), vm.group(1)))
    if uses_wrangler:
        if problems:
            res.append(result("tooling.wrangler", "Deploy tool pinned to an exact version", "FAIL", ledger.join_hits(problems, 6, "; "), severity="low",
                              fix="pin wrangler in package.json (installed by npm ci) or as npx wrangler@<exact version>"))
        else:
            res.append(result("tooling.wrangler", "Deploy tool pinned to an exact version", "PASS",
                              ("wrangler locked at %s" % ", ".join("%s (%s)" % (lv, k) for k, lv in locked.items())) if locked else
                              ("wrangler pinned exactly in %s" % ", ".join(pinned_in_pkg)) if pinned_in_pkg else "every npx wrangler call carries an exact version"))
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

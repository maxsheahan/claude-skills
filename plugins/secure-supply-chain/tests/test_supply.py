#!/usr/bin/env python3
"""secure-supply-chain tests. Known-bad first. Network-free: audits come from saved JSON."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "secure-core", "lib"))
import testkit as T  # noqa: E402

S = os.path.join(HERE, "..", "scripts")

# ---------- check_deps ----------
AUDIT_BAD = {"vulnerabilities": {
    "next": {"severity": "critical", "fixAvailable": {"name": "next", "version": "16.0.0", "isSemVerMajor": True},
             "via": [{"source": 1101, "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]},
    "@extractus/article-extractor": {"severity": "high", "fixAvailable": {"name": "@extractus/article-extractor", "version": "8.1.0", "isSemVerMajor": False},
             "via": [{"source": 1102, "url": "https://github.com/advisories/GHSA-dddd-eeee-ffff"}]},
    "nanoid": {"severity": "moderate", "fixAvailable": True, "via": [{"source": 1103, "url": "https://github.com/advisories/GHSA-gggg-hhhh-jjjj"}]},
}}
bad = T.tree({"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps(AUDIT_BAD), "web/package.json": "{}"})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), bad, "--audit-json", os.path.join(bad, "audit.json"))
T.status_is("deps bad", c, "deps.audit.root.next", "FAIL", out)
T.expect("deps: a major fix is named as a separate decision", "MAJOR" in c.get("deps.audit.root.next", {}).get("fix", ""))
T.status_is("deps bad", c, "deps.audit.root.@extractus/article-extractor", "FAIL", out)
T.status_is("deps bad", c, "deps.audit.root.moderate", "FAIL", out)
T.status_is("deps bad", c, "deps.lockfile.web", "FAIL", out)

good = T.tree({"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps(AUDIT_BAD),
               "security/advisory-triage.json": json.dumps({"advisories": [
                   {"package": "next", "advisory": "GHSA-aaaa-bbbb-cccc", "reachable": False, "reason": "static export: the Next server never runs", "reviewed": "2026-10-08"},
                   {"package": "@extractus/article-extractor", "advisory": "1102", "reachable": False, "reason": "parser path not imported", "reviewed": "2026-10-08"},
                   {"package": "nanoid", "advisory": "GHSA-gggg-hhhh-jjjj", "reachable": False, "reason": "build-only", "reviewed": "2026-10-08"}]})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), good, "--audit-json", os.path.join(good, "audit.json"))
T.expect("deps: everything triaged unreachable, with reasons shown, is all PASS", rc == 0 and all(v["status"] == "PASS" for v in c.values()) and "static export" in json.dumps(c), out[-400:])
reach = T.tree({"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps(AUDIT_BAD),
                "security/advisory-triage.json": json.dumps({"advisories": [{"package": "next", "advisory": "GHSA-aaaa-bbbb-cccc", "reachable": True, "reason": "SSR runs", "reviewed": "2026-10-08"}]})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), reach, "--audit-json", os.path.join(reach, "audit.json"))
T.expect("deps: triaged REACHABLE stays FAIL", c.get("deps.audit.root.next", {}).get("status") == "FAIL" and "REACHABLE" in c["deps.audit.root.next"].get("detail", ""))
err = T.tree({"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps({"error": {"summary": "getaddrinfo ENOTFOUND registry.npmjs.org"}})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), err, "--audit-json", os.path.join(err, "audit.json"))
T.status_is("deps offline", c, "deps.audit.root", "UNKNOWN", out)
T.expect("deps: offline audit exits 3, never 0", rc == 3)

# ---------- check_pinning ----------
WF_BAD = """name: deploy
on: push
env:
  CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/deploy-action@main
      - run: npx wrangler@latest pages deploy out
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
"""
bad = T.tree({".github/workflows/deploy.yml": WF_BAD, "package.json": "{}"})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), bad)
T.status_is("pinning bad", c, "actions.pinned", "FAIL", out)
T.expect("pinning: a third-party tag makes it medium", c.get("actions.pinned", {}).get("severity") == "medium")
T.status_is("pinning bad", c, "actions.secret-scope", "FAIL", out)
T.expect("pinning: both the workflow- and job-level env are named", "workflow-level" in c["actions.secret-scope"]["evidence"] and "job-level" in c["actions.secret-scope"]["evidence"])
T.status_is("pinning bad", c, "tooling.wrangler", "FAIL", out)
SHA1 = "a" * 40
WF_GOOD = """name: deploy
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@%s # v4.2.2
      - run: npm ci
      - name: deploy
        run: npx wrangler pages deploy out
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
""" % SHA1
good = T.tree({".github/workflows/deploy.yml": WF_GOOD, "package.json": json.dumps({"devDependencies": {"wrangler": "4.148.0"}})})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), good)
for cid in ("actions.pinned", "actions.secret-scope", "tooling.wrangler"):
    T.status_is("pinning good", c, cid, "PASS", out)

# ---------- load_built ----------
def pkgtree(entry_src):
    return T.tree({
        "node_modules/fakepkg/package.json": json.dumps({"name": "fakepkg", "exports": {".": "./index.js"}}),
        "node_modules/fakepkg/index.js": "export default 1\n",
        "node_modules/fakepkg/sub.js": "export default 2\n",
        "package.json": json.dumps({"type": "module"}),
        "dist/server.js": entry_src,
    })
bad = pkgtree("import x from 'fakepkg/sub';\nconsole.log(x)\n")
rc, c, out = T.run(os.path.join(S, "load_built.py"), bad)
T.status_is("built bad", c, "built.resolve", "FAIL", out)
T.expect("built: names the exports-map error", "ERR_PACKAGE_PATH_NOT_EXPORTED" in c.get("built.resolve", {}).get("evidence", ""))
good = pkgtree("import x from 'fakepkg';\nimport fs from 'node:fs';\nexport const y = x;\n")
rc, c, out = T.run(os.path.join(S, "load_built.py"), good, "--entry", "dist/server.js")
T.status_is("built good", c, "built.resolve", "PASS", out)
T.status_is("built good", c, "built.import.dist_server.js", "PASS", out)
broken_entry = pkgtree("import x from 'fakepkg';\nthrow new TypeError('boom at import');\n")
rc, c, out = T.run(os.path.join(S, "load_built.py"), broken_entry, "--entry", "dist/server.js")
T.status_is("built entry throws", c, "built.import.dist_server.js", "FAIL", out)
commented = pkgtree("/**\n * @example\n * import { Hono } from 'hono'\n * import { fire } from 'hono/service-worker'\n */\n// import x from 'missing-pkg'\nimport x from 'fakepkg';\nexport const y = x;\n")
rc, c, out = T.run(os.path.join(S, "load_built.py"), commented)
T.status_is("2026-10-15: imports inside comments are not imports", c, "built.resolve", "PASS", out)
none = T.tree({"package.json": "{}", "src/index.ts": "export {}"})
rc, c, out = T.run(os.path.join(S, "load_built.py"), none)
T.status_is("no build", c, "built.resolve", "UNKNOWN", out)
T.expect("built: no build output exits 3, never 0", rc == 3)

# ---------- pnpm audit report shape (a classroom app, Phase 4) ----------
PNPM = {"actions": [], "advisories": {"1": {"module_name": "undici", "severity": "high", "patched_versions": ">=6.21.1"},
                                      "2": {"module_name": "esbuild", "severity": "moderate", "patched_versions": ">=0.25.0"}},
        "metadata": {"vulnerabilities": {"high": 1, "moderate": 1}}}
pn = T.tree({"package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: 9\n", "audit.json": json.dumps(PNPM)})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), pn, "--audit-json", os.path.join(pn, "audit.json"))
T.status_is("pnpm format", c, "deps.audit.root.undici", "FAIL", out)
T.status_is("pnpm format", c, "deps.audit.root.moderate", "FAIL", out)
pn_clean = T.tree({"package.json": "{}", "pnpm-lock.yaml": "x\n", "audit.json": json.dumps({"actions": [], "advisories": {}, "metadata": {}})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), pn_clean, "--audit-json", os.path.join(pn_clean, "audit.json"))
T.status_is("pnpm clean", c, "deps.audit.root.moderate", "PASS", out)

# ---------- Phase 5 audit #13: a triage covers one advisory, never every future one in the package ----------
newer = json.loads(json.dumps(AUDIT_BAD))
newer["vulnerabilities"]["next"]["via"].append({"source": 1201, "url": "https://github.com/advisories/GHSA-zzzz-yyyy-xxxx"})
nr = T.tree({"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps(newer),
             "security/advisory-triage.json": json.dumps({"advisories": [
                 {"package": "next", "advisory": "GHSA-aaaa-bbbb-cccc", "reachable": False, "reason": "static export", "reviewed": "2026-10-08"}]})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), nr, "--audit-json", os.path.join(nr, "audit.json"))
T.status_is("audit #13: a new advisory in a triaged package", c, "deps.audit.root.next", "FAIL", out)
T.expect("audit #13: the untriaged advisory is named", "GHSA-zzzz-yyyy-xxxx" in c.get("deps.audit.root.next", {}).get("detail", ""))
pkg_only = T.tree({"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps(AUDIT_BAD),
                   "security/advisory-triage.json": json.dumps({"advisories": [{"package": "next", "reachable": False, "reason": "r", "reviewed": "2026-10-08"}]})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), pkg_only, "--audit-json", os.path.join(pkg_only, "audit.json"))
T.status_is("audit #13: a package-level triage with no advisory id covers nothing", c, "deps.audit.root.next", "FAIL", out)

# ---------- Phase 5 audit: composite actions and inline env maps ----------
comp = T.tree({".github/workflows/ci.yml": "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    env: { TOKEN: ${{ secrets.TOKEN }} }\n    steps:\n      - uses: ./.github/actions/setup\n",
               ".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: some-org/thing@v2\n"})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), comp)
T.status_is("audit: a composite action's unpinned uses is seen", c, "actions.pinned", "FAIL", out)
T.status_is("audit: an inline job-level env map with a secret is seen", c, "actions.secret-scope", "FAIL", out)

# ---------- second audit: a caret range with no lockfile is not pinned ----------
car = T.tree({".github/workflows/d.yml": "jobs:\n  d:\n    steps:\n      - run: npx wrangler deploy\n", "package.json": json.dumps({"devDependencies": {"wrangler": "^4.0.0"}})})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), car)
T.status_is("audit 2: wrangler ^4 with no lockfile", c, "tooling.wrangler", "FAIL", out)
lockd = T.tree({".github/workflows/d.yml": "jobs:\n  d:\n    steps:\n      - run: npx wrangler deploy\n", "package.json": json.dumps({"devDependencies": {"wrangler": "^4.0.0"}}),
                "package-lock.json": json.dumps({"packages": {"node_modules/wrangler": {"version": "4.148.0"}}})})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), lockd)
T.expect("a caret range locked by package-lock.json PASSes and names the locked version", c.get("tooling.wrangler", {}).get("status") == "PASS" and "4.148.0" in c["tooling.wrangler"]["evidence"], out[-200:])

# ---------- Phase 8 (bench known misses turned into fixes) ----------
# check_deps: a parent flagged only through a child inherits the child's triage (bench parent-of-triaged-transitive-decoy)
def child_report(triaged):
    rep = {"vulnerabilities": {
        "postcss": {"severity": "high", "fixAvailable": True, "via": [{"source": 2001, "url": "https://github.com/advisories/GHSA-p0st-cssl-1ne0"}]},
        "next": {"severity": "high", "fixAvailable": True, "via": ["postcss"]}}}
    files = {"package.json": "{}", "package-lock.json": "{}", "audit.json": json.dumps(rep)}
    if triaged is not None:
        files["security/advisory-triage.json"] = json.dumps({"advisories": [
            {"package": "postcss", "advisory": "GHSA-p0st-cssl-1ne0", "reachable": triaged, "reason": "build-time only, own CSS", "reviewed": "2026-10-30"}]})
    return T.tree(files)
par = child_report(False)
rc, c, out = T.run(os.path.join(S, "check_deps.py"), par, "--audit-json", os.path.join(par, "audit.json"))
T.status_is("phase 8: child triaged unreachable credits the parent", c, "deps.audit.root.next", "PASS", out)
T.expect("phase 8: the parent's PASS names the child it was flagged through", "through postcss" in c.get("deps.audit.root.next", {}).get("detail", ""))
par = child_report(None)
rc, c, out = T.run(os.path.join(S, "check_deps.py"), par, "--audit-json", os.path.join(par, "audit.json"))
T.status_is("phase 8: an untriaged child keeps the parent FAIL", c, "deps.audit.root.next", "FAIL", out)
T.expect("phase 8: the parent's FAIL names the child's advisory", "GHSA-p0st-cssl-1ne0 (via postcss)" in c.get("deps.audit.root.next", {}).get("detail", ""))
par = child_report(True)
rc, c, out = T.run(os.path.join(S, "check_deps.py"), par, "--audit-json", os.path.join(par, "audit.json"))
T.status_is("phase 8: a child triaged REACHABLE keeps the parent FAIL", c, "deps.audit.root.next", "FAIL", out)

# check_deps: yarn classic NDJSON (bench yarn-classic-ndjson)
YARN_LINES = [
    {"type": "auditAdvisory", "data": {"resolution": {"id": 4001, "path": "minimist", "dev": False},
                                       "advisory": {"id": 4001, "module_name": "minimist", "severity": "high", "url": "https://github.com/advisories/GHSA-m1n1-m1st-0001", "patched_versions": ">=1.2.6"}}},
    {"type": "auditAdvisory", "data": {"resolution": {"id": 4002, "path": "vitest>esbuild", "dev": True},
                                       "advisory": {"id": 4002, "module_name": "esbuild", "severity": "high", "url": "https://github.com/advisories/GHSA-esbu-1ld0-0002", "patched_versions": ">=0.25.0"}}},
    {"type": "auditSummary", "data": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 2, "critical": 0}, "dependencies": 14}},
]
yl = T.tree({"package.json": "{}", "yarn.lock": "# yarn lockfile v1\n", "audit.json": "\n".join(json.dumps(x) for x in YARN_LINES) + "\n"})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), yl, "--audit-json", os.path.join(yl, "audit.json"))
T.status_is("phase 8: yarn v1 NDJSON advisory surfaces", c, "deps.audit.root.minimist", "FAIL", out)
T.expect("phase 8: a dev-only yarn resolution is not a production advisory", "deps.audit.root.esbuild" not in c, str(sorted(c)))
yl_clean = T.tree({"package.json": "{}", "yarn.lock": "# yarn lockfile v1\n", "audit.json": json.dumps(YARN_LINES[2]) + "\n"})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), yl_clean, "--audit-json", os.path.join(yl_clean, "audit.json"))
T.status_is("phase 8: yarn NDJSON with only a summary is a clean audit", c, "deps.audit.root.moderate", "PASS", out)
yl_bad = T.tree({"package.json": "{}", "yarn.lock": "# yarn lockfile v1\n", "audit.json": "warning Skipping preferred cache folder\nerror An unexpected error occurred\n"})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), yl_bad, "--audit-json", os.path.join(yl_bad, "audit.json"))
T.status_is("phase 8: non-JSON audit output stays UNKNOWN", c, "deps.audit.root", "UNKNOWN", out)
yl_err = T.tree({"package.json": "{}", "yarn.lock": "# yarn lockfile v1\n", "audit.json": json.dumps({"type": "error", "data": "Received malformed response from registry"}) + "\n"})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), yl_err, "--audit-json", os.path.join(yl_err, "audit.json"))
T.status_is("phase 8: a yarn error line with no summary is UNKNOWN, never clean", c, "deps.audit.root", "UNKNOWN", out)

# check_deps: workspace members are locked by the root lockfile (bench workspace-member-decoy); a non-member is not
ws = T.tree({"package.json": json.dumps({"name": "mono", "private": True, "workspaces": ["apps/*"]}), "package-lock.json": "{}",
             "apps/web/package.json": json.dumps({"name": "web"}), "tools/seed/package.json": json.dumps({"name": "seed"}),
             "audit.json": json.dumps({"vulnerabilities": {}})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), ws, "--audit-json", os.path.join(ws, "audit.json"))
T.status_is("phase 8: npm workspace member locked by the root", c, "deps.lockfile.apps_web", "PASS", out)
T.expect("phase 8: the member's PASS names the root lockfile", "package-lock.json locks workspace member apps/web" in c.get("deps.lockfile.apps_web", {}).get("evidence", ""))
T.status_is("phase 8: a package folder outside the workspace globs still FAILs", c, "deps.lockfile.tools_seed", "FAIL", out)
T.expect("phase 8: the member's audit is the root's (no deps.audit.apps_web row)", "deps.audit.apps_web" not in c, str(sorted(c)))
pw = T.tree({"package.json": json.dumps({"name": "mono"}), "pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n  - '!packages/legacy'\n",
             "packages/ui/package.json": json.dumps({"name": "ui"}), "packages/ui/sub/package.json": json.dumps({"name": "ui-sub"}),
             "audit.json": json.dumps({"actions": [], "advisories": {}, "metadata": {}})})
rc, c, out = T.run(os.path.join(S, "check_deps.py"), pw, "--audit-json", os.path.join(pw, "audit.json"))
T.status_is("phase 8: pnpm-workspace.yaml member locked by the root", c, "deps.lockfile.packages_ui", "PASS", out)
T.status_is("phase 8: `*` stays inside one path segment: a nested folder is not a member", c, "deps.lockfile.packages_ui_sub", "FAIL", out)

# check_deps: a git-ignored lockfile is not committed (bench deps.lockfile.gitignored)
gi = T.git_init(T.tree({"package.json": "{}", "package-lock.json": "{}", ".gitignore": "package-lock.json\n", "audit.json": json.dumps({"vulnerabilities": {}})}))
rc, c, out = T.run(os.path.join(S, "check_deps.py"), gi, "--audit-json", os.path.join(gi, "audit.json"))
T.status_is("phase 8: a lockfile on disk but git-ignored FAILs", c, "deps.lockfile.root", "FAIL", out)
T.expect("phase 8: the FAIL says why", "git-ignored" in c.get("deps.lockfile.root", {}).get("evidence", ""))
gt = T.git_init(T.tree({"package.json": "{}", "package-lock.json": "{}", ".gitignore": "node_modules/\n", "audit.json": json.dumps({"vulnerabilities": {}})}))
rc, c, out = T.run(os.path.join(S, "check_deps.py"), gt, "--audit-json", os.path.join(gt, "audit.json"))
T.status_is("phase 8: a tracked lockfile PASSes", c, "deps.lockfile.root", "PASS", out)

# check_pinning: flow-style steps, commented-out steps, secret-context spellings, runners, name-first steps
flow = T.tree({".github/workflows/lint.yml": "on: [pull_request]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - { uses: actions/checkout@%s }\n      - { name: markdown lint, uses: some-org/markdownlint-action@v1 }\n      - { name: spell, uses: other-org/typos-action@master, with: { config: .typos.toml } }\n" % SHA1})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), flow)
T.status_is("phase 8: a flow-style `- { uses: x@v1 }` step on a tag FAILs", c, "actions.pinned", "FAIL", out)
T.expect("phase 8: both flow-style tags are named, the SHA one is not", "markdownlint-action@v1" in c["actions.pinned"]["evidence"] and "typos-action@master" in c["actions.pinned"]["evidence"] and "2 unpinned" in c["actions.pinned"]["detail"], out[-300:])
cmt = T.tree({".github/workflows/ci.yml": "on: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s # v4.2.2\n      # - uses: some-org/old-action@v2   (removed)\n      # - { uses: other-org/thing@v1 }\n      - run: echo ok\n" % SHA1})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), cmt)
T.status_is("phase 8: a commented-out step is not a step", c, "actions.pinned", "PASS", out)
for label, expr in (("no spaces", "${{secrets.NPM_TOKEN}}"), ("toJSON(secrets)", "${{ toJSON(secrets) }}"), ("index access", "${{ secrets['NPM_TOKEN'] }}")):
    sc = T.tree({".github/workflows/p.yml": "on: [push]\nenv:\n  TOKEN: %s\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n" % expr})
    rc, c, out = T.run(os.path.join(S, "check_pinning.py"), sc)
    T.status_is("phase 8: workflow env with %s FAILs" % label, c, "actions.secret-scope", "FAIL", out)
notsec = T.tree({".github/workflows/p.yml": "on: [push]\nenv:\n  URL: ${{ vars.SECRETS_URL }}\n  MODE: ${{ inputs.secrets }}\n  # TOKEN: ${{ secrets.NPM_TOKEN }}\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          TOKEN: ${{secrets.NPM_TOKEN}}\n"})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), notsec)
T.status_is("phase 8: vars.SECRETS_URL, inputs.secrets, a commented secret and a step-scoped one are not broad", c, "actions.secret-scope", "PASS", out)
for runner in ("pnpm dlx wrangler deploy", "bunx wrangler deploy", "bun x wrangler deploy", "yarn dlx wrangler deploy", "pnpx wrangler deploy", "bunx wrangler@latest deploy"):
    rn = T.tree({".github/workflows/d.yml": "on: [push]\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: %s\n" % runner, "package.json": json.dumps({"name": "edge"})})
    rc, c, out = T.run(os.path.join(S, "check_pinning.py"), rn)
    T.status_is("phase 8: `%s` with nothing pinned FAILs" % runner, c, "tooling.wrangler", "FAIL", out)
rn = T.tree({".github/workflows/d.yml": "on: [push]\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pnpm dlx wrangler@4.148.0 deploy\n", "package.json": json.dumps({"name": "edge"})})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), rn)
T.status_is("phase 8: `pnpm dlx wrangler@<exact>` PASSes", c, "tooling.wrangler", "PASS", out)
nf = T.tree({".github/workflows/d.yml": "on: [push]\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s\n      - name: Deploy worker\n        uses: cloudflare/wrangler-action@%s # v3.13.0\n        with:\n          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n          wranglerVersion: \"4.148.0\"\n" % (SHA1, SHA1)})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), nf)
T.status_is("phase 8: wrangler-action with `name:` first and wranglerVersion PASSes", c, "tooling.wrangler", "PASS", out)
nf_bad = T.tree({".github/workflows/d.yml": "on: [push]\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Deploy worker\n        uses: cloudflare/wrangler-action@%s # v3.13.0\n        with:\n          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n      - name: Next step\n        uses: actions/checkout@%s\n        with:\n          wranglerVersion: \"4.148.0\"\n" % (SHA1, SHA1)})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), nf_bad)
T.status_is("phase 8: wranglerVersion in the NEXT step does not count for the action step", c, "tooling.wrangler", "FAIL", out)
nf_flow = T.tree({".github/workflows/d.yml": "on: [push]\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - { name: deploy, uses: cloudflare/wrangler-action@%s, with: { wranglerVersion: '4.148.0' } }\n" % SHA1})
rc, c, out = T.run(os.path.join(S, "check_pinning.py"), nf_flow)
T.status_is("phase 8: a flow-style wrangler-action step with wranglerVersion PASSes", c, "tooling.wrangler", "PASS", out)

# load_built: minified server bundles are read, browser bundles are not; template literals are text
minsrv = T.tree({"package.json": json.dumps({"name": "svc"}), "dist/server.min.js": "\"use strict\";var e=require(\"fastify-lite\");e().listen({port:3000});\n"})
rc, c, out = T.run(os.path.join(S, "load_built.py"), minsrv)
T.status_is("phase 8: a minified server bundle requiring a missing package FAILs", c, "built.resolve", "FAIL", out)
minweb = T.tree({"package.json": json.dumps({"name": "site"}), "dist/widget.min.js": "!function(){var e=window.document,t=require(\"react\");e.body.append(t.createElement(\"div\"))}();\n",
                 "dist/server.js": "module.exports = { ok: true }\n"})
rc, c, out = T.run(os.path.join(S, "load_built.py"), minweb)
T.status_is("phase 8: a minified browser bundle (window.document, no Node API) is skipped", c, "built.resolve", "PASS", out)
tmpl = pkgtree("import x from 'fakepkg';\nexport function scaffold() {\n  const src = `\nimport { Hono } from 'hono'\nconst app = new Hono()\nexport default app\n`;\n  const alt = \"import y from 'left-pad'\";\n  return src + alt + x;\n}\n")
rc, c, out = T.run(os.path.join(S, "load_built.py"), tmpl)
T.status_is("phase 8: import lines inside a template literal or a string are text, not imports", c, "built.resolve", "PASS", out)
T.expect("phase 8: the real import was still counted", "1 imports" in c.get("built.resolve", {}).get("evidence", ""), c.get("built.resolve", {}).get("evidence", ""))
tmpl_bad = pkgtree("import x from 'fakepkg';\nconst src = `import { Hono } from 'hono'`;\nimport { z } from 'zod-missing';\nexport const y = [x, z, src];\n")
rc, c, out = T.run(os.path.join(S, "load_built.py"), tmpl_bad)
T.status_is("phase 8: a real missing import next to a template literal still FAILs", c, "built.resolve", "FAIL", out)
T.expect("phase 8: the FAIL names the real specifier, not the template text", "zod-missing" in c.get("built.resolve", {}).get("evidence", "") and "hono" not in c["built.resolve"]["evidence"], c.get("built.resolve", {}).get("evidence", ""))

# ---- Phase 10 supply-core-gate ----
# One FAIL and one PASS fixture per mechanism introduced in Phase 10 (the audit's fixtures become bench cases later).
def _deps(files, *args):
    r = T.tree(files)
    if "audit.json" in files:
        args = ("--audit-json", os.path.join(r, "audit.json")) + args
    return T.run(os.path.join(S, "check_deps.py"), r, *args)


_NPM_EMPTY = json.dumps({"vulnerabilities": {}})
# workspace globs: `!` exclusions, `./` prefixes, flow-style pnpm lists
rc, c, out = _deps({"package.json": json.dumps({"private": True, "workspaces": ["./apps/*", "!./apps/old"]}), "package-lock.json": "{}", "audit.json": _NPM_EMPTY,
                    "apps/site/package.json": "{}", "apps/old/package.json": json.dumps({"dependencies": {"left-pad": "1.3.0"}})})
T.status_is("phase 10: a folder excluded by `!./apps/old` is not a member, and has no lockfile", c, "deps.lockfile.apps_old", "FAIL", out)
T.status_is("phase 10: ...while `./apps/*` still makes apps/site a member", c, "deps.lockfile.apps_site", "PASS", out)
rc, c, out = _deps({"package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "pnpm-workspace.yaml": "packages: [\"services/*\"]  # flow style\n",
                    "services/api/package.json": "{}", "tools/x/package.json": "{}", "audit.json": _NPM_EMPTY})
T.status_is("phase 10: a flow-style pnpm-workspace.yaml list makes services/api a member", c, "deps.lockfile.services_api", "PASS", out)
T.status_is("phase 10: ...and a folder outside it still needs its own lockfile", c, "deps.lockfile.tools_x", "FAIL", out)
# yarn berry `yarn npm audit --json`
_berry = json.dumps({"value": "tar-lite", "children": {"ID": 4242, "Issue": "Path traversal", "URL": "https://github.com/advisories/GHSA-tttt-aaaa-rrrr", "Severity": "critical", "Vulnerable Versions": "<2"}})
rc, c, out = _deps({"package.json": "{}", "yarn.lock": "__metadata:\n  version: 8\n", "audit.json": _berry + "\n"})
T.status_is("phase 10: a yarn berry audit line with a critical advisory FAILs", c, "deps.audit.root.tar-lite", "FAIL", out)
rc, c, out = _deps({"package.json": "{}", "yarn.lock": "__metadata:\n  version: 8\n", "audit.json": _berry + "\n",
                    "security/advisory-triage.json": json.dumps({"advisories": [{"package": "tar-lite", "advisory": "GHSA-tttt-aaaa-rrrr", "reachable": False, "reason": "never extracts uploads", "reviewed": "2026-11-01"}]})})
T.status_is("phase 10: ...and PASSes once that advisory id is triaged unreachable", c, "deps.audit.root.tar-lite", "PASS", out)
# every package folder gets a lockfile check; only audits are capped
_many = {"package.json": "{}", "package-lock.json": "{}", "audit.json": _NPM_EMPTY}
for _i in range(13):
    _many["svc%02d/package.json" % _i] = "{}"
    _many["svc%02d/package-lock.json" % _i] = "{}"
_many["zz/package.json"] = "{}"
rc, c, out = _deps(_many)
T.status_is("phase 10: a 15th package folder with no lockfile is still checked", c, "deps.lockfile.zz", "FAIL", out)
T.status_is("phase 10: ...an audit past the cap is UNKNOWN, never dropped", c, "deps.audit.svc12", "UNKNOWN", out)
T.status_is("phase 10: ...and audits under the cap still run", c, "deps.audit.svc00.moderate", "PASS", out)


def _pin(wf, extra=None):
    files = {".github/workflows/w.yml": wf}
    files.update(extra or {})
    r = T.tree(files)
    return T.run(os.path.join(S, "check_pinning.py"), r)


_JOB = "on: [push]\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
# a `uses:` inside a block scalar is text
rc, c, out = _pin(_JOB + "    steps:\n      - uses: actions/checkout@%s\n      - run: >-\n          echo 'uses: acme/x@v2'\n          > out.yml\n" % SHA1)
T.status_is("phase 10: a `uses:` inside a folded run: block is text", c, "actions.pinned", "PASS", out)
rc, c, out = _pin(_JOB + "    steps:\n      - run: |\n          echo hi\n      - uses: acme/x@v2\n" % ())
T.status_is("phase 10: ...a real step right after a block scalar is still read", c, "actions.pinned", "FAIL", out)
# docker:// actions are pinned only by digest
rc, c, out = _pin(_JOB + "    steps:\n      - uses: docker://alpine:3.20\n")
T.status_is("phase 10: docker://image:tag is a mutable image", c, "actions.pinned", "FAIL", out)
rc, c, out = _pin(_JOB + "    steps:\n      - uses: docker://alpine@sha256:%s\n" % ("b" * 64))
T.status_is("phase 10: docker://image@sha256:<digest> is pinned", c, "actions.pinned", "PASS", out)
# job container env and secrets: inherit
rc, c, out = _pin(_JOB + "    container:\n      image: node:22\n      env:\n        TOKEN: ${{secrets.TOKEN}}\n    steps:\n      - run: make\n")
T.status_is("phase 10: a secret in jobs.<id>.container.env reaches every step", c, "actions.secret-scope", "FAIL", out)
rc, c, out = _pin(_JOB + "    services:\n      db:\n        image: postgres:16\n        env:\n          POSTGRES_PASSWORD: ${{ secrets.PG }}\n    steps:\n      - run: make\n")
T.status_is("phase 10: a secret in a service container's env reaches only that service", c, "actions.secret-scope", "PASS", out)
rc, c, out = _pin("on: [push]\njobs:\n  call:\n    uses: acme/wf/.github/workflows/x.yml@%s\n    secrets: inherit\n" % SHA1)
T.status_is("phase 10: `secrets: inherit` hands every secret to the called workflow", c, "actions.secret-scope", "FAIL", out)
rc, c, out = _pin("on: [push]\njobs:\n  call:\n    uses: acme/wf/.github/workflows/x.yml@%s\n    secrets:\n      token: ${{ secrets.ONE }}\n" % SHA1)
T.status_is("phase 10: ...passing one named secret to it is scoped", c, "actions.secret-scope", "PASS", out)
# runner versions must be exact; more runner spellings
for _cmd in ("npx --yes wrangler@~4.1.0 deploy", "npm exec --yes -- wrangler@next deploy", "npx --package=wrangler@4 wrangler deploy"):
    rc, c, out = _pin(_JOB + "    steps:\n      - run: %s\n" % _cmd)
    T.status_is("phase 10: `%s` is not an exact version" % _cmd, c, "tooling.wrangler", "FAIL", out)
rc, c, out = _pin(_JOB + "    steps:\n      - run: npm x --yes wrangler@4.148.0 deploy\n      - run: npx --package=wrangler@4.148.0 wrangler d1 list\n")
T.status_is("phase 10: npm x and npx --package= with an exact version PASS", c, "tooling.wrangler", "PASS", out)
rc, c, out = _pin(_JOB + "    steps:\n      - run: pnpm dlx wrangler deploy\n", {"package.json": json.dumps({"devDependencies": {"wrangler": "4.148.0"}})})
T.status_is("phase 10: pnpm dlx with no version downloads latest even when package.json pins wrangler", c, "tooling.wrangler", "FAIL", out)
rc, c, out = _pin(_JOB + "    steps:\n      - run: npx wrangler deploy\n", {"package.json": json.dumps({"devDependencies": {"wrangler": "4.148.0"}})})
T.status_is("phase 10: ...npx with no version uses the pinned local wrangler", c, "tooling.wrangler", "PASS", out)
# wranglerVersion value and blank lines in a step
rc, c, out = _pin(_JOB + "    steps:\n      - uses: cloudflare/wrangler-action@%s\n        with:\n          wranglerVersion: '4'\n" % SHA1)
T.status_is("phase 10: wranglerVersion '4' is a range", c, "tooling.wrangler", "FAIL", out)
rc, c, out = _pin(_JOB + "    steps:\n      - name: deploy\n\n        uses: cloudflare/wrangler-action@%s\n\n        with:\n          wranglerVersion: 4.148.0\n" % SHA1)
T.status_is("phase 10: blank lines inside the action step do not hide its exact wranglerVersion", c, "tooling.wrangler", "PASS", out)

# load_built: devDependency-only imports, template specifiers, NODE_ENV in browser bundles, server output dirs
def _built(files):
    return T.run(os.path.join(S, "load_built.py"), T.tree(files))


_lib = {"node_modules/pino-lite/package.json": json.dumps({"name": "pino-lite", "version": "1.0.0", "main": "index.js"}), "node_modules/pino-lite/index.js": "module.exports = {}\n"}
rc, c, out = _built(dict(_lib, **{"package.json": json.dumps({"name": "s", "devDependencies": {"pino-lite": "1.0.0"}}), "dist/main.js": "const p = require('pino-lite');\nmodule.exports = p;\n"}))
T.status_is("phase 10: a built require of a devDependency-only package FAILs (absent after --omit=dev)", c, "built.resolve", "FAIL", out)
rc, c, out = _built(dict(_lib, **{"package.json": json.dumps({"name": "s", "dependencies": {"pino-lite": "1.0.0"}, "devDependencies": {"pino-lite": "1.0.0"}}), "dist/main.js": "const p = require('pino-lite');\nmodule.exports = p;\n"}))
T.status_is("phase 10: ...a package that is also a production dependency PASSes", c, "built.resolve", "PASS", out)
rc, c, out = _built({"package.json": json.dumps({"name": "s"}), "dist/a.cjs": "module.exports = () => require(`gone-pkg`);\n"})
T.status_is("phase 10: require(`pkg`) with a template-literal specifier is resolved", c, "built.resolve", "FAIL", out)
rc, c, out = _built({"package.json": json.dumps({"name": "s"}), "dist/a.cjs": "module.exports = (n) => require(`./locales/${n}.js`);\n"})
T.status_is("phase 10: ...a template with a substitution is computed, not a bare import", c, "built.resolve", "PASS", out)
rc, c, out = _built({"package.json": json.dumps({"name": "s"}), "dist/x.min.js": "!function(){if(process.env.NODE_ENV!==\"production\")console.log(1);var d=document.body,r=require(\"preact\");d.append(r)}();\n", "dist/s.js": "module.exports = 1\n"})
T.status_is("phase 10: a minified browser bundle that branches on process.env.NODE_ENV is still a browser bundle", c, "built.resolve", "PASS", out)
rc, c, out = _built({"package.json": json.dumps({"name": "s"}), "dist/x.min.js": "var k=process.env.API_URL,d=typeof document;var r=require(\"gone-http\");module.exports=r;\n"})
T.status_is("phase 10: ...a minified bundle reading another process.env value is Node code and is read", c, "built.resolve", "FAIL", out)
rc, c, out = _built({"package.json": json.dumps({"name": "s"}), ".output/server/chunks/x.mjs": "export const a = 1\n", ".output/server/index.mjs": "import 'missing-h3';\n"})
T.status_is("phase 10: Nitro's .output/server is built output", c, "built.resolve", "FAIL", out)
rc, c, out = _built({"package.json": json.dumps({"name": "s"}), ".next/standalone/server.js": "const p = require('path');\nmodule.exports = p;\n"})
T.status_is("phase 10: ...and so is .next/standalone (a builtin-only server PASSes)", c, "built.resolve", "PASS", out)
# ---- end Phase 10 supply-core-gate ----

T.finish()

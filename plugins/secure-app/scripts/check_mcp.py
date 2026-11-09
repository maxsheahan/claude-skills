#!/usr/bin/env python3
"""check_mcp.py - authorization inside an MCP server's tools.

  check_mcp.py REPO

An MCP app usually has one HTTP route (/mcp) behind OAuth, so the route checks
(asvs-lite, auth-gate-check) see it gated and stop. The real authorization is
in the tools: each takes ids as arguments and answers from a database. These
checks read that layer. Built 2026-11-01 after a run on an MCP app found the
suite blind to it.

  mcp.none               no MCP tool registration found (PASS).
  mcp.tool-scope         every SQL read or write in the app's server code that
                         is keyed on an id carries a predicate on the signed-in
                         identity: `user_id = ?`, `owner_id = ?`, a membership
                         subquery, or a helper whose body builds one. A
                         statement keyed only on a caller-supplied id (`WHERE
                         id = ?`, `WHERE channel_id = ?`) FAILs high: any
                         signed-in caller can read or change another person's
                         rows by passing their id. An unscoped id lookup nested
                         inside a statement that IS scoped FAILs low (it leaks
                         the looked-up value, a timestamp or a count, not the
                         rows).
  mcp.identity-from-args a tool whose input schema takes the caller's identity
                         (user_id, viewer, owner_id, account_id, tenant_id)
                         FAILs high: identity comes from the verified token
                         (OAuth props, the session), never from what the model
                         or the caller typed.
  mcp.tool-descriptions  no tool description, parameter description or server
                         instructions carry hidden directions to the model
                         (OWASP MCP03, tool poisoning): an instruction tag
                         (<IMPORTANT>, an HTML comment, zero-width text),
                         concealment ("do not tell the user", "silently"), an
                         order to read secret files, an order to send data to a
                         URL, or steering another tool ("BCC ... on every
                         email", "ignore previous instructions"). FAIL high.
  mcp.privileged-tools   a tool that runs a sync, delete, purge or admin job,
                         or writes rows not keyed on the caller, has an owner,
                         admin or role check in its handler. Missing FAILs high.

Static reading: a PASS means each statement carries the predicate, not that
the predicate is right (prove the visibility logic with mutation-proven-tests:
remove the predicate and a test must go red). Statements with no id in their
WHERE (a list of every synced server) are not judged here.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import walk  # noqa: E402
import surface  # noqa: E402
from ledger import result  # noqa: E402

# server.registerTool('name', ...), server.tool('name', ...), and the MCP Apps helper registerAppTool(server, 'name', ...),
# which registers the card tool (an MCP app's main tool was invisible to a first draft that knew only the first two).
TOOL_JS = re.compile(r"(?:\b[\w$.]*\.(?:registerTool|tool)\s*\(|\bregister\w*Tool\s*\(\s*[\w$.]+\s*,)\s*['\"`]([\w.-]+)['\"`]")
TOOL_PY = re.compile(r"@[\w.]*tool\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)", re.S)
MCP_IMPORT = re.compile(r"""@modelcontextprotocol/sdk|['"]agents/mcp['"]|createMcpHandler|McpServer|McpAgent|\bfastmcp\b|from\s+mcp(?:\.server)?\s+import""")

# Any string or template literal that is a SQL statement, wherever it goes: prepare(), query(), or the app's own
# helper (an MCP app passed every read through `rows(db, \`SELECT ...\`)`, which a prepare()-only reading missed).
SQL_ANY = re.compile(r"""(`\s*(?:SELECT|UPDATE|DELETE|INSERT|WITH)\b(?:[^`\\]|\\.)*`|'\s*(?:SELECT|UPDATE|DELETE|INSERT|WITH)\b(?:[^'\\\n]|\\.)*'|"\s*(?:SELECT|UPDATE|DELETE|INSERT|WITH)\b(?:[^"\\\n]|\\.)*")""", re.S | re.I)
# A SQL statement as a string or template literal handed to prepare/query/execute/sql.
SQL_LIT = re.compile(r"""(?:\.(?:prepare|query|execute|run|all|get|first|raw|unsafe)|\bsql|\bexec)\s*\(\s*(`(?:[^`\\]|\\.)*`|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", re.S)
SQL_TAG = re.compile(r"""\bsql\s*(`(?:[^`\\]|\\.)*`)""", re.S)
STMT_KIND = re.compile(r"^\s*(SELECT|UPDATE|DELETE|INSERT|WITH)\b", re.I)
# The signed-in identity in a predicate: the column names, or a membership subquery on them.
IDENT_COL = r"(?:user_?id|owner_?id|viewer_?id|account_?id|member_?id|tenant_?id|author_?id|created_by|uid|org_?id)"
IDENT_PRED = re.compile(r"\b(?:\w+\.)?" + IDENT_COL + r"\s*(?:=|IN\b)", re.I)
# A caller-supplied id in a WHERE: id, <thing>_id, <thing>Id, excluding the identity columns themselves.
# A bare `id` counts: `WHERE id = ?` is the most common lookup there is (a first draft required a prefix and
# missed every primary-key lookup, 2026-11-01).
# `col IN (SELECT ...)` or `col IN (${subquery})` is matched against a subquery, which is judged on its own;
# only `IN (?, ?)` takes ids from the caller.
ID_PRED = re.compile(r"\b(?:\w+\.)?(id|\w+_id|\w+Id)\s*(?:=\s*(?:\?|\$\d+|:\w+|@\w+|\$\{)|IN\s*\(\s*(?:\?|\$\d+|:\w+))", re.I)
INTERP = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\(")
SUBSELECT = re.compile(r"\(\s*SELECT\b", re.I)

ARG_IDENTITY = re.compile(r"""(?:^|[\s{,(])['"]?(user_?id|userId|viewer(?:_?id|Id)?|owner_?id|ownerId|account_?id|accountId|tenant_?id|tenantId|as_user|actor_?id)['"]?\s*[:=]""")
PRIV_NAME = re.compile(r"\b(?:sync|purge|delete|remove|admin|wipe|reset|reindex|import|backfill|ban|grant|revoke)\w*\s*\(", re.I)
PRIV_TOOL = re.compile(r"(?:^|[_-])(?:sync|purge|delete|remove|admin|wipe|reset|reindex|import|backfill|ban|grant|revoke)(?:$|[_-])", re.I)
GATE = re.compile(r"\b(?:owner|isOwner|is_owner|isAdmin|is_admin|admin|role|roles|requireOwner|requireAdmin|require_admin|permission|permissions|can\w*)\b[^\n]{0,80}(?:\)|\bthen\b|\breturn\b|\bthrow\b|\braise\b|\?)|\b(?:403|Forbidden|PermissionError|Unauthorized)\b", re.I)
WRITE_SQL = re.compile(r"\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.I)


def _strip_sql(lit):
    body = lit[1:-1]
    return body


# `col IN (SELECT col FROM visible_channels WHERE user_id = ?)`: a scope on `col` through a per-person table.
# Only a membership-style table keyed by the signed-in person defines a grain; "rows I wrote" (author_id) is a
# filter, not a visibility grain (a first draft read it as one and called `id` the finest grain).
GRAIN_COL = r"(?:user_?id|viewer_?id|member_?id|account_?id|tenant_?id|org_?id)"
SCOPE_SUB = re.compile(r"\bIN\s*\(\s*SELECT\s+(?:\w+\.)?(\w+)\s+FROM\s+(\w+)\s+(?:\w+\s+)?WHERE[^()]*\b" + GRAIN_COL + r"\b", re.I | re.S)
CREATE_TABLE = re.compile(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?\s*\((.*?)\)\s*;", re.I | re.S)
ADD_COLUMN = re.compile(r"\bALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+ADD\s+(?:COLUMN\s+)?[`\"]?(\w+)", re.I)
FROM_TABLES = re.compile(r"\b(?:FROM|JOIN)\s+[`\"]?([A-Za-z_]\w*)[`\"]?", re.I)


def sql_schema(repo):
    """table -> set(columns), from every .sql file (migrations, schema dumps)."""
    tables = {}
    for p in walk.files(repo, exts=(".sql",), tests=False):
        t = re.sub(r"--[^\n]*", "", walk.read(p))  # SQL line comments are not columns
        for m in CREATE_TABLE.finditer(t):
            cols = set()
            for part in re.split(r",(?![^(]*\))", m.group(2)):
                w = part.strip().split()
                if w and w[0].upper() not in ("PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT"):
                    cols.add(w[0].strip('`"').lower())
            tables.setdefault(m.group(1).lower(), set()).update(cols)
        for m in ADD_COLUMN.finditer(t):
            tables.setdefault(m.group(1).lower(), set()).add(m.group(2).lower())
    return tables


def scope_grains(texts, tables):
    """Scope columns the app filters through a per-person table, finest first. A column is finer than another
    when its scope table also carries the other (visible_channels holds guild_id too, so channel_id is finer
    than a guild_id scoped through member_access)."""
    seen = {}
    for t in texts:
        for m in SCOPE_SUB.finditer(t):
            seen[m.group(1).lower()] = m.group(2).lower()
    def depth(col):
        return sum(1 for other in seen if other != col and other in tables.get(seen[col], set()))
    return sorted(seen, key=depth, reverse=True), seen


def scoped_on(sql, helper_bodies):
    """Scope columns a statement filters on, including through interpolated helpers and consts."""
    cols = {m.group(1).lower() for m in SCOPE_SUB.finditer(sql)}
    for name in re.findall(r"\$\{\s*([A-Za-z_$][\w$]*)", sql):
        body = helper_bodies.get(name, "")
        cols |= {m.group(1).lower() for m in SCOPE_SUB.finditer(body)}
        # a helper whose body builds `${column} IN (SELECT channel_id ...)` scopes the column it is handed
    return cols


def helper_bodies_of(text):
    out = {}
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^\n]{0,600})", text):
        out[m.group(1)] = m.group(2)
    for m in re.finditer(r"function\s+([A-Za-z_$][\w$]*)\s*\(", text):
        out[m.group(1)] = text[m.end(): m.end() + 800]
    return out


def scope_helpers(text):
    """Names of functions or consts in this file whose body builds an identity predicate, so a
    `${visible("m.channel_id")}` interpolation counts as one."""
    names = set()
    # a string const holding an identity predicate: `const mine = \`SELECT g.id ... a.user_id = ?1\``
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(`(?:[^`\\]|\\.)*`|'[^'\n]*'|\"[^\"\n]*\")", text):
        if IDENT_PRED.search(m.group(2)):
            names.add(m.group(1))
    for m in re.finditer(r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\()", text):
        name = m.group(1) or m.group(2)
        body = text[m.end(): m.end() + 800]
        stop = re.search(r"\n(?:export\s+)?(?:async\s+)?function\s|\n(?:export\s+)?const\s", body)
        if stop:
            body = body[: stop.start()]
        if IDENT_PRED.search(body):
            names.add(name)
    return names


def _split_subqueries(sql):
    """(outer text with each parenthesized SELECT replaced by a marker, [subquery texts])."""
    subs, out, i = [], [], 0
    while True:
        m = SUBSELECT.search(sql, i)
        if not m:
            out.append(sql[i:])
            break
        depth, j = 0, m.start()
        while j < len(sql):
            if sql[j] == "(":
                depth += 1
            elif sql[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        subs.append(sql[m.start() + 1: j])
        out.append(sql[i:m.start()] + " (SUB) ")
        i = j + 1
    return "".join(out), subs


def _scoped(sql, helpers):
    return bool(IDENT_PRED.search(sql) or any(n in helpers for n in INTERP.findall(sql)) or
                re.search(r"\$\{\s*(?:" + "|".join(map(re.escape, helpers or {"__none__"})) + r")\s*\}", sql))


def _keyed(sql):
    """Caller-supplied id predicates in the WHERE of this statement (identity columns excluded)."""
    where = re.split(r"\bWHERE\b", sql, maxsplit=1, flags=re.I)
    if len(where) < 2:
        return []
    out = []
    for m in ID_PRED.finditer(where[1]):
        col = m.group(1)
        if re.fullmatch(IDENT_COL, col, re.I):
            continue
        out.append(col)
    return out


def judge_statement(sql, helpers, derived=frozenset()):
    """None when fine, 'high' when the whole statement is keyed on a caller id with no identity
    predicate, 'low' when only a nested lookup is. `derived` holds columns this function already read
    through a scoped statement: an id taken from there is not caller-supplied (a context lookup
    reads the anchor message under the visibility filter, then its neighbors by that channel)."""
    outer, subs = _split_subqueries(sql)
    keyed = _keyed(outer)
    if keyed and not _scoped(sql, helpers) and not all(k.split(".")[-1].lower() in derived for k in keyed):
        return "high"
    if _scoped(outer, helpers) or not _keyed(outer):
        for s in subs:
            if _keyed(s) and not _scoped(s, helpers):
                return "low" if _scoped(outer, helpers) else "high"
    return None


# OAuth client registration (dynamic registration or client-ID metadata documents) and the host allowlist that tames it.
REG_ON = re.compile(r"clientRegistrationEndpoint\s*:|registration_endpoint\s*[:=]|\bregisterClient\s*\(|pathname\s*={2,3}\s*['\"]/(?:oauth/)?register['\"]|['\"]/(?:oauth/)?register['\"]\s*[,)]")
CIMD_ON = re.compile(r"clientIdMetadataDocumentEnabled\s*:\s*true|client_id_metadata_document_supported\s*[:=]\s*(?:true|True)")
# A real allowlist: a hostname compared against a set or list of allowed hosts, or a named allow-function. A bare
# `redirect_uri` near `new URL(...)` is not one (a first draft passed an app whose only such code was its own
# upstream sign-in redirect).
HOST_CMP = r"\.hostname\b[^\n;]{0,80}(?:\.has\(|\.includes\(|===|==|\bin\b)|(?:\.has|\.includes)\(\s*[\w.]*\.?hostname\b"
REDIRECT_GATE = re.compile(r"(?:allowed|allow|permit|trusted|valid)\w*Redirect\w*\s*\(|ALLOWED_REDIRECT|REDIRECT_(?:HOSTS|ALLOWLIST)|redirect_uris[\s\S]{0,1500}?(?:" + HOST_CMP + ")", re.I)
CLIENT_ID_GATE = re.compile(r"(?:allowed|allow|permit|trusted|valid)\w*Client\w*\s*\(|client_?id[\s\S]{0,600}?(?:" + HOST_CMP + ")", re.I)
# A tool hidden from the model: `_meta: { ui: { visibility: ["app"] } }`, inline or through a const.
APP_ONLY_INLINE = re.compile(r"visibility\s*:\s*\[\s*['\"]app['\"]", re.I)
STATE_CALL = re.compile(r"\b(?:dismiss|hide|archive|unarchive|pin|unpin|star|unstar|snooze|mute|mark\w*|delete\w*|remove\w*|purge\w*|setState|set[A-Z]\w*|update[A-Z]\w*|save[A-Z]\w*|insert[A-Z]\w*)\s*\(")


# Text the model reads as part of a tool's definition: descriptions (concatenated literals included), zod
# .describe(...) parameter text, server.tool(name, "description", ...), server instructions, and Python
# descriptions and tool docstrings. Cisco's key-free scanner caught 1 of 3 planted poisonings and flagged a
# real app's "every synced server" as exfiltration (trial 2026-11-01); these rules are scoped to directions.
_LIT = r"""(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`)"""
DESC_FIELD = re.compile(r"\b(?:description|instructions)\s*[:=]\s*(" + _LIT + r"(?:\s*\+\s*" + _LIT + r")*)")
DESCRIBE_CALL = re.compile(r"\.describe\(\s*(" + _LIT + r"(?:\s*\+\s*" + _LIT + r")*)")
TOOL_DESC_ARG = re.compile(r"\.tool\(\s*" + _LIT + r"\s*,\s*(" + _LIT + r"(?:\s*\+\s*" + _LIT + r")*)")
PY_DOCSTRING = re.compile(r"@[\w.]*tool\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\)[^:]*:\s*\n\s*((?:\x22){3}[\s\S]*?(?:\x22){3}|(?:\x27){3}[\s\S]*?(?:\x27){3})")
POISON = [
    ("an instruction tag", re.compile(r"<\s*/?\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|HIDDEN|SECRET|ADMIN|NOTE TO (?:AI|ASSISTANT|MODEL))\b|<!--|\[/?INST\]|[\u200b-\u200f\u2060\u2066-\u2069\ufeff]", re.I)),
    ("concealment from the user", re.compile(r"\b(?:do not|don't|never|without)\s+(?:tell|telling|mention|mentioning|inform|informing|reveal|revealing|notify|notifying|alert|alerting|show|showing)\s+(?:this\s+|it\s+)?(?:to\s+)?the\s+user|\b(?:silently|secretly|covertly)\b|\bthe user (?:must|should) not (?:know|see|be told)", re.I)),
    ("an order to read secrets", re.compile(r"~/\.ssh|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|/etc/(?:passwd|shadow)|\.netrc\b|\.npmrc\b|\b(?:read|open|cat|load|include|attach|pass)\b[^.]{0,60}(?:\.env\b|private key|keychain)|\b(?:api keys?|passwords?|tokens?|credentials|secrets)\s+(?:you have seen|in (?:the|this) (?:conversation|context|chat)|from (?:the )?(?:conversation|context|environment|memory))", re.I)),
    ("an order to send data out", re.compile(r"\b(?:send|forward|post|upload|transmit|exfiltrate|relay|copy)\b[^.]{0,160}\bhttps?://|\bhttps?://\S+[^.]{0,80}\b(?:with|including|containing)\b[^.]{0,40}\b(?:conversation|history|keys?|tokens?|contents|secrets|credentials)|\bvia the (?:fetch|http|web|curl|browser) tool\b[^.]{0,80}\b(?:silently|history|keys?|tokens?|conversation)", re.I)),
    ("steering another tool", re.compile(r"\b(?:BCC|CC)\s+\S+@\S+|\binstead of (?:following|doing what|what) the user\b|\b(?:when|if|whenever)\s+(?:another|a|any)\s+tool\s+(?:named|called)\b|\bignore (?:all\s+)?(?:previous|prior|above|earlier|the user'?s?|system) (?:instructions|prompts?|messages?)\b|\boverride\w*\s+(?:the\s+)?(?:user|system)\b", re.I)),
]


def _literal_text(run):
    """The text of a run of concatenated string literals, with \\uXXXX, \\u{...} and \\xXX escapes decoded: a hidden
    character usually sits in source as an escape, and undecoded it neither looks hidden nor leaves a word
    boundary before the next word."""
    raw = "".join(m.group(0)[1:-1] for m in re.finditer(_LIT, run))
    raw = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}", lambda m: chr(int(m.group(1), 16)), raw)
    raw = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), raw)
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), raw)


def described_texts(repo):
    """[(file:line, text)] for every piece of tool-definition text a model reads."""
    out = []
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)  # comments blanked, strings kept
        if not (TOOL_JS.search(t) or TOOL_PY.search(t) or MCP_IMPORT.search(t)):
            continue
        r = walk.rel(repo, p)
        for rx in (DESC_FIELD, DESCRIBE_CALL, TOOL_DESC_ARG):
            for m in rx.finditer(t):
                out.append(("%s:%d" % (r, walk.line_of(t, m.start())), _literal_text(m.group(1))))
        if p.endswith(".py"):
            raw = walk.read(p)
            for m in PY_DOCSTRING.finditer(raw):
                out.append(("%s:%d" % (r, walk.line_of(raw, m.start())), m.group(1)[3:-3]))
    return out


def _app_only(schema, file_text):
    """True when the tool's config hides it from the model (inline, or through a const that does)."""
    if APP_ONLY_INLINE.search(schema):
        return True
    for name in re.findall(r"_meta\s*:\s*([A-Za-z_$][\w$]*)", schema):
        m = re.search(r"(?:const|let|var)\s+%s\s*=\s*([^\n;]{0,300})" % re.escape(name), file_text)
        if m and APP_ONLY_INLINE.search(m.group(1)):
            return True
    return False


def _privileged(name, handler):
    """A tool that runs a sync, delete, purge or admin job, or writes rows not keyed on the caller."""
    h = walk.strip_comments(handler, "x.ts", strings=False)
    writes = [w for w in WRITE_SQL.finditer(handler) if not IDENT_PRED.search(handler[w.start(): w.start() + 300])]
    return bool(PRIV_TOOL.search(name) or PRIV_NAME.search(h) or writes)


FUNC_DEF = re.compile(r"(?:^|\n)[ \t]*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|(?:^|\n)[ \t]*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^=]{0,80})?=>|(?:^|\n)[ \t]*(?:async\s+)?def\s+(\w+)\s*\(")


def _after_params(text, open_paren):
    """Index just past the `)` that closes the parameter list opening at `open_paren`."""
    depth = 0
    for i in range(open_paren, min(len(text), open_paren + 4000)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return open_paren + 1


def function_index(repo):
    """name -> [(file, body)] for every function defined in served code."""
    idx = {}
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)
        r = walk.rel(repo, p)
        for m in FUNC_DEF.finditer(t):
            name = m.group(1) or m.group(2) or m.group(3)
            if m.group(3):
                rest = t[m.end(): m.end() + 6000]
                stop = re.search(r"\n(?=\S)", rest)
                body = rest[: stop.start()] if stop else rest
            else:
                # The body opens after the parameter list closes: a typed parameter carries braces of its own
                # (`o: Scope & { now: number }`), which a first draft read as the body and so never saw the
                # function's SQL (2026-11-01: 11 of about 50 statements read on an MCP app).
                start = _after_params(t, m.end() - 1) if t[m.end() - 1: m.end()] == "(" else m.end()
                arrow = re.match(r"\s*(?::[^=]{0,80})?=>\s*", t[start:]) if m.group(2) else None
                if m.group(2) and t[m.end() - 2: m.end()] == "=>":
                    arrow = re.match(r"\s*", t[m.end():]); start = m.end()
                if arrow and not t[start + arrow.end(): start + arrow.end() + 1] == "{":
                    # an arrow with no braces: its body is the expression (`const now = () => Date.now()`), never the
                    # next block in the file (which once handed a log writer's body to a clock helper)
                    rest = t[start + arrow.end(): start + arrow.end() + 600]
                    body = re.split(r";|\n(?=\S)", rest, maxsplit=1)[0]
                else:
                    body = walk.block(t, start)
            idx.setdefault(name, []).append((r, body))
    return idx


CALL = re.compile(r"(?:\b([A-Za-z_$][\w$]*)\.)?\b([A-Za-z_$][\w$]*)\s*\(")
NS_IMPORT = re.compile(r"""import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"](\.{1,2}/[^'"]+)['"]""")


class Resolver:
    """Resolves a called name the way the code does: a namespace import (q.faq -> the file `q` names), the same
    file, a named import, and only then a name that is unique in the repo. A first draft took any function of
    that name anywhere, and a server's `now()` helper picked up an unrelated function that writes a log."""

    def __init__(self, repo, index):
        self.repo, self.index, self.cache = repo, index, {}

    def _imports(self, rel):
        if rel not in self.cache:
            text = walk.read_code(os.path.join(self.repo, rel))
            ns = {m.group(1): surface.resolve_import(self.repo, rel, m.group(2)) for m in NS_IMPORT.finditer(text)}
            self.cache[rel] = (ns, surface.import_names(self.repo, rel, text))
        return self.cache[rel]

    def calls(self, rel, body):
        """[(file, function body)] for every call in body that resolves."""
        out = []
        ns, named = self._imports(rel)
        for m in CALL.finditer(body):
            prefix, name = m.group(1), m.group(2)
            defs = self.index.get(name, [])
            if not defs:
                continue
            if prefix:
                target = ns.get(prefix)
                pick = [d for d in defs if target and d[0] == target]
            else:
                same = [d for d in defs if d[0] == rel]
                imp = named.get(name)
                pick = same or [d for d in defs if imp and d[0] == imp[0]] or (defs if len(defs) == 1 else [])
            out += pick
        return out


def tools(repo):
    """[(file, line, name, handler_text, schema_text)] for every tool registered in served code."""
    out = []
    for p in walk.files(repo, tests=False, served=True):
        t = walk.read_code(p)
        r = walk.rel(repo, p)
        for m in TOOL_JS.finditer(t):
            span = t[m.end(): m.end() + 12000]
            h = re.search(r"(?:async\s*)?(?:function\s*)?\(\s*[^()]*\)\s*(?::[^=]{0,80})?=>\s*\{|async\s+function\s*\([^)]*\)\s*\{", span)
            schema = span[: h.start()] if h else span[:2000]
            handler = walk.block(span, h.end() - 1) if h else ""
            out.append((r, walk.line_of(t, m.start()), m.group(1), handler, schema))
        if p.endswith(".py"):
            for m in TOOL_PY.finditer(t):
                body = t[m.end(): m.end() + 6000]
                stop = re.search(r"\n(?=\S)", body)
                out.append((r, walk.line_of(t, m.start()), m.group(1), body[: stop.start()] if stop else body, m.group(2)))
    return out


def main():
    repo = os.path.abspath(sys.argv[1])
    ts = tools(repo)
    has_mcp = any(MCP_IMPORT.search(walk.read_code(p)) for p in walk.files(repo, tests=False, served=True))
    if not ts:
        why = "an MCP server import was found but no tool registration was recognized; list the tools by hand" if has_mcp else ""
        if has_mcp:
            return ledger.emit([result("mcp.tool-scope", "MCP tool reads are scoped to the signed-in identity", "UNKNOWN", "0 tools recognized", reason=why)])
        return ledger.emit([result("mcp.none", "MCP tools in the code", "PASS", "no MCP tool registration in served code")])

    res = []
    gated = {n for f, ln, n, h, schema in ts if _privileged(n, h) and GATE.search(walk.strip_comments(h, "x.ts", strings=False))}
    # tool-scope: SQL a caller can reach. Start from every handler of a tool that is not owner-gated and follow
    # the functions it calls, two hops, across served files; an owner-only sync job is judged by
    # mcp.privileged-tools instead.
    index = function_index(repo)
    reach, seen = [], set()
    frontier = [(f, h) for f, ln, n, h, schema in ts if n not in gated]
    resolver = Resolver(repo, index)
    for hop in range(3):
        nxt = []
        for f, body in frontier:
            reach.append((f, body))
            for rel, fbody in resolver.calls(f, body):
                key = (rel, hash(fbody))
                if key not in seen:
                    seen.add(key)
                    nxt.append((rel, fbody))
        frontier = nxt
    tables = sql_schema(repo)
    all_text = [walk.read_code(p) for p in walk.files(repo, tests=False, served=True)]
    grains, grain_table = scope_grains(all_text, tables)
    high, low, coarse, n_stmt, done = [], [], [], 0, set()
    for rel, body in reach:
        code = walk.read_code(os.path.join(repo, rel))
        helpers = scope_helpers(code)
        hbodies = helper_bodies_of(code)
        derived = set()
        for rx in (SQL_ANY,):
            for m in rx.finditer(body):
                sql = _strip_sql(m.group(1))
                if not STMT_KIND.match(sql):
                    continue
                pos = code.find(m.group(1))
                at = "%s:%d" % (rel, walk.line_of(code, pos) if pos >= 0 else 0)
                if at in done:
                    continue
                done.add(at)
                n_stmt += 1
                verdict = judge_statement(sql, helpers, frozenset(derived))
                if _scoped(_split_subqueries(sql)[0], helpers):
                    sel = re.match(r"\s*SELECT\s+(.*?)\s+FROM\b", sql, re.I | re.S)
                    if sel:
                        derived |= {c.strip().split(".")[-1].split()[-1].lower() for c in sel.group(1).split(",")}
                if verdict == "high":
                    high.append(at)
                elif verdict == "low":
                    low.append(at)
                # scope grain: a statement that is scoped, over a table carrying a finer scope column than the one
                # it filters on (sync notes per channel, filtered only by server membership: issue #2 of a real review)
                outer = _split_subqueries(sql)[0]
                if not verdict and re.match(r"\s*(?:SELECT|WITH)\b", sql, re.I) and _scoped(sql, helpers):
                    read = {t.lower() for t in FROM_TABLES.findall(outer)} - set(grain_table.values())
                    cols = set().union(*(tables.get(t, set()) for t in read)) if read else set()
                    on = scoped_on(sql, hbodies)
                    direct = any(re.search(r"\b(?:\w+\.)?" + IDENT_COL + r"\s*=", outer, re.I) and t for t in read)
                    finest = next((g for g in grains if g in cols), None)
                    # fire only when every grain it filters on is COARSER than the finest its tables carry; a channel
                    # filter over a table that also carries guild_id is finer, not coarser
                    rank = {g: i for i, g in enumerate(grains)}
                    coarser = finest and on and min(rank.get(g, len(grains)) for g in on) > rank[finest]
                    if coarser and not direct:
                        coarse.append("%s (scoped on %s; rows carry %s, which the app scopes elsewhere)" % (at, "/".join(sorted(on)), finest))
    where = "%d tool(s), %d SQL statement(s) read" % (len(ts), n_stmt)
    if high:
        res.append(result("mcp.tool-scope", "MCP tool reads are scoped to the signed-in identity", "FAIL", ledger.join_hits(sorted(set(high)), 8, ", "), severity="high",
                          fix="add the signed-in identity to the WHERE (user_id = ? bound from the token, or a membership subquery); an id the caller passed is never enough",
                          detail="statement keyed on a caller-supplied id with no identity predicate" + ("; also nested lookups at " + ledger.join_hits(sorted(set(low)), 4, ", ") if low else "")))
    elif low:
        res.append(result("mcp.tool-scope", "MCP tool reads are scoped to the signed-in identity", "FAIL", ledger.join_hits(sorted(set(low)), 8, ", "), severity="low",
                          fix="scope the nested lookup too (add the identity predicate inside the subquery); it leaks the looked-up value for an id the caller cannot see",
                          detail="the outer statement is scoped; a subquery keyed on a caller id is not"))
    else:
        res.append(result("mcp.tool-scope", "MCP tool reads are scoped to the signed-in identity", "PASS", where + "; every id-keyed statement carries an identity predicate"))

    if coarse:
        res.append(result("mcp.scope-grain", "Reads are scoped at the finest grain the app knows", "FAIL", ledger.join_hits(sorted(set(coarse)), 6, "; "), severity="medium",
                          fix="filter on the finer column too (for example channel visibility, not only server membership); rows the person cannot see at that grain still carry names and ids"))
    else:
        res.append(result("mcp.scope-grain", "Reads are scoped at the finest grain the app knows", "PASS",
                          "scope columns found: %s; every scoped read filters at the finest one its tables carry" % (", ".join(grains) or "none")))
    ident = ["%s:%d %s" % (f, ln, n) for f, ln, n, h, schema in ts if ARG_IDENTITY.search(walk.strip_comments(schema, "x.ts", strings=False) if not f.endswith(".py") else schema)]
    if ident:
        res.append(result("mcp.identity-from-args", "Identity comes from the token, never from tool arguments", "FAIL", ledger.join_hits(ident, 6, "; "), severity="high",
                          fix="drop the identity argument; read the caller from the verified token (OAuth props, session) inside the handler"))
    else:
        res.append(result("mcp.identity-from-args", "Identity comes from the token, never from tool arguments", "PASS", "%d tool input schema(s) read; none takes the caller's identity" % len(ts)))

    priv_bad, priv_seen = [], []
    for f, ln, n, h, schema in ts:
        if _privileged(n, h):
            priv_seen.append("%s:%d %s" % (f, ln, n))
            if not GATE.search(walk.strip_comments(h, "x.ts", strings=False)):
                priv_bad.append("%s:%d %s" % (f, ln, n))
    if priv_bad:
        res.append(result("mcp.privileged-tools", "Tools that sync, delete or administer check an owner or role", "FAIL", ledger.join_hits(priv_bad, 6, "; "), severity="high",
                          fix="check the caller is an owner or holds the role before the work starts; answer with a plain refusal otherwise"))
    else:
        res.append(result("mcp.privileged-tools", "Tools that sync, delete or administer check an owner or role", "PASS",
                          (ledger.join_hits(priv_seen, 4, "; ") + ": each checks an owner or role") if priv_seen else "no privileged tool among %d" % len(ts)))
    # model-writes: a tool the model can call that changes stored state (OWASP MCP06, intent flow subversion): a
    # prompt-injected model can bury a person's items or reset their markers. Owner-gated tools are judged above.
    writes, side = [], []
    for f, ln, n, h, schema in ts:
        if n in gated or _app_only(schema, walk.read_code(os.path.join(repo, f))):
            continue
        hc = walk.strip_comments(h, "x.ts", strings=False)
        args = set(re.findall(r"\b([A-Za-z_]\w*)\s*:\s*z\.", schema)) | set(re.findall(r"\b([A-Za-z_]\w*)\s*:\s*\{\s*type\s*:", schema))
        # the handler and the functions it calls directly (one hop); deeper writes are the app's own bookkeeping
        one_hop = [b for _, b in resolver.calls(f, hc)]
        hit = None
        for m in STATE_CALL.finditer(hc):
            call_args = hc[m.end(): m.end() + 200].split(")")[0]
            arg_driven = any(re.search(r"(?<![\w$])(?:\w+\.)?%s\b" % re.escape(a), call_args) for a in args)
            hit = (m.group(0).rstrip("( "), arg_driven)
            if arg_driven:
                break
        if not hit:
            for b in one_hop:
                if WRITE_SQL.search(b):
                    hit = ("SQL write in a called function", False)
                    break
        if hit:
            (writes if hit[1] else side).append("%s:%d %s (%s)" % (f, ln, n, hit[0]))
    if writes:
        res.append(result("mcp.model-writes", "Tools the model can call do not change stored state", "FAIL", ledger.join_hits(writes + side, 6, "; "), severity="medium",
                          fix="move the write into its own tool hidden from the model (_meta: { ui: { visibility: ['app'] } }) and call it from the card; a steered model can then read but not change",
                          detail="an argument the model chooses drives a write" + ("; side-effect writes too: " + ledger.join_hits(side, 3, "; ") if side else "")))
    elif side:
        res.append(result("mcp.model-writes", "Tools the model can call do not change stored state", "FAIL", ledger.join_hits(side, 6, "; "), severity="low",
                          fix="make the write a separate, card-only step (or accept it): calling the tool changes this person's stored state, so a steered model can trigger it",
                          detail="the write is a side effect of calling the tool, not driven by an argument"))
    else:
        res.append(result("mcp.model-writes", "Tools the model can call do not change stored state", "PASS", "%d model-visible tool(s) read; none writes stored state" % sum(1 for t in ts if t[2] not in gated)))

    # tool-descriptions: hidden directions in what the model reads about each tool (OWASP MCP03)
    poisoned = []
    texts = described_texts(repo)
    for at, text in texts:
        kinds = [label for label, rx in POISON if rx.search(text)]
        if kinds:
            poisoned.append("%s (%s)" % (at, ", ".join(kinds)))
    if poisoned:
        res.append(result("mcp.tool-descriptions", "Tool descriptions carry no hidden directions", "FAIL", ledger.join_hits(poisoned, 6, "; "), severity="high",
                          fix="describe what the tool does and nothing else: no instruction tags, nothing kept from the user, no file reads, no sending data out, no rules for other tools"))
    else:
        res.append(result("mcp.tool-descriptions", "Tool descriptions carry no hidden directions", "PASS", "%d description text(s) read; none carries a hidden direction" % len(texts)))

    # oauth-registration: who may become an OAuth client (OWASP MCP07)
    served = [walk.read_code(p) for p in walk.files(repo, tests=False, served=True)]
    blob = "\n".join(served)
    reg, cimd = bool(REG_ON.search(blob)), bool(CIMD_ON.search(blob))
    open_bits = []
    if reg and not REDIRECT_GATE.search(blob):
        open_bits.append("dynamic client registration with no redirect-host allowlist")
    if cimd and not CLIENT_ID_GATE.search(blob):
        open_bits.append("client-ID metadata documents accepted from any host")
    if open_bits:
        res.append(result("mcp.oauth-registration", "Only known clients can register for OAuth codes", "FAIL", "; ".join(open_bits), severity="medium",
                          fix="before the OAuth library sees the request, refuse /register unless every redirect_uri is on an allowed host (the host you serve, loopback), and refuse client-ID metadata URLs outside the same list"))
    elif reg or cimd:
        res.append(result("mcp.oauth-registration", "Only known clients can register for OAuth codes", "PASS",
                          "registration%s present with a host allowlist in code" % (" and client-ID metadata" if cimd else "")))
    else:
        res.append(result("mcp.oauth-registration", "Only known clients can register for OAuth codes", "PASS", "no OAuth client registration in served code"))
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

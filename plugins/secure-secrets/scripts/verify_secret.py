#!/usr/bin/env python3
"""verify_secret.py - prove a rotated key works with ONE read-only call, and
print only the HTTP status.

  verify_secret.py PROVIDER --file .dev.vars --name NAME [--base-url URL]

The value is read from FILE in-process and sent in the provider's auth header.
Nothing but the provider, the endpoint path and the status code is printed.
Each endpoint is a read that costs nothing (no generation, no charge).
--base-url is for tests (a local server); it must be http://127.0.0.1 or the
provider's own host.

Exit: 0 the key works (2xx), 1 refused (401/403), 3 could not tell (network,
other status, missing value). 3 is never a pass.
"""
import argparse
import re
import sys
import urllib.error
import urllib.request

PROVIDERS = {  # name: (default base, path, header builder)
    "anthropic": ("https://api.anthropic.com", "/v1/models", lambda v: {"x-api-key": v, "anthropic-version": "2023-06-01"}),
    "deepgram": ("https://api.deepgram.com", "/v1/projects", lambda v: {"Authorization": "Token " + v}),
    "elevenlabs": ("https://api.elevenlabs.io", "/v1/models", lambda v: {"xi-api-key": v}),
    "stripe": ("https://api.stripe.com", "/v1/balance", lambda v: {"Authorization": "Bearer " + v}),
    "github": ("https://api.github.com", "/user", lambda v: {"Authorization": "Bearer " + v, "User-Agent": "verify-secret"}),
    "cloudflare": ("https://api.cloudflare.com", "/client/v4/user/tokens/verify", lambda v: {"Authorization": "Bearer " + v}),
    "openai": ("https://api.openai.com", "/v1/models", lambda v: {"Authorization": "Bearer " + v}),
}


def read_value(path, name):
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^\s*(?:export\s+)?%s\s*=(.*)$" % re.escape(name), line.rstrip("\n"))
        if m:
            v = m.group(1).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            return v
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("provider", choices=sorted(PROVIDERS))
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--base-url")
    a = ap.parse_args()
    base, path, headers = PROVIDERS[a.provider]
    if a.base_url:
        if not (a.base_url.startswith("http://127.0.0.1:") or a.base_url == base):
            print("refused: --base-url must be a 127.0.0.1 test server or %s" % base)
            return 2
        base = a.base_url
    try:
        v = read_value(a.file, a.name)
    except OSError as exc:
        print("could not read %s: %s" % (a.file, exc.strerror))
        return 3
    if not v:
        print("%s not set in %s" % (a.name, a.file))
        return 3
    req = urllib.request.Request(base + path, headers=headers(v), method="GET")
    try:
        # base is the provider's fixed https host or a http://127.0.0.1 test server (checked above).
        code = urllib.request.urlopen(req, timeout=20).status  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    except urllib.error.HTTPError as e:
        code = e.code
    except (urllib.error.URLError, OSError) as e:
        print("%s %s: no answer (%s)" % (a.provider, path, type(e).__name__))
        return 3
    print("%s %s -> HTTP %d" % (a.provider, path, code))
    if 200 <= code < 300:
        return 0
    if code in (401, 403):
        return 1
    return 3


if __name__ == "__main__":
    sys.exit(main())

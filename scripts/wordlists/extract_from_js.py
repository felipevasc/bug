#!/usr/bin/env python3
import re
import sys
from pathlib import Path

# Very lightweight JS/HTML token extraction.
# - endpoints: things like /api/v1/users, /v1/login, /.well-known/openid-configuration
# - params: query param keys from ?a=b&c=d and from common patterns

ENDPOINT_RE = re.compile(r"(?<![A-Za-z0-9_])(/(?:[A-Za-z0-9._~\-]|%[0-9A-Fa-f]{2}){1,64}(?:/(?:[A-Za-z0-9._~\-]|%[0-9A-Fa-f]{2}){1,64}){0,6})(?![A-Za-z0-9_])")
PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{1,60})=")


def main():
    if len(sys.argv) < 3:
        print("usage: extract_from_js.py endpoints|params <file_or_dir>", file=sys.stderr)
        return 2

    kind = sys.argv[1]
    root = Path(sys.argv[2])
    files = []
    if root.is_dir():
        for p in root.rglob('*'):
            if p.is_file() and p.suffix.lower() in ('.js', '.mjs', '.cjs', '.html'):
                files.append(p)
    else:
        files = [root]

    out = set()
    for f in files:
        try:
            txt = f.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue

        if kind == 'endpoints':
            for m in ENDPOINT_RE.finditer(txt):
                ep = m.group(1)
                if len(ep) <= 140:
                    out.add(ep)
        elif kind == 'params':
            for m in PARAM_RE.finditer(txt):
                out.add(m.group(1))
        else:
            print("kind must be endpoints|params", file=sys.stderr)
            return 2

    for t in sorted(out):
        print(t)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

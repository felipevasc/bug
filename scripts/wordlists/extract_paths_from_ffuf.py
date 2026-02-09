#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

# Extract path tokens from ffuf json output.
# Prints one token per line (no scheme/host). Example: "admin" from "https://x/y/admin".

URL_RE = re.compile(r"^https?://[^/]+(?P<path>/.*)$", re.I)


def norm_token(p: str) -> str:
    p = p.strip()
    if not p:
        return ""
    # strip query/fragment
    p = p.split("?", 1)[0].split("#", 1)[0]
    # remove leading/trailing slashes
    p = p.strip("/")
    if not p:
        return ""
    # only first segment for wordlist seed
    seg = p.split("/", 1)[0].strip()
    if not seg or len(seg) > 80:
        return ""
    return seg


def main():
    if len(sys.argv) < 2:
        print("usage: extract_paths_from_ffuf.py <ffuf.json>", file=sys.stderr)
        return 2
    p = Path(sys.argv[1])
    d = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    out = set()
    for r in d.get("results") or []:
        url = str(r.get("url") or "").strip()
        m = URL_RE.match(url)
        if not m:
            continue
        token = norm_token(m.group("path"))
        if token:
            out.add(token)
    for t in sorted(out):
        print(t)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate a focused Nuclei allowlist of templates with CVSS score 10.

We intentionally keep this regex-based (no PyYAML dependency) to run on Kali/WSL.

Selection rules (opinionated):
- Only templates under http/cves
- Must contain a cvss score of 10 or 10.0 (common in nuclei-templates metadata)
- Exclude headless/code/file/network templates by path

Output:
- One template path per line (relative to nuclei templates root)
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

CVSS_RE = re.compile(r"^\s*cvss-score\s*:\s*(10(?:\.0+)?)\s*$", re.IGNORECASE | re.MULTILINE)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--templates-root", default=str(Path.home() / ".local" / "nuclei-templates"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.templates_root)
    out_path = Path(args.out)

    if not root.exists():
        raise SystemExit(f"templates root not found: {root}")

    selected: list[str] = []

    for p in root.rglob("*.yaml"):
        rel = p.relative_to(root).as_posix()

        # Path filters: keep it tight and web-first.
        if not rel.startswith("http/cves/"):
            continue
        if "/headless/" in rel or rel.startswith("headless/"):
            continue
        if rel.startswith("code/") or rel.startswith("file/") or rel.startswith("network/") or rel.startswith("ssl/"):
            continue

        try:
            s = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if not CVSS_RE.search(s):
            continue

        selected.append(rel)

    selected = sorted(set(selected))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(selected) + ("\n" if selected else ""), encoding="utf-8")

    print(f"count={len(selected)}")
    print(str(out_path))


if __name__ == "__main__":
    main()

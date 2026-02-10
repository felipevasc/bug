#!/usr/bin/env python3
"""
@skill: python/recon/dns-recon
@inputs: target[, out-dir, scope-file, rate, timeout]
@outputs: asset|finding|note
@tools: dig, dnsx
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def emit(record):
    if "ts" not in record:
        record["ts"] = now_iso()
    if "timestamp" not in record:
        record["timestamp"] = record["ts"]
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")


def load_scope(scope_file):
    if not scope_file:
        return []
    p = Path(scope_file)
    if not p.exists():
        return []
    entries = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        entries.append(s)
    return entries


def hostname_in_scope(host, entry):
    h = host.lower().rstrip(".")
    e = entry.lower().rstrip(".")
    if e.startswith("*."):
        root = e[2:]
        return h == root or h.endswith("." + root)
    return h == e or h.endswith("." + e)


def target_in_scope(target, entries):
    if not entries:
        return True
    # Basic: only hostname/domain entries here (dns skill)
    for e in entries:
        if "/" in e:
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", e):
            continue
        if hostname_in_scope(target, e):
            return True
    return False


def run_capture(cmd, timeout_s):
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def split_target(raw: str):
    s = (raw or "").strip()
    if not s:
        return "", ""
    is_url = "://" in s or "/" in s or "?" in s or "#" in s or re.match(r"^[^/]+:\\d{1,5}$", s or "")
    if not is_url:
        return s.lower().rstrip("."), ""
    u = s
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "https://" + u
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").lower().rstrip(".")
        return host, u
    except Exception:
        return s.lower().rstrip("."), ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--scope-file", default=None)
    parser.add_argument("--rate", default=None)
    parser.add_argument("--timeout", default=None)
    args = parser.parse_args()

    source = "src/skills/python/recon/01-dns-recon.py"
    stage = "recon"
    target, _target_url = split_target(args.target)
    scope_entries = load_scope(args.scope_file)
    if not target_in_scope(target, scope_entries):
        emit({
            "type": "note",
            "tool": "scope",
            "stage": stage,
            "target": target,
            "severity": "info",
            "evidence": [f"out_of_scope: {target}"],
            "data": {"reason": "target not in scope (blocked)"},
            "source": source,
        })
        return

    timeout_s = int(float(args.timeout or 20))
    run_ts = os.environ.get("RUN_TS") or "run"
    root_out = Path(args.out_dir or os.environ.get("OUT_DIR") or Path("data") / "runs" / run_ts)
    ev_dir = root_out / "evidence" / "recon" / "dns"
    ev_dir.mkdir(parents=True, exist_ok=True)

    evidence = []
    ips = []
    txt_out = []

    if shutil.which("dig"):
        for rr in ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]:
            code, out, err = run_capture(["dig", "+short", rr, target], timeout_s)
            txt_out.append(f";; {rr} (code={code})\\n{out}{err}\\n")
            if rr == "A":
                for line in out.splitlines():
                    s = line.strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
                        ips.append(s)
        ev_path = ev_dir / f"{target}.dig.txt"
        ev_path.write_text("".join(txt_out), encoding="utf-8", errors="ignore")
        evidence.append(str(ev_path))
    else:
        emit({
            "type": "note",
            "tool": "dig",
            "stage": stage,
            "target": target,
            "severity": "info",
            "evidence": [],
            "data": {"skipped": True, "reason": "tool not found"},
            "source": source,
        })

    if shutil.which("dnsx"):
        cmd = ["dnsx", "-silent", "-a", "-resp"]
        code, out, err = run_capture(cmd + ["-d", target], timeout_s)
        ev_path = ev_dir / f"{target}.dnsx.txt"
        ev_path.write_text(out + err, encoding="utf-8", errors="ignore")
        evidence.append(str(ev_path))
    else:
        emit({
            "type": "note",
            "tool": "dnsx",
            "stage": stage,
            "target": target,
            "severity": "info",
            "evidence": [],
            "data": {"skipped": True, "reason": "tool not found"},
            "source": source,
        })

    ips = sorted(set(ips))
    if ips:
        for ip in ips:
            emit({
                "type": "asset",
                "tool": "dns",
                "stage": stage,
                "target": ip,
                "severity": "info",
                "evidence": evidence,
                "data": {"resolved_from": target},
                "source": source,
            })

    emit({
        "type": "note",
        "tool": "dns-recon",
        "stage": stage,
        "target": target,
        "severity": "info",
        "evidence": evidence,
        "data": {"a_records": ips},
        "source": source,
    })


if __name__ == "__main__":
    main()

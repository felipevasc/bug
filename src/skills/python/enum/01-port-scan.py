#!/usr/bin/env python3
"""
@skill: python/enum/port-scan
@inputs: target[, out-dir, scope-file, rate, timeout]
@outputs: asset|finding|note
@tools: naabu, nmap
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


def ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    nums = []
    for p in parts:
        try:
            n = int(p)
        except ValueError:
            return None
        if n < 0 or n > 255:
            return None
        nums.append(n)
    return (nums[0] << 24) + (nums[1] << 16) + (nums[2] << 8) + nums[3]


def cidr_range(cidr):
    ip, pref = cidr.split("/", 1)
    try:
        prefix = int(pref)
    except ValueError:
        return None
    if prefix < 0 or prefix > 32:
        return None
    base = ip_to_int(ip)
    if base is None:
        return None
    mask = 0 if prefix == 0 else (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    start = base & mask
    end = start | (~mask & 0xFFFFFFFF)
    return start, end


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
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        ip_int = ip_to_int(target)
        if ip_int is None:
            return False
        for e in entries:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", e) and e == target:
                return True
            if "/" in e:
                r = cidr_range(e)
                if r and ip_int >= r[0] and ip_int <= r[1]:
                    return True
        return False
    for e in entries:
        if "/" in e or re.match(r"^\d+\.\d+\.\d+\.\d+$", e):
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--scope-file", default=None)
    parser.add_argument("--rate", default=None)
    parser.add_argument("--timeout", default=None)
    args = parser.parse_args()

    source = "src/skills/python/enum/01-port-scan.py"
    stage = "enum"
    target = args.target
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

    timeout_s = int(float(args.timeout or 120))
    run_ts = os.environ.get("RUN_TS") or "run"
    root_out = Path(args.out_dir or os.environ.get("OUT_DIR") or Path("data") / "runs" / run_ts)
    ev_dir = root_out / "evidence" / "enum" / "ports"
    ev_dir.mkdir(parents=True, exist_ok=True)

    rate = None
    try:
        if args.rate is not None:
            rate = int(float(args.rate))
    except ValueError:
        rate = None

    open_ports = []
    evidence = []

    # If target is a hostname, resolve A records first and scan IP(s) to avoid DNS-induced tool weirdness.
    scan_targets = [target]
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target) and shutil.which("dig"):
        _c, out, _e = run_capture(["dig", "+short", "A", target], min(timeout_s, 10))
        ips = []
        for line in (out or "").splitlines():
            s = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
                ips.append(s)
        ips = sorted(set(ips))
        if ips:
            scan_targets = ips[:3]
            emit({
                "type": "asset",
                "tool": "dns",
                "stage": stage,
                "target": ips[0],
                "severity": "info",
                "evidence": [],
                "data": {"resolved_from": target, "all_a": ips[:10]},
                "source": source,
            })

    if shutil.which("naabu"):
        out_jsonl = ev_dir / f"{target}.naabu.jsonl"
        cmd = ["naabu", "-host", target, "-silent", "-json"]
        if rate:
            cmd += ["-rate", str(rate)]
        code, out, err = run_capture(cmd, timeout_s)
        out_jsonl.write_text(out, encoding="utf-8", errors="ignore")
        evidence.append(str(out_jsonl))
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            p = obj.get("port")
            if isinstance(p, int):
                open_ports.append(p)
    elif shutil.which("nmap"):
        # Run nmap against each scan target (IP preferred). Keep it fast-ish.
        for t in scan_targets:
            suffix = t.replace("/", "_")
            out_gnmap = ev_dir / f"{target}.{suffix}.nmap.gnmap"
            out_nmap = ev_dir / f"{target}.{suffix}.nmap.txt"
            out_err = ev_dir / f"{target}.{suffix}.nmap.stderr.txt"

            cmd = [
                "nmap",
                "-Pn",
                "-sV",
                "--top-ports",
                "200",
                "--host-timeout",
                f"{max(10, timeout_s)}s",
                "-oG",
                str(out_gnmap),
                "-oN",
                str(out_nmap),
                t,
            ]
            code, out, err = run_capture(cmd, timeout_s)
            out_err.write_text((err or "") + f"\n(exit={code})\n", encoding="utf-8", errors="ignore")
            evidence += [str(out_gnmap), str(out_nmap), str(out_err)]

            if out_gnmap.exists():
                for line in out_gnmap.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if "Ports:" not in line:
                        continue
                    parts = line.split("Ports:", 1)[1]
                    for seg in parts.split(","):
                        seg = seg.strip()
                        m = re.match(r"^(\d+)/open", seg)
                        if m:
                            open_ports.append(int(m.group(1)))
    else:
        emit({
            "type": "note",
            "tool": "naabu/nmap",
            "stage": stage,
            "target": target,
            "severity": "info",
            "evidence": [],
            "data": {"skipped": True, "reason": "naabu and nmap not found"},
            "source": source,
        })
        return

    open_ports = sorted(set(open_ports))
    if open_ports:
        emit({
            "type": "finding",
            "tool": "port-scan",
            "stage": stage,
            "target": target,
            "severity": "info",
            "evidence": evidence,
            "data": {"open_ports": open_ports},
            "source": source,
        })
        for p in open_ports:
            emit({
                "type": "asset",
                "tool": "port",
                "stage": stage,
                "target": target,
                "severity": "info",
                "evidence": evidence,
                "data": {"port": p},
                "source": source,
            })
    else:
        emit({
            "type": "note",
            "tool": "port-scan",
            "stage": stage,
            "target": target,
            "severity": "info",
            "evidence": evidence,
            "data": {"message": "no open ports found (or scan produced no parsable output)"},
            "source": source,
        })


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
@skill: python/enum/port-scan
@inputs: target
@outputs: finding
@tools: nmap, masscan
"""

import argparse
import json
import sys
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def emit(record):
    if "timestamp" not in record:
        record["timestamp"] = now_iso()
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    emit({
        "type": "finding",
        "target": args.target,
        "data": {"category": "port-scan", "ports": [80, 443], "notes": "placeholder"},
        "source": "src/skills/python/enum/01-port-scan.py"
    })


if __name__ == "__main__":
    main()

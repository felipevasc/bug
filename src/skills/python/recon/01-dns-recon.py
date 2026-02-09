#!/usr/bin/env python3
"""
@skill: python/recon/dns-recon
@inputs: target
@outputs: asset
@tools: dig, dnsrecon
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
        "type": "asset",
        "target": args.target,
        "data": {"method": "dns-recon", "notes": "placeholder"},
        "source": "src/skills/python/recon/01-dns-recon.py"
    })


if __name__ == "__main__":
    main()

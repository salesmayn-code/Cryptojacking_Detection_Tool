#!/usr/bin/env python3
"""Send crafted safe test metrics to backend /api/metrics/batch.

Purpose: validate alert pipeline independent of local process collection.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime

import requests


def make_metric() -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "cpu": {"percent": 95.0, "cpu_percent": 95.0},
        "memory": {"percent": 78.0, "memory_percent": 78.0},
        "network": {"bytes_sent": 1024, "bytes_recv": 2048},
        "process_counts": {"running": 140},
        "processes": [
            {
                "pid": 4242,
                "name": "xmrig.exe",
                "cpu_percent": 88.0,
                "memory_percent": 12.0,
                "exe_path": "C:\\xmrig\\xmrig.exe",
                "exe_hash": "",
                "parent_name": "explorer.exe",
                "signature_status": "unknown",
                "publisher": "",
                "network_summary": {
                    "connection_count": 3,
                    "established_count": 2,
                    "unique_remote_ip_count": 1,
                    "remote_ips_sample": ["127.0.0.1"],
                    "remote_ports": [3333],
                    "has_external_connection": False,
                    "has_miner_port": True,
                },
                "static_analysis": None,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Send crafted test metrics batch")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--system-id", required=True)
    parser.add_argument("--count", type=int, default=4, help="Number of samples to send")
    args = parser.parse_args()

    url = args.api_url.rstrip("/") + "/api/metrics/batch"
    payload = {
        "system_id": args.system_id,
        "metrics": [make_metric() for _ in range(max(1, args.count))],
    }
    headers = {"X-API-Key": args.api_key, "Content-Type": "application/json"}

    resp = requests.post(url, data=json.dumps(payload), headers=headers, timeout=20)
    print(f"HTTP {resp.status_code}")
    print(resp.text)


if __name__ == "__main__":
    main()

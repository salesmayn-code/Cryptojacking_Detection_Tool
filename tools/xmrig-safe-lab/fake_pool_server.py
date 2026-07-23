#!/usr/bin/env python3
"""Local fake Stratum server for safe XMRig lab testing.

Safety properties:
- Binds only to 127.0.0.1 by default.
- Returns dummy responses for common mining JSON-RPC methods.
- Never connects outbound.
"""

from __future__ import annotations

import argparse
import json
import secrets
import socketserver
import threading
from datetime import datetime, timezone


DEFAULT_BLOB = "0" * 152
DEFAULT_TARGET = "ffffffff"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class StratumHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        client = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[{now_utc()}] client connected: {client}", flush=True)

        while True:
            raw = self.rfile.readline()
            if not raw:
                break

            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            print(f"[{now_utc()}] <- {line}", flush=True)
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self._send({"id": None, "error": {"code": -32700, "message": "parse error"}, "result": None})
                continue

            response = self._handle_rpc(req)
            if response is not None:
                self._send(response)

        print(f"[{now_utc()}] client disconnected: {client}", flush=True)

    def _handle_rpc(self, req: dict) -> dict | None:
        method = req.get("method", "")
        request_id = req.get("id")

        if method in {"login", "mining.authorize"}:
            return {
                "id": request_id,
                "error": None,
                "result": {
                    "id": secrets.token_hex(8),
                    "job": {
                        "job_id": secrets.token_hex(6),
                        "blob": DEFAULT_BLOB,
                        "target": DEFAULT_TARGET,
                        "algo": "rx/0",
                        "height": 1,
                    },
                    "status": "OK",
                },
            }

        if method in {"mining.subscribe", "keepalived"}:
            return {"id": request_id, "error": None, "result": ["xmrig-safe-lab", "1"]}

        if method in {"submit", "mining.submit"}:
            return {"id": request_id, "error": None, "result": {"status": "OK"}}

        if method == "mining.extranonce.subscribe":
            return {"id": request_id, "error": None, "result": True}

        return {"id": request_id, "error": {"code": -32601, "message": f"method not supported: {method}"}, "result": None}

    def _send(self, payload: dict) -> None:
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        self.wfile.write(encoded)
        self.wfile.flush()
        print(f"[{now_utc()}] -> {encoded.decode('utf-8').strip()}", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a localhost-only fake Stratum server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3333, help="Bind port (default: 3333)")
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("Safety check failed: host must be 127.0.0.1 or localhost")

    with ThreadedTCPServer(("127.0.0.1", args.port), StratumHandler) as server:
        print(f"[{now_utc()}] fake pool listening on 127.0.0.1:{args.port}", flush=True)
        print(f"[{now_utc()}] press Ctrl+C to stop", flush=True)
        stop_event = threading.Event()

        try:
            while not stop_event.is_set():
                server.handle_request()
        except KeyboardInterrupt:
            print(f"[{now_utc()}] shutdown requested", flush=True)


if __name__ == "__main__":
    main()

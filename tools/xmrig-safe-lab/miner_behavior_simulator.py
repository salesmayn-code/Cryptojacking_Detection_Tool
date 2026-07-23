#!/usr/bin/env python3
"""Safe miner-behavior simulator for detector testing.

This does NOT mine cryptocurrency. It simulates cryptojacking signals only:
- sustained per-process CPU load
- miner-like process naming/patterns
- persistent Stratum-style JSON-RPC traffic to localhost fake pool
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import random
import socket
import time
from datetime import datetime, timezone


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def send_line(sock: socket.socket, payload: dict) -> None:
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    sock.sendall(data)


def recv_line(sock: socket.socket, timeout: float = 3.0) -> str:
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch or ch == b"\n":
            break
        buf.extend(ch)
    return buf.decode("utf-8", errors="replace")


def worker_loop(stop: mp.Event, host: str, port: int, intensity: int, interval: float, worker_id: int, agent_name: str) -> None:
    intensity = max(1, min(intensity, 100))
    period = 0.2
    busy = period * (intensity / 100.0)
    idle = max(0.0, period - busy)
    req_id = 1

    while not stop.is_set():
        try:
            with socket.create_connection((host, port), timeout=4.0) as sock:
                print(f"[{now_utc()}] worker-{worker_id} connected to {host}:{port}", flush=True)

                login = {
                    "id": req_id,
                    "jsonrpc": "2.0",
                    "method": "login",
                    "params": {
                        "login": "test_wallet",
                        "pass": "x",
                        "agent": agent_name,
                    },
                }
                send_line(sock, login)
                _ = recv_line(sock)
                req_id += 1

                last_rpc = time.time()
                while not stop.is_set():
                    # Keep CPU hot in this same process (so CPU + network correlate).
                    start = time.perf_counter()
                    while (time.perf_counter() - start) < busy:
                        _ = (1234567 * 7654321) % 97
                    if idle > 0:
                        time.sleep(idle)

                    if time.time() - last_rpc >= max(0.5, interval):
                        keepalive = {
                            "id": req_id,
                            "jsonrpc": "2.0",
                            "method": "keepalived",
                            "params": {"id": f"session-{worker_id}"},
                        }
                        send_line(sock, keepalive)
                        _ = recv_line(sock)
                        req_id += 1

                        submit = {
                            "id": req_id,
                            "jsonrpc": "2.0",
                            "method": "submit",
                            "params": {
                                "id": f"session-{worker_id}",
                                "job_id": f"{random.randint(100000, 999999)}",
                                "nonce": f"{random.getrandbits(32):08x}",
                                "result": "0" * 64,
                            },
                        }
                        send_line(sock, submit)
                        _ = recv_line(sock)
                        req_id += 1
                        last_rpc = time.time()
        except (ConnectionError, TimeoutError, OSError):
            time.sleep(1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe miner-behavior simulator (no mining)")
    parser.add_argument("--host", default="127.0.0.1", help="Fake pool host (must be localhost)")
    parser.add_argument("--port", type=int, default=3333, help="Fake pool port")
    parser.add_argument("--workers", type=int, default=4, help="Worker process count")
    parser.add_argument("--cpu-intensity", type=int, default=92, help="Per-worker CPU intensity percent (1-100)")
    parser.add_argument("--rpc-interval", type=float, default=1.0, help="Seconds between keepalive/submit rounds")
    parser.add_argument("--agent-name", default="xmrig/6.22.2", help="Agent string to mimic miner clients")
    args, _unknown = parser.parse_known_args()

    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("Safety check failed: host must be 127.0.0.1 or localhost")

    print(f"[{now_utc()}] starting safe miner-behavior simulator", flush=True)
    print(f"[{now_utc()}] target fake pool: 127.0.0.1:{args.port}", flush=True)
    print(f"[{now_utc()}] workers: {args.workers}, intensity: {args.cpu_intensity}%", flush=True)

    mp.set_start_method("spawn", force=True)
    stop = mp.Event()
    procs: list[mp.Process] = []

    for i in range(max(1, args.workers)):
        p = mp.Process(
            target=worker_loop,
            args=(stop, "127.0.0.1", args.port, args.cpu_intensity, args.rpc_interval, i + 1, args.agent_name),
            name=f"xmrig-worker-{i+1}",
        )
        p.start()
        procs.append(p)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"[{now_utc()}] shutdown requested", flush=True)
    finally:
        stop.set()
        for p in procs:
            p.join(timeout=3)
            if p.is_alive():
                p.terminate()


if __name__ == "__main__":
    mp.freeze_support()
    main()

#!/usr/bin/env python3
"""Offline TCP/UDP canary used by the browser containment proof."""

from __future__ import annotations

import json
import socket
import sys


MAX_INPUT_BYTES = 16 * 1024
TIMEOUT_SECONDS = 0.75


def attempt_tcp(host: str, port: int, request: bytes | None = None) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as connection:
            if request:
                connection.sendall(request)
                connection.recv(128)
        return True
    except OSError:
        return False


def attempt_udp(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.sendto(b"lynceuz-containment-canary", (host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def main() -> int:
    raw = sys.stdin.buffer.readline(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES or sys.stdin.buffer.read(1):
        return 2
    try:
        request = json.loads(raw)
        if set(request) != {
            "version", "proxy_host", "proxy_port", "proxy_token",
            "tcp_host", "tcp_port", "udp_host", "udp_port",
        }:
            return 2
        if request["version"] != 1:
            return 2
        ports = [request["proxy_port"], request["tcp_port"], request["udp_port"]]
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            return 2
        for key in ("proxy_host", "proxy_token", "tcp_host", "udp_host"):
            if not isinstance(request[key], str) or not request[key]:
                return 2
    except (json.JSONDecodeError, TypeError, ValueError):
        return 2

    proxy_request = (
        "HEAD http://public.example.com/probe HTTP/1.1\r\n"
        "Host: public.example.com\r\n"
        f"Proxy-Authorization: Bearer {request['proxy_token']}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    result = {
        "version": 1,
        "proxy_tcp": attempt_tcp(
            request["proxy_host"], request["proxy_port"], proxy_request
        ),
        "direct_tcp": attempt_tcp(request["tcp_host"], request["tcp_port"]),
        "direct_udp_send": attempt_udp(request["udp_host"], request["udp_port"]),
    }
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

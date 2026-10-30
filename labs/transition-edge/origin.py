#!/usr/bin/env python3
"""Minimal IPv6-only HTTP HMAC challenge origin for VPS-side path verification.

Binds AF_INET6/IPV6_V6ONLY exclusively. Authentication token is kept in a
private local file and never included in server responses or logs.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
import socket
import sys

from transition import challenge_digest, positive_port, secure_token


class IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    server_version = "46labs-origin/1.0"
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        segments = self.path.split("/")
        if len(segments) != 3 or segments[1] != "probe" or len(segments[2]) != 32:
            self.send_error(404)
            return
        nonce = segments[2]
        try:
            bytes.fromhex(nonce)
        except ValueError:
            self.send_error(400)
            return
        body = (challenge_digest(self.server.secret, nonce) + "\n").encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("Origin request from", self.client_address[0], flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="2a05:541:104:66::1", help="IPv6-only VPS IP; override if different")
    ap.add_argument("--port", type=positive_port, default=18080)
    ap.add_argument("--token-file", required=True)
    args = ap.parse_args()
    try:
        ipaddress.IPv6Address(args.bind)
        secret = secure_token(Path(args.token_file))
        with IPv6Server((args.bind, args.port), Handler) as server:
            server.secret = secret
            print(f"ORIGIN READY: [{args.bind}]:{args.port}, AF_INET6 IPV6_V6ONLY", flush=True)
            server.serve_forever(poll_interval=0.3)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())

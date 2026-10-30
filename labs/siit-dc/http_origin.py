#!/usr/bin/env python3
"""IPv6-only HTTP origin in isolated namespace; no external dependencies."""
import socket

ADDR = '2001:db8:66::2'
with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ADDR, 8080))
    server.listen(32)
    print(f'ORIGIN READY: [{ADDR}]:8080 (AF_INET6 only)', flush=True)
    while True:
        conn, addr = server.accept()
        with conn:
            conn.settimeout(5)
            try:
                data = conn.recv(4096)
                if data:
                    body = b'SIIT_DC_OK\n'
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
                                 + b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
                                 + b'Connection: close\r\n\r\n' + body)
                    print(f'HTTP connection from {addr[0]}, bytes={len(data)}', flush=True)
            except (TimeoutError, OSError) as exc:
                print(f'HTTP error: {exc}', flush=True)

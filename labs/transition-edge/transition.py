#!/usr/bin/env python3
"""Provider transition discovery and verified IPv4-to-IPv6 service path tests.

No root required. Network requests only under explicit `6a44`, `edge` or
`origin-v6` commands. Never changes routes, interfaces or the firewall.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time

DEFAULT_V6 = "2a05:541:104:66::1"
SIXA44_RELAY = "192.88.99.2"
SIXA44_PORT = 1027


def parse_6rd(raw: bytes) -> dict:
    """Decode RFC 5969 DHCP option 212: either payload or complete TLV."""
    if len(raw) >= 2 and raw[0] == 212 and raw[1] == len(raw) - 2:
        raw = raw[2:]
    if len(raw) < 22 or (len(raw) - 18) % 4:
        raise ValueError("6rd data must contain 18+4*N bytes, N>=1 (or a full option-212 TLV)")
    ipv4_mask, prefix_len = raw[0], raw[1]
    if ipv4_mask > 32 or prefix_len > 128 or prefix_len + 32 - ipv4_mask > 128:
        raise ValueError("invalid 6rd IPv4 mask or IPv6 prefix length")
    prefix = ipaddress.IPv6Network((int.from_bytes(raw[2:18], "big"), prefix_len), strict=False)
    relay_addresses = [str(ipaddress.IPv4Address(raw[i:i+4])) for i in range(18, len(raw), 4)]
    return {
        "ipv4_mask_length": ipv4_mask,
        "ipv6_prefix": str(prefix),
        "border_relay_ipv4": relay_addresses,
        "note": "Option proves provisioning only if it came from the actual provider-facing CPE WAN DHCP session.",
    }


def delegated_prefix(parsed: dict, ce_ipv4: str) -> str:
    """RFC 5969: append low (32 - IPv4MaskLen) bits of CE WAN IPv4."""
    v4 = int(ipaddress.IPv4Address(ce_ipv4))
    base = ipaddress.IPv6Network(parsed["ipv6_prefix"])
    bits = 32 - parsed["ipv4_mask_length"]
    delegated_len = base.prefixlen + bits
    if delegated_len > 128:
        raise ValueError("computed 6rd delegated prefix exceeds /128")
    low = v4 & ((1 << bits) - 1)
    return str(ipaddress.IPv6Network((int(base.network_address) | (low << (128 - delegated_len)), delegated_len)))


def run_ip(*args: str) -> dict:
    try:
        proc = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=4)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    if proc.returncode:
        return {"error": (proc.stderr or proc.stdout).strip()}
    try:
        return {"data": json.loads(proc.stdout)}
    except json.JSONDecodeError as exc:
        return {"error": str(exc)}


def inspect() -> dict:
    links = run_ip("-d", "link", "show")
    routes = run_ip("-6", "route", "show")
    tunnel_links = []
    if "data" in links:
        for link in links["data"]:
            info = link.get("linkinfo", {})
            if info.get("info_kind") in ("sit", "ip6tnl", "vti6"):
                tunnel_links.append({"ifname": link.get("ifname"), "kind": info.get("info_kind"),
                                     "details": info.get("info_data", {})})
    return {"local_tunnel_devices": tunnel_links, "ipv6_routes": routes,
            "discovery_limit": "LAN-side host cannot normally read PPPoE/DHCPv4 WAN provisioning received by home router. "
                               "No 6rd link does not prove the ISP lacks 6rd."}


def probe_6a44(timeout: float) -> dict:
    """One RFC 6751 bubble. No source spoofing, no retries, no permanent socket."""
    bubble_id = secrets.token_bytes(8)
    payload = b"\x00" * 12 + bubble_id
    result = {"relay": f"{SIXA44_RELAY}:{SIXA44_PORT}", "response_verified": False}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.bind(("0.0.0.0", SIXA44_PORT))
            sock.sendto(payload, (SIXA44_RELAY, SIXA44_PORT))
            reply, addr = sock.recvfrom(128)
            if addr[0] != SIXA44_RELAY or addr[1] != SIXA44_PORT:
                result["error"] = "Reply source does not match the designated relay"
            elif not 20 <= len(reply) < 40 or reply[12:20] != bubble_id:
                result["error"] = "Unexpected bubble length or mismatched random bubble ID"
            else:
                value = int.from_bytes(reply[:12], "big") << 32
                result["response_verified"] = True
                result["received_client_prefix_96"] = str(ipaddress.IPv6Network((value, 96)))
    except socket.timeout:
        result["error"] = "No bubble reply within timeout"
    except OSError as exc:
        result["error"] = f"Socket error: {exc}"
    result["limit"] = "A valid bubble is evidence of a responding 6a44-like relay, not yet full IPv6 connectivity. "
    result["limit"] += "No reply may be caused by absent relay, routing, NAT, or filtering."
    return result


def secure_token(path: Path) -> bytes:
    token = path.read_bytes().strip()
    if len(token) != 64 or not re.fullmatch(rb"[0-9a-fA-F]{64}", token):
        raise ValueError("token file must hold exactly 64 hex characters (created with token command)")
    return bytes.fromhex(token.decode("ascii"))


def make_token(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite existing token file: {path}") from exc
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(secrets.token_hex(32) + "\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return {"created": str(path), "mode": "0600", "note": "Copy token privately to VPS, not to GitHub."}


def challenge_digest(key: bytes, nonce: str) -> str:
    return hmac.new(key, nonce.encode("ascii"), hashlib.sha256).hexdigest()


def probe_edge(ip: str, port: int, family: int, key: bytes, timeout: float) -> dict:
    nonce = secrets.token_hex(16)
    address = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    output = {"destination": ip, "port": port, "address_family": "IPv6" if family == socket.AF_INET6 else "IPv4",
              "verified": False}
    start = time.monotonic()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(address)
            request = (f"GET /probe/{nonce} HTTP/1.0\r\nHost: 46labs\r\nConnection: close\r\n\r\n").encode("ascii")
            sock.sendall(request)
            received = bytearray()
            while len(received) < 4096:
                block = sock.recv(min(4096 - len(received), 1024))
                if not block:
                    break
                received.extend(block)
        output["rtt_ms"] = round((time.monotonic() - start) * 1000, 2)
        headers, marker, body = bytes(received).partition(b"\r\n\r\n")
        if not marker or not headers.startswith(b"HTTP/1.0 200"):
            output["error"] = "No valid HTTP/1.0 200 challenge response"
        elif hmac.compare_digest(body.strip().decode("ascii", errors="replace"), challenge_digest(key, nonce)):
            output["verified"] = True
        else:
            output["error"] = "Server response did not match HMAC for this random challenge"
    except (OSError, ValueError) as exc:
        output["error"] = str(exc)
    output["meaning"] = ("Matched the private challenge key: reachable endpoint leads to the configured origin. "
                         "This does not distinguish SIIT from an ordinary TCP proxy." if output["verified"] else
                         "No verified origin path established; absence of response does not disprove all possible relays.")
    return output


def selftest() -> None:
    data = (bytes([8, 32]) + ipaddress.IPv6Address("2001:db8::").packed
            + ipaddress.IPv4Address("10.0.0.1").packed)
    decoded = parse_6rd(data)
    assert decoded["border_relay_ipv4"] == ["10.0.0.1"]
    assert delegated_prefix(decoded, "10.100.100.1") == "2001:db8:6464:100::/56"
    assert parse_6rd(bytes([212, len(data)]) + data) == decoded
    for bad in (b"", data[:21], bytes([33, 32]) + data[2:]):
        try:
            parse_6rd(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid 6rd option was accepted")
    key = bytes(range(32))
    assert hmac.compare_digest(challenge_digest(key, "abc"), hmac.new(key, b"abc", hashlib.sha256).hexdigest())
    print("SELFTEST OK: 6rd option 212, delegated prefix and HMAC challenge")


def positive_port(raw: str) -> int:
    value = int(raw)
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return value


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="offline unit tests, no network")
    sub.add_parser("inspect", help="read-only local SIT/6rd device and IPv6 route inventory")
    dhcp = sub.add_parser("decode-6rd", help="decode option 212 captured on ISP-facing CPE WAN")
    dhcp.add_argument("--hex", required=True, help="hex of option payload or complete 212/length TLV")
    dhcp.add_argument("--ce-ipv4", help="CPE WAN IPv4 from provisioning, not LAN IPv4")
    a44 = sub.add_parser("6a44", help="send one RFC 6751 bubble to 192.88.99.2:1027")
    a44.add_argument("--timeout", type=float, default=2.0)
    token = sub.add_parser("token", help="create shared authentication token (0600)")
    token.add_argument("--output", type=Path, required=True)
    edge = sub.add_parser("edge", help="prove IPv4 service address reaches IPv6-only VPS origin")
    edge.add_argument("--ipv4", required=True, help="candidate IPv4 service address from hoster; no auto-scan")
    edge.add_argument("--port", type=positive_port, default=18080)
    edge.add_argument("--token-file", type=Path, required=True)
    edge.add_argument("--timeout", type=float, default=3.0)
    v6 = sub.add_parser("origin-v6", help="IPv6 reference check where IPv6 is available")
    v6.add_argument("--ipv6", default=DEFAULT_V6)
    v6.add_argument("--port", type=positive_port, default=18080)
    v6.add_argument("--token-file", type=Path, required=True)
    v6.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()
    try:
        if args.cmd == "selftest":
            selftest()
            return 0
        if args.cmd == "inspect":
            result = inspect()
        elif args.cmd == "decode-6rd":
            raw = bytes.fromhex(re.sub(r"[\s:]", "", args.hex))
            result = parse_6rd(raw)
            if args.ce_ipv4:
                result["delegated_ipv6_prefix"] = delegated_prefix(result, args.ce_ipv4)
        elif args.cmd == "6a44":
            if not 0 < args.timeout <= 15:
                raise ValueError("timeout must be >0 and <=15s")
            result = probe_6a44(args.timeout)
        elif args.cmd == "token":
            result = make_token(args.output)
        elif args.cmd in ("edge", "origin-v6"):
            if not 0 < args.timeout <= 15:
                raise ValueError("timeout must be >0 and <=15s")
            key = secure_token(args.token_file)
            if args.cmd == "edge":
                ipaddress.IPv4Address(args.ipv4)
                result = probe_edge(args.ipv4, args.port, socket.AF_INET, key, args.timeout)
            else:
                ipaddress.IPv6Address(args.ipv6)
                result = probe_edge(args.ipv6, args.port, socket.AF_INET6, key, args.timeout)
        else:
            raise AssertionError("unreachable")
    except (ValueError, OSError) as exc:
        ap.error(str(exc))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

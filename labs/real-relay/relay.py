#!/usr/bin/env python3
"""Real 6rd border-relay probe: IPv6 ICMP Echo / TCP SYN in IPv4 protocol 41.

Reads operator-provisioned 6rd parameters. Sends at most one packet per
requested type to ONE configured IPv4 border relay. Never changes routes,
network interfaces, DNS or firewall. Requires root for Linux raw sockets.

This is a PROBE, not a TCP stack or a full tunnel.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import time

DEFAULT_VPS = "2a05:541:104:66::1"
PROTOCOL_41 = 41
DEMO_NETS4 = tuple(ipaddress.IPv4Network(n) for n in
                   ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def checksum(payload: bytes) -> int:
    if len(payload) & 1:
        payload += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(payload) // 2), payload))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def pseudo6(src: bytes, dst: bytes, proto: int, n: int) -> bytes:
    return src + dst + struct.pack("!I3xB", n, proto)


def load_config(path: Path) -> dict:
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("could not read 6rd configuration JSON: " + str(exc)) from exc
    if not isinstance(cfg, dict):
        raise ValueError("config must be a JSON object")
    try:
        mask = int(cfg["ipv4_mask_length"])
        prefix = ipaddress.IPv6Network(cfg["ipv6_prefix"], strict=True)
        relay = ipaddress.IPv4Address(cfg["border_relay_ipv4"])
        ce = ipaddress.IPv4Address(cfg["ce_wan_ipv4"])
        target = ipaddress.IPv6Address(cfg.get("target_ipv6", DEFAULT_VPS))
        port = int(cfg.get("target_port", 22))
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("invalid or missing 6rd field: " + str(exc)) from exc
    if not 0 <= mask <= 32 or prefix.prefixlen + 32 - mask > 128:
        raise ValueError("invalid 6rd IPv4 mask/prefix length")
    if not 1 <= port <= 65535:
        raise ValueError("target_port must be 1..65535")
    if relay.is_multicast or relay.is_unspecified or ce.is_multicast or ce.is_unspecified:
        raise ValueError("relay and CE IPv4 must be unicast")
    bits = 32 - mask
    subnet_len = prefix.prefixlen + bits
    value = int(prefix.network_address) | (
        (int(ce) & ((1 << bits) - 1)) << (128 - subnet_len))
    delegated = ipaddress.IPv6Network((value, subnet_len))
    if subnet_len == 128:
        source = delegated.network_address
    else:
        source = ipaddress.IPv6Address(int(delegated.network_address) + 1)
    return {
        "ipv4_mask_length": mask,
        "provider_ipv6_prefix": str(prefix),
        "border_relay_ipv4": str(relay),
        "ce_wan_ipv4": str(ce),
        "target_ipv6": str(target),
        "target_port": port,
        "delegated_prefix": str(delegated),
        "ipv6_source": str(source),
        "demo_parameters": not source.is_global or not target.is_global or
                           any(relay in n for n in DEMO_NETS4),
    }


def route_source_for(relay: str) -> tuple[str | None, str | None]:
    """UDP connect only chooses a route; no traffic is sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((relay, 9))
            return sock.getsockname()[0], None
    except OSError as exc:
        return None, str(exc)


def readiness(cfg: dict) -> dict:
    route_source, error = route_source_for(cfg["border_relay_ipv4"])
    matches = route_source == cfg["ce_wan_ipv4"]
    reasons = []
    if error:
        reasons.append("no IPv4 route to the configured relay: " + error)
    if not matches:
        reasons.append("host's route source IPv4 does not equal the 6rd CE WAN IPv4; "
                       "run on the actual CE/router, not behind 192.168.x.x NAT")
    if cfg["demo_parameters"]:
        reasons.append("example/documentation or non-global IPv6 source or target; "
                       "real relay probe forbidden")
    return {
        "border_relay_ipv4": cfg["border_relay_ipv4"],
        "ce_wan_ipv4": cfg["ce_wan_ipv4"],
        "host_ipv4_route_source": route_source,
        "local_source_matches_ce_wan": matches,
        "delegated_ipv6_prefix": cfg["delegated_prefix"],
        "source_ipv6": cfg["ipv6_source"],
        "target_ipv6": cfg["target_ipv6"],
        "target_tcp_port": cfg["target_port"],
        "ready_to_send": not reasons,
        "blockers": reasons,
        "scope": "No traffic has been sent. Readiness does not prove protocol 41 or relay support.",
    }


def ipv6_header(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    if len(payload) > 65535:
        raise ValueError("payload too large")
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64, src, dst) + payload


def echo_request(src: bytes, dst: bytes, ident: int) -> bytes:
    payload = bytearray(struct.pack("!BBHHH", 128, 0, 0, ident, 1) + b"46labs-relay")
    payload[2:4] = struct.pack("!H", checksum(pseudo6(src, dst, 58, len(payload)) + payload))
    return ipv6_header(src, dst, 58, payload)


def syn_request(src: bytes, dst: bytes, sport: int, dport: int, seq: int) -> bytes:
    payload = bytearray(struct.pack("!HHIIHHHH", sport, dport, seq, 0, 0x5002, 64240, 0, 0))
    payload[16:18] = struct.pack("!H", checksum(pseudo6(src, dst, 6, len(payload)) + payload))
    return ipv6_header(src, dst, 6, payload)


def parse_reply(raw: bytes, cfg: dict, kind: str, ident: int = 0,
                sport: int = 0, seq: int = 0) -> str | None:
    """Require exact outer relay, endpoint addresses, request identifier."""
    if len(raw) < 60 or raw[0] >> 4 != 4:
        return None
    hlen = (raw[0] & 15) * 4
    if hlen < 20 or len(raw) < hlen + 40 or raw[9] != PROTOCOL_41:
        return None
    if struct.unpack_from("!H", raw, 6)[0] & 0x3fff:
        return None
    if str(ipaddress.IPv4Address(raw[12:16])) != cfg["border_relay_ipv4"]:
        return None
    if str(ipaddress.IPv4Address(raw[16:20])) != cfg["ce_wan_ipv4"]:
        return None
    total_v4 = struct.unpack_from("!H", raw, 2)[0]
    if total_v4 < hlen + 40 or len(raw) < total_v4:
        return None
    packet = raw[hlen:total_v4]
    if packet[0] >> 4 != 6:
        return None
    length = struct.unpack_from("!H", packet, 4)[0]
    if len(packet) != 40 + length:
        return None
    if str(ipaddress.IPv6Address(packet[8:24])) != cfg["target_ipv6"]:
        return None
    if str(ipaddress.IPv6Address(packet[24:40])) != cfg["ipv6_source"]:
        return None
    payload = packet[40:]
    if kind == "ping":
        if packet[6] != 58 or len(payload) < 8 or payload[0] != 129 or payload[1] != 0:
            return None
        if struct.unpack_from("!HH", payload, 4) != (ident, 1):
            return None
        if checksum(pseudo6(packet[8:24], packet[24:40], 58, len(payload)) + payload):
            return None
        return "ICMPv6_ECHO_REPLY"
    if kind == "syn":
        if packet[6] != 6 or len(payload) < 20:
            return None
        srcport, destport, _rseq, ack, flags, _window, _sum, _urg = struct.unpack("!HHIIHHHH", payload[:20])
        if srcport != cfg["target_port"] or destport != sport or ack != (seq + 1) & 0xffffffff:
            return None
        if checksum(pseudo6(packet[8:24], packet[24:40], 6, len(payload)) + payload):
            return None
        if flags & 0x12 == 0x12:
            return "TCP_SYN_ACK"
        if flags & 0x04:
            return "TCP_RST"
    return None


def probe(cfg: dict, kind: str, timeout: float) -> dict:
    status = readiness(cfg)
    result = {"kind": kind, "border_relay": cfg["border_relay_ipv4"],
              "target_ipv6": cfg["target_ipv6"], "verified_reply": False}
    if not status["ready_to_send"]:
        result["error"] = "preflight blocked outgoing packet"
        result["blockers"] = status["blockers"]
        return result
    if os.geteuid() != 0:
        result["error"] = "CAP_NET_RAW/root required for IPv4 protocol 41 sockets"
        return result
    src = ipaddress.IPv6Address(cfg["ipv6_source"]).packed
    dst = ipaddress.IPv6Address(cfg["target_ipv6"]).packed
    ident = secrets.randbelow(65536)
    sport = 40000 + secrets.randbelow(20000)
    seq = secrets.randbits(32)
    packet = (echo_request(src, dst, ident) if kind == "ping" else
              syn_request(src, dst, sport, cfg["target_port"], seq))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTOCOL_41) as receiver:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTOCOL_41) as sender:
                receiver.bind((cfg["ce_wan_ipv4"], 0))
                sender.sendto(packet, (cfg["border_relay_ipv4"], 0))
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    receiver.settimeout(max(0.001, deadline - time.monotonic()))
                    try:
                        data, _ = receiver.recvfrom(65535)
                    except socket.timeout:
                        break
                    verdict = parse_reply(data, cfg, kind, ident=ident, sport=sport, seq=seq)
                    if verdict:
                        result.update({"verified_reply": True, "reply": verdict})
                        break
    except OSError as exc:
        result["error"] = str(exc)
        return result
    if not result["verified_reply"]:
        result["interpretation"] = ("No verified IPv6 response inside IPv4 protocol 41; "
                                    "relay/firewall/return route/VPS ICMP or TCP policy unknown.")
    else:
        result["interpretation"] = ("Verified a real packet path via the declared IPv4 relay "
                                    "to the IPv6-only target. No SSH session established.")
    return result


def selftest() -> None:
    import tempfile
    demo = {"ipv4_mask_length": 8, "ipv6_prefix": "2001:db8::/32",
            "border_relay_ipv4": "10.0.0.1", "ce_wan_ipv4": "10.100.100.1",
            "target_ipv6": "2001:db8:66::2", "target_port": 22}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(demo))
        cfg = load_config(path)
    assert cfg["delegated_prefix"] == "2001:db8:6464:100::/56"
    assert not cfg["ipv6_source"] == cfg["target_ipv6"]
    s = ipaddress.IPv6Address(cfg["ipv6_source"]).packed
    d = ipaddress.IPv6Address(cfg["target_ipv6"]).packed
    out = echo_request(s, d, 1234)
    assert out[6] == 58 and checksum(pseudo6(s, d, 58, len(out) - 40) + out[40:]) == 0
    tcp = syn_request(s, d, 45000, 22, 0x10203040)
    assert tcp[6] == 6 and checksum(pseudo6(s, d, 6, len(tcp) - 40) + tcp[40:]) == 0

    def frame(proto: int, segment: bytes) -> bytes:
        encapsulated = ipv6_header(d, s, proto, segment)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(encapsulated), 1,
                             0, 55, PROTOCOL_41, 0,
                             ipaddress.IPv4Address(cfg["border_relay_ipv4"]).packed,
                             ipaddress.IPv4Address(cfg["ce_wan_ipv4"]).packed)
        return header + encapsulated

    icmp = bytearray(struct.pack("!BBHHH", 129, 0, 0, 1234, 1) + b"46labs-relay")
    icmp[2:4] = struct.pack("!H", checksum(pseudo6(d, s, 58, len(icmp)) + icmp))
    assert parse_reply(frame(58, icmp), cfg, "ping", ident=1234) == "ICMPv6_ECHO_REPLY"
    assert parse_reply(frame(58, icmp), cfg, "ping", ident=1235) is None

    ack = bytearray(struct.pack("!HHIIHHHH", 22, 45000, 77, 0x10203041, 0x5012, 64240, 0, 0))
    ack[16:18] = struct.pack("!H", checksum(pseudo6(d, s, 6, len(ack)) + ack))
    assert parse_reply(frame(6, ack), cfg, "syn", sport=45000, seq=0x10203040) == "TCP_SYN_ACK"
    assert parse_reply(frame(6, ack), cfg, "syn", sport=45001, seq=0x10203040) is None
    assert readiness(cfg)["ready_to_send"] is False
    print("SELFTEST OK: 6rd prefix, raw protocol-41 requests, checksums and authenticated reply parsing")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("selftest", help="offline deterministic tests")
    for action in ("preflight", "probe"):
        p = subs.add_parser(action, help="6rd readiness without traffic" if action == "preflight" else
                            "send one ICMPv6 Echo and/or TCP SYN via IPv4 protocol 41")
        p.add_argument("--config", type=Path, required=True)
        if action == "probe":
            p.add_argument("--kind", choices=("ping", "syn", "both"), default="both")
            p.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    if args.action == "selftest":
        selftest()
        return 0
    try:
        cfg = load_config(args.config)
    except ValueError as exc:
        parser.error(str(exc))
    if args.action == "preflight":
        print(json.dumps(readiness(cfg), indent=2))
        return 0
    if not 0 < args.timeout <= 15:
        parser.error("timeout must be >0 and <=15 seconds")
    kinds = ("ping", "syn") if args.kind == "both" else (args.kind,)
    results = [probe(cfg, kind, args.timeout) for kind in kinds]
    print(json.dumps(results, indent=2))
    return 0 if all(x["verified_reply"] for x in results) else 2


if __name__ == "__main__":
    sys.exit(main())

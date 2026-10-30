#!/usr/bin/env python3
"""Read-only IPv4/IPv6 WAN diagnostics. No root, raw sockets or extra packages.

Tests host routing, connectivity and DNS64 hints. Cannot prove the existence
of an IPv4-to-IPv6 gateway, CGNAT, or arbitrary IP protocol traversal.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path


def command_json(argv: list[str]) -> dict:
    if not shutil.which(argv[0]):
        return {"ok": False, "error": f"{argv[0]} not found in PATH"}
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}
    if result.returncode:
        return {"ok": False, "error": (result.stderr or result.stdout).strip(), "code": result.returncode}
    try:
        return {"ok": True, "data": json.loads(result.stdout)}
    except json.JSONDecodeError:
        return {"ok": False, "error": "ip command returned invalid JSON"}


def tcp_probe(host: str, port: int, family: int, timeout: float) -> dict:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            endpoint = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
            sock.connect(endpoint)
            return {"connected": True, "peer": host, "port": port,
                    "local_address": sock.getsockname()[0]}
    except OSError as exc:
        return {"connected": False, "peer": host, "port": port,
                "errno": exc.errno, "error": str(exc)}


def addresses(entries: dict, version: int) -> list[dict]:
    result = []
    for iface in entries.get("data", []) if entries.get("ok") else []:
        for addr in iface.get("addr_info", []):
            if addr.get("family") != ("inet6" if version == 6 else "inet"):
                continue
            value = addr.get("local")
            if not value:
                continue
            obj = ipaddress.ip_address(value)
            result.append({"device": iface.get("ifname"), "address": value,
                           "prefixlen": addr.get("prefixlen"), "scope": addr.get("scope"),
                           "is_global_unicast": obj.is_global})
    return result


def classify_ipv6_path(v6addrs: list[dict], route: dict) -> dict:
    usable = [a for a in v6addrs if a["is_global_unicast"] and a.get("scope") == "global"]
    result = {"globally_routable_source_configured": bool(usable),
              "globally_routable_addresses": [a["address"] for a in usable],
              "route_reported": bool(route.get("ok") and route.get("data"))}
    if not result["route_reported"]:
        result["interpretation"] = "OS has no confirmed IPv6 route to the target"
    elif not usable:
        result["interpretation"] = (
            "An IPv6 route may exist but no globally routable IPv6 source address "
            "was found; a link-local RA gateway alone cannot reach the public VPS")
    else:
        result["interpretation"] = "Global IPv6 source exists; TCP test decides target reachability"
    return result


def dns64_probe() -> dict:
    """AAAA lookup through OS resolver; not interface-specific RFC 7050 discovery."""
    try:
        answers = socket.getaddrinfo("ipv4only.arpa", None, socket.AF_INET6, socket.SOCK_DGRAM)
        unique = sorted({entry[4][0] for entry in answers})
        return {"queried": True, "aaaa_addresses": unique, "synthesized_aaaa_seen": bool(unique),
                "caveat": "Not RFC 7050 proof unless the interface-provided resolver was used; "
                          "a VPN or external DNS64 may mislead."}
    except OSError as exc:
        return {"queried": True, "aaaa_addresses": [], "synthesized_aaaa_seen": False,
                "error": str(exc), "caveat": "No AAAA does not rule out PREF64 RA or manual NAT64."}


def resolver_description() -> dict:
    try:
        lines = Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines()
        servers = [line.split()[1] for line in lines
                   if line.strip().startswith("nameserver ") and len(line.split()) >= 2]
        return {"resolver_addresses": servers,
                "caveat": "127.0.0.53/127.0.0.1 is a local stub; per-interface DNS may differ."}
    except OSError as exc:
        return {"error": str(exc)}


def wan_ipv4_info(wan: str | None) -> dict:
    if not wan:
        return {"provided": False, "note": "WAN address not supplied; CGNAT cannot be inferred from LAN IP"}
    addr = ipaddress.IPv4Address(wan)
    shared = addr in ipaddress.IPv4Network("100.64.0.0/10")
    private = addr.is_private
    return {"provided": True, "wan_address": wan, "shared_address_space_100_64_10": shared,
            "private_or_special_purpose": private,
            "interpretation": ("WAN address in shared CGNAT range; upstream NAT is likely" if shared else
                               "WAN address is not globally routable; upstream NAT may exist" if private else
                               "WAN address may be globally routable; port reachability is untested")}


def run(args: argparse.Namespace) -> dict:
    v4addr = command_json(["ip", "-j", "-4", "addr", "show"])
    v6addr = command_json(["ip", "-j", "-6", "addr", "show"])
    v4route = command_json(["ip", "-j", "-4", "route", "get", args.ipv4_control])
    v6route = command_json(["ip", "-j", "-6", "route", "get", args.target])
    v4tcp = tcp_probe(args.ipv4_control, args.ipv4_control_port, socket.AF_INET, args.timeout)
    v6tcp = tcp_probe(args.target, args.port, socket.AF_INET6, args.timeout)
    v6addresses = addresses(v6addr, 6)
    return {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "probe": {"ipv6_target": args.target, "ipv6_port": args.port,
                  "ipv4_control": args.ipv4_control, "ipv4_control_port": args.ipv4_control_port,
                  "timeout_seconds": args.timeout},
        "local": {"ipv4_addresses": addresses(v4addr, 4), "ipv6_addresses": v6addresses,
                  "ipv4_route_to_control": v4route, "ipv6_route_to_vps": v6route,
                  "ipv6_path": classify_ipv6_path(v6addresses, v6route)},
        "connectivity": {"ipv4_tcp_control": v4tcp, "ipv6_tcp_target": v6tcp},
        "dns64": dns64_probe(), "resolver": resolver_description(),
        "router_wan_ipv4": wan_ipv4_info(args.wan_ipv4),
        "limits": [
            "TCP connection refusal and timeouts are not proofs of missing IP routing.",
            "DNS64/NAT64 normally helps IPv6 clients reach IPv4 servers, not the reverse.",
            "Protocol 41/253 traversal needs a controlled IPv4 receiver and return traffic.",
            "CGNAT cannot be confirmed from a private LAN IPv4 address alone.",
            "This diagnostic does not discover or provide an IPv4-to-IPv6 translator for a VPS.",
        ],
    }


def selftest() -> None:
    fake = {"ok": True, "data": [
        {"ifname": "lo", "addr_info": [
            {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]},
        {"ifname": "enp4s0", "addr_info": [
            {"family": "inet6", "local": "fe80::123", "prefixlen": 64, "scope": "link"},
            {"family": "inet", "local": "192.168.0.11", "prefixlen": 24, "scope": "global"}]},
    ]}
    v6 = addresses(fake, 6)
    assert len(v6) == 2 and not any(a["is_global_unicast"] for a in v6)
    assert addresses(fake, 4)[0]["address"] == "192.168.0.11"
    route = {"ok": True, "data": [
        {"dst": "2a05:541:104:66::1", "gateway": "fe80::1", "dev": "enp4s0"}]}
    assert classify_ipv6_path(v6, route)["route_reported"]
    assert not classify_ipv6_path(v6, route)["globally_routable_source_configured"]
    assert wan_ipv4_info("100.64.10.2")["shared_address_space_100_64_10"]
    assert not wan_ipv4_info(None)["provided"]
    print("SELFTEST OK: scope, route interpretation and WAN IPv4 classification")


def positive_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="2a05:541:104:66::1", help="IPv6 target (default: VPS)")
    parser.add_argument("--port", type=positive_port, default=22, help="target TCP port")
    parser.add_argument("--ipv4-control", default="77.88.8.8", help="known IPv4 test endpoint")
    parser.add_argument("--ipv4-control-port", type=positive_port, default=53)
    parser.add_argument("--timeout", type=float, default=2.0, help="per TCP probe seconds")
    parser.add_argument("--wan-ipv4", help="optional WAN IPv4 as shown in router admin UI")
    parser.add_argument("--output", type=Path, help="write full JSON report to file")
    parser.add_argument("--selftest", action="store_true", help="run offline checks")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    try:
        ipaddress.IPv6Address(args.target)
        ipaddress.IPv4Address(args.ipv4_control)
        if args.wan_ipv4:
            ipaddress.IPv4Address(args.wan_ipv4)
        if not 0 < args.timeout <= 15:
            raise ValueError("timeout must be >0 and <=15 seconds")
    except ValueError as exc:
        parser.error(str(exc))
    report = run(args)
    print("WAN capabilities probe")
    print("IPv4 TCP control:", "CONNECTED" if report["connectivity"]["ipv4_tcp_control"]["connected"] else "FAILED")
    print("IPv6 TCP VPS:    ", "CONNECTED" if report["connectivity"]["ipv6_tcp_target"]["connected"] else "FAILED")
    print("Global IPv6 src: ", "YES" if report["local"]["ipv6_path"]["globally_routable_source_configured"] else "NO")
    print("DNS64 AAAA seen: ", "YES" if report["dns64"]["synthesized_aaaa_seen"] else "NO")
    print("Interpretation:  ", report["local"]["ipv6_path"]["interpretation"])
    if not args.output:
        print("JSON report:     use --output report.json to save details")
    else:
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Saved report:    ", args.output)
        print("Privacy: report contains local IPs, DNS servers and interface names; review before sharing")
    return 0


if __name__ == "__main__":
    sys.exit(main())

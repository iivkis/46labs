#!/usr/bin/env python3
"""Find the *announcing network* of an IPv6-only service, then verify an explicitly
provisioned IPv4 service edge. No scanning or assumed IPv4-to-IPv6 mapping.

Standard library only; public metadata queries are opt-in, root is never needed.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import sys
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

TARGET = "2a05:541:104:66::1"
PREFIX = "2a05:541:104::/48"
RIPESTAT = "https://stat.ripe.net/data/network-info/data.json"
RDAP = "https://rdap.db.ripe.net/ip/"


def parse_network_info(document: dict, target: str) -> dict:
    if document.get("status") != "ok":
        raise ValueError("RIPEstat did not report success")
    data = document.get("data", {})
    prefix = ipaddress.IPv6Network(data["prefix"], strict=False)
    if ipaddress.IPv6Address(target) not in prefix:
        raise ValueError("Returned prefix does not contain the requested IPv6 address")
    asns = sorted({int(n) for n in data.get("asns", []) if str(n).isdigit()})
    return {
        "target_ipv6": target, "observed_bgp_prefix": str(prefix),
        "origin_asns": asns,
        "operator_hint": ("AS215540 (Global Connectivity Solutions LLP) was identified "
                          "in public routing sources; actual VPS reseller may differ"),
        "meaning": "An origin ASN identifies BGP announcement, NOT an IPv4 service mapping.",
    }


def read_json(url: str, timeout: float) -> dict:
    req = Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "46labs-hosting-edge/1.0 (non-scanning network metadata)",
    })
    with urlopen(req, timeout=timeout) as response:
        payload = response.read(262145)
        if len(payload) > 262144:
            raise ValueError("metadata response too large")
        return json.loads(payload)


def lookup(target: str, timeout: float) -> dict:
    query = RIPESTAT + "?" + urlencode({"resource": target})
    result = {"source": "RIPEstat network-info", "query_url": query}
    try:
        result["network"] = parse_network_info(read_json(query, timeout), target)
    except (ValueError, KeyError, URLError, HTTPError, TimeoutError, OSError) as exc:
        result["network_error"] = str(exc)
    rdap_url = RDAP + quote(target, safe=":")
    result["rdap_url"] = rdap_url
    try:
        rdap = read_json(rdap_url, timeout)
        result["registry"] = {
            "handle": rdap.get("handle"), "name": rdap.get("name"),
            "country": rdap.get("country"), "startAddress": rdap.get("startAddress"),
            "endAddress": rdap.get("endAddress"),
            "notice": "Registration metadata does not establish a contract with the VPS hoster.",
        }
    except (ValueError, KeyError, URLError, HTTPError, TimeoutError, OSError) as exc:
        result["rdap_error"] = str(exc)
    result["limitation"] = (
        "These are passive public metadata queries. No IPv4 endpoint is tested, "
        "and neither ASN nor RDAP ownership proves NAT46/SIIT availability.")
    return result


def provisioning_contract(target: str, port: int, service_ipv4: str | None) -> dict:
    ipaddress.IPv6Address(target)
    if not 1 <= port <= 65535:
        raise ValueError("port must be in 1..65535")
    if service_ipv4:
        addr = ipaddress.IPv4Address(service_ipv4)
        if not addr.is_global:
            raise ValueError("IPv4 service address must be globally routable")
    return {
        "goal": "Ordinary IPv4 TCP client reaches IPv6-only origin without client VPN/tunnel.",
        "ipv6_origin": {"address": target, "tcp_port": port, "ipv4_assigned_to_origin": False},
        "operator_edge_requirements": {
            "public_ipv4_service_address": service_ipv4,
            "ipv4_service_port": port,
            "ipv6_destination": target,
            "ipv6_destination_port": port,
            "implementation": "Provider-controlled SIIT-DC (RFC7755) with an "
                              "Explicit Address Mapping (EAM), or equivalent managed TCP relay.",
            "return_path": "IPv6 return packets must be routed to translator / relay.",
            "scope": "No access to, or dependency on, the VPS's existing IPv4 address.",
        },
        "can_run_end_to_end_test": service_ipv4 is not None,
        "acceptance": ("Start the repository's IPv6-only HMAC origin on the VPS; "
                       "send a fresh signed challenge from the IPv4-only client to "
                       "the operator-provisioned IPv4 service address; verify signed reply."),
        "important": ("A successful HMAC response proves a working IPv4-to-IPv6 service "
                      "path but does not, by itself, identify SIIT versus TCP proxy. "
                      "An IPv4 service address must actually be provisioned by the provider."),
    }


def prove(service_ipv4: str, port: int, token_file: Path, timeout: float) -> dict:
    # Reuse the existing auth implementation: one authoritative verification
    # path instead of copying the socket/HMAC code into every new lab.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "transition-edge"))
    from transition import probe_edge, secure_token
    ipaddress.IPv4Address(service_ipv4)
    if not ipaddress.IPv4Address(service_ipv4).is_global:
        raise ValueError("candidate IPv4 must be a globally routable, provider-provisioned service address")
    key = secure_token(token_file)
    result = probe_edge(service_ipv4, port, socket.AF_INET, key, timeout)
    result["candidate_origin"] = "supplied by operator / hosting provider, never discovered by scanning"
    result["ipv6_origin"] = TARGET
    result["interpretation"] = (
        "Authenticated IPv4-to-IPv6 service reachability established" if result.get("verified")
        else "No authenticated path. Do not infer that ALL relays are absent.")
    return result


def selftest() -> None:
    data = {"status": "ok", "data": {"prefix": PREFIX, "asns": [215540, "215540"]}}
    parsed = parse_network_info(data, TARGET)
    assert parsed["origin_asns"] == [215540]
    assert parsed["observed_bgp_prefix"] == PREFIX
    try:
        parse_network_info(data, "2001:db8::1")
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched prefix accepted")
    assert not provisioning_contract(TARGET, 18080, None)["can_run_end_to_end_test"]
    assert provisioning_contract(TARGET, 18080, "8.8.8.8")["can_run_end_to_end_test"]
    try:
        provisioning_contract(TARGET, 18080, "192.0.2.1")
    except ValueError:
        pass
    else:
        raise AssertionError("documentation address accepted as an IPv4 service")
    print("SELFTEST OK: BGP prefix validation, provisioning contract and test gate")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="offline checks, no network")
    lookup_parser = sub.add_parser("lookup", help="two public HTTPS metadata lookups, no packet scan")
    lookup_parser.add_argument("--target", default=TARGET)
    lookup_parser.add_argument("--timeout", type=float, default=5)
    for cmd in ("plan", "prove"):
        p = sub.add_parser(cmd, help="render provider provisioning contract" if cmd == "plan"
                           else "verify a configured IPv4 service path with HMAC")
        p.add_argument("--target", default=TARGET)
        p.add_argument("--port", type=int, default=18080)
        p.add_argument("--service-ipv4", required=(cmd == "prove"))
        if cmd == "prove":
            p.add_argument("--token-file", type=Path, required=True)
            p.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    try:
        if args.cmd == "selftest":
            selftest()
            return 0
        if args.cmd == "lookup":
            ipaddress.IPv6Address(args.target)
            if not 0 < args.timeout <= 15:
                raise ValueError("timeout must be >0 and <=15s")
            report = lookup(args.target, args.timeout)
        elif args.cmd == "plan":
            report = provisioning_contract(args.target, args.port, args.service_ipv4)
        else:
            if args.target != TARGET:
                raise ValueError("proof currently uses the configured default VPS IPv6 target")
            if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 15:
                raise ValueError("port or timeout out of range")
            report = prove(args.service_ipv4, args.port, args.token_file, args.timeout)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.cmd == "prove" and not report["verified"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

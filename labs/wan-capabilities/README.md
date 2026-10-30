# WAN capabilities (read-only, rootless)

Discover what an **actual IPv4-only or dual-stack access network** provides before testing experimental packet transports. Unlike the other labs, this diagnostic **uses the host's real network**. It does not create namespaces, install routes, or modify firewall/DNS settings.

## Run

From the repository root, with `nix develop` already active:

```sh
cd labs/wan-capabilities
python3 probe.py --selftest
python3 probe.py --output report.json
```

Probe another target/port, or optionally provide the **WAN** IPv4 shown in the router UI:

```sh
python3 probe.py --target 2a05:541:104:66::1 --port 22 --wan-ipv4 100.64.12.34 --output report.json
```

Do **not** pass a workstation's `192.168.*` LAN address as `--wan-ipv4`. A private LAN IPv4 alone is **not evidence of CGNAT**.

The report contains local addresses and configured DNS servers: **inspect/redact before publishing**. `report.json` is ignored by the repository.

## Checks

- IPv4/IPv6 addresses and route lookup (`ip -j`). A route advertised via `fe80::1` does **not** imply global IPv6 connectivity when no globally routable IPv6 source address exists.
- TCP to an IPv4 control (`77.88.8.8:53` by default) and configured IPv6 VPS (`2a05:541:104:66::1:22` by default). If the IPv4 TCP control is blocked, choose another trusted IPv4 host and port with `--ipv4-control` and `--ipv4-control-port`.
- `ipv4only.arpa` AAAA query through the OS resolver (a possible DNS64 signal). This is **not** authoritative NAT64 discovery unless the resolver is the active interface's provider-assigned resolver; see RFC 7050, RFC 8880, RFC 9872.
- Optional classification of a router-reported WAN IPv4. No third-party IP discovery or geolocation service.

## Limits

NAT64/DNS64 normally allows **IPv6 clients to reach IPv4 servers**, not IPv4 clients to reach IPv6-only servers. No discovery or deployment of NAT46/SIIT is performed.

This script does **not** test IP Protocol 41 or 253 over an ISP/CGNAT. For reliable results those require a **controlled public IPv4 receiver** and packet observations or acknowledgments. A successful local `sendto` proves nothing about remote delivery.

Only Python's standard library and `iproute2` are required; the repository's `flake.nix` includes both. CI runs only the offline `--selftest`, never live network probes.

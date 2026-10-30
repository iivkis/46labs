# SIIT-DC userspace packet lab (v0.3)

Experiment with **IPv4-only TCP client → stateless IP translation → IPv6-only origin**. Four isolated Linux network namespaces, two TUN interfaces on the translator, and a normal AF_INET6 HTTP origin. No tunnel endpoint on the client.

Addresses: client `198.18.0.2`; IPv4 service `198.19.0.22`; origin `2001:db8:66::2`. A fixed explicit mapping translates `198.19.0.22` to `2001:db8:66::2`; a /96 prefix embeds the client IPv4 source in the IPv6 source.

## Run

From the repository root:

```sh
nix develop
cd labs/siit-dc
python3 translator.py --selftest
sudo env PATH="$PATH" bash siit_lab.sh setup
sudo env PATH="$PATH" bash siit_lab.sh test
sudo env PATH="$PATH" bash siit_lab.sh status
sudo env PATH="$PATH" bash siit_lab.sh negative
sudo env PATH="$PATH" bash siit_lab.sh teardown
```

For capture after `test`: `sudo env PATH="$PATH" bash siit_lab.sh watch` in a second terminal while making another client request.

Expected HTTP response: `SIIT_DC_OK`.

Requires root, Linux network namespaces, and `/dev/net/tun`. The Python implementation intentionally supports **only unfragmented TCP and ICMP Echo**, not general SIIT, UDP, ICMP errors, IPv6 extension headers or PMTUD. It is for education and **must not** be deployed as an internet gateway.

A publicly reachable IPv4 service address and an on-path translator would still be necessary for real IPv4-only clients; this lab does not discover a universal direct IPv4-to-IPv6 route.

References: RFC 7755 (SIIT-DC), RFC 7757 (EAM), RFC 7915 (IP/ICMP translation).

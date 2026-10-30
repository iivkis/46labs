# Hosting edge: real IPv4 → IPv6 service path

This lab asks a **different** question from the ISP-side 6rd experiments:
Can the operator of the IPv6 VPS network expose a **public IPv4 service
address** and forward/translate that connection to our IPv6-only origin?

Target: `2a05:541:104:66::1`; public routing sources associate
`2a05:541:104::/48` with **AS215540 / Global Connectivity Solutions LLP**.
**BGP origin is not proof of who sold the VPS or who can provision its
border gateway.** Verify with your actual VPS hoster.

The VPS's existing IPv4 address is intentionally not used anywhere.

## Quick test (no root)

From the repository root, with `nix develop` active:

```sh
cd labs/hosting-edge
python3 provider.py selftest
python3 provider.py lookup
python3 provider.py plan
```

- `selftest`: deterministic syntax/logic checks, no network.
- `lookup`: fetches **public HTTPS metadata** from RIPEstat (BGP-announced
  prefix/ASN) and RIPE RDAP (registered holder). Only two metadata requests;
  **no ping, port scans or probing any IP in the provider's prefixes**.
  Routing information may change; interpret the current result, not old snapshots.
- `plan`: generates the exact required operator-side IPv4-to-IPv6 EAM /
  forwarding contract. The IPv4 service address is `null` until the
  operator actually provisions one; this is not an error.
  It **cannot** be automatically derived from the IPv6 VPS address.

## Operator provisioning

An IPv4-only client cannot route to an IPv6-only VPS by addressing it
with IPv4. In RFC 7755 (SIIT-DC), the hosting border router must own or
route a **real IPv4 service address** and associate it with the IPv6
origin via **Explicit Address Mapping (EAM)**, including a correct IPv6
return path to the same border function. This is not a feature provided
automatically just because the network announces both protocol families.

Give the actual hosting operator the following specification:

- Origin remains IPv6-only: `2a05:541:104:66::1`.
- Provide a dedicated **public IPv4 service address** at the operator
  border, NOT on the VPS.
- Map inbound TCP/18080 on that IPv4 address to
  `[2a05:541:104:66::1]:18080`, with working return traffic.
- Preferred: SIIT-DC / NAT46 at IP layer. A managed TCP relay is also
  acceptable for verifying connectivity, but it is NOT the same as an IP tunnel.
- For real SSH afterward, map port 22 in both directions / set the
  appropriate IP-layer EAM and return routing. Distinguish a full IP
  translator from an L4 proxy.
- Request the **specific IPv4 service address and activation status**;
  do not try arbitrary IPv4s in the ASN.

The registry lists an ASN/organisation, not necessarily the customer
service of your specific VPS reseller. Ask the VPS hoster first.

## Once the IPv4 service address exists

Reuse the authenticated **IPv6-only origin** already implemented in
`../transition-edge`, avoiding duplicate crypto and TCP probe logic.

1. On your client, generate a local secret:

```sh
cd ../transition-edge
python3 transition.py token --output origin.token
```

2. Transfer `transition.py`, `origin.py`, and `origin.token` to the
VPS via its **already functioning management channel** / an IPv6-capable
admin connection (the IPv4-only laptop itself still cannot directly
reach the IPv6 VPS). Keep the token private.

3. On the VPS, start the test service with an allowed TCP/18080 firewall
rule. The server explicitly binds only `AF_INET6/IPV6_V6ONLY`:

```sh
python3 origin.py --bind 2a05:541:104:66::1 \
  --port 18080 --token-file origin.token
```

4. From the IPv4-only client run (substitute the **actual
provisioned** IPv4 service address):

```sh
cd ../hosting-edge
python3 provider.py plan --service-ipv4 SERVICE_IPV4
python3 provider.py prove --service-ipv4 SERVICE_IPV4 \
  --port 18080 --token-file ../transition-edge/origin.token
```

Only `"verified": true` proves the path reached the origin holding the
shared private key. If `verified` is false, it could mean provisioning
is missing, firewall/port filtering, or broken return routing.

**Warning:** this HMAC test proves a working IPv4-to-IPv6 **service
path**, not that the implementation is specifically SIIT. A TCP proxy can
produce exactly the same result. If you want packet-level classification,
capture IPv6 traffic at the origin and coordinate with the operator's
translator. The lab does not create the missing IPv4 edge.

## Safety, scope and limitations

- No public port enumeration, no probes to random IPv4s announced by AS215540.
- No host route/firewall changes, no root, no dependency beyond the existing
  root `flake.nix`.
- `lookup` accesses RIPE metadata over HTTPS, so it requires ordinary
  IPv4 internet and DNS. `plan`/`selftest` work offline.
- Keep `origin.token` out of Git and stop the test service after use.
- Positive BGP metadata is **not** evidence of NAT46 availability.
- This is the next measurable step, not a claim of a direct tunnel.

References: [RFC 7755 SIIT-DC](https://www.rfc-editor.org/rfc/rfc7755),
[RIPEstat](https://stat.ripe.net/),
[PeeringDB AS215540](https://www.peeringdb.com/asn/215540).

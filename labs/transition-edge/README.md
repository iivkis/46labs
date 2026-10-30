# Transition edge discovery

Real-world tests for two *existing-infrastructure* IPv4-to-IPv6 paths.

This is a **rootless** lab. It does not create tunnels, change routes or firewalls, scan public IPv4 addresses, or provision provider equipment.

## Requirements

From the repository root run `nix develop`. All dependencies (`python3` and `iproute2`) are already in the root `flake.nix`. No new packages required.

## A. Operator transition access: 6rd and 6a44

On the **IPv4-only client**:

```sh
cd labs/transition-edge
python3 transition.py selftest
python3 transition.py inspect
python3 transition.py 6a44
```

- `inspect` lists locally configured SIT/IP6 tunnels and IPv6 routes. No discovered tunnel **does not prove** that the ISP lacks a border relay.
- `6a44` sends **one** RFC 6751 bubble from UDP port 1027 to the reserved relay anycast `192.88.99.2:1027`, with an unpredictable 64-bit bubble ID. A valid matching reply suggests an accessible 6a44 relay. Lack of reply is inconclusive. The client is not configured for native IPv6 automatically.
- 6rd provisioning is usually delivered to the **WAN side of the CPE** using RFC 5969 DHCPv4 option **212**, or via non-DHCP ISP provisioning. With Rostelecom PPPoE, a LAN host generally cannot retrieve these parameters itself. Inspect the *router's WAN configuration/provider documentation*, not the client LAN DHCP lease. The diagnostic deliberately does not generate DHCP requests or alter the WAN.

If a **real WAN-side** option 212 has been obtained, decode its bytes:

```sh
python3 transition.py decode-6rd --hex 'd416082020010db80000000000000000000000000a000001' --ce-ipv4 10.100.100.1
```

This is an RFC test fixture, **not a live provider relay**. It calculates delegated `2001:db8:6464:100::/56`. The `--ce-ipv4` argument means the actual *customer-edge WAN IPv4*, not `192.168.0.11` on the laptop. A configured / working 6rd service still requires an operator border relay and valid routing and firewall behavior.

## B. Hosting edge: prove an IPv4 service maps to our IPv6-only VPS

**Important prerequisite:** the hosting provider (or another existing operator) must expose a **specific IPv4 service address**, and configure an IPv4→IPv6 path for TCP port `18080` to the IPv6-only VPS `2a05:541:104:66::1`. The VPS itself needs *no IPv4*. If the provider offers no such service IP and mapping, this test cannot magically create it.

1. Create a private shared key on the client:

```sh
cd labs/transition-edge
python3 transition.py token --output origin.token
```

2. Transfer **only** `origin.py`, `transition.py`, and `origin.token` to the VPS via an **already-working management channel** (hosting console / file upload / an IPv6-capable administrative connection). Do **not** assume the IPv4-only client can SCP directly to an IPv6-only VPS. Keep the key private (`chmod 600 origin.token`).

3. Run on the VPS using its Python 3 runtime:

```sh
python3 origin.py --bind 2a05:541:104:66::1 --port 18080 --token-file origin.token
```

Open TCP 18080 in the VPS firewall only where appropriate; restrict access during testing. The server binds **AF_INET6 + IPV6_V6ONLY**, and never binds IPv4.

4. If the testing machine has native IPv6 (or on the VPS itself), optionally check the IPv6 origin:

```sh
python3 transition.py origin-v6 --ipv6 2a05:541:104:66::1 --port 18080 --token-file origin.token
```

5. From the **IPv4-only client**, test the **provider-supplied service IPv4**:

```sh
python3 transition.py edge --ipv4 SERVICE_IPV4 --port 18080 --token-file origin.token
```

`verified: true` means an IPv4 socket received a correct HMAC-SHA256 response from the key-holding origin for a fresh random challenge. This verifies a usable **IPv4→IPv6 service path**, not which transition technique was used: **SIIT, TCP proxy and NAT46 can all satisfy the test**. On the VPS, inspect `tcpdump -ni any 'ip6 and tcp port 18080'` if packet-level evidence is required. The origin's source address/port may help characterize the type of forwarding, but is not definitive proof of stateless translation.

If no verified response exists, check the candidate IPv4 service's provisioning, forwarding configuration, VPS firewall, and the origin process. Do not interpret `connection timed out` as proof that *all* transitions are impossible.

## Security and limitations

- Token files are ignored by Git. **Never commit or paste `origin.token`.** The client sends random challenges; the server returns HMAC digests but not the secret.
- The test server is a minimal diagnostic HTTP endpoint, not a hardened production service. Stop it after testing (`Ctrl+C`).
- The 6a44 packet and edge TCP test send real traffic **only when explicitly invoked**. `selftest`, `inspect` and `decode-6rd` do not make internet requests.
- `6rd` / `6a44` provide **IPv6-over-IPv4 access via an operator relay**. They are not NAT46, and they still require a transition node even though the VPS remains IPv6-only.
- Standards: [RFC 5969](https://www.rfc-editor.org/rfc/rfc5969) (6rd option 212), [RFC 6751](https://www.rfc-editor.org/rfc/rfc6751) (6a44), [RFC 7755](https://www.rfc-editor.org/rfc/rfc7755) (SIIT-DC), [RFC 7915](https://www.rfc-editor.org/rfc/rfc7915) (IP/ICMP translation).

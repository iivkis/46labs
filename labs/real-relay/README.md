# Real 6rd relay path probe (Protocol 41)

Goal: confirm that a **real ISP border relay** can deliver packets from an
IPv4-only CE to the **IPv6-only destination** `2a05:541:104:66::1`.
The VPS IPv4 address is never used.

Unlike the namespace labs, this sends a *real* IPv4 Protocol 41 packet to an
**explicitly configured ISP relay**. It never changes host routes, DNS,
interfaces or firewall. `probe` needs root (CAP_NET_RAW); all other commands
are unprivileged.

**This lab is a raw packet *probe*, not yet a working SSH tunnel.** A verified
TCP SYN-ACK demonstrates that the target port can be reached via the configured
relay. To run actual SSH, a working IPv6 interface/6rd tunnel must subsequently
be configured on the actual CE/router.

## 1. Find real 6rd provisioning parameters

6rd is NOT a universal public relay. RFC 5969 requires your ISP to supply
four items: provider IPv6 prefix, IPv4 mask length, the CE **WAN IPv4** and
a border-relay IPv4. These are normally found in the **WAN** provisioning
of the home CPE (DHCPv4 option 212 or provider-specific PPP/IPCP/TR-069),
not the LAN DHCP lease. See [RFC 5969](https://www.rfc-editor.org/rfc/rfc5969.html).

The last `transition-edge` 6a44 probe received no reply and we have no
evidence that Rostelecom provisions a 6rd service on your line. The
configuration file included here is **documentation-only**: do not treat
`10.0.0.1` as a real border relay.

## 2. Run preflight first (no packets sent)

From repo root (Nix dev shell active):

```sh
cd labs/real-relay
python3 relay.py selftest
python3 relay.py preflight --config example-6rd.json
```

The example deliberately fails readiness. After obtaining **genuine** ISP
values, copy `example-6rd.json` to `local-6rd.json` and replace all
fields:

```json
{
  "ipv4_mask_length": 8,
  "ipv6_prefix": "2001:db8::/32",
  "border_relay_ipv4": "10.0.0.1",
  "ce_wan_ipv4": "10.100.100.1",
  "target_ipv6": "2a05:541:104:66::1",
  "target_port": 22
}
```

These sample values are test vectors, not usable public addresses. A private
CE-WAN IPv4 might be legitimate *within the operator's own 6rd domain*;
do not replace it with an arbitrary external NAT address.

Run:

```sh
python3 relay.py preflight --config local-6rd.json
```

`ready_to_send: true` only means the local source IPv4 equals the
configured CE-WAN address and the parameters look suitable. It does not
confirm the relay works.

### Why a normal home Linux PC will fail preflight

Earlier diagnostics showed Linux using `192.168.0.11` via CPE
`192.168.0.1`. Your actual PPPoE/WAN IPv4 is on the **router**, so the
Linux host cannot simply claim that address. A 6rd CE should run at the
operator-facing WAN boundary. IPv4 NAT usually cannot transparently
forward Protocol 41, and the return route is based on the *real* CE IPv4.

This lab **refuses to send** when the local IPv4 routing source differs
from the provisioned CE-WAN source. No raw-IP spoofing or NAT bypass.

## 3. Real packet test (only if preflight succeeds)

On the host which actually owns the CE-WAN IPv4, with working raw sockets:

```sh
sudo env PATH="$PATH" python3 relay.py probe --config local-6rd.json --kind both --timeout 3
```

Exactly **one ICMPv6 Echo Request and one TCP SYN** are encapsulated in
IPv4 Protocol 41 to your configured relay. Received IP Protocol 41 is
validated: outer IPv4 relay and CE addresses, inner IPv6 source/target,
checksums and random ICMP identifier or TCP sequence.

A verified `ICMPv6_ECHO_REPLY` shows an end-to-end IPv6 ping path.
A verified `TCP_SYN_ACK` shows that `[2a05:541:104:66::1]:22`
accepted a SYN through the specified relay. The test does **not** establish
an SSH session; the crafted SYN is not part of the host TCP stack.

No response is **inconclusive**: no service, filtering, ICMP disabled,
relay inaccessible, wrong provisioning or return routing can all produce
the same result. If the response is verified, configure 6rd normally
on the CE to use SSH. The program deliberately does **not** change the
default route or add a tunnel on the host.

For packet-level corroboration when you control the WAN-facing CE, run
`sudo tcpdump -ni WAN_DEVICE 'ip proto 41'` during the probe. On the VPS,
you can watch `sudo tcpdump -ni any 'ip6 and (icmp6 or tcp port 22)'`.
Those captures may expose provider addresses: review before sharing.

## 4. After a verified probe

Configure a standard kernel 6rd SIT tunnel on the operator-facing
CE/router using the **same provisioned prefix, mask and relay**, then
configure an IPv6 source address from the delegated prefix and IPv6
routing. With native IPv6 reachability confirmed:

```sh
ssh -6 user@2a05:541:104:66::1
```

Do not assign the PPPoE CE-WAN address to a second host or replace the
normal default route on your workstation. If this ISP offers no 6rd relay,
**this path cannot succeed** and the next step must be another
provider-supported IPv4-to-IPv6 transition service.

## Safety / limits

- No third-party probes, no guessed relay IPs, no scans, no changes to WAN
  router or host routing tables.
- `probe` uses two raw AF_INET sockets and one timed receive window per
  test, and needs CAP_NET_RAW.
- Only IPv4 Protocol 41 is used; if blocked by NAT/CGNAT, packets cannot
  magically reach a 6rd border relay.
- The IPv6 destination is the VPS; the IPv4 address of the VPS is **never
  used or probed**.
- `local-6rd.json` contains WAN IPv4 provisioning and is ignored by Git.
- The script intentionally does not implement a full 6rd IPv6 stack,
  automatic CE setup, or SSH authentication.

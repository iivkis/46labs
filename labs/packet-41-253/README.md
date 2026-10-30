# Protocol 41 and experimental protocol 253 (v0.2)

An isolated Linux network experiment with four network namespaces: IPv4 client, IPv4 router, SIT edge, and IPv6-only server. IPv6 travels inside IPv4 via protocol 41. A raw IPv4 packet with experimental protocol 253 is separately delivered to the **IPv4 edge**, not the IPv6 server.

## Run

From the repository root:

```sh
nix develop
cd labs/packet-41-253
sudo env PATH="$PATH" bash packet_lab.sh setup
sudo env PATH="$PATH" bash packet_lab.sh test
sudo env PATH="$PATH" bash packet_lab.sh status
sudo env PATH="$PATH" bash packet_lab.sh negative
sudo env PATH="$PATH" bash packet_lab.sh ping6
sudo env PATH="$PATH" bash packet_lab.sh teardown
```

Optional commands: `watch41`, `watch253`, `send253`.

The `negative` command installs an IPv6 /128 blackhole on the edge instead of cycling its SIT interface, removes it in a trap, and verifies recovery. It tests dependence on the edge's IPv6 forwarding, **not** absence of all IPv4/IPv6 transition methods on the internet.

Requires a Linux kernel with network namespaces, SIT support, and root; the dev shell provides the userspace dependencies. No host network settings are changed.

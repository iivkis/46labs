# 46labs

Linux network experiments exploring IPv4/IPv6 interoperability, translation and actual ISP capabilities.

## Labs

- [Protocol 41 and 253](labs/packet-41-253/README.md): IPv6-in-IPv4 SIT tunneling and raw experimental IPv4 packet forwarding in isolated namespaces.
- [SIIT-DC](labs/siit-dc/README.md): stateless IPv4-to-IPv6 translation for ICMP Echo and TCP in isolated namespaces.
- [WAN capabilities](labs/wan-capabilities/README.md): **read-only, rootless** diagnostics of actual IPv4/IPv6 connectivity.
- [Transition edge](labs/transition-edge/README.md): 6rd DHCP option 212 decoding, 6a44 relay probe and authenticated IPv4-to-IPv6 service verification.
- [Real relay](labs/real-relay/README.md): ISP-provisioned 6rd readiness check and verified raw Protocol 41 ICMP/TCP SYN path to IPv6-only VPS (no host route changes).

## Development

On Linux with Nix flakes:

```sh
nix develop
```

For isolated namespace experiments:

```sh
cd labs/siit-dc
sudo env PATH="$PATH" bash siit_lab.sh setup
sudo env PATH="$PATH" bash siit_lab.sh test
sudo env PATH="$PATH" bash siit_lab.sh teardown
```

For actual provider checks, run unprivileged preflight first:

```sh
cd labs/real-relay
python3 relay.py selftest
python3 relay.py preflight --config example-6rd.json
```

The real Protocol 41 probe requires valid ISP-provisioned 6rd parameters,
a CE-WAN IPv4 owned by the running host, and root/CAP_NET_RAW. It does **not**
automatically create an IPv6/SSH tunnel.

CI intentionally runs only quick unprivileged syntax/selftests.
Prototypes are not production gateways, and namespace tests do not
demonstrate real Internet reachability.

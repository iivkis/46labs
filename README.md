# 46labs

Linux network experiments exploring IPv4/IPv6 interoperability, translation and actual ISP capabilities.

## Labs

- [Protocol 41 and 253](labs/packet-41-253/README.md): IPv6-in-IPv4 SIT tunneling and raw experimental IPv4 packet forwarding in isolated namespaces.
- [SIIT-DC](labs/siit-dc/README.md): stateless IPv4-to-IPv6 translation for ICMP Echo and TCP in isolated namespaces.
- [WAN capabilities](labs/wan-capabilities/README.md): **read-only, rootless** diagnostics of the actual host's IPv4/IPv6 connectivity and DNS64 hints.
- [Transition edge](labs/transition-edge/README.md): 6rd option 212 decoding, optional RFC 6751 6a44 relay probe, and authenticated IPv4-to-IPv6 service verification against an IPv6-only VPS.

## Development

On Linux with Nix flakes:

```sh
nix develop
```

For namespace experiments:

```sh
cd labs/siit-dc
sudo env PATH="$PATH" bash siit_lab.sh setup
sudo env PATH="$PATH" bash siit_lab.sh test
sudo env PATH="$PATH" bash siit_lab.sh teardown
```

For real network diagnostics, **do not use sudo**:

```sh
cd labs/wan-capabilities
python3 probe.py --output report.json
cd ../transition-edge
python3 transition.py selftest
python3 transition.py inspect
python3 transition.py 6a44
```

Each laboratory explains assumptions and limitations in its README. The transition-edge authentication origin uses a separate shared key, and cannot discover or create a provider IPv4-to-IPv6 edge where none is offered.

CI runs only quick, unprivileged syntax and selftests; full namespace integration tests must be run locally. These prototypes are not production gateways. Results of local namespace tests do **not** establish internet reachability.

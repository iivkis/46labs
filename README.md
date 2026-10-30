# 46labs

Linux network experiments exploring IPv4/IPv6 interoperability, translation and actual ISP capabilities.

## Labs

- [Protocol 41 and 253](labs/packet-41-253/README.md): IPv6-in-IPv4 SIT tunneling and raw experimental IPv4 packet forwarding in isolated namespaces.
- [SIIT-DC](labs/siit-dc/README.md): stateless IPv4-to-IPv6 translation for ICMP Echo and TCP in isolated namespaces.
- [WAN capabilities](labs/wan-capabilities/README.md): **read-only, rootless** diagnostics of the actual host's IPv4/IPv6 connectivity and DNS64 hints.

## Development

On Linux with Nix flakes:

```sh
nix develop
```

To run a namespace lab, enter its directory and use the named setup/test/teardown script as root; preserve Nix's PATH with `sudo env PATH="$PATH"`.

```sh
cd labs/siit-dc
sudo env PATH="$PATH" bash siit_lab.sh setup
sudo env PATH="$PATH" bash siit_lab.sh test
sudo env PATH="$PATH" bash siit_lab.sh teardown
```

For actual WAN diagnostics, **do not use sudo**:

```sh
cd labs/wan-capabilities
python3 probe.py --output report.json
```

Namespace labs do not alter host networking. WAN diagnostics send only explicit TCP connection attempts and a DNS lookup; they do not change configuration.

CI intentionally runs only quick, unprivileged syntax and selftests; full namespace integration tests must be run locally. These prototypes are not production gateways. Results of local namespace tests do **not** establish internet reachability.

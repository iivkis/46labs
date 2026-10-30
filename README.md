# 46labs

Linux network experiments exploring IPv4/IPv6 interoperability, translation and actual ISP capabilities.

## Labs

- [Protocol 41 and 253](labs/packet-41-253/README.md): IPv6-in-IPv4 SIT tunneling and raw experimental IPv4 packet forwarding in isolated namespaces.
- [SIIT-DC](labs/siit-dc/README.md): stateless IPv4-to-IPv6 translation for ICMP Echo and TCP in isolated namespaces.
- [WAN capabilities](labs/wan-capabilities/README.md): read-only diagnostics of actual IPv4/IPv6 connectivity.
- [Transition edge](labs/transition-edge/README.md): 6rd option 212 decoding, 6a44 relay probe and authenticated IPv4-to-IPv6 service verification.
- [Real relay](labs/real-relay/README.md): configured 6rd relay probe with raw Protocol 41 ICMP/TCP traffic.
- [Hosting edge](labs/hosting-edge/README.md): identify the VPS IPv6 prefix announcer via public RIPE data, produce an explicit SIIT-DC provisioning contract and verify a provider-supplied IPv4 entry with HMAC.

## Development

On Linux with Nix flakes:

```sh
nix develop
```

For the newest read-only lab:

```sh
cd labs/hosting-edge
python3 provider.py selftest
python3 provider.py lookup
python3 provider.py plan
```

The authenticated IPv4→IPv6 service test can run only when the hosting
operator has provisioned a **specific IPv4 service address** pointing
to the IPv6-only origin. It does **not** use the VPS's existing IPv4.

CI stays minimal: unprivileged syntax and offline selftests only.
Full namespace experiments run locally. Prototype networking tools are
not production gateways. Local tests do not establish public Internet
reachability.

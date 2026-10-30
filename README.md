# 46labs

Isolated Linux network labs for exploring IPv4/IPv6 interoperability and packet forwarding.

## Labs

- [`labs/packet-41-253`](labs/packet-41-253/README.md): IPv6-in-IPv4 (SIT, protocol 41) and experimental IPv4 protocol 253.
- [`labs/siit-dc`](labs/siit-dc/README.md): stateless IPv4-to-IPv6 translation for ICMP Echo and TCP.

Each lab runs in Linux network namespaces and requires root and a Linux kernel with the necessary networking features. They do not change the host routes, DNS, or firewall.

## Development

On NixOS or other systems with Nix flakes:

```sh
nix develop
```

In each lab directory, use the lab-specific script (`packet_lab.sh` or `siit_lab.sh`). For example:

```sh
cd labs/siit-dc
sudo env PATH="$PATH" bash siit_lab.sh setup
sudo env PATH="$PATH" bash siit_lab.sh test
sudo env PATH="$PATH" bash siit_lab.sh teardown
```

`sudo env PATH="$PATH"` preserves tools from the Nix dev shell. Do not use these prototype translators as public internet gateways.

CI intentionally runs only quick unprivileged syntax and unit checks. Full network namespace integration tests run locally.

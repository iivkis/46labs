#!/usr/bin/env bash
# Isolated protocol-41 and protocol-253 lab; real network is untouched.
set -Eeuo pipefail
D="$(cd -- "$(dirname -- "$0")" && pwd)"
C=xip_client; R=xip_router; E=xip_edge; S=xip_server
NAMES=("$C" "$R" "$E" "$S")
ns() { ip netns exec "$1" "${@:2}"; }
has() { ip netns list | grep -Eq "^$1([[:space:]]|$)"; }
root() { [[ "$EUID" -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }; }
present() { for n in "${NAMES[@]}"; do has "$n" || { echo "Missing $n. Run setup." >&2; exit 1; }; done; }
cleanup() { for n in "${NAMES[@]}"; do if has "$n"; then ip netns del "$n"; fi; done; }
setup() {
  for n in "${NAMES[@]}"; do if has "$n"; then echo "Already exists: $n. Refusing to overwrite." >&2; exit 1; fi; done
  trap 'echo "Setup failed, cleaning up" >&2; cleanup' ERR
  for n in "${NAMES[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done
  ip link add xc0 type veth peer name xr0
  ip link set xc0 netns "$C"; ip link set xr0 netns "$R"
  ip link add xr1 type veth peer name xe0
  ip link set xr1 netns "$R"; ip link set xe0 netns "$E"
  ip link add xe1 type veth peer name xs0
  ip link set xe1 netns "$E"; ip link set xs0 netns "$S"
  ip -n "$C" -4 addr add 198.18.0.2/30 dev xc0
  ip -n "$R" -4 addr add 198.18.0.1/30 dev xr0
  ip -n "$R" -4 addr add 198.18.0.5/30 dev xr1
  ip -n "$E" -4 addr add 198.18.0.6/30 dev xe0
  ip -n "$E" -6 addr add 2001:db8:66::1/64 dev xe1
  ip -n "$S" -6 addr add 2001:db8:66::2/64 dev xs0
  for entry in "$C:xc0" "$R:xr0" "$R:xr1" "$E:xe0" "$E:xe1" "$S:xs0"; do
    ip -n "${entry%%:*}" link set "${entry##*:}" up
  done
  ip -n "$C" -4 route add default via 198.18.0.1
  ip -n "$E" -4 route add 198.18.0.0/30 via 198.18.0.5
  ip -n "$S" -6 route add default via 2001:db8:66::1
  ns "$R" sysctl -qw net.ipv4.ip_forward=1
  ns "$E" sysctl -qw net.ipv6.conf.all.forwarding=1
  ns "$C" ip tunnel add xip6 mode sit local 198.18.0.2 remote 198.18.0.6 ttl 64
  ns "$E" ip tunnel add xip6 mode sit local 198.18.0.6 remote 198.18.0.2 ttl 64
  ip -n "$C" link set xip6 up; ip -n "$E" link set xip6 up
  ip -n "$C" -6 addr add 2001:db8:41::0/127 dev xip6
  ip -n "$E" -6 addr add 2001:db8:41::1/127 dev xip6
  ip -n "$C" -6 route add 2001:db8:66::/64 via 2001:db8:41::1 dev xip6
  trap - ERR
  echo 'SETUP OK. IPv4-only middle router and IPv6-only end-server created.'
  echo "Next: sudo env PATH=\"\$PATH\" bash $0 test"
}
labtest() {
  present
  echo '--- 1. IPv4 packet crosses IPv4-only router ---'
  ns "$C" ping -4 -c 2 -W 2 198.18.0.6
  echo '--- 2. IPv6 packet reaches IPv6-only server THROUGH SIT edge ---'
  ns "$C" ping -6 -c 3 -W 2 2001:db8:66::2
  echo '--- 3. Check routes ---'
  ns "$C" ip -6 route get 2001:db8:66::2
  ns "$R" ip -br addr
  echo '--- 4. Experimental IP protocol 253 ---'
  if command -v tcpdump >/dev/null; then
    log="$(mktemp)"; code=0
    timeout 8 ip netns exec "$E" tcpdump -ni xe0 -c 1 -vv 'ip proto 253' >"$log" 2>&1 & pid=$!
    sleep 1
    ns "$C" python3 "$D/xip_probe.py"
    wait "$pid" || code=$?
    cat "$log"; rm -f "$log"
    [[ "$code" -eq 0 ]] || echo 'WARNING: no capture; try watch253/send253 in two terminals.'
  else
    echo 'tcpdump not found: optional capture skipped.'
    ns "$C" python3 "$D/xip_probe.py"
  fi
}
status() {
  present
  for n in "$C" "$R" "$E" "$S"; do
    echo "--- $n ---"
    ip -n "$n" -br link
    ip -n "$n" -4 route show
    ip -n "$n" -6 route show
  done
  echo '--- SIT details on client ---'
  ns "$C" ip -d link show xip6
  echo '--- SIT details on edge ---'
  ns "$E" ip -d link show xip6
  echo '--- edge IPv6 forwarding ---'
  ns "$E" sysctl net.ipv6.conf.all.forwarding
}
negative() {
  present
  echo 'Temporarily BLACKHOLING the IPv6 destination route on the edge.'
  echo 'This keeps the SIT interface UP and avoids destructive down/up transitions.'
  ip -n "$E" -6 route add blackhole 2001:db8:66::2/128
  trap 'ip -n "$E" -6 route del blackhole 2001:db8:66::2/128 2>/dev/null || true' EXIT
  if ns "$C" ping -6 -c 1 -W 2 2001:db8:66::2; then
    echo 'UNEXPECTED SUCCESS: check whether the blackhole is on the forwarding path.'
    fail=1
  else
    echo 'EXPECTED FAILURE: edge forwarding to IPv6 server was disabled.'
    fail=0
  fi
  ip -n "$E" -6 route del blackhole 2001:db8:66::2/128
  trap - EXIT
  echo '--- Verifying that connectivity has recovered ---'
  if ! ns "$C" ping -6 -c 3 -W 2 2001:db8:66::2; then
    echo 'ERROR: connectivity was not restored. Inspect diagnostics:' >&2
    status >&2
    exit 1
  fi
  echo 'RECOVERY OK: IPv6 reachable again.'
  return "$fail"
}
root
case "${1:-help}" in
  setup) setup ;;
  test) labtest ;;
  negative) negative ;;
  ping6) present; ns "$C" ping -6 -c 4 -W 2 2001:db8:66::2 ;;
  watch41) present; ns "$R" tcpdump -ni xr1 -vv 'ip proto 41' ;;
  watch253) present; ns "$E" tcpdump -ni xe0 -vv 'ip proto 253' ;;
  send253) present; ns "$C" python3 "$D/xip_probe.py" ;;
  status) status ;;
  teardown) cleanup; echo 'Four lab namespaces removed.' ;;
  *) echo "Usage: $0 setup|test|negative|status|watch41|ping6|watch253|send253|teardown" ;;
esac

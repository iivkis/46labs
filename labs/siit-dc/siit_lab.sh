#!/usr/bin/env bash
# XIP SIIT-DC subset network lab, fully isolated in Linux network namespaces.
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="/tmp/xip-siit-lab-state"
CLIENT='xip4_client'
ROUTER='xip4_router'
XLAT='xip_xlat'
SERVER='xip6_server'

need_root() {
    if [[ "${EUID}" != 0 ]]; then echo 'Run with sudo env PATH="$PATH" bash siit_lab.sh COMMAND' >&2; exit 1; fi
}
ns() { ip netns exec "$1" "${@:2}"; }
existing() { ip netns list | grep -q "^${1}\([[:space:]]\|$\)"; }

setup() {
    for n in "$CLIENT" "$ROUTER" "$XLAT" "$SERVER"; do
        if existing "$n"; then echo "Namespace $n already exists; run teardown first" >&2; exit 1; fi
    done
    if [[ ! -c /dev/net/tun ]]; then
        echo '/dev/net/tun unavailable: load Linux tun module (modprobe tun) before setup' >&2
        exit 1
    fi
    mkdir -p "$STATE_DIR"
    python3 "$HERE/translator.py" --selftest

    for n in "$CLIENT" "$ROUTER" "$XLAT" "$SERVER"; do ip netns add "$n"; ip -n "$n" link set lo up; done
    ip link add x4c type veth peer name x4r
    ip link set x4c netns "$CLIENT"
    ip link set x4r netns "$ROUTER"
    ip link add x4r2 type veth peer name x4e
    ip link set x4r2 netns "$ROUTER"
    ip link set x4e netns "$XLAT"
    ip link add x6e type veth peer name x6s
    ip link set x6e netns "$XLAT"
    ip link set x6s netns "$SERVER"

    for spec in "$CLIENT:x4c" "$ROUTER:x4r" "$ROUTER:x4r2" "$XLAT:x4e" "$XLAT:x6e" "$SERVER:x6s"; do
        n="${spec%%:*}"; dev="${spec##*:}"
        ip -n "$n" link set "$dev" up
    done
    ip -n "$CLIENT" addr add 198.18.0.2/30 dev x4c
    ip -n "$ROUTER" addr add 198.18.0.1/30 dev x4r
    ip -n "$ROUTER" addr add 198.18.0.5/30 dev x4r2
    ip -n "$XLAT" addr add 198.18.0.6/30 dev x4e
    ip -n "$XLAT" -6 addr add 2001:db8:66::1/64 dev x6e
    ip -n "$SERVER" -6 addr add 2001:db8:66::2/64 dev x6s

    ns "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
    ns "$XLAT" sysctl -qw net.ipv4.ip_forward=1
    ns "$XLAT" sysctl -qw net.ipv6.conf.all.forwarding=1
    ns "$CLIENT" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    ns "$ROUTER" sysctl -qw net.ipv6.conf.all.disable_ipv6=1

    ip -n "$CLIENT" route add default via 198.18.0.1
    ip -n "$CLIENT" route add 198.19.0.22/32 via 198.18.0.1 mtu 1200
    ip -n "$ROUTER" route add 198.19.0.22/32 via 198.18.0.6
    ip -n "$XLAT" route add 198.18.0.0/30 via 198.18.0.5
    ip -n "$SERVER" -6 route add 2001:db8:46::/96 via 2001:db8:66::1 mtu 1280

    ip -n "$XLAT" tuntap add dev siit4 mode tun
    ip -n "$XLAT" tuntap add dev siit6 mode tun
    ip -n "$XLAT" link set siit4 mtu 1280 up
    ip -n "$XLAT" link set siit6 mtu 1280 up
    ip -n "$XLAT" -4 route add 198.19.0.22/32 dev siit4
    ip -n "$XLAT" -6 route add 2001:db8:46::/96 dev siit6
    echo 'SETUP OK: client IPv4-only, middle router IPv4-only, server IPv6-only; translator uses two TUN interfaces.'
}

pid_running() { [[ -s "$1" ]] && kill -0 "$(cat "$1")" 2>/dev/null; }
start_process() {
    local n="$1" name="$2" file="$3"
    if pid_running "$STATE_DIR/$name.pid"; then echo "$name already running"; return; fi
    ip netns exec "$n" python3 -u "$HERE/$file" >"$STATE_DIR/$name.log" 2>&1 &
    echo "$!" >"$STATE_DIR/$name.pid"
    sleep 0.5
    if ! pid_running "$STATE_DIR/$name.pid"; then
        echo "$name failed to start:" >&2
        cat "$STATE_DIR/$name.log" >&2
        exit 1
    fi
    echo "STARTED $name PID $(cat "$STATE_DIR/$name.pid")"
}
start() {
    if ! existing "$XLAT"; then echo 'Run setup first' >&2; exit 1; fi
    start_process "$XLAT" translator translator.py
    start_process "$SERVER" origin http_origin.py
}
stop_one() {
    local name="$1" pidfile="$STATE_DIR/$1.pid"
    if pid_running "$pidfile"; then
        kill "$(cat "$pidfile")" || true
        sleep 0.2
    fi
    rm -f "$pidfile"
}
stop() { stop_one translator; stop_one origin; echo 'STOPPED background translator and HTTP origin'; }

test() {
    start
    echo '--- Client must have NO globally usable IPv6 ---'
    ip -n "$CLIENT" -6 addr show
    echo '--- IPv6-only origin has no IPv4 WAN address ---'
    ip -n "$SERVER" -4 addr show dev x6s
    echo '--- 1. ICMPv4 ping to IPv4 service address ---'
    ns "$CLIENT" ping -n -c 3 -W 2 198.19.0.22
    echo '--- 2. Real IPv4 TCP/HTTP request to IPv6-only server ---'
    local response
    response="$(ns "$CLIENT" curl -4 --noproxy '*' -fsS --max-time 10 http://198.19.0.22:8080/)"
    echo "RESPONSE: $response"
    [[ "$response" == 'SIIT_DC_OK' ]] || { echo 'UNEXPECTED HTTP response' >&2; exit 1; }
    echo '--- 3. Translator logs ---'
    tail -n 20 "$STATE_DIR/translator.log" || true
    echo '--- 4. IPv6 origin logs ---'
    tail -n 20 "$STATE_DIR/origin.log" || true
    echo 'TEST OK: IPv4 TCP has reached IPv6-only HTTP server with NO tunnel, stateless translation on the edge.'
}

negative() {
    start
    echo '--- Stop ONLY the IPv4/IPv6 translator ---'
    stop_one translator
    sleep 0.3
    if ns "$CLIENT" ping -n -c 1 -W 1 198.19.0.22; then
        echo 'UNEXPECTED SUCCESS: translation may still be running' >&2
        start_process "$XLAT" translator translator.py
        exit 1
    fi
    echo 'EXPECTED FAILURE: native IPv4 routing alone cannot deliver to IPv6-only origin.'
    echo '--- Restore translator and verify ---'
    start_process "$XLAT" translator translator.py
    ns "$CLIENT" ping -n -c 2 -W 2 198.19.0.22
    echo 'RECOVERY OK'
}

status() {
    for n in "$CLIENT" "$ROUTER" "$XLAT" "$SERVER"; do
        echo "===== $n ====="
        ip -n "$n" -br addr
        ip -n "$n" -4 route
        ip -n "$n" -6 route
    done
    echo '===== process state ====='
    for process in translator origin; do
        if pid_running "$STATE_DIR/$process.pid"; then echo "$process running"; else echo "$process NOT running"; fi
    done
}
watch() { ns "$XLAT" tcpdump -ni any -vv "${1:-tcp or icmp or icmp6}"; }
teardown() {
    stop || true
    for n in "$CLIENT" "$ROUTER" "$XLAT" "$SERVER"; do
        ip netns del "$n" 2>/dev/null || true
    done
    echo 'TEARDOWN OK: all isolated namespaces removed.'
}

need_root
case "${1:-}" in
    setup) setup ;;
    start) start ;;
    test) test ;;
    negative) negative ;;
    status) status ;;
    watch) watch "${2:-tcp or icmp or icmp6}" ;;
    stop) stop ;;
    teardown) teardown ;;
    *) echo 'Usage: sudo env PATH="$PATH" bash siit_lab.sh {setup|start|test|negative|status|watch|stop|teardown}' >&2; exit 2 ;;
esac

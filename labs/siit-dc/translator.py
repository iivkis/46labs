#!/usr/bin/env python3
"""Educational stateless IPv4<->IPv6 SIIT-DC subset via Linux TUN devices.
Only: unfragmented IPv4/IPv6 TCP and ICMP Echo. No IPv6 extensions/ICMP errors.
Only use in isolated network namespaces: never deploy as an internet gateway.
"""
import argparse
import fcntl
import ipaddress
import os
import select
import socket
import struct

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
V4_SERVICE = ipaddress.IPv4Address('198.19.0.22')
V6_SERVICE = ipaddress.IPv6Address('2001:db8:66::2')
TRANSLATION_PREFIX = ipaddress.IPv6Network('2001:db8:46::/96')


def ck(data):
    if len(data) % 2:
        data += b'\x00'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def pseudo6(src, dst, proto, length):
    return src + dst + struct.pack('!I3xB', length, proto)


def pseudo4(src, dst, proto, length):
    return src + dst + struct.pack('!BBH', 0, proto, length)


def rewrite_tcp(payload, src, dst, new_family):
    if len(payload) < 20:
        return None
    seg = bytearray(payload)
    seg[16:18] = b'\x00\x00'
    ps = (pseudo6 if new_family == 6 else pseudo4)(src, dst, 6, len(seg))
    seg[16:18] = struct.pack('!H', ck(ps + seg))
    return bytes(seg)


def v4_to_v6(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    hlen = (packet[0] & 15) * 4
    if hlen < 20 or len(packet) < hlen:
        return None
    total = struct.unpack_from('!H', packet, 2)[0]
    if total < hlen or total > len(packet):
        return None
    flags_offset = struct.unpack_from('!H', packet, 6)[0]
    if hlen != 20 or (flags_offset & 0x3fff) or packet[8] <= 1:
        return None
    src4 = ipaddress.IPv4Address(packet[12:16])
    dst4 = ipaddress.IPv4Address(packet[16:20])
    if dst4 != V4_SERVICE:
        return None
    src6 = ipaddress.IPv6Address(int(TRANSLATION_PREFIX.network_address) + int(src4)).packed
    dst6 = V6_SERVICE.packed
    proto = packet[9]
    payload = packet[hlen:total]
    if proto == 1:
        if len(payload) < 8 or payload[0] not in (8, 0):
            return None
        icmp = bytearray(payload)
        icmp[0] = 128 if icmp[0] == 8 else 129
        icmp[2:4] = b'\x00\x00'
        icmp[2:4] = struct.pack('!H', ck(pseudo6(src6, dst6, 58, len(icmp)) + icmp))
        out_proto = 58
        data = bytes(icmp)
    elif proto == 6:
        data = rewrite_tcp(payload, src6, dst6, 6)
        if data is None:
            return None
        out_proto = 6
    else:
        return None
    class_field = packet[1]
    vtf = (6 << 28) | (class_field << 20)
    hdr = struct.pack('!IHBB16s16s', vtf, len(data), out_proto, packet[8], src6, dst6)
    return hdr + data


def v6_to_v4(packet):
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    payload_len = struct.unpack_from('!H', packet, 4)[0]
    if payload_len == 0 or len(packet) < 40 + payload_len or packet[7] <= 1:
        return None
    src6 = ipaddress.IPv6Address(packet[8:24])
    dst6 = ipaddress.IPv6Address(packet[24:40])
    if src6 != V6_SERVICE or dst6 not in TRANSLATION_PREFIX:
        return None
    src4 = V4_SERVICE.packed
    dst4 = ipaddress.IPv4Address(int(dst6) - int(TRANSLATION_PREFIX.network_address)).packed
    proto = packet[6]
    payload = packet[40:40 + payload_len]
    if proto == 58:
        if len(payload) < 8 or payload[0] not in (128, 129):
            return None
        icmp = bytearray(payload)
        icmp[0] = 8 if icmp[0] == 128 else 0
        icmp[2:4] = b'\x00\x00'
        icmp[2:4] = struct.pack('!H', ck(icmp))
        data = bytes(icmp)
        out_proto = 1
    elif proto == 6:
        data = rewrite_tcp(payload, src4, dst4, 4)
        if data is None:
            return None
        out_proto = 6
    else:
        return None
    if 20 + len(data) > 65535:
        return None
    traffic_class = ((packet[0] & 15) << 4) | (packet[1] >> 4)
    hdr = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, traffic_class, 20 + len(data), 0,
                                0x4000, packet[7], out_proto, 0, src4, dst4))
    hdr[10:12] = struct.pack('!H', ck(hdr))
    return bytes(hdr) + data


def selftest():
    ip4src = ipaddress.IPv4Address('198.18.0.2').packed
    dst4 = V4_SERVICE.packed

    def make_ipv4(proto, segment):
        hdr = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), 123,
                                     0x4000, 64, proto, 0, ip4src, dst4))
        hdr[10:12] = struct.pack('!H', ck(hdr))
        return bytes(hdr) + segment

    icmp = bytearray(struct.pack('!BBHHH', 8, 0, 0, 7, 1) + b'hello')
    icmp[2:4] = struct.pack('!H', ck(icmp))
    v6 = v4_to_v6(make_ipv4(1, icmp))
    assert v6 and v6[6] == 58 and v6[40] == 128
    assert ck(pseudo6(v6[8:24], v6[24:40], 58, len(v6)-40) + v6[40:]) == 0
    reply = bytearray(v6[40:]); reply[0] = 129; reply[2:4] = b'\x00\x00'
    reply[2:4] = struct.pack('!H', ck(pseudo6(v6[24:40],v6[8:24],58,len(reply))+reply))
    rep6 = struct.pack('!IHBB16s16s', 6 << 28, len(reply), 58, 64, v6[24:40], v6[8:24]) + reply
    result = v6_to_v4(rep6)
    assert result and result[9] == 1 and result[20] == 0
    assert ck(result[:20]) == 0 and ck(result[20:]) == 0
    syn = bytearray(struct.pack('!HHIIHHHH', 33000, 8080, 1234, 0, 0x5002, 65535, 0, 0))
    syn[16:18] = struct.pack('!H', ck(pseudo4(ip4src, dst4, 6, len(syn)) + syn))
    v6syn = v4_to_v6(make_ipv4(6, syn))
    assert v6syn and ck(pseudo6(v6syn[8:24], v6syn[24:40], 6, len(v6syn)-40) + v6syn[40:]) == 0
    synack = bytearray(struct.pack('!HHIIHHHH', 8080, 33000, 5678, 1235, 0x5012, 65535, 0, 0))
    synack[16:18] = struct.pack('!H', ck(pseudo6(v6syn[24:40], v6syn[8:24], 6, len(synack)) + synack))
    p6 = struct.pack('!IHBB16s16s',6 << 28,len(synack),6,64,v6syn[24:40],v6syn[8:24])+synack
    p4 = v6_to_v4(p6)
    assert p4 and ck(p4[:20]) == 0
    assert ck(pseudo4(p4[12:16],p4[16:20],6,len(p4)-20) + p4[20:]) == 0
    assert v4_to_v6(make_ipv4(17,b'12345678')) is None
    print('SELFTEST OK: ICMPv4<->ICMPv6 echo and TCP checksum both directions')


def open_tun(name):
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI))
    return fd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--selftest', action='store_true')
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    v4fd = open_tun('siit4')
    v6fd = open_tun('siit6')
    print('READY: stateless IPv4<->IPv6 translator, TCP and ICMP Echo only', flush=True)
    c4 = c6 = 0
    while True:
        fds, _, _ = select.select([v4fd, v6fd], [], [], 10)
        for fd in fds:
            try:
                packet = os.read(fd, 65535)
            except BlockingIOError:
                continue
            if fd == v4fd:
                translated = v4_to_v6(packet)
                if translated:
                    os.write(v6fd, translated)
                    c4 += 1
            else:
                translated = v6_to_v4(packet)
                if translated:
                    os.write(v4fd, translated)
                    c6 += 1
        if c4 or c6:
            print(f'TRANSLATED v4->v6={c4}, v6->v4={c6}', flush=True)
            c4 = c6 = 0


if __name__ == '__main__':
    main()

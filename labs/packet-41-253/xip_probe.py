#!/usr/bin/env python3
"""IPv4 protocol 253 raw packet sender, restricted to the test topology."""
import socket
import struct

SRC = '198.18.0.2'
DST = '198.18.0.6'
DATA = b'XIP-v0|IPv6-target=2001:db8:66::2|no-IP-forwarding-magic'


def checksum(data):
    data += b'\0' * (len(data) % 2)
    words = struct.unpack('!' + 'H' * (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(DATA),
                  0x541, 0, 64, 253, 0,
                  socket.inet_aton(SRC), socket.inet_aton(DST))
hdr = hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    n = sock.sendto(hdr + DATA, (DST, 0))
print(f'Sent {n} bytes: IPv4 {SRC} -> {DST}, protocol=253, with embedded IPv6 label')

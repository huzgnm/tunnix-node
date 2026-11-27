#!/usr/bin/env python3
"""Sends one DNS query (A example.com) to 1.1.1.1:53 through a SOCKS5 UDP ASSOCIATE.
Usage: socks_udp_dns.py SOCKS_PORT   -> prints OK <answer bytes> or FAIL <reason>"""
import socket, struct, sys

port = int(sys.argv[1])
tcp = socket.create_connection(("127.0.0.1", port), timeout=5)
tcp.sendall(b"\x05\x01\x00"); tcp.recv(2)
tcp.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
rep = tcp.recv(10)
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
if relay[0] == "0.0.0.0":
    relay = ("127.0.0.1", relay[1])
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
pkt = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 53) + q
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(6)
u.sendto(pkt, relay)
try:
    data, _ = u.recvfrom(4096)
    ans = data[10:]
    print("OK", len(ans), "bytes" if ans[:2] == b"\x12\x34" else "(id mismatch)")
except Exception as e:
    print("FAIL", e)

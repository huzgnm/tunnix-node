#!/usr/bin/env python3
"""UDP round-trip time through a SOCKS5 proxy against a local echo server.
Usage: udp_rtt.py SOCKS_PORT [COUNT] [TARGET_IP]
Starts an echo server on 0.0.0.0:39999; TARGET_IP (default 127.0.0.1) is where the proxy sends."""
import socket, statistics, struct, sys, threading, time

port = int(sys.argv[1]); count = int(sys.argv[2]) if len(sys.argv) > 2 else 500
target = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); echo.bind(("0.0.0.0", 39999))
def serve():
    while True:
        data, addr = echo.recvfrom(65535); echo.sendto(data, addr)
threading.Thread(target=serve, daemon=True).start()
tcp = socket.create_connection(("127.0.0.1", port)); tcp.sendall(b"\x05\x01\x00"); tcp.recv(2)
tcp.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0)); rep = tcp.recv(10)
relay = ("127.0.0.1", struct.unpack(">H", rep[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1)
head = b"\x00\x00\x00\x01" + socket.inet_aton(target) + struct.pack(">H", 39999)
rtts = []
for i in range(count):
    payload = struct.pack(">I", i) + b"x" * 60
    t = time.perf_counter(); u.sendto(head + payload, relay)
    try:
        while True:
            data, _ = u.recvfrom(4096)
            if data[10:14] == payload[:4]: break
        rtts.append((time.perf_counter() - t) * 1000)
    except socket.timeout:
        pass
    time.sleep(0.002)
rtts.sort()
print(f"answered {len(rtts)}/{count}  median {statistics.median(rtts):.3f} ms  p90 {rtts[int(len(rtts)*0.9)]:.3f} ms  min {rtts[0]:.3f} ms")

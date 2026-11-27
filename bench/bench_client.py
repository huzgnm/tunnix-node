#!/usr/bin/env python3
"""Client-side benchmark for proxy nodes (TunnixNode, v2node, V2bX, remnanode, ...).

Starts a local Xray client that connects to the node under test, then runs these
phases through its SOCKS5 port:

  idle        no traffic (baseline memory on the node)
  latency     sequential short HTTPS requests, each on a new proxied connection
  single      one download stream for --duration seconds
  multi       --streams parallel download streams for --duration seconds
  conns       --conns concurrent idle connections held for --duration seconds
  udp         --udp-queries DNS queries over SOCKS5 UDP

Requirements on the client machine: python3, curl, and an Xray binary (--xray).

    python3 bench_client.py --label tunnix --link 'vless://...' --out results/tunnix.client.json

The node under test must reach --target-url. Use a server you control for stable
throughput numbers; speed.cloudflare.com is the default.
"""

import argparse
import asyncio
import base64
import json
import os
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

# ---------------------------------------------------------------- share links


def _qs(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}


def _stream(q, host):
    network = q.get("type", "tcp")
    if network == "raw":
        network = "tcp"
    stream = {"network": network}
    security = q.get("security", "none")
    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    elif security == "tls":
        stream["security"] = "tls"
        tls = {"serverName": q.get("sni", host), "fingerprint": q.get("fp", "chrome")}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        if q.get("pcs"):
            tls["pinnedPeerCertSha256"] = q["pcs"]
        stream["tlsSettings"] = tls
    if network == "ws":
        stream["wsSettings"] = {"path": q.get("path", "/"), "host": q.get("host", "")}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": q.get("path", "/"), "host": q.get("host", "")}
    elif network in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": q.get("path", "/"), "mode": q.get("mode", "auto")}
    return stream


def outbound_from_link(link):
    """Xray outbound for vless://, vmess://, trojan:// and ss:// share links."""
    link = link.strip()
    if link.startswith("vmess://"):
        v = json.loads(base64.b64decode(link[8:] + "=" * (-len(link[8:]) % 4)))
        q = {
            "type": v.get("net", "tcp"),
            "security": "tls" if v.get("tls") == "tls" else "none",
            "sni": v.get("sni", ""),
            "path": v.get("path", "/"),
            "host": v.get("host", ""),
            "serviceName": v.get("path", ""),
        }
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": v["add"], "port": int(v["port"]),
                                    "users": [{"id": v["id"], "security": v.get("scy", "auto")}]}]},
            "streamSettings": _stream(q, v["add"]),
        }
    url = urllib.parse.urlparse(link)
    q = _qs(url)
    host, port = url.hostname, url.port
    if url.scheme == "vless":
        user = {"id": urllib.parse.unquote(url.username), "encryption": q.get("encryption", "none")}
        if q.get("flow"):
            user["flow"] = q["flow"]
        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": _stream(q, host),
        }
    if url.scheme == "trojan":
        q.setdefault("security", "tls")
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port,
                                      "password": urllib.parse.unquote(url.username)}]},
            "streamSettings": _stream(q, host),
        }
    if url.scheme == "ss":
        userinfo = urllib.parse.unquote(url.username or "")
        if ":" not in userinfo:
            userinfo = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        method, _, password = userinfo.partition(":")
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
        }
    raise SystemExit(f"unsupported share link scheme: {url.scheme} (use --outbound for others)")


# ---------------------------------------------------------------- helpers


def wait_port(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"Xray did not open port {port}")


def curl(socks, url, max_time, extra=()):
    fmt = "%{http_code} %{size_download} %{size_upload} %{time_starttransfer} %{time_total}"
    cmd = ["curl", "-s", "-o", "/dev/null", "--max-time", str(max_time),
           "--socks5-hostname", f"127.0.0.1:{socks}", "-w", fmt, *extra, url]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout.split()
    if len(out) != 5:
        return None
    code, down, up, ttfb, total = out
    return {"code": int(code), "down": int(float(down)), "up": int(float(up)),
            "ttfb": float(ttfb), "total": float(total)}


def percentile(values, p):
    if not values:
        return None
    values = sorted(values)
    k = min(len(values) - 1, max(0, round(p / 100 * (len(values) - 1))))
    return values[k]


class Totals:
    def __init__(self):
        self.lock = threading.Lock()
        self.down = 0
        self.up = 0

    def add(self, r):
        if r:
            with self.lock:
                self.down += r["down"]
                self.up += r["up"]


# ---------------------------------------------------------------- phases


def phase_latency(args, totals):
    ttfb, failures = [], 0
    for _ in range(args.latency_requests):
        r = curl(args.socks_port, args.small_url, 15)
        totals.add(r)
        if r and 200 <= r["code"] < 400:
            ttfb.append(r["ttfb"] * 1000)
        else:
            failures += 1
    return {
        "requests": args.latency_requests,
        "failures": failures,
        "ttfb_ms_median": round(statistics.median(ttfb), 1) if ttfb else None,
        "ttfb_ms_p95": round(percentile(ttfb, 95), 1) if ttfb else None,
    }


def download_worker(args, deadline, totals, result):
    url = args.target_url.format(bytes=args.chunk_bytes)
    got = 0
    while True:
        remaining = deadline - time.time()
        if remaining < 1:
            break
        r = curl(args.socks_port, url, max(1, int(remaining)))
        totals.add(r)
        if not r or r["down"] == 0:
            result["errors"] = result.get("errors", 0) + 1
            time.sleep(0.5)
            continue
        got += r["down"]
    with totals.lock:
        result["bytes"] = result.get("bytes", 0) + got


def phase_download(args, streams, totals):
    result = {}
    start = time.time()
    deadline = start + args.duration
    threads = [threading.Thread(target=download_worker, args=(args, deadline, totals, result))
               for _ in range(streams)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    mbps = result.get("bytes", 0) * 8 / elapsed / 1e6
    return {"streams": streams, "seconds": round(elapsed, 1), "bytes": result.get("bytes", 0),
            "mbps": round(mbps, 1), "errors": result.get("errors", 0)}


async def socks_connect(port, host, dport):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    await reader.readexactly(2)
    addr = host.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack(">H", dport))
    await writer.drain()
    rep = await reader.readexactly(4)
    if rep[1] != 0:
        raise OSError(f"socks reply {rep[1]}")
    atyp = rep[3]
    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)
    else:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n + 2)
    return writer


async def phase_conns_async(args):
    host, _, port = args.conn_target.rpartition(":")
    sem = asyncio.Semaphore(200)
    writers, errors = [], 0

    async def one():
        nonlocal errors
        async with sem:
            try:
                writers.append(await asyncio.wait_for(socks_connect(args.socks_port, host, int(port)), 15))
            except Exception:
                errors += 1

    t0 = time.time()
    await asyncio.gather(*(one() for _ in range(args.conns)))
    opened = time.time() - t0
    await asyncio.sleep(args.duration)
    alive = 0
    for w in writers:
        if not w.is_closing():
            alive += 1
        w.close()
    return {"target": args.conns, "opened": len(writers), "errors": errors,
            "open_seconds": round(opened, 1), "alive_after_hold": alive, "hold_seconds": args.duration}


def phase_udp(args):
    tcp = socket.create_connection(("127.0.0.1", args.socks_port), timeout=5)
    tcp.sendall(b"\x05\x01\x00")
    tcp.recv(2)
    tcp.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
    rep = tcp.recv(10)
    relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
    if relay[0] == "0.0.0.0":
        relay = ("127.0.0.1", relay[1])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    rtts, ok = [], 0
    for i in range(args.udp_queries):
        qid = i & 0xFFFF
        q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack(">H", 53) + q
        t = time.time()
        u.sendto(pkt, relay)
        try:
            while True:
                data, _ = u.recvfrom(4096)
                if data[10:12] == struct.pack(">H", qid):
                    break
            ok += 1
            rtts.append((time.time() - t) * 1000)
        except socket.timeout:
            pass
    tcp.close()
    return {"queries": args.udp_queries, "answered": ok,
            "rtt_ms_median": round(statistics.median(rtts), 1) if rtts else None}


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--link", help="vless://, vmess://, trojan:// or ss:// share link")
    src.add_argument("--outbound", help="JSON file with one Xray outbound object (any protocol)")
    ap.add_argument("--label", required=True, help="name of the node implementation, e.g. tunnix, v2node")
    ap.add_argument("--out", required=True, help="result JSON file")
    ap.add_argument("--xray", default="xray", help="path to the Xray client binary")
    ap.add_argument("--socks-port", type=int, default=10808)
    ap.add_argument("--target-url", default="https://speed.cloudflare.com/__down?bytes={bytes}",
                    help="download URL; {bytes} is replaced with --chunk-bytes")
    ap.add_argument("--chunk-bytes", type=int, default=50_000_000)
    ap.add_argument("--small-url", default="https://www.cloudflare.com/cdn-cgi/trace")
    ap.add_argument("--duration", type=int, default=30, help="seconds per throughput/conns phase")
    ap.add_argument("--idle", type=int, default=20, help="seconds of idle baseline")
    ap.add_argument("--streams", type=int, default=8)
    ap.add_argument("--conns", type=int, default=500)
    ap.add_argument("--conn-target", default="1.1.1.1:80")
    ap.add_argument("--latency-requests", type=int, default=30)
    ap.add_argument("--udp-queries", type=int, default=100)
    ap.add_argument("--phases", default="idle,latency,single,multi,conns,udp")
    args = ap.parse_args()

    outbound = outbound_from_link(args.link) if args.link else json.load(open(args.outbound))
    if "outbounds" in outbound:
        outbound = outbound["outbounds"][0]
    outbound = dict(outbound, tag="proxy")
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": args.socks_port, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [outbound],
    }
    cfg = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(config, cfg)
    cfg.close()
    xray = subprocess.Popen([args.xray, "run", "-c", cfg.name], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        wait_port(args.socks_port)
        probe = curl(args.socks_port, args.small_url, 15)
        if not probe or probe["code"] == 0:
            raise SystemExit("the node does not pass traffic; check the link and the node")
        totals = Totals()
        totals.add(probe)
        result = {"label": args.label, "started": time.time(), "settings": vars(args) | {"link": bool(args.link)},
                  "phases": {}}
        for phase in [p.strip() for p in args.phases.split(",") if p.strip()]:
            print(f"[{args.label}] {phase} ...", file=sys.stderr, flush=True)
            start = time.time()
            if phase == "idle":
                time.sleep(args.idle)
                data = {}
            elif phase == "latency":
                data = phase_latency(args, totals)
            elif phase == "single":
                data = phase_download(args, 1, totals)
            elif phase == "multi":
                data = phase_download(args, args.streams, totals)
            elif phase == "conns":
                data = asyncio.run(phase_conns_async(args))
            elif phase == "udp":
                data = phase_udp(args)
            else:
                raise SystemExit(f"unknown phase {phase}")
            data.update(start=round(start, 3), end=round(time.time(), 3))
            result["phases"][phase] = data
            print(f"[{args.label}] {phase}: {json.dumps({k: v for k, v in data.items() if k not in ('start', 'end')})}",
                  file=sys.stderr, flush=True)
            time.sleep(3)  # let the node settle between phases
        result["client_bytes"] = {"down": totals.down, "up": totals.up}
        result["finished"] = time.time()
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[{args.label}] HTTP bytes through the node: down {totals.down:,}  up {totals.up:,}", file=sys.stderr)
        print(f"[{args.label}] saved {args.out}", file=sys.stderr)
    finally:
        xray.terminate()
        os.unlink(cfg.name)


if __name__ == "__main__":
    main()

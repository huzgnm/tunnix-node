#!/usr/bin/env python3
"""Fake Cloudflare DNS API + DoH for DNS-01 tests. TXT records are pushed to
pebble-challtestsrv's management API so Pebble can validate them.
Usage: mock_cloudflare.py PORT ZONE CHALLTESTSRV_MGMT_URL TOKEN"""
import json, sys, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT, ZONE, MGMT, TOKEN = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
records = {}


def mgmt(path, body):
    req = urllib.request.Request(MGMT + path, data=json.dumps(body).encode(), method="POST")
    urllib.request.urlopen(req, timeout=5).read()


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        sys.stderr.write("[cf] " + (fmt % a) + "\n")

    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send(403, {"success": False, "errors": [{"message": "bad token"}]})
            return False
        return True

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/dns-query":
            name = q.get("name", [""])[0].rstrip(".")
            ans = [{"data": f'"{v}"'} for (n, v) in records.values() if n == name]
            return self.send(200, {"Answer": ans} if ans else {})
        if not self.authed():
            return
        if u.path == "/client/v4/zones":
            name = q.get("name", [""])[0]
            return self.send(200, {"result": [{"id": "zone1"}] if name == ZONE else []})
        self.send(404, {})

    def do_POST(self):
        if not self.authed():
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        rid = f"r{len(records) + 1}"
        records[rid] = (body["name"], body["content"])
        mgmt("/set-txt", {"host": body["name"] + ".", "value": body["content"]})
        self.send(200, {"success": True, "result": {"id": rid}})

    def do_DELETE(self):
        if not self.authed():
            return
        rid = self.path.rsplit("/", 1)[-1]
        name, _ = records.pop(rid, ("", ""))
        if name:
            mgmt("/clear-txt", {"host": name + "."})
        self.send(200, {"success": True})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()

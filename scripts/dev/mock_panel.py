#!/usr/bin/env python3
"""Minimal XiaoBoard/Xboard node API for local testing.

State dir holds node.json (config payload) and users.json ({"users": [...]}).
Pushed traffic and alive reports are appended to pushes.jsonl.
Usage: mock_panel.py STATE_DIR [PORT] [TOKEN]
"""
import hashlib, json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

STATE = Path(sys.argv[1])
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18080
TOKEN = sys.argv[3] if len(sys.argv) > 3 else "test"


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        sys.stderr.write("[panel] " + (fmt % a) + "\n")

    def send(self, code, obj, etag=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if etag:
            self.send_header("ETag", f'"{etag}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def auth(self):
        q = parse_qs(urlparse(self.path).query)
        if q.get("token", [""])[0] != TOKEN:
            self.send(500, {"message": "token is error"})
            return False
        return True

    def do_GET(self):
        if not self.auth():
            return
        p = urlparse(self.path).path
        if p == "/api/v2/server/config":
            q = parse_qs(urlparse(self.path).query)
            f = STATE / f"node-{q.get('node_id', [''])[0]}.json"
            self.send(200, json.loads((f if f.exists() else STATE / "node.json").read_text()))
        elif p == "/api/v1/server/UniProxy/user":
            data = json.loads((STATE / "users.json").read_text())
            etag = hashlib.sha1(json.dumps(data).encode()).hexdigest()
            if etag in (self.headers.get("If-None-Match") or ""):
                self.send_response(304)
                self.end_headers()
                return
            self.send(200, data, etag)
        elif p == "/api/v1/server/UniProxy/alivelist":
            f = STATE / "alive.json"
            self.send(200, json.loads(f.read_text()) if f.exists() else {"alive": {}})
        else:
            self.send(404, {"message": "not found"})

    def do_POST(self):
        if not self.auth():
            return
        p = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        kind = p.rsplit("/", 1)[-1]
        with open(STATE / "pushes.jsonl", "a") as f:
            f.write(json.dumps({"t": time.time(), "kind": kind, "body": body}) + "\n")
        self.send(200, {"data": True})


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()

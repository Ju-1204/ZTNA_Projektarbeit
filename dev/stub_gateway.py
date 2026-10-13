#!/usr/bin/env python3
"""Stub-Gateway für die lokale Demo: ahmt die Go-API nach (Port 9090),
ohne WireGuard/nftables anzufassen. Zeichnet alle Aufrufe im Log mit."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PEERS = {}
SETS = {}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        elif self.path == "/pubkey":
            self._send(200, {"pubkey": "STUB-GATEWAY-PUBKEY-FUER-DEMO=="})
        else:
            self._send(404, {"error": "not found"})

    def do_PUT(self):
        body = self._body()
        if self.path.startswith("/peers/"):
            pid = self.path.split("/")[2]
            PEERS[pid] = body
            print(f"[stub] PUT /peers/{pid} -> {body}", flush=True)
            self._send(200, {"status": "peer gesetzt (stub)"})
        elif self.path.startswith("/service/"):
            name = self.path.split("/")[2]
            SETS[name] = body.get("clients", [])
            print(f"[stub] PUT /service/{name}/clients -> {SETS[name]}", flush=True)
            self._send(200, {"status": "ok", "clients": len(SETS[name])})
        else:
            self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if self.path.startswith("/peers/"):
            pid = self.path.split("/")[2]
            PEERS.pop(pid, None)
            print(f"[stub] DELETE /peers/{pid}", flush=True)
            self._send(200, {"status": "peer entfernt (stub)"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/reload":
            self._send(200, {"status": "synchronisiert (stub)"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print("[stub]", fmt % args, flush=True)


if __name__ == "__main__":
    print("[stub-gateway] lauscht auf http://127.0.0.1:9090", flush=True)
    HTTPServer(("127.0.0.1", 9090), Handler).serve_forever()

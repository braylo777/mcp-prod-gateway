"""Tiny stdlib HTTP binding so the gateway can be exercised over a real socket."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .gateway import Gateway


def serve(
    gateway: Gateway, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, status, headers, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/.well-known/oauth-protected-resource":
                self._send(200, {}, gateway.well_known())
            else:
                self._send(404, {}, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(n))
            except ValueError:
                return self._send(
                    400,
                    {},
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "parse error"},
                    },
                )
            status, headers, out = gateway.handle_http(dict(self.headers), body)
            self._send(status, headers, out)

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

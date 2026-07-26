#!/usr/bin/env python3
"""
Simple HTTP server for local network tests and benchmarks.

Responds to all requests with a minimal JSON body. Used by smoke_test.sh
(allowlisted domain via proxy) and benchmark.sh (proxy overhead) so neither
depends on the public internet.

Usage:
    python3 scripts/local-server.py [port]
    # Default port: 8765
    # Server runs on http://127.0.0.1:<port>/

    # In another terminal:
    curl http://127.0.0.1:8765/
"""

import http.server
import json
import socketserver
import sys

DEFAULT_PORT = 8765


class LocalHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler for local network tests."""

    def do_GET(self):
        """Handle GET requests with minimal response."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {"status": "ok", "path": self.path}
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        """Handle POST requests with minimal response."""
        content_length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_length)  # Read and discard body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {"status": "ok", "method": "POST"}
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        """Suppress request logging for cleaner test/benchmark output."""
        pass


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}", file=sys.stderr)
            sys.exit(2)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), LocalHandler) as httpd:
        print(f"Local server running on http://127.0.0.1:{port}/", file=sys.stderr)
        print("Press Ctrl+C to stop", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...", file=sys.stderr)
            httpd.shutdown()


if __name__ == "__main__":
    main()

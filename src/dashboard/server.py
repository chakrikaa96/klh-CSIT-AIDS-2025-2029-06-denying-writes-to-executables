#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
ExecGuard dashboard - a deliberately minimal, READ-ONLY status viewer.

It serves a single HTML page plus two JSON endpoints:
  /api/status  -> parsed output of `egctl status`
  /api/events  -> the last N audit events from the JSONL log

The dashboard performs no control actions; it cannot change policy or
enforcement. Bind it to localhost only (the default) and put it behind an
authenticated reverse proxy if you expose it. It is intentionally small: the
audit log and egctl are the source of truth.
"""
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUDIT_LOG = os.environ.get("EG_AUDIT_LOG", "/var/log/execguard/audit.jsonl")
HERE = os.path.dirname(os.path.abspath(__file__))
BIND = os.environ.get("EG_DASH_BIND", "127.0.0.1")
PORT = int(os.environ.get("EG_DASH_PORT", "8787"))
MAX_EVENTS = 200


def read_status():
    """Return egctl status as a dict of key/value pairs."""
    try:
        out = subprocess.run(
            ["egctl", "status"], capture_output=True, text=True, timeout=5
        ).stdout
    except Exception as exc:  # egctl missing or daemon down
        return {"error": str(exc)}
    # egctl status prints an ASCII box; extract "Label : Value" rows.
    status = {}
    for line in out.splitlines():
        if "|" in line and ":" in line:
            inner = line.strip().strip("|").strip()
            if ":" in inner:
                k, _, v = inner.partition(":")
                status[k.strip()] = v.strip()
    return status


def read_events(limit=MAX_EVENTS):
    """Return the last `limit` audit events as a list of dicts."""
    events = []
    try:
        with open(AUDIT_LOG, "r") as fh:
            lines = fh.readlines()[-limit:]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        pass
    events.reverse()  # newest first
    return events


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        payload = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "index.html"), "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, b"index.html not found", "text/plain")
        elif self.path == "/api/status":
            self._send(200, json.dumps(read_status()))
        elif self.path == "/api/events":
            self._send(200, json.dumps(read_events()))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, *args):
        pass  # keep the console quiet


def main():
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"ExecGuard dashboard (read-only) on http://{BIND}:{PORT}")
    print(f"Reading audit log: {AUDIT_LOG}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()

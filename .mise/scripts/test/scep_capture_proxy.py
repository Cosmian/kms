#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recording reverse proxy for SCEP interoperability captures.

Forwards every request to the KMS unchanged and writes, for each exchange,
`NNN-<METHOD>-<operation>.req` (request body, or the decoded GET `message`) and
`NNN-<METHOD>-<operation>.resp` (response body) into the capture directory, plus a
line in `exchanges.log`. Test-only: captures contain challenge passwords.

Usage: scep_capture_proxy.py <listen_port> <upstream_base_url> <capture_dir>
"""

from __future__ import annotations

import base64
import itertools
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

COUNTER = itertools.count(1)
LOCK = threading.Lock()


def make_handler(upstream: str, capture_dir: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _forward(self, method: str) -> None:
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            operation = query.get('operation', ['none'])[0]
            # Only a GET PKIOperation `message` is base64 DER; GetCACert's is a CA identifier.
            if method == 'GET' and operation == 'PKIOperation' and 'message' in query:
                body_to_save = base64.b64decode(query['message'][0].replace(' ', '+'))
            else:
                body_to_save = body

            request = urllib.request.Request(
                upstream + self.path,
                data=body if method == 'POST' else None,
                method=method,
            )
            for name in ('Content-Type', 'User-Agent'):
                if self.headers.get(name):
                    request.add_header(name, self.headers[name])
            try:
                with urllib.request.urlopen(request, timeout=60) as resp:
                    status, headers, payload = resp.status, resp.headers, resp.read()
            except urllib.error.HTTPError as err:
                status, headers, payload = err.code, err.headers, err.read()

            with LOCK:
                stem = f"{next(COUNTER):03d}-{method}-{operation}"
                (capture_dir / f"{stem}.req").write_bytes(body_to_save)
                (capture_dir / f"{stem}.resp").write_bytes(payload)
                with (capture_dir / 'exchanges.log').open('a') as log:
                    agent = self.headers.get('User-Agent', '-')
                    log.write(f"{stem} status={status} user_agent={agent}\n")

            self.send_response(status)
            if headers.get('Content-Type'):
                self.send_header('Content-Type', headers['Content-Type'])
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            self._forward('GET')

        def do_POST(self) -> None:  # noqa: N802 (http.server naming)
            self._forward('POST')

        def log_message(self, fmt: str, *args: object) -> None:
            sys.stderr.write(f"scep-proxy: {fmt % args}\n")

    return Handler


def main() -> None:
    if len(sys.argv) != 4:
        print(
            f"usage: {sys.argv[0]} <listen_port> <upstream_base_url> <capture_dir>",
            file=sys.stderr,
        )
        sys.exit(1)
    port, upstream, capture_dir = (
        int(sys.argv[1]),
        sys.argv[2].rstrip('/'),
        Path(sys.argv[3]),
    )
    capture_dir.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(
        ('127.0.0.1', port), make_handler(upstream, capture_dir)
    )
    server.serve_forever()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expose an OpenBao server as the KMS token verifier.

The KMS calls `GET /auth/token/lookup-self`, while OpenBao serves it under `/v1/`. This proxy only
prepends `/v1` to that one path and forwards the `X-Vault-Token` header unchanged.

The proxy binds 127.0.0.1 on a port chosen by the kernel and keeps that listener, then writes the
bound port to <port_file> (atomically, once it accepts connections). The caller reads the port
from the file instead of picking a free port first, so no other process can take it in between.

Usage: bao_lookup_proxy.py <port_file> <openbao_base_url>
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

LOOKUP_PATH = '/auth/token/lookup-self'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != LOOKUP_PATH:
            self.send_error(404)
            return
        request = urllib.request.Request(
            self.server.upstream + '/v1' + LOOKUP_PATH,
            headers={'X-Vault-Token': self.headers.get('X-Vault-Token', '')},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


def start(upstream: str) -> HTTPServer:
    """Bind and listen on a kernel-chosen loopback port (the server keeps the listener)."""
    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.upstream = upstream.rstrip('/')
    return server


def publish_port(port_file: str, port: int) -> None:
    """Write the port so that a reader never sees a partial file."""
    tmp = f'{port_file}.tmp'
    with open(tmp, 'w', encoding='ascii') as handle:
        handle.write(f'{port}\n')
    os.replace(tmp, port_file)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    proxy = start(sys.argv[2])
    publish_port(sys.argv[1], proxy.server_address[1])
    proxy.serve_forever()

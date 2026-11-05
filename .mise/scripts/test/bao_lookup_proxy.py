#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expose an OpenBao server as the KMS token verifier.

The KMS calls `GET /auth/token/lookup-self`, while OpenBao serves it under `/v1/`. This proxy only
prepends `/v1` to that one path and forwards the `X-Vault-Token` header unchanged.

Usage: bao_lookup_proxy.py <listen_port> <openbao_base_url>
"""
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

LOOKUP_PATH = '/auth/token/lookup-self'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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

    def log_message(self, *_args):
        pass


if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler)
    server.upstream = sys.argv[2].rstrip('/')
    server.serve_forever()

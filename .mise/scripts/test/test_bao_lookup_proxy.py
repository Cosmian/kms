#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-check of bao_lookup_proxy.py: port handoff, path mapping, token and status forwarding.

Run: python3 .mise/scripts/test/test_bao_lookup_proxy.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bao_lookup_proxy  # noqa: E402  (imported from this directory)


class FakeOpenBao(BaseHTTPRequestHandler):
    """Echo the path and token; refuse the token `bad` with 403 like OpenBao."""

    def do_GET(self) -> None:
        token = self.headers.get('X-Vault-Token', '')
        body = json.dumps({'path': self.path, 'token': token}).encode()
        self.send_response(403 if token == 'bad' else 200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


def serve(server: HTTPServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


class ProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream = HTTPServer(('127.0.0.1', 0), FakeOpenBao)
        serve(self.upstream)
        self.proxy = bao_lookup_proxy.start(
            f'http://127.0.0.1:{self.upstream.server_address[1]}/'
        )
        serve(self.proxy)
        self.base = f'http://127.0.0.1:{self.proxy.server_address[1]}'

    def tearDown(self) -> None:
        for server in (self.proxy, self.upstream):
            server.shutdown()
            server.server_close()

    def get(self, path: str, token: str) -> tuple[int, bytes]:
        request = urllib.request.Request(
            self.base + path, headers={'X-Vault-Token': token}
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def test_lookup_is_mapped_to_v1_with_the_token(self) -> None:
        status, body = self.get(bao_lookup_proxy.LOOKUP_PATH, 'good')
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body), {'path': '/v1/auth/token/lookup-self', 'token': 'good'}
        )

    def test_upstream_refusal_is_forwarded(self) -> None:
        self.assertEqual(self.get(bao_lookup_proxy.LOOKUP_PATH, 'bad')[0], 403)

    def test_other_paths_are_not_proxied(self) -> None:
        self.assertEqual(self.get('/v1/sys/health', 'good')[0], 404)

    def test_published_port_is_the_bound_listener(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port_file = os.path.join(tmp, 'proxy.port')
            bao_lookup_proxy.publish_port(port_file, self.proxy.server_address[1])
            with open(port_file, encoding='ascii') as handle:
                self.assertEqual(int(handle.read()), self.proxy.server_address[1])
            self.assertEqual(os.listdir(tmp), ['proxy.port'])
        self.assertNotEqual(self.proxy.server_address[1], 0)


if __name__ == '__main__':
    unittest.main()

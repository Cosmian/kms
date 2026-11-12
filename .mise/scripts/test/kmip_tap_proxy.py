#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mTLS tap between a KMIP client and the KMS binary KMIP listener.

The KMS does not log request contents, so the OpenBao KMIP seal test needs another way to see
what OpenBao sends. This proxy terminates the client's mutual TLS with the KMS server
certificate, writes every TTLV request to the log as `request: <hex>`, and forwards it to the
KMS over mutual TLS with the client's own certificate, so the KMS still authenticates the
client identity.

Usage: kmip_tap_proxy.py <listen_host> <listen_port> <kms_host> <kms_port> <server.crt>
       <server.key> <ca.crt> <client.crt> <client.key> <tap.log>
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
from typing import TextIO

TTLV_HEADER_LENGTH = 8


def read_exact(conn: ssl.SSLSocket, size: int) -> bytes | None:
    """Read exactly `size` bytes, or return None if the peer closed the connection first."""
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def read_ttlv(conn: ssl.SSLSocket) -> bytes | None:
    """Read one TTLV message: tag (3), type (1), length (4), then `length` bytes of value."""
    header = read_exact(conn, TTLV_HEADER_LENGTH)
    if header is None:
        return None
    body = read_exact(conn, int.from_bytes(header[4:8], 'big'))
    if body is None:
        return None
    return header + body


def relay(
    client: ssl.SSLSocket,
    upstream_ctx: ssl.SSLContext,
    upstream: tuple[str, int],
    log: TextIO,
    lock: threading.Lock,
) -> None:
    """Forward request/response pairs between one client and the KMS, logging each request."""
    with client, socket.create_connection(upstream) as raw:
        with upstream_ctx.wrap_socket(raw, server_hostname='localhost') as kms:
            while (request := read_ttlv(client)) is not None:
                with lock:
                    log.write(f'request: {request.hex()}\n')
                    log.flush()
                kms.sendall(request)
                response = read_ttlv(kms)
                if response is None:
                    return
                client.sendall(response)


def serve(argv: list[str]) -> None:
    """Accept TLS clients forever and relay each one on its own thread."""
    (
        listen_host,
        listen_port,
        kms_host,
        kms_port,
        server_cert,
        server_key,
        ca_cert,
        client_cert,
        client_key,
        log_path,
    ) = argv

    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=ca_cert)
    server_ctx.load_cert_chain(server_cert, server_key)
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    upstream_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
    upstream_ctx.load_cert_chain(client_cert, client_key)
    # A FIPS KMS requires the Extended Master Secret for TLS 1.2, which not every Python/OpenSSL
    # build sends; TLS 1.3 does not use that derivation.
    upstream_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    lock = threading.Lock()
    with open(log_path, 'a', encoding='utf-8') as log, socket.create_server(
        (listen_host, int(listen_port))
    ) as listener:
        while True:
            raw, _ = listener.accept()

            def handle(conn: socket.socket = raw) -> None:
                try:
                    client = server_ctx.wrap_socket(conn, server_side=True)
                    relay(client, upstream_ctx, (kms_host, int(kms_port)), log, lock)
                except (OSError, ssl.SSLError) as error:
                    print(
                        f"kmip_tap_proxy: connection failed: {error}", file=sys.stderr
                    )

            threading.Thread(target=handle, daemon=True).start()


if __name__ == '__main__':
    if len(sys.argv) != 11:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    serve(sys.argv[1:])

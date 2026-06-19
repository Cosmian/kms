# -*- coding: utf-8 -*-
# Restore ssl.wrap_socket removed in Python 3.12 for PyKMIP 0.10.x compatibility.
# PyKMIP uses ssl.wrap_socket() in kmip/services/kmip_client.py; Python 3.12 dropped it.
# This shim re-adds it using the modern ssl.SSLContext API, keeping the same call signature.
import ssl as _ssl

if not hasattr(_ssl, 'wrap_socket'):

    def _wrap_socket(
        sock,
        keyfile=None,
        certfile=None,
        server_side=False,
        cert_reqs=_ssl.CERT_NONE,
        ssl_version=None,
        ca_certs=None,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        ciphers=None,
    ):
        ctx = _ssl.SSLContext(
            _ssl.PROTOCOL_TLS_SERVER if server_side else _ssl.PROTOCOL_TLS_CLIENT
        )
        ctx.check_hostname = False
        ctx.verify_mode = cert_reqs if cert_reqs is not None else _ssl.CERT_NONE
        if ca_certs:
            ctx.load_verify_locations(ca_certs)
        if certfile:
            ctx.load_cert_chain(certfile, keyfile)
        return ctx.wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
        )

    _ssl.wrap_socket = _wrap_socket

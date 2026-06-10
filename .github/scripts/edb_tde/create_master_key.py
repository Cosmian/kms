# -*- coding: utf-8 -*-
"""Create and activate an AES-256 master key via KMIP, print its UID.

The official edb_tde_kmip_client.py (shipped by EDB) implements only the
'encrypt' and 'decrypt' commands used by PGDATAKEYWRAPCMD / PGDATAKEYUNWRAPCMD.
It does not provide a key-creation command, so this minimal helper fills that
gap for integration tests.

Usage:
    python3 create_master_key.py --pykmip-config-file=<path> [--pykmip-config-block=<block>]

Outputs the new key UID to stdout and exits 0 on success.
"""
import argparse

from kmip import enums
from kmip.pie.client import ProxyKmipClient


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Create and activate an AES-256 KMIP symmetric key'
    )
    parser.add_argument('--pykmip-config-file', metavar='FILE', required=True)
    parser.add_argument('--pykmip-config-block', metavar='NAME', default='client')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    client = ProxyKmipClient(
        config_file=args.pykmip_config_file,
        config=args.pykmip_config_block,
    )
    with client:
        uid = client.create(
            enums.CryptographicAlgorithm.AES,
            256,
            cryptographic_usage_mask=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.DECRYPT,
            ],
        )
        client.activate(uid)
        if args.verbose:
            import sys

            print(f"Created and activated AES-256 master key: {uid}", file=sys.stderr)
        print(uid)


if __name__ == '__main__':
    main()

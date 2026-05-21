#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JOSE interoperability helper for KMS REST Crypto API testing.

Subcommands
-----------
verify-jws   Verify a detached JWS using a DER-encoded public key (via jwcrypto).
decrypt-jwe  Decrypt a flattened JWE using raw symmetric key bytes (via jwcrypto).
encrypt-jwe  Encrypt plaintext as a flattened JWE using raw symmetric key bytes (via jwcrypto).
mac-sha256   Compute HMAC-SHA256 over raw bytes using a base64url key (via jwcrypto).

All inputs/outputs use hex or base64url encoding to be shell-friendly.

Requirements: Python 3.9+, jwcrypto, cryptography
"""
from __future__ import annotations

import argparse
import binascii
import json
import sys

from jwcrypto import jwe, jwk, jws


def _b64url_no_pad(data: bytes) -> str:
    """Encode bytes to base64url without padding (RFC 4648 §5)."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    import base64

    # Add back padding
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ── verify-jws ────────────────────────────────────────────────────────────────


def cmd_verify_jws(args: argparse.Namespace) -> None:
    """Verify a compact JWS (header.payload.signature) using a DER public key."""
    pub_der = binascii.unhexlify(args.pub_der_hex)

    # Import the public key from DER
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    pub_key_crypto = load_der_public_key(pub_der)

    # Convert to JWK
    key = jwk.JWK()
    key.import_from_pyca(pub_key_crypto)

    # Verify the compact JWS
    jws_obj = jws.JWS()
    try:
        jws_obj.deserialize(args.compact, key, alg=args.alg)
        print('valid=true')
    except jws.InvalidJWSSignature:
        print('valid=false')
        sys.exit(1)
    except Exception as e:
        print(f"error={e}", file=sys.stderr)
        sys.exit(2)


# ── decrypt-jwe ───────────────────────────────────────────────────────────────


def cmd_decrypt_jwe(args: argparse.Namespace) -> None:
    """Decrypt a flattened JWE using raw symmetric key bytes."""
    key_bytes = binascii.unhexlify(args.key_hex)

    # Build a JWK from raw bytes (symmetric / oct)
    key = jwk.JWK(kty='oct', k=_b64url_no_pad(key_bytes))

    # Reconstruct the flattened JWE JSON
    jwe_dict = {
        'protected': args.protected,
        'encrypted_key': args.encrypted_key or '',
        'iv': args.iv,
        'ciphertext': args.ciphertext,
        'tag': args.tag,
    }
    if args.aad:
        jwe_dict['aad'] = args.aad

    jwe_json = json.dumps(jwe_dict)

    jwe_obj = jwe.JWE()
    try:
        jwe_obj.deserialize(jwe_json, key)
        plaintext = jwe_obj.payload
        # Output as hex
        print(plaintext.hex())
    except Exception as e:
        print(f"error={e}", file=sys.stderr)
        sys.exit(1)


# ── encrypt-jwe ───────────────────────────────────────────────────────────────


def cmd_encrypt_jwe(args: argparse.Namespace) -> None:
    """Encrypt plaintext as flattened JWE using raw symmetric key bytes."""
    key_bytes = binascii.unhexlify(args.key_hex)
    plaintext = binascii.unhexlify(args.plaintext_hex)

    key = jwk.JWK(kty='oct', k=_b64url_no_pad(key_bytes))

    protected_header = {
        'alg': 'dir',
        'enc': args.enc,
        'kid': args.kid,
    }

    jwe_obj = jwe.JWE(
        plaintext,
        recipient=key,
        protected=json.dumps(protected_header),
    )

    # Serialize as flattened JSON
    serialized = jwe_obj.serialize(compact=False)
    # Output the flattened JSON so the shell script can parse it
    print(serialized)


# ── mac-sha256 ────────────────────────────────────────────────────────────────


def cmd_mac_sha256(args: argparse.Namespace) -> None:
    """Compute HMAC-SHA256 over raw bytes and output as base64url."""
    import hmac
    import hashlib

    key_bytes = _b64url_decode(args.key_b64url)
    data_bytes = binascii.unhexlify(args.data_hex)

    mac_value = hmac.new(key_bytes, data_bytes, hashlib.sha256).digest()
    print(_b64url_no_pad(mac_value))


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description='JOSE interoperability helper for KMS testing'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # verify-jws
    p_vj = sub.add_parser('verify-jws', help='Verify a compact JWS')
    p_vj.add_argument('--alg', required=True, help='JOSE algorithm (e.g. RS256)')
    p_vj.add_argument(
        '--pub-der-hex', required=True, help='Public key in DER format (hex)'
    )
    p_vj.add_argument(
        '--compact', required=True, help='Compact JWS (header.payload.signature)'
    )

    # decrypt-jwe
    p_dj = sub.add_parser('decrypt-jwe', help='Decrypt a flattened JWE')
    p_dj.add_argument('--key-hex', required=True, help='Raw symmetric key bytes (hex)')
    p_dj.add_argument('--protected', required=True, help='Protected header (base64url)')
    p_dj.add_argument('--encrypted-key', default='', help='Encrypted key (base64url)')
    p_dj.add_argument('--iv', required=True, help='IV (base64url)')
    p_dj.add_argument('--ciphertext', required=True, help='Ciphertext (base64url)')
    p_dj.add_argument('--tag', required=True, help='Tag (base64url)')
    p_dj.add_argument('--aad', default=None, help='AAD (base64url)')

    # encrypt-jwe
    p_ej = sub.add_parser('encrypt-jwe', help='Encrypt as flattened JWE')
    p_ej.add_argument('--key-hex', required=True, help='Raw symmetric key bytes (hex)')
    p_ej.add_argument('--kid', required=True, help='KMS key UID for protected header')
    p_ej.add_argument(
        '--enc', default='A256GCM', help='Content encryption alg (default: A256GCM)'
    )
    p_ej.add_argument('--plaintext-hex', required=True, help='Plaintext bytes (hex)')

    # mac-sha256
    p_mac = sub.add_parser('mac-sha256', help='Compute HMAC-SHA256')
    p_mac.add_argument(
        '--key-b64url', required=True, help='Key (base64url, no padding)'
    )
    p_mac.add_argument('--data-hex', required=True, help='Data bytes (hex)')

    args = parser.parse_args()

    commands = {
        'verify-jws': cmd_verify_jws,
        'decrypt-jwe': cmd_decrypt_jwe,
        'encrypt-jwe': cmd_encrypt_jwe,
        'mac-sha256': cmd_mac_sha256,
    }
    commands[args.command](args)


if __name__ == '__main__':
    main()

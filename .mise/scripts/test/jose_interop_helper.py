#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JOSE interoperability helper for KMS REST Crypto API testing.

Subcommands
-----------
verify-jws          Verify a detached JWS using a DER-encoded public key (via jwcrypto).
sign-jws            Sign data with a DER-encoded private key, output compact JWS.
decrypt-jwe         Decrypt a flattened JWE using raw symmetric key bytes (via jwcrypto).
encrypt-jwe         Encrypt plaintext as a flattened JWE using raw symmetric key bytes (via jwcrypto).
decrypt-jwe-rsa     Decrypt a flattened JWE using an RSA private key (RSA-OAEP / RSA-OAEP-256).
encrypt-jwe-rsa     Encrypt plaintext as a flattened JWE using an RSA public key (RSA-OAEP / RSA-OAEP-256).
mac-sha256          Compute HMAC-SHA256 over raw bytes using a base64url key (via jwcrypto).
mac                 Compute HMAC (HS256/HS384/HS512) over raw bytes using a hex key.
mac-verify          Verify HMAC (HS256/HS384/HS512) over raw bytes using a hex key.
wrap-cek-rsa        Wrap a symmetric CEK using RSA-OAEP with a DER public key.
generate-jwk        Generate a JWK key and output full private JWK JSON.

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


# ── sign-jws ──────────────────────────────────────────────────────────────────


def cmd_sign_jws(args: argparse.Namespace) -> None:
    """Sign data with a DER-encoded private key, output compact JWS."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    priv_der = binascii.unhexlify(args.priv_der_hex)
    priv_key_crypto = load_der_private_key(priv_der, password=None)

    key = jwk.JWK()
    key.import_from_pyca(priv_key_crypto)

    payload_bytes = _b64url_decode(args.payload_b64url)

    protected_header: dict = {'alg': args.alg}
    if args.kid:
        protected_header['kid'] = args.kid

    jws_obj = jws.JWS(payload_bytes)
    jws_obj.add_signature(key, alg=args.alg, protected=json.dumps(protected_header))

    # Output compact serialization: header.payload.signature
    print(jws_obj.serialize(compact=True))


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


# ── encrypt-jwe-rsa ───────────────────────────────────────────────────────────


def cmd_encrypt_jwe_rsa(args: argparse.Namespace) -> None:
    """Encrypt plaintext as flattened JWE using an RSA public key (RSA-OAEP)."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    pub_der = binascii.unhexlify(args.pub_der_hex)
    plaintext = binascii.unhexlify(args.plaintext_hex)

    pub_key_crypto = load_der_public_key(pub_der)
    key = jwk.JWK()
    key.import_from_pyca(pub_key_crypto)

    protected_header = {
        'alg': args.alg,
        'enc': args.enc,
        'kid': args.kid,
    }

    jwe_obj = jwe.JWE(
        plaintext,
        recipient=key,
        protected=json.dumps(protected_header),
    )

    serialized = jwe_obj.serialize(compact=False)
    print(serialized)


# ── decrypt-jwe-rsa ───────────────────────────────────────────────────────────


def cmd_decrypt_jwe_rsa(args: argparse.Namespace) -> None:
    """Decrypt a flattened JWE using an RSA private key (RSA-OAEP)."""
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    priv_der = binascii.unhexlify(args.priv_der_hex)
    priv_key_crypto = load_der_private_key(priv_der, password=None)

    key = jwk.JWK()
    key.import_from_pyca(priv_key_crypto)

    jwe_dict = {
        'protected': args.protected,
        'encrypted_key': args.encrypted_key,
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
        print(plaintext.hex())
    except Exception as e:
        print(f"error={e}", file=sys.stderr)
        sys.exit(1)


# ── mac-sha256 ────────────────────────────────────────────────────────────────


def cmd_mac_sha256(args: argparse.Namespace) -> None:
    """Compute HMAC-SHA256 over raw bytes and output as base64url."""
    import hashlib
    import hmac

    key_bytes = _b64url_decode(args.key_b64url)
    data_bytes = binascii.unhexlify(args.data_hex)

    mac_value = hmac.new(key_bytes, data_bytes, hashlib.sha256).digest()
    print(_b64url_no_pad(mac_value))


# ── mac (generic) ─────────────────────────────────────────────────────────────

_HMAC_ALG_MAP = {
    'HS256': 'sha256',
    'HS384': 'sha384',
    'HS512': 'sha512',
}


def cmd_mac(args: argparse.Namespace) -> None:
    """Compute HMAC (HS256/HS384/HS512) over raw bytes, output as base64url."""
    import hashlib
    import hmac

    hash_name = _HMAC_ALG_MAP.get(args.alg)
    if not hash_name:
        print(f"error=unsupported alg: {args.alg}", file=sys.stderr)
        sys.exit(1)

    key_bytes = binascii.unhexlify(args.key_hex)
    data_bytes = binascii.unhexlify(args.data_hex)

    mac_value = hmac.new(key_bytes, data_bytes, getattr(hashlib, hash_name)).digest()
    print(_b64url_no_pad(mac_value))


# ── mac-verify ────────────────────────────────────────────────────────────────


def cmd_mac_verify(args: argparse.Namespace) -> None:
    """Verify HMAC (HS256/HS384/HS512) over raw bytes."""
    import hashlib
    import hmac

    hash_name = _HMAC_ALG_MAP.get(args.alg)
    if not hash_name:
        print(f"error=unsupported alg: {args.alg}", file=sys.stderr)
        sys.exit(1)

    key_bytes = binascii.unhexlify(args.key_hex)
    data_bytes = binascii.unhexlify(args.data_hex)
    expected_mac = _b64url_decode(args.mac_b64url)

    computed = hmac.new(key_bytes, data_bytes, getattr(hashlib, hash_name)).digest()
    if hmac.compare_digest(computed, expected_mac):
        print('valid=true')
    else:
        print('valid=false')
        sys.exit(1)


# ── wrap-cek-rsa ──────────────────────────────────────────────────────────────


def cmd_wrap_cek_rsa(args: argparse.Namespace) -> None:
    """Wrap a symmetric CEK with RSA-OAEP using a DER public key.

    Outputs the wrapped key as base64url (no padding).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    pub_der = binascii.unhexlify(args.pub_der_hex)
    cek_bytes = binascii.unhexlify(args.cek_hex)

    pub_key = load_der_public_key(pub_der)

    if args.alg == 'RSA-OAEP':
        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        )
    elif args.alg == 'RSA-OAEP-256':
        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    else:
        print(f"error=unsupported alg: {args.alg}", file=sys.stderr)
        sys.exit(1)

    wrapped = pub_key.encrypt(cek_bytes, oaep_padding)
    print(_b64url_no_pad(wrapped))


# ── generate-jwk ──────────────────────────────────────────────────────────────


def cmd_generate_jwk(args: argparse.Namespace) -> None:
    """Generate a JWK key using jwcrypto, output full private JWK JSON.

    Supports RSA, EC, OKP (Ed25519), and oct (symmetric).
    The output includes all private components needed for import into KMS.
    """
    if args.kty == 'RSA':
        key = jwk.JWK.generate(kty='RSA', size=args.bits or 2048)
    elif args.kty == 'EC':
        crv = args.crv or 'P-256'
        key = jwk.JWK.generate(kty='EC', crv=crv)
    elif args.kty == 'OKP':
        crv = args.crv or 'Ed25519'
        key = jwk.JWK.generate(kty='OKP', crv=crv)
    elif args.kty == 'oct':
        size = args.bits or 256
        key = jwk.JWK.generate(kty='oct', size=size)
    else:
        print(f"error=unsupported kty: {args.kty}", file=sys.stderr)
        sys.exit(1)

    # Export full JWK (private for asymmetric, symmetric for oct)
    if args.kty == 'oct':
        jwk_dict = json.loads(key.export_symmetric())
    else:
        jwk_dict = json.loads(key.export_private())
    print(json.dumps(jwk_dict))


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

    # sign-jws
    p_sj = sub.add_parser('sign-jws', help='Sign data and output compact JWS')
    p_sj.add_argument('--alg', required=True, help='JOSE algorithm (e.g. RS256)')
    p_sj.add_argument(
        '--priv-der-hex', required=True, help='Private key in DER format (hex)'
    )
    p_sj.add_argument(
        '--payload-b64url', required=True, help='Payload (base64url, no padding)'
    )
    p_sj.add_argument(
        '--kid', default=None, help='Key ID to include in protected header'
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
    p_ej = sub.add_parser('encrypt-jwe', help='Encrypt as flattened JWE (dir)')
    p_ej.add_argument('--key-hex', required=True, help='Raw symmetric key bytes (hex)')
    p_ej.add_argument('--kid', required=True, help='KMS key UID for protected header')
    p_ej.add_argument(
        '--enc', default='A256GCM', help='Content encryption alg (default: A256GCM)'
    )
    p_ej.add_argument('--plaintext-hex', required=True, help='Plaintext bytes (hex)')

    # encrypt-jwe-rsa
    p_ejr = sub.add_parser(
        'encrypt-jwe-rsa', help='Encrypt as flattened JWE (RSA-OAEP)'
    )
    p_ejr.add_argument(
        '--pub-der-hex', required=True, help='RSA public key in DER format (hex)'
    )
    p_ejr.add_argument('--kid', required=True, help='KMS key UID for protected header')
    p_ejr.add_argument(
        '--alg',
        default='RSA-OAEP-256',
        help='Key management alg (default: RSA-OAEP-256)',
    )
    p_ejr.add_argument(
        '--enc', default='A256GCM', help='Content encryption alg (default: A256GCM)'
    )
    p_ejr.add_argument('--plaintext-hex', required=True, help='Plaintext bytes (hex)')

    # decrypt-jwe-rsa
    p_djr = sub.add_parser('decrypt-jwe-rsa', help='Decrypt a flattened JWE (RSA-OAEP)')
    p_djr.add_argument(
        '--priv-der-hex', required=True, help='RSA private key in DER format (hex)'
    )
    p_djr.add_argument(
        '--protected', required=True, help='Protected header (base64url)'
    )
    p_djr.add_argument(
        '--encrypted-key', required=True, help='Encrypted key (base64url)'
    )
    p_djr.add_argument('--iv', required=True, help='IV (base64url)')
    p_djr.add_argument('--ciphertext', required=True, help='Ciphertext (base64url)')
    p_djr.add_argument('--tag', required=True, help='Tag (base64url)')
    p_djr.add_argument('--aad', default=None, help='AAD (base64url)')

    # mac-sha256
    p_mac = sub.add_parser('mac-sha256', help='Compute HMAC-SHA256')
    p_mac.add_argument(
        '--key-b64url', required=True, help='Key (base64url, no padding)'
    )
    p_mac.add_argument('--data-hex', required=True, help='Data bytes (hex)')

    # mac (generic)
    p_mac_g = sub.add_parser('mac', help='Compute HMAC (HS256/HS384/HS512)')
    p_mac_g.add_argument(
        '--alg', required=True, help='HMAC algorithm (HS256, HS384, HS512)'
    )
    p_mac_g.add_argument('--key-hex', required=True, help='Key bytes (hex)')
    p_mac_g.add_argument('--data-hex', required=True, help='Data bytes (hex)')

    # mac-verify
    p_mac_v = sub.add_parser('mac-verify', help='Verify HMAC (HS256/HS384/HS512)')
    p_mac_v.add_argument(
        '--alg', required=True, help='HMAC algorithm (HS256, HS384, HS512)'
    )
    p_mac_v.add_argument('--key-hex', required=True, help='Key bytes (hex)')
    p_mac_v.add_argument('--data-hex', required=True, help='Data bytes (hex)')
    p_mac_v.add_argument(
        '--mac-b64url', required=True, help='Expected MAC (base64url, no padding)'
    )

    # wrap-cek-rsa
    p_wrap = sub.add_parser('wrap-cek-rsa', help='Wrap CEK with RSA-OAEP public key')
    p_wrap.add_argument(
        '--pub-der-hex', required=True, help='RSA public key in DER format (hex)'
    )
    p_wrap.add_argument('--cek-hex', required=True, help='CEK bytes (hex)')
    p_wrap.add_argument(
        '--alg',
        default='RSA-OAEP-256',
        help='Key management alg (default: RSA-OAEP-256)',
    )

    # generate-jwk
    p_gen = sub.add_parser(
        'generate-jwk', help='Generate a JWK key and output full private JWK JSON'
    )
    p_gen.add_argument('--kty', required=True, help='Key type (RSA, EC, OKP, oct)')
    p_gen.add_argument(
        '--crv', default=None, help='Curve (P-256, P-384, P-521, Ed25519)'
    )
    p_gen.add_argument('--bits', type=int, default=None, help='Key size in bits')

    args = parser.parse_args()

    commands = {
        'verify-jws': cmd_verify_jws,
        'sign-jws': cmd_sign_jws,
        'decrypt-jwe': cmd_decrypt_jwe,
        'encrypt-jwe': cmd_encrypt_jwe,
        'decrypt-jwe-rsa': cmd_decrypt_jwe_rsa,
        'encrypt-jwe-rsa': cmd_encrypt_jwe_rsa,
        'mac-sha256': cmd_mac_sha256,
        'mac': cmd_mac,
        'mac-verify': cmd_mac_verify,
        'wrap-cek-rsa': cmd_wrap_cek_rsa,
        'generate-jwk': cmd_generate_jwk,
    }
    commands[args.command](args)


if __name__ == '__main__':
    main()

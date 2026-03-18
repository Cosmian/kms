#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a CycloneDX 1.6 CBOM (Cryptographic Bill of Materials) for Cosmian KMS.

Usage
-----
    python3 scripts/generate_cbom.py [--output cbom/cbom.cdx.json]

How it works
------------
1. Runs ``cargo metadata --features non-fips`` to resolve implementing-library
   versions from Cargo.lock (reproducible, no network required).
2. Scans Rust source files under ``crate/`` for grep patterns that confirm each
   algorithm is actively referenced in the code base.
3. Emits a CycloneDX 1.6 CBOM JSON document.

Updating after a code change
-----------------------------
Re-run the script.  Library versions and source-scan results are refreshed
automatically; the algorithm catalog below (ALGORITHMS) is the only part that
requires manual maintenance when a new algorithm is added or removed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Implementing-library catalogue
# ---------------------------------------------------------------------------
# key       → used in ALGORITHMS[].implementing_libs
# display   → human-readable name in the CBOM
# purl_name → the cargo crate name for the pkg:cargo/… PURL
LIBRARIES: dict[str, dict[str, str]] = {
    'openssl': {
        'display': 'openssl (Rust bindings to OpenSSL FIPS provider)',
        'purl_name': 'openssl',
    },
    'aes-gcm-siv': {
        'display': 'aes-gcm-siv (RustCrypto)',
        'purl_name': 'aes-gcm-siv',
    },
    'chacha20poly1305': {
        'display': 'chacha20poly1305 (RustCrypto)',
        'purl_name': 'chacha20poly1305',
    },
    'argon2': {'display': 'argon2 (RustCrypto)', 'purl_name': 'argon2'},
    'k256': {'display': 'k256 (RustCrypto / secp256k1)', 'purl_name': 'k256'},
    'ml-kem': {'display': 'ml-kem (RustCrypto / FIPS 203)', 'purl_name': 'ml-kem'},
    'sha1': {'display': 'sha1 (RustCrypto)', 'purl_name': 'sha1'},
    'sha2': {'display': 'sha2 (RustCrypto)', 'purl_name': 'sha2'},
    'sha3': {'display': 'sha3 (RustCrypto)', 'purl_name': 'sha3'},
    'cosmian_cover_crypt': {
        'display': 'cosmian_cover_crypt (Cosmian ABE + hybrid KEM)',
        'purl_name': 'cosmian_cover_crypt',
    },
    'cosmian_crypto_core': {
        'display': 'cosmian_crypto_core (Cosmian KEM combiner + traits)',
        'purl_name': 'cosmian_crypto_core',
    },
    'cosmian_openssl_provider': {
        'display': 'cosmian_openssl_provider (P-256 KEM via OpenSSL)',
        'purl_name': 'cosmian_openssl_provider',
    },
    'cosmian_rust_curve25519_provider': {
        'display': 'cosmian_rust_curve25519_provider (X25519 / R25519 KEM)',
        'purl_name': 'cosmian_rust_curve25519_provider',
    },
}

# ---------------------------------------------------------------------------
# Algorithm catalogue
# ---------------------------------------------------------------------------
# Each entry describes one cryptographic algorithm as used in Cosmian KMS.
#
# Fields
#   bom_ref          unique bom-ref identifier
#   name             human-readable name (e.g. "AES-256-GCM")
#   primitive        CycloneDX 1.6 primitive:
#                      ae, block-cipher, stream-cipher, hash, kdf, kem,
#                      signature, key-agree, xof, combiner, pke
#   mode             block-cipher mode: gcm cbc ecb xts kw kwp  (optional)
#   padding          padding scheme: oaep pkcs1v15 pss raw none (optional)
#   key_size         key size in bits; None = variable / curve-dependent
#   classical_security  classical security level in bits
#   nist_pqc_level   NIST PQC category (0 = classical, 1/3/5 = PQC)
#   fips             True = FIPS 140-3 approved
#                    False = non-FIPS only (feature-flagged at compile time)
#                    "restricted" = conditionally approved (e.g. SHA-1)
#   functions        CycloneDX cryptoFunctions list
#   implementing_libs  list of keys from LIBRARIES above
#   usage            plain-English description of where this is used in KMS
#   oid              ASN.1 OID (optional)
#   patterns         list of Python regex patterns (re.search) that should
#                    match in crate/ source when the algorithm is active;
#                    used to validate the catalogue
ALGORITHMS: list[dict[str, Any]] = [
    # ── Symmetric authenticated encryption ──────────────────────────────────
    {
        'bom_ref': 'algo-aes-128-gcm',
        'name': 'AES-128-GCM',
        'primitive': 'ae',
        'mode': 'gcm',
        'key_size': 128,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'DEM in ECIES P-256; KMIP Encrypt/Decrypt; CoverCrypt data encapsulation',
        'oid': '2.16.840.1.101.3.4.1.6',
        'patterns': [r'aes_128_gcm|Aes128Gcm'],
    },
    {
        'bom_ref': 'algo-aes-192-gcm',
        'name': 'AES-192-GCM',
        'primitive': 'ae',
        'mode': 'gcm',
        'key_size': 192,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt (192-bit symmetric keys)',
        'oid': '2.16.840.1.101.3.4.1.26',
        'patterns': [r'aes_192_gcm|Aes192Gcm'],
    },
    {
        'bom_ref': 'algo-aes-256-gcm',
        'name': 'AES-256-GCM',
        'primitive': 'ae',
        'mode': 'gcm',
        'key_size': 256,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'DEM in ECIES P-384/P-521; KMIP Encrypt/Decrypt; CoverCrypt data encapsulation',
        'oid': '2.16.840.1.101.3.4.1.46',
        'patterns': [r'aes_256_gcm|Aes256Gcm'],
    },
    {
        'bom_ref': 'algo-aes-128-cbc',
        'name': 'AES-128-CBC',
        'primitive': 'block-cipher',
        'mode': 'cbc',
        'key_size': 128,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt',
        'oid': '2.16.840.1.101.3.4.1.2',
        'patterns': [r'aes_128_cbc|Aes128Cbc'],
    },
    {
        'bom_ref': 'algo-aes-192-cbc',
        'name': 'AES-192-CBC',
        'primitive': 'block-cipher',
        'mode': 'cbc',
        'key_size': 192,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt',
        'oid': '2.16.840.1.101.3.4.1.22',
        'patterns': [r'aes_192_cbc|Aes192Cbc'],
    },
    {
        'bom_ref': 'algo-aes-256-cbc',
        'name': 'AES-256-CBC',
        'primitive': 'block-cipher',
        'mode': 'cbc',
        'key_size': 256,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt',
        'oid': '2.16.840.1.101.3.4.1.42',
        'patterns': [r'aes_256_cbc|Aes256Cbc'],
    },
    {
        'bom_ref': 'algo-aes-128-ecb',
        'name': 'AES-128-ECB',
        'primitive': 'block-cipher',
        'mode': 'ecb',
        'key_size': 128,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt (not recommended for new data-at-rest encryption)',
        'oid': '2.16.840.1.101.3.4.1.1',
        'patterns': [r'aes_128_ecb|Aes128Ecb'],
    },
    {
        'bom_ref': 'algo-aes-192-ecb',
        'name': 'AES-192-ECB',
        'primitive': 'block-cipher',
        'mode': 'ecb',
        'key_size': 192,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt',
        'oid': '2.16.840.1.101.3.4.1.21',
        'patterns': [r'aes_192_ecb|Aes192Ecb'],
    },
    {
        'bom_ref': 'algo-aes-256-ecb',
        'name': 'AES-256-ECB',
        'primitive': 'block-cipher',
        'mode': 'ecb',
        'key_size': 256,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt',
        'oid': '2.16.840.1.101.3.4.1.41',
        'patterns': [r'aes_256_ecb|Aes256Ecb'],
    },
    {
        'bom_ref': 'algo-aes-128-xts',
        'name': 'AES-128-XTS',
        'primitive': 'block-cipher',
        'mode': 'xts',
        'key_size': 128,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt (storage / disk encryption)',
        'patterns': [r'aes_128_xts|Aes128Xts'],
    },
    {
        'bom_ref': 'algo-aes-256-xts',
        'name': 'AES-256-XTS',
        'primitive': 'block-cipher',
        'mode': 'xts',
        'key_size': 256,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Encrypt/Decrypt (storage / disk encryption)',
        'patterns': [r'aes_256_xts|Aes256Xts'],
    },
    # ── Non-FIPS symmetric (feature = non-fips) ──────────────────────────────
    {
        'bom_ref': 'algo-aes-128-gcm-siv',
        'name': 'AES-128-GCM-SIV',
        'primitive': 'ae',
        'mode': 'gcm',
        'key_size': 128,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['aes-gcm-siv'],
        'usage': 'KMIP Encrypt/Decrypt; nonce-misuse-resistant AEAD (non-FIPS only)',
        'patterns': [r'GcmSiv|gcm_siv'],
    },
    {
        'bom_ref': 'algo-aes-256-gcm-siv',
        'name': 'AES-256-GCM-SIV',
        'primitive': 'ae',
        'mode': 'gcm',
        'key_size': 256,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['aes-gcm-siv'],
        'usage': 'KMIP Encrypt/Decrypt; nonce-misuse-resistant AEAD (non-FIPS only)',
        'patterns': [r'GcmSiv|gcm_siv'],
    },
    {
        'bom_ref': 'algo-chacha20-poly1305',
        'name': 'ChaCha20-Poly1305',
        'primitive': 'ae',
        'key_size': 256,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt'],
        'implementing_libs': ['chacha20poly1305'],
        'usage': 'KMIP Encrypt/Decrypt (non-FIPS only)',
        'patterns': [r'ChaCha20Poly1305|chacha20poly1305|Chacha20Poly1305'],
    },
    # ── AES key wrapping ─────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-aes-kw',
        'name': 'AES-KW',
        'primitive': 'block-cipher',
        'mode': 'kw',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Import/Export key wrapping without padding (RFC 3394 / NIST SP 800-38F)',
        'oid': '2.16.840.1.101.3.4.1.5',
        'patterns': [r'Rfc3394|rfc3394'],
    },
    {
        'bom_ref': 'algo-aes-kwp',
        'name': 'AES-KWP',
        'primitive': 'block-cipher',
        'mode': 'kwp',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Import/Export key wrapping with padding (RFC 5649); used inside CKM_RSA_AES_KEY_WRAP',
        'oid': '2.16.840.1.101.3.4.1.8',
        'patterns': [r'Rfc5649|rfc5649'],
    },
    # ── RSA ──────────────────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-rsa-oaep',
        'name': 'RSA-OAEP',
        'primitive': 'pke',
        'padding': 'oaep',
        'key_size': None,
        'classical_security': 112,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encrypt', 'decrypt', 'wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP key wrapping (CKM_RSA_PKCS_OAEP); RSA key sizes 2048 / 3072 / 4096 bits',
        'oid': '1.2.840.113549.1.1.7',
        'patterns': [r'CkmRsaPkcsOaep|Oaep|oaep'],
    },
    {
        'bom_ref': 'algo-ckm-rsa-aes-key-wrap',
        'name': 'CKM_RSA_AES_KEY_WRAP',
        'primitive': 'pke',
        'padding': 'oaep',
        'key_size': None,
        'classical_security': 112,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'PKCS#11-compatible hybrid key wrapping: RSA-OAEP wraps a per-session AES key; AES-KWP wraps the target key',
        'patterns': [r'CkmRsaAesKeyWrap|RsaAesKeyWrap'],
    },
    {
        'bom_ref': 'algo-rsa-pkcs1v15',
        'name': 'RSA-PKCS1-v1.5',
        'primitive': 'pke',
        'padding': 'pkcs1v15',
        'key_size': None,
        'classical_security': 112,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt', 'wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP key wrapping (CKM_RSA_PKCS) — deprecated; removed from FIPS 140-3 approved list',
        'oid': '1.2.840.113549.1.1.1',
        'patterns': [r'CkmRsaPkcs\b|PkcsV1_5|Pkcs1v15'],
    },
    # ── ECIES (non-FIPS) ─────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-ecies-p256',
        'name': 'ECIES-P256',
        'primitive': 'ae',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt', 'wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'Hybrid encrypt/wrap with P-256: ECDH + SHAKE-128 (KDF+IV) + AES-128-GCM; non-FIPS only',
        'patterns': [r'ecies_encrypt|ecies_decrypt'],
    },
    {
        'bom_ref': 'algo-ecies-p384',
        'name': 'ECIES-P384',
        'primitive': 'ae',
        'key_size': 384,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt', 'wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'Hybrid encrypt/wrap with P-384: ECDH + SHAKE-256 (KDF+IV) + AES-256-GCM; non-FIPS only',
        'patterns': [r'ecies_encrypt|ecies_decrypt|Secp384R1|secp384r1'],
    },
    {
        'bom_ref': 'algo-ecies-p521',
        'name': 'ECIES-P521',
        'primitive': 'ae',
        'key_size': 521,
        'classical_security': 260,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt', 'wrap', 'unwrap'],
        'implementing_libs': ['openssl'],
        'usage': 'Hybrid encrypt/wrap with P-521: ECDH + SHAKE-256 (KDF+IV) + AES-256-GCM; non-FIPS only',
        'patterns': [r'ecies_encrypt|ecies_decrypt|Secp521R1|secp521r1'],
    },
    {
        'bom_ref': 'algo-ecies-salsa',
        'name': 'ECIES-X25519-XSalsa20-Poly1305',
        'primitive': 'ae',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encrypt', 'decrypt', 'wrap', 'unwrap'],
        'implementing_libs': ['cosmian_rust_curve25519_provider'],
        'usage': 'Salsa Sealed Box: libsodium-compatible (X25519 ECDH + XSalsa20-Poly1305); non-FIPS only',
        'patterns': [r'salsa_sealbox|SalsaSealbox|sealed_box|SealedBox|crypto_box'],
    },
    # ── KEM ──────────────────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-kem-p256',
        'name': 'P256-KEM',
        'primitive': 'kem',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_openssl_provider'],
        'usage': 'Pre-quantum KEM over P-256: MonadicKEM<32, P256, SHA-256>; shared secret 32 bytes; used in CoverCrypt',
        'patterns': [
            r'cover_crypt|Covercrypt'
        ],  # P256 KEM is internal to cosmian_cover_crypt; used via Covercrypt API
    },
    {
        'bom_ref': 'algo-kem-r25519',
        'name': 'R25519-KEM',
        'primitive': 'kem',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_rust_curve25519_provider'],
        'usage': 'Pre-quantum KEM over Ristretto255/X25519: GenericKEM<32, R25519, SHA-256>; non-FIPS',
        'patterns': [
            r'cover_crypt|Covercrypt'
        ],  # R25519 KEM is internal to cosmian_cover_crypt; used via Covercrypt API
    },
    {
        'bom_ref': 'algo-ml-kem-512',
        'name': 'ML-KEM-512',
        'primitive': 'kem',
        'key_size': 800,
        'classical_security': 128,
        'nist_pqc_level': 1,
        'fips': True,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['ml-kem'],
        'usage': 'Post-quantum KEM (NIST FIPS 203 Level 1); used in CoverCrypt hybrid KEM',
        'oid': '1.3.6.1.4.1.22554.5.6.1',
        'patterns': [r'MlKem512|ml_kem.*512'],
    },
    {
        'bom_ref': 'algo-ml-kem-768',
        'name': 'ML-KEM-768',
        'primitive': 'kem',
        'key_size': 1184,
        'classical_security': 192,
        'nist_pqc_level': 3,
        'fips': True,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['ml-kem'],
        'usage': 'Post-quantum KEM (NIST FIPS 203 Level 3); used in CoverCrypt hybrid KEM',
        'oid': '1.3.6.1.4.1.22554.5.6.2',
        'patterns': [r'MlKem768|ml_kem.*768'],
    },
    {
        'bom_ref': 'algo-hybrid-kem-p256-mlkem512',
        'name': 'P256+ML-KEM-512 Hybrid KEM',
        'primitive': 'kem',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 1,
        'fips': True,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_cover_crypt'],
        'usage': 'Hybrid KEM: P256-KEM ⊕ ML-KEM-512 via KemCombiner<SHA-256>; CoverCrypt ABE policy encryption',
        'patterns': [r'cover_crypt|Covercrypt'],
    },
    {
        'bom_ref': 'algo-hybrid-kem-p256-mlkem768',
        'name': 'P256+ML-KEM-768 Hybrid KEM',
        'primitive': 'kem',
        'key_size': 256,
        'classical_security': 192,
        'nist_pqc_level': 3,
        'fips': True,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_cover_crypt'],
        'usage': 'Hybrid KEM: P256-KEM ⊕ ML-KEM-768 via KemCombiner<SHA-256>; CoverCrypt ABE policy encryption',
        'patterns': [r'cover_crypt|Covercrypt'],
    },
    {
        'bom_ref': 'algo-hybrid-kem-r25519-mlkem512',
        'name': 'R25519+ML-KEM-512 Hybrid KEM',
        'primitive': 'kem',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 1,
        'fips': False,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_cover_crypt'],
        'usage': 'Hybrid KEM: R25519-KEM ⊕ ML-KEM-512 via KemCombiner<SHA-256>; non-FIPS',
        'patterns': [r'cover_crypt|Covercrypt'],
    },
    {
        'bom_ref': 'algo-hybrid-kem-r25519-mlkem768',
        'name': 'R25519+ML-KEM-768 Hybrid KEM',
        'primitive': 'kem',
        'key_size': 256,
        'classical_security': 192,
        'nist_pqc_level': 3,
        'fips': False,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_cover_crypt'],
        'usage': 'Hybrid KEM: R25519-KEM ⊕ ML-KEM-768 via KemCombiner<SHA-256>; non-FIPS',
        'patterns': [r'cover_crypt|Covercrypt'],
    },
    {
        'bom_ref': 'algo-kem-combiner',
        'name': 'KEM Combiner (SHA-256)',
        'primitive': 'combiner',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['encapsulate', 'decapsulate'],
        'implementing_libs': ['cosmian_crypto_core'],
        'usage': 'Combines two KEM outputs: SHA-256(ek ‖ ss₁ ‖ ss₂ ‖ enc₁ ‖ enc₂); CCA-secure if either KEM is secure',
        'patterns': [
            r'cover_crypt|Covercrypt'
        ],  # combiner is internal to cosmian_cover_crypt / cosmian_crypto_core
    },
    # ── Digital signatures ───────────────────────────────────────────────────
    {
        'bom_ref': 'algo-rsassa-pss-2048',
        'name': 'RSASSA-PSS-2048',
        'primitive': 'signature',
        'padding': 'pss',
        'key_size': 2048,
        'classical_security': 112,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — RSA-2048 with PSS padding (FIPS 186-5)',
        'oid': '1.2.840.113549.1.1.10',
        'patterns': [
            r'RsaPss|RSASSAPSS'
        ],  # crate uses RsaPss (PKCS11) and RSASSAPSS (DigitalSignatureAlgorithm)
    },
    {
        'bom_ref': 'algo-rsassa-pss-3072',
        'name': 'RSASSA-PSS-3072',
        'primitive': 'signature',
        'padding': 'pss',
        'key_size': 3072,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — RSA-3072 with PSS padding (FIPS 186-5)',
        'oid': '1.2.840.113549.1.1.10',
        'patterns': [r'RsaPss|RSASSAPSS'],
    },
    {
        'bom_ref': 'algo-rsassa-pss-4096',
        'name': 'RSASSA-PSS-4096',
        'primitive': 'signature',
        'padding': 'pss',
        'key_size': 4096,
        'classical_security': 140,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — RSA-4096 with PSS padding (FIPS 186-5)',
        'oid': '1.2.840.113549.1.1.10',
        'patterns': [r'RsaPss|RSASSAPSS'],
    },
    {
        'bom_ref': 'algo-ecdsa-p256',
        'name': 'ECDSA-P256',
        'primitive': 'signature',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — NIST P-256 (FIPS 186-5 / SP 800-186)',
        'oid': '1.2.840.10045.4.3.2',
        'patterns': [r'ecdsa|Ecdsa|ECDSA'],
    },
    {
        'bom_ref': 'algo-ecdsa-p384',
        'name': 'ECDSA-P384',
        'primitive': 'signature',
        'key_size': 384,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — NIST P-384 (FIPS 186-5 / SP 800-186)',
        'oid': '1.2.840.10045.4.3.3',
        'patterns': [r'ecdsa|Ecdsa|ECDSA'],
    },
    {
        'bom_ref': 'algo-ecdsa-p521',
        'name': 'ECDSA-P521',
        'primitive': 'signature',
        'key_size': 521,
        'classical_security': 260,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — NIST P-521 (FIPS 186-5 / SP 800-186)',
        'oid': '1.2.840.10045.4.3.4',
        'patterns': [r'ecdsa|Ecdsa|ECDSA'],
    },
    {
        'bom_ref': 'algo-ecdsa-secp256k1',
        'name': 'ECDSA-secp256k1',
        'primitive': 'signature',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['k256'],
        'usage': 'KMIP Sign/Verify — secp256k1 with RFC 6979 deterministic signing; non-FIPS only',
        'patterns': [r'k256|secp256k1|Secp256k1'],
    },
    {
        'bom_ref': 'algo-eddsa-ed25519',
        'name': 'EdDSA-Ed25519',
        'primitive': 'signature',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — Ed25519 (FIPS 186-5)',
        'oid': '1.3.101.112',
        'patterns': [r'Ed25519|ed25519'],
    },
    {
        'bom_ref': 'algo-eddsa-ed448',
        'name': 'EdDSA-Ed448',
        'primitive': 'signature',
        'key_size': 448,
        'classical_security': 224,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['sign', 'verify'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP Sign/Verify — Ed448 (FIPS 186-5)',
        'oid': '1.3.101.113',
        'patterns': [r'Ed448|ed448'],
    },
    # ── Key agreement ────────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-ecdh-p256',
        'name': 'ECDH-P256',
        'primitive': 'key-agree',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['generate'],
        'implementing_libs': ['openssl'],
        'usage': 'ECDH key agreement step inside ECIES P-256',
        'oid': '1.2.840.10045.3.1.7',
        'patterns': [r'ecies_encrypt|ecies_decrypt|standard_curves'],
    },
    {
        'bom_ref': 'algo-ecdh-p384',
        'name': 'ECDH-P384',
        'primitive': 'key-agree',
        'key_size': 384,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['generate'],
        'implementing_libs': ['openssl'],
        'usage': 'ECDH key agreement step inside ECIES P-384',
        'oid': '1.3.132.0.34',
        'patterns': [r'ecies_encrypt|ecies_decrypt|Secp384R1'],
    },
    {
        'bom_ref': 'algo-ecdh-p521',
        'name': 'ECDH-P521',
        'primitive': 'key-agree',
        'key_size': 521,
        'classical_security': 260,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['generate'],
        'implementing_libs': ['openssl'],
        'usage': 'ECDH key agreement step inside ECIES P-521',
        'oid': '1.3.132.0.35',
        'patterns': [r'ecies_encrypt|ecies_decrypt|Secp521R1'],
    },
    {
        'bom_ref': 'algo-x25519',
        'name': 'X25519',
        'primitive': 'key-agree',
        'key_size': 256,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['generate'],
        'implementing_libs': ['cosmian_rust_curve25519_provider'],
        'usage': 'ECDH key agreement inside ECIES Salsa Sealed Box; X25519 KMIP key type',
        'oid': '1.3.101.110',
        'patterns': [r'X25519|x25519'],
    },
    # ── Key derivation ───────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-pbkdf2-sha256',
        'name': 'PBKDF2-HMAC-SHA-256',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['keyderive'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP DeriveKey (PBKDF2 method, default hash, default 600 000 iterations)',
        'oid': '1.2.840.113549.1.5.12',
        'patterns': [r'pbkdf2_hmac|Pbkdf2|PBKDF2'],
    },
    {
        'bom_ref': 'algo-pbkdf2-sha384',
        'name': 'PBKDF2-HMAC-SHA-384',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['keyderive'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP DeriveKey (PBKDF2 method)',
        'oid': '1.2.840.113549.1.5.12',
        'patterns': [r'pbkdf2_hmac|Pbkdf2|PBKDF2'],
    },
    {
        'bom_ref': 'algo-pbkdf2-sha512',
        'name': 'PBKDF2-HMAC-SHA-512',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['keyderive'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP DeriveKey (PBKDF2 method); password-based key derivation in FIPS mode (210 000 iterations, random 128-bit salt)',
        'oid': '1.2.840.113549.1.5.12',
        'patterns': [r'pbkdf2_hmac|FIPS_MIN_ITER'],
    },
    {
        'bom_ref': 'algo-hkdf-sha256',
        'name': 'HKDF-SHA-256',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['keyderive'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP DeriveKey (HKDF method, default hash)',
        'patterns': [r'Id::HKDF|HKDF\b|hkdf'],
    },
    {
        'bom_ref': 'algo-hkdf-sha384',
        'name': 'HKDF-SHA-384',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['keyderive'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP DeriveKey (HKDF method)',
        'patterns': [r'Id::HKDF|HKDF\b|hkdf'],
    },
    {
        'bom_ref': 'algo-hkdf-sha512',
        'name': 'HKDF-SHA-512',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['keyderive'],
        'implementing_libs': ['openssl'],
        'usage': 'KMIP DeriveKey (HKDF method)',
        'patterns': [r'Id::HKDF|HKDF\b|hkdf'],
    },
    {
        'bom_ref': 'algo-argon2id',
        'name': 'Argon2id',
        'primitive': 'kdf',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['keyderive'],
        'implementing_libs': ['argon2'],
        'usage': 'Password-based key derivation in non-FIPS mode (random 128-bit salt; computationally hard)',
        'oid': '1.3.6.1.4.1.40885.1.1.2',
        'patterns': [r'Argon2|argon2'],
    },
    # ── Hash functions ───────────────────────────────────────────────────────
    {
        'bom_ref': 'algo-sha-1',
        'name': 'SHA-1',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 80,
        'nist_pqc_level': 0,
        'fips': 'restricted',
        'functions': ['digest'],
        'implementing_libs': ['openssl', 'sha1'],
        'usage': 'Accepted only as optional hash argument for PBKDF2 and HKDF; not used by default',
        'oid': '1.3.14.3.2.26',
        'patterns': [r'\bsha1\b|\bSha1\b|\bSHA1\b|sha_1'],
    },
    {
        'bom_ref': 'algo-sha-224',
        'name': 'SHA-224',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 112,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl'],
        'usage': 'Supported hash for RSASSA-PSS, PBKDF2, HKDF, RSA-OAEP',
        'oid': '2.16.840.1.101.3.4.2.4',
        'patterns': [r'sha224|Sha224|sha_224'],
    },
    {
        'bom_ref': 'algo-sha-256',
        'name': 'SHA-256',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl', 'sha2'],
        'usage': 'Default hash in RSASSA-PSS, PBKDF2, HKDF, RSA-OAEP; KEM combiner KDF',
        'oid': '2.16.840.1.101.3.4.2.1',
        'patterns': [r'sha256|Sha256|sha_256'],
    },
    {
        'bom_ref': 'algo-sha-384',
        'name': 'SHA-384',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl'],
        'usage': 'Supported hash for RSASSA-PSS, PBKDF2, HKDF, RSA-OAEP',
        'oid': '2.16.840.1.101.3.4.2.2',
        'patterns': [r'sha384|Sha384|sha_384'],
    },
    {
        'bom_ref': 'algo-sha-512',
        'name': 'SHA-512',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl'],
        'usage': 'Supported hash for RSASSA-PSS, PBKDF2, HKDF, RSA-OAEP; FIPS-mode password derivation',
        'oid': '2.16.840.1.101.3.4.2.3',
        'patterns': [r'sha512|Sha512|sha_512|FIPS_MIN_ITER'],
    },
    {
        'bom_ref': 'algo-sha3-224',
        'name': 'SHA3-224',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 112,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl', 'sha3'],
        'usage': 'Supported hash for RSA-OAEP and general KMIP hash operations',
        'oid': '2.16.840.1.101.3.4.2.7',
        'patterns': [r'sha3_224|Sha3_224|sha3.*224'],
    },
    {
        'bom_ref': 'algo-sha3-256',
        'name': 'SHA3-256',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl', 'sha3'],
        'usage': 'Supported hash for RSA-OAEP and general KMIP hash operations',
        'oid': '2.16.840.1.101.3.4.2.8',
        'patterns': [r'sha3_256|Sha3_256|sha3.*256'],
    },
    {
        'bom_ref': 'algo-sha3-384',
        'name': 'SHA3-384',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 192,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl', 'sha3'],
        'usage': 'Supported hash for RSA-OAEP and general KMIP hash operations',
        'oid': '2.16.840.1.101.3.4.2.9',
        'patterns': [r'sha3_384|Sha3_384|sha3.*384'],
    },
    {
        'bom_ref': 'algo-sha3-512',
        'name': 'SHA3-512',
        'primitive': 'hash',
        'key_size': None,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': True,
        'functions': ['digest'],
        'implementing_libs': ['openssl', 'sha3'],
        'usage': 'Supported hash for RSA-OAEP and general KMIP hash operations',
        'oid': '2.16.840.1.101.3.4.2.10',
        'patterns': [r'sha3_512|Sha3_512|sha3.*512'],
    },
    # ── Extendable-output functions (XOF) ────────────────────────────────────
    {
        'bom_ref': 'algo-shake-128',
        'name': 'SHAKE-128',
        'primitive': 'xof',
        'key_size': None,
        'classical_security': 128,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['digest'],
        'implementing_libs': ['openssl'],
        'usage': 'KDF + IV derivation in ECIES P-256 (non-FIPS context; NIST FIPS 202)',
        'patterns': [r'shake_128|shake128|SHAKE128|Shake128'],
    },
    {
        'bom_ref': 'algo-shake-256',
        'name': 'SHAKE-256',
        'primitive': 'xof',
        'key_size': None,
        'classical_security': 256,
        'nist_pqc_level': 0,
        'fips': False,
        'functions': ['digest'],
        'implementing_libs': ['openssl'],
        'usage': 'KDF + IV derivation in ECIES P-384 / P-521 (non-FIPS context; NIST FIPS 202)',
        'patterns': [r'shake_256|shake256|SHAKE256|Shake256'],
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def cargo_meta_versions(root: Path) -> dict[str, str]:
    """Run cargo metadata and return {crate_name: version} for known libs."""
    cmd = [
        'cargo',
        'metadata',
        '--format-version',
        '1',
        '--features',
        'non-fips',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=root)
    if result.returncode != 0:
        print(
            f"Warning: cargo metadata failed — library versions will be 'unknown'.\n"
            f"  stderr: {result.stderr[:300]}",
            file=sys.stderr,
        )
        return {}
    meta = json.loads(result.stdout)
    versions: dict[str, str] = {}
    for pkg in meta['packages']:
        name = pkg['name']
        if name in LIBRARIES and name not in versions:
            versions[name] = pkg['version']
    return versions


def find_in_sources(root: Path, patterns: list[str]) -> bool:
    """Return True if any pattern matches in *.rs files under crate/."""
    src_root = root / 'crate'
    if not src_root.exists():
        return True  # can't scan, assume present
    combined = '|'.join(f"(?:{p})" for p in patterns)
    try:
        result = subprocess.run(
            ['grep', '-rqE', '--include=*.rs', combined, str(src_root)],
            capture_output=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return True  # grep not available (Windows); skip scan


def certification_level(fips: bool | str) -> list[str]:
    if fips is True:
        return ['fips140-3']
    if fips == 'restricted':
        return ['fips140-3']  # conditionally approved
    return []


def build_algorithm_component(
    algo: dict[str, Any],
    found_in_source: bool,
) -> dict[str, Any]:
    algo_props: dict[str, Any] = {
        'primitive': algo['primitive'],
        'executionEnvironment': 'software',
        'implementationLevel': 'library',
        'certificationLevel': certification_level(algo['fips']),
        'cryptoFunctions': algo['functions'],
        'classicalSecurityLevel': algo['classical_security'],
        'nistQuantumSecurityLevel': algo['nist_pqc_level'],
    }
    if algo.get('mode'):
        algo_props['mode'] = algo['mode']
    if algo.get('padding'):
        algo_props['padding'] = algo['padding']
    if algo.get('key_size') is not None:
        algo_props['parameterSetIdentifier'] = str(algo['key_size'])

    crypto_props: dict[str, Any] = {
        'assetType': 'algorithm',
        'algorithmProperties': algo_props,
    }
    if algo.get('oid'):
        crypto_props['oid'] = algo['oid']

    comp: dict[str, Any] = {
        'type': 'cryptographic-asset',
        'bom-ref': algo['bom_ref'],
        'name': algo['name'],
        'description': algo['usage'],
        'cryptoProperties': crypto_props,
        'properties': [
            {
                'name': 'fips140-3:approved',
                'value': (
                    'true'
                    if algo['fips'] is True
                    else ('restricted' if algo['fips'] == 'restricted' else 'false')
                ),
            },
            {
                'name': 'cosmian:non-fips-feature-required',
                'value': 'false' if algo['fips'] is not False else 'true',
            },
            {
                'name': 'cosmian:found-in-source',
                'value': str(found_in_source).lower(),
            },
        ],
    }
    return comp


def build_library_component(key: str, versions: dict[str, str]) -> dict[str, Any]:
    info = LIBRARIES[key]
    version = versions.get(key, 'unknown')
    comp: dict[str, Any] = {
        'type': 'library',
        'bom-ref': f"lib-{key}",
        'name': info['display'],
        'version': version,
    }
    if version != 'unknown':
        comp['purl'] = f"pkg:cargo/{info['purl_name']}@{version}"
    return comp


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------


def build_cbom(root: Path, kms_version: str) -> dict[str, Any]:
    print('Resolving library versions from cargo metadata…', file=sys.stderr)
    versions = cargo_meta_versions(root)

    print('Scanning source files for algorithm references…', file=sys.stderr)
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    all_lib_keys: set[str] = set()

    for algo in ALGORITHMS:
        found = find_in_sources(root, algo['patterns'])
        if not found:
            print(
                f"  ⚠  {algo['name']}: no source match for patterns {algo['patterns']}",
                file=sys.stderr,
            )
        comp = build_algorithm_component(algo, found)
        components.append(comp)
        lib_keys = algo['implementing_libs']
        all_lib_keys.update(lib_keys)
        dependencies.append(
            {
                'ref': algo['bom_ref'],
                'dependsOn': [f"lib-{k}" for k in lib_keys],
            }
        )

    # Library components (after algorithms to keep algorithms first)
    lib_components = []
    for key in sorted(all_lib_keys):
        lib_components.append(build_library_component(key, versions))
    components = lib_components + components

    # Top-level depends-on list
    top_depends_on = [f"lib-{k}" for k in sorted(all_lib_keys)] + [
        a['bom_ref'] for a in ALGORITHMS
    ]
    dependencies.insert(
        0,
        {'ref': 'kms-server', 'dependsOn': top_depends_on},
    )

    cbom: dict[str, Any] = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': f"urn:uuid:{uuid.uuid4()}",
        'version': 1,
        'metadata': {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'tools': [
                {
                    'type': 'application',
                    'name': 'generate_cbom.py',
                    'version': '1.0',
                    'description': 'Cosmian KMS CBOM generator — combines cargo metadata with source scanning',
                }
            ],
            'component': {
                'type': 'application',
                'bom-ref': 'kms-server',
                'name': 'cosmian-kms',
                'version': kms_version,
                'description': 'Cosmian Key Management System — FIPS 140-3 compliant KMS server',
                'externalReferences': [
                    {
                        'type': 'vcs',
                        'url': 'https://github.com/Cosmian/kms',
                    }
                ],
            },
        },
        'components': components,
        'dependencies': dependencies,
    }
    return cbom


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Generate a CycloneDX 1.6 CBOM for Cosmian KMS'
    )
    parser.add_argument(
        '--output',
        '-o',
        metavar='FILE',
        default=str(ROOT / 'cbom' / 'cbom.cdx.json'),
        help='Output path (default: cbom/cbom.cdx.json)',
    )
    parser.add_argument(
        '--kms-version',
        default='5.17.0',
        help='KMS version string to embed in metadata (default: 5.17.0)',
    )
    args = parser.parse_args()

    cbom = build_cbom(ROOT, args.kms_version)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('w', encoding='utf-8') as fh:
        json.dump(cbom, fh, indent=2, ensure_ascii=False)
        fh.write('\n')

    algo_count = sum(
        1 for c in cbom['components'] if c['type'] == 'cryptographic-asset'
    )
    lib_count = sum(1 for c in cbom['components'] if c['type'] == 'library')
    print(
        f"CBOM written to {output_path}\n"
        f"  {algo_count} cryptographic-asset components, {lib_count} library components",
        file=sys.stderr,
    )


if __name__ == '__main__':
    main()

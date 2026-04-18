#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptographic Source Scanner
==============================
Scans Rust source files under one or more directories to build a
cryptographic inventory: algorithms used, libraries imported, key sizes,
deprecated primitives, PQC coverage, and zeroize discipline.

Usage:
    python3 scan_source.py --repo-root /path/to/repo --output findings.json
    python3 scan_source.py --repo-root /path/to/repo --scan-dirs src,lib --output findings.json

Output (findings.json):
    {
      "scan_date": "...",
      "repo_root": "...",
      "commit": "...",
      "findings": [ { "file", "line", "category", "algorithm", "severity",
                       "detail", "framework_ref" }, ... ],
      "summary": { "algorithms": {...}, "libraries": {...}, "stats": {...} }
    }
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple


# ── Finding record ──────────────────────────────���────────────��─────────────────


class Finding(NamedTuple):
    file: str  # path relative to repo_root
    line: int
    category: str  # algorithm_usage | deprecated | weak_key | hardcoded_material |
    # library_import | pkcs11 | pqc | zeroize | tls_cert
    algorithm: str  # canonical algorithm name or library name
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    detail: str  # human-readable explanation
    framework_ref: str  # NIST/OWASP/CWE reference


# ── Detection rules ───────────────────────────────��────────────────────────────

# Each rule: (regex, category, algorithm_name, severity, detail, framework_ref)
# Ordered: deprecated first so they take precedence in summary coloring.
RULES: list[tuple[re.Pattern, str, str, str, str, str]] = [
    # ─ Deprecated / broken ────────────────────────────────────────────────────
    (
        re.compile(r'\bMd5::|\bmd5::compute|\bMessageDigest::md5\b'),
        'deprecated',
        'MD5',
        'CRITICAL',
        'MD5 is cryptographically broken — do not use for any security purpose.',
        'CWE-327 / OWASP A02:2021',
    ),
    (
        re.compile(r'\bSha1::|\bMessageDigest::sha1\b'),
        'deprecated',
        'SHA-1',
        'HIGH',
        'SHA-1 is deprecated for signing and integrity. Use SHA-256 or SHA-3.',
        'CWE-327 / NIST SP 800-131A',
    ),
    (
        re.compile(r'\b(DES|TripleDes|Des3|des_edge|des3_cbc)\b'),
        'deprecated',
        'DES/3DES',
        'CRITICAL',
        'DES/3DES prohibited by NIST SP 800-131A Rev. 2. Replace with AES-256-GCM.',
        'CWE-327 / NIST SP 800-131A',
    ),
    (
        re.compile(r'\bRC4\b|\brc4\b|\bArcfour\b'),
        'deprecated',
        'RC4',
        'CRITICAL',
        'RC4 is broken (RFC 7465). Replace with ChaCha20-Poly1305 or AES-GCM.',
        'CWE-327 / RFC 7465',
    ),
    # ─ Weak key sizes ───────────────────────────��─────────────────────────────
    (
        re.compile(r'(?i)\brsa[_\s]*1024\b|\b1024[_\s]*rsa\b|bits\s*=\s*1024'),
        'weak_key',
        'RSA-1024',
        'HIGH',
        'RSA-1024 is below the NIST 112-bit security floor. Use RSA-2048 minimum.',
        'CWE-326 / NIST SP 800-131A',
    ),
    (
        re.compile(r'\bP192\b|\bNistP192\b|\bsecp192'),
        'weak_key',
        'EC-P192',
        'HIGH',
        'P-192 is below the 112-bit security level. Use P-256 or higher.',
        'CWE-326 / NIST SP 800-131A',
    ),
    # ─ Hardcoded key/IV material ─────────────────────────────────���────────────
    (
        re.compile(
            r'(?i)\b(key|secret|token|iv|nonce|seed)\s*[:=]\s*b"[0-9a-fA-F]{32,}"'
        ),
        'hardcoded_material',
        'HARDCODED-KEY',
        'HIGH',
        'Hardcoded key/IV literal detected. Load from a secure key store or HSM.',
        'CWE-321 / OWASP A02:2021',
    ),
    (
        re.compile(r'(?i)\b(key|iv|nonce)\s*=\s*&\[(?:0x[0-9a-fA-F]{2},?\s*){16,}\]'),
        'hardcoded_material',
        'HARDCODED-KEY',
        'HIGH',
        'Hardcoded key array detected. Load from a secure key store or HSM.',
        'CWE-321 / OWASP A02:2021',
    ),
    # ─ Algorithm usage — informational ────────────────────────────────────────
    (
        re.compile(
            r'CryptographicAlgorithm::Aes\b|aes_gcm::|aes_gcm_siv::|AesGcm|AesGcmSiv'
        ),
        'algorithm_usage',
        'AES-GCM/GCM-SIV',
        'INFO',
        'AES-GCM or AES-GCM-SIV usage detected (FIPS approved).',
        'NIST SP 800-38D',
    ),
    (
        re.compile(r'CryptographicAlgorithm::ChaCha20Poly1305|chacha20poly1305::'),
        'algorithm_usage',
        'ChaCha20-Poly1305',
        'INFO',
        'ChaCha20-Poly1305 usage detected (approved for non-FIPS deployments).',
        'RFC 8439',
    ),
    (
        re.compile(r'CryptographicAlgorithm::Rsa\b|ckm_rsa_pkcs|RsaPkcs|RsaOaep'),
        'algorithm_usage',
        'RSA',
        'INFO',
        'RSA usage detected.',
        'NIST SP 800-131A',
    ),
    (
        re.compile(
            r'CryptographicAlgorithm::EcDsa|EcDh|CryptographicAlgorithm::Ec\b|ecdsa::|elliptic_curve::'
        ),
        'algorithm_usage',
        'EC (ECDSA/ECDH)',
        'INFO',
        'Elliptic-curve usage detected (ECDSA / ECDH).',
        'FIPS 186-5',
    ),
    (
        re.compile(r'CryptographicAlgorithm::EdDsa|Ed25519|Ed448'),
        'algorithm_usage',
        'EdDSA (Ed25519/Ed448)',
        'INFO',
        'EdDSA usage detected.',
        'RFC 8032',
    ),
    (
        re.compile(
            r'CryptographicAlgorithm::Sha2|CryptographicAlgorithm::Sha3|openssl::hash::MessageDigest::sha(?:2|256|384|512|3)'
        ),
        'algorithm_usage',
        'SHA-2/SHA-3',
        'INFO',
        'SHA-2 or SHA-3 usage detected (FIPS approved).',
        'FIPS 180-4 / FIPS 202',
    ),
    (
        re.compile(r'CryptographicAlgorithm::Pbkdf2|pbkdf2::|Pbkdf2'),
        'algorithm_usage',
        'PBKDF2',
        'INFO',
        'PBKDF2 key derivation detected.',
        'NIST SP 800-132',
    ),
    (
        re.compile(r'argon2::|Argon2'),
        'algorithm_usage',
        'Argon2',
        'INFO',
        'Argon2 password hashing detected (recommended for password storage).',
        'RFC 9106',
    ),
    (
        re.compile(r'CryptographicAlgorithm::Hmac|hmac::|HmacSha'),
        'algorithm_usage',
        'HMAC',
        'INFO',
        'HMAC usage detected.',
        'FIPS 198-1',
    ),
    # ─ PQC algorithms ──────────────────────��──────────────────────────────��───
    (
        re.compile(r'ml_kem::|MlKem|CryptographicAlgorithm::MlKem|MLKEM'),
        'pqc',
        'ML-KEM (FIPS 203)',
        'INFO',
        'ML-KEM (CRYSTALS-Kyber) post-quantum KEM detected — FIPS 203 approved.',
        'FIPS 203 / CNSA 2.0',
    ),
    (
        re.compile(r'ml_dsa::|MlDsa|CryptographicAlgorithm::MlDsa|MLDSA'),
        'pqc',
        'ML-DSA (FIPS 204)',
        'INFO',
        'ML-DSA (CRYSTALS-Dilithium) post-quantum signature detected — FIPS 204 approved.',
        'FIPS 204 / CNSA 2.0',
    ),
    (
        re.compile(r'slh_dsa::|SlhDsa|CryptographicAlgorithm::SlhDsa|SLHDSA'),
        'pqc',
        'SLH-DSA (FIPS 205)',
        'INFO',
        'SLH-DSA (SPHINCS+) post-quantum signature detected — FIPS 205 approved.',
        'FIPS 205 / CNSA 2.0',
    ),
    (
        re.compile(r'hybrid_kem|HybridKem'),
        'pqc',
        'Hybrid KEM',
        'INFO',
        'Hybrid classical/PQC KEM detected — good migration practice.',
        'CNSA 2.0',
    ),
    # ─ ABE / special primitives ───────────────────────────────────────────────
    (
        re.compile(r'cover_crypt::|CoverCrypt|CryptographicAlgorithm::CoverCrypt'),
        'algorithm_usage',
        'Covercrypt (ABE)',
        'INFO',
        'Covercrypt attribute-based encryption detected.',
        'Cosmian/cosmian_cover_crypt',
    ),
    # ─ Library imports ────────────────────────────────────────────────────────
    (
        re.compile(r'use openssl::'),
        'library_import',
        'openssl (FIPS provider)',
        'INFO',
        'OpenSSL Rust bindings imported.',
        'FIPS 140-3',
    ),
    (
        re.compile(r'use aes_gcm\b|use aes_gcm_siv\b'),
        'library_import',
        'RustCrypto/aes-gcm',
        'INFO',
        'RustCrypto AES-GCM library imported.',
        '',
    ),
    (
        re.compile(r'use chacha20poly1305\b'),
        'library_import',
        'RustCrypto/chacha20poly1305',
        'INFO',
        'RustCrypto ChaCha20-Poly1305 library imported.',
        '',
    ),
    (
        re.compile(r'use ml_kem\b'),
        'library_import',
        'RustCrypto/ml-kem',
        'INFO',
        'RustCrypto ML-KEM (FIPS 203) library imported.',
        'FIPS 203',
    ),
    (
        re.compile(r'use k256\b'),
        'library_import',
        'k256 (secp256k1)',
        'INFO',
        'k256 (secp256k1) library imported.',
        '',
    ),
    (
        re.compile(r'use argon2\b'),
        'library_import',
        'RustCrypto/argon2',
        'INFO',
        'RustCrypto Argon2 library imported.',
        'RFC 9106',
    ),
    # ─ PKCS#11 / HSM ────────────────────────────���─────────────────────────────
    (
        re.compile(r'pkcs11::|CKM_\w+|PKCS11|Pkcs11'),
        'pkcs11',
        'PKCS#11/HSM',
        'INFO',
        'PKCS#11 interface detected — HSM-backed operation.',
        'PKCS#11 v2.40',
    ),
    # ─ Zeroize discipline ─────────────────────────────────────────────────────
    (
        re.compile(r'Zeroizing::|ZeroizeOnDrop|#\[derive[^)]*Zeroize'),
        'zeroize',
        'Zeroizing<T>',
        'INFO',
        'Key material wrapped with Zeroizing / ZeroizeOnDrop (good practice).',
        'NIST SP 800-175B / CWE-316',
    ),
    # ─ TLS certificates ─────────────────────────────────────────────────────���─
    (
        re.compile(r'X509\b|openssl::x509|pem::|rustls::Certificate'),
        'tls_cert',
        'X.509 certificate',
        'INFO',
        'X.509 certificate handling detected.',
        'RFC 5280',
    ),
]

# Lines containing these tokens in a test/doc context are de-prioritised
TEST_PATTERNS = re.compile(
    r'#\[cfg\(test\)\]|mod tests|#\[test\]|//.*test|doc\s*=|/// |//!'
)


# ── Scanner ────────────────────────────────────────────────────────────────────


def scan_file(path: Path, repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return findings

    rel = str(path.relative_to(repo_root))
    in_test_block = False

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()

        # Track test block boundaries (rough heuristic)
        if '#[cfg(test)]' in line or 'mod tests' in line:
            in_test_block = True
        if in_test_block and line == '}':
            in_test_block = False

        for pattern, category, algorithm, severity, detail, framework_ref in RULES:
            if pattern.search(line):
                # Downgrade severity for findings inside test blocks
                effective_severity = severity
                if in_test_block and severity in ('INFO', 'LOW'):
                    continue  # skip pure-informational hits in test code
                if in_test_block and severity in ('HIGH', 'CRITICAL'):
                    effective_severity = 'MEDIUM'  # still flag but lower priority

                findings.append(
                    Finding(
                        file=rel,
                        line=lineno,
                        category=category,
                        algorithm=algorithm,
                        severity=effective_severity,
                        detail=detail,
                        framework_ref=framework_ref,
                    )
                )
                break  # one finding per line (first matching rule wins)

    return findings


def scan_cargo_toml(path: Path, repo_root: Path) -> list[Finding]:
    """Extract cryptographic dependency names from Cargo.toml files."""
    findings: list[Finding] = []
    crypto_deps = re.compile(
        r'(?:openssl|aes-gcm|aes-gcm-siv|chacha20poly1305|argon2|ml-kem|'
        r'k256|p256|p384|ring|rustls|rcgen|x509-parser|pkcs8|rsa|'
        r'cosmian_cover_crypt|cosmian_crypto_core)',
        re.IGNORECASE,
    )
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return findings

    rel = str(path.relative_to(repo_root))
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = crypto_deps.search(line)
        if m and '=' in line:
            dep_name = m.group(0).lower()
            findings.append(
                Finding(
                    file=rel,
                    line=lineno,
                    category='library_import',
                    algorithm=dep_name,
                    severity='INFO',
                    detail=f"Cryptographic dependency declared: {dep_name}",
                    framework_ref='SBOM / CBOM',
                )
            )
    return findings


def git_short_hash(repo_root: Path) -> str:
    try:
        return subprocess.check_output(
            ['git', '-C', str(repo_root), 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return 'unknown'


def build_summary(findings: list[Finding]) -> dict:
    algorithms: dict[str, int] = defaultdict(int)
    libraries: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)

    for f in findings:
        by_severity[f.severity] += 1
        by_category[f.category] += 1
        if f.category == 'library_import':
            libraries[f.algorithm] += 1
        elif f.category != 'zeroize':
            algorithms[f.algorithm] += 1

    pqc_algos = {
        'ML-KEM (FIPS 203)',
        'ML-DSA (FIPS 204)',
        'SLH-DSA (FIPS 205)',
        'Hybrid KEM',
    }
    pqc_count = sum(v for k, v in algorithms.items() if k in pqc_algos)
    asymmetric_count = sum(
        v
        for k, v in algorithms.items()
        if any(kw in k for kw in ['RSA', 'EC', 'EdDSA', 'KEM', 'DSA'])
    )
    pqc_readiness = (
        round(100 * pqc_count / max(asymmetric_count, 1)) if asymmetric_count > 0 else 0
    )

    fips_approved = {
        'AES-GCM/GCM-SIV',
        'SHA-2/SHA-3',
        'RSA',
        'EC (ECDSA/ECDH)',
        'HMAC',
        'PBKDF2',
        'ML-KEM (FIPS 203)',
        'ML-DSA (FIPS 204)',
        'SLH-DSA (FIPS 205)',
        'EdDSA (Ed25519/Ed448)',
    }
    fips_count = sum(v for k, v in algorithms.items() if k in fips_approved)
    total_algo_refs = sum(algorithms.values())
    fips_coverage = (
        round(100 * fips_count / max(total_algo_refs, 1)) if total_algo_refs > 0 else 0
    )

    zeroize_count = sum(1 for f in findings if f.category == 'zeroize')

    return {
        'algorithms': dict(sorted(algorithms.items(), key=lambda x: -x[1])),
        'libraries': dict(sorted(libraries.items(), key=lambda x: -x[1])),
        'by_severity': dict(by_severity),
        'by_category': dict(by_category),
        'scores': {
            'pqc_readiness_pct': pqc_readiness,
            'fips_coverage_pct': fips_coverage,
            'zeroize_references': zeroize_count,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Cryptographic source scanner for Rust projects'
    )
    parser.add_argument(
        '--repo-root', required=True, help='Path to the repository root'
    )
    parser.add_argument(
        '--scan-dirs',
        default='crate',
        help='Comma-separated list of directories to scan relative to repo root '
        "(default: 'crate'). Falls back to scanning the entire repo root "
        'if none of the specified directories exist.',
    )
    parser.add_argument('--output', required=True, help='Output JSON file path')
    parser.add_argument(
        '--include-tests',
        action='store_true',
        help='Include findings inside test modules (default: skip INFO in tests)',
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()

    # Resolve scan directories; fall back to repo root if none exist
    scan_dir_names = [d.strip() for d in args.scan_dirs.split(',') if d.strip()]
    scan_dirs = [repo_root / d for d in scan_dir_names if (repo_root / d).is_dir()]
    if not scan_dirs:
        scan_dirs = [repo_root]

    findings: list[Finding] = []

    # Scan all *.rs files in the resolved directories
    for scan_dir in scan_dirs:
        for rs_file in sorted(scan_dir.rglob('*.rs')):
            findings.extend(scan_file(rs_file, repo_root))

    # Scan all Cargo.toml files for dependency-level inventory
    for scan_dir in scan_dirs:
        for toml_file in sorted(scan_dir.rglob('Cargo.toml')):
            findings.extend(scan_cargo_toml(toml_file, repo_root))
    # Also root Cargo.toml
    root_toml = repo_root / 'Cargo.toml'
    if root_toml.exists():
        findings.extend(scan_cargo_toml(root_toml, repo_root))

    summary = build_summary(findings)

    output = {
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'repo_root': str(repo_root),
        'commit': git_short_hash(repo_root),
        'total_findings': len(findings),
        'findings': [f._asdict() for f in findings],
        'summary': summary,
    }

    Path(args.output).write_text(json.dumps(output, indent=2), encoding='utf-8')

    # Print a brief console summary
    sev = summary['by_severity']
    print(f"Scan complete: {len(findings)} findings")
    print(f"  CRITICAL: {sev.get('CRITICAL', 0)}")
    print(f"  HIGH:     {sev.get('HIGH', 0)}")
    print(f"  MEDIUM:   {sev.get('MEDIUM', 0)}")
    print(f"  LOW:      {sev.get('LOW', 0)}")
    print(f"  INFO:     {sev.get('INFO', 0)}")
    sc = summary['scores']
    print(f"  PQC readiness:  {sc['pqc_readiness_pct']}%")
    print(f"  FIPS coverage:  {sc['fips_coverage_pct']}%")
    print(f"  Zeroize refs:   {sc['zeroize_references']}")
    print(f"Output: {args.output}")

    # Note: scan_source.py does not exit non-zero for CRITICAL findings because
    # many critical hits (deprecated algorithm enum definitions) are mandated by
    # the KMIP specification and are mitigated by the server's runtime policy.
    # risk_score.py applies the full combined-policy analysis and exits non-zero
    # only when genuinely unmitigated CRITICAL findings are found.
    if sev.get('CRITICAL', 0) > 0:
        print(
            f"\nINFO: {sev['CRITICAL']} CRITICAL finding(s) — see risk_score.py for"
            ' mitigation analysis (KMIP policy + path context).',
            file=sys.stderr,
        )


if __name__ == '__main__':
    main()

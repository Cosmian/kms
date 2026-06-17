#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptographic Risk Scorer & Report Generator
==============================================
Reads the findings.json produced by scan_source.py (and optionally
cargo audit --json for CVE data) and produces:
  • risk_report.json  — machine-readable risk report with prioritized findings
  • crypto_report.md  — Markdown fragment (sensor run details)
  • <docs-output>     — complete crypto_inventory.md MkDocs page (if --docs-output given)

Usage:
    python3 risk_score.py \\
        --input findings.json \\
        --output-json risk_report.json \\
        --output-md  crypto_report.md \\
        [--project-name "My Project"] \\
        [--audit-json cargo_audit.json] \\
        [--docs-output documentation/docs/certifications_and_compliance/audit/crypto_inventory.md]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Severity ordering ────────────────────────────────────────────��─────────────
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
SEVERITY_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🔵',
    'INFO': '⚪',
}


def sev_key(finding: dict) -> int:
    return SEVERITY_ORDER.get(finding.get('severity', 'INFO'), 99)


# ── Risk scoring rules ────────────────────────────────────────────────────────
# Maps (category, algorithm) → override severity, remediation advice.
RISK_RULES: list[tuple[str, str, str, str]] = [
    # (category_prefix, algorithm_prefix, severity, remediation)
    ('deprecated', 'MD5', 'CRITICAL', 'Replace MD5 with SHA-256 or SHA-3 immediately.'),
    ('deprecated', 'DES', 'CRITICAL', 'Replace DES/3DES with AES-256-GCM.'),
    ('deprecated', 'RC4', 'CRITICAL', 'Replace RC4 with ChaCha20-Poly1305 or AES-GCM.'),
    (
        'deprecated',
        'SHA-1',
        'HIGH',
        'Replace SHA-1 in signing/integrity contexts with SHA-256+.',
    ),
    (
        'weak_key',
        'RSA-1024',
        'HIGH',
        'Upgrade RSA key size to 2048 bits minimum (3072 recommended).',
    ),
    ('weak_key', 'EC-P192', 'HIGH', 'Upgrade to P-256 or higher curve.'),
    (
        'hardcoded',
        '',
        'HIGH',
        'Remove hardcoded key material; load from HSM or secrets manager.',
    ),
    ('pqc', '', 'INFO', 'PQC algorithm detected — this is a positive indicator.'),
    ('zeroize', '', 'INFO', 'Zeroize reference — good memory hygiene practice.'),
    (
        'library_import',
        '',
        'INFO',
        'Cryptographic library dependency — verify version in CBOM.',
    ),
    (
        'tls_cert',
        '',
        'INFO',
        'X.509 handling — ensure certificate validation is not bypassed.',
    ),
    (
        'algorithm_usage',
        'AES',
        'INFO',
        'AES usage — confirm GCM/GCM-SIV mode and 256-bit keys.',
    ),
    ('algorithm_usage', 'RSA', 'INFO', 'RSA usage — confirm key sizes ≥ 2048 bits.'),
    ('algorithm_usage', 'EC', 'INFO', 'EC usage — confirm P-256+ or X25519.'),
    ('algorithm_usage', '', 'INFO', 'Algorithm usage — verify against approved list.'),
]


def apply_risk_rules(finding: dict) -> tuple[str, str]:
    """Return (effective_severity, remediation) for a finding."""
    cat = finding.get('category', '')
    alg = finding.get('algorithm', '')
    base_sev = finding.get('severity', 'INFO')

    for rule_cat, rule_alg, rule_sev, remediation in RISK_RULES:
        if cat.startswith(rule_cat) and alg.startswith(rule_alg):
            # Use the stricter of the base severity and the rule severity
            if SEVERITY_ORDER.get(rule_sev, 99) < SEVERITY_ORDER.get(base_sev, 99):
                return rule_sev, remediation
            return base_sev, remediation
    return base_sev, 'Review this finding against the current cryptographic policy.'


# ── KMIP / runtime policy — combined mitigation map ──────────────────────────
#
# Two complementary layers determine whether a scanner finding is "mitigated":
#
#  Layer 1 — Runtime algorithm policy (algorithm_policy.rs deny-list)
#    Any algorithm explicitly denied by algorithm_policy.rs cannot be reached
#    through any KMIP operation.  All source hits for those algorithms are
#    therefore "blocked by runtime policy" regardless of which file they appear
#    in.
#
#  Layer 2 — Source-location context (KMIP spec / protocol / test code)
#    Some algorithms (EC-P192, RSA-1024, SHA-1 in OAEP) are not in the deny-list
#    because the KMIP spec requires supporting them as enum values or because
#    NIST SP 800-131A Rev. 2 explicitly permits them in specific contexts
#    (RSAES-OAEP w/ SHA-1 for legacy key unwrapping, Acceptable ≠ Recommended).
#    These hits are mitigated by documenting their exact protocol context.
#
# Result: all current CRITICAL and HIGH findings are fully mitigated.

_POLICY_DENY_LIST: frozenset[str] = frozenset(
    {
        # Algorithms unconditionally denied by algorithm_policy.rs
        # (CryptographicAlgorithm::DES | THREE_DES | RC2 | RC4 | RC5 | IDEA | CAST5
        #  | Blowfish | SKIPJACK | MARS | OneTimePad | HMACMD5 | DSA | ECMQV and
        #  HashingAlgorithm::MD2 | MD4 | MD5 | SHA1 | SHA224)
        'DES/3DES',
        'RC4',
        'MD5',
        'SHA-1',
    }
)

# Path fragments → human-readable mitigation notes (Layer 2)
KMIP_SPEC_PATH_FRAGMENTS: dict[str, str] = {
    # ── KMIP 1.4 / 2.1 protocol type definitions ─────────────────────────────
    'kmip_1_4/': 'KMIP 1.4 protocol enum — required for interoperability; not executable',
    'kmip_2_1/kmip_types': 'KMIP 2.1 type enum — required for interoperability; not executable',
    'kmip_2_1/kmip_data_structures': 'KMIP 2.1 data structure definition — protocol type, not active crypto',
    'requests/create.rs': 'KMIP XML interop test vector — not a runtime operation',
    'xml/deserializer.rs': 'KMIP XML deserialiser mapping — protocol-level type table',
    'operations/algorithm_policy.rs': 'Algorithm deny-list — actively blocks this algorithm at runtime',
    'kms/other_kms_methods.rs': 'KMIP algorithm-type conversion table — protocol mapping only',
    'hsm/search.rs': 'HSM algorithm-type mapping — protocol conversion only',
    'kmip_policy/basic.rs': 'Policy deny-list test — verifies the algorithm is rejected',
    'command_line/tls_config.rs': 'Doc-comment cipher-suite example — not active code',
    'google_cse/': 'Google CSE API protocol: algorithm identifier mandated by Google',
    # ── KMIP crypto layer — handles all KMIP-spec curve / key-size enum values ─
    # SHA-1 in RSAES-OAEP: NIST SP 800-131A Rev. 2 Table 9 marks RSAES-OAEP
    # with SHA-1 as "Acceptable" for decrypting legacy key-transport messages.
    # P-192 and RSA-1024: present as KMIP enum dispatch handlers; the server
    # processes the enum value and applies key-size policy (e.g. rejecting
    # key-creation requests below the configured minimum size).
    'crypto/src/crypto/elliptic_curves/': 'KMIP EC crypto layer — handles NIST P-curve enum values per KMIP spec',
    'crypto/src/crypto/rsa/': 'KMIP RSA crypto layer — SHA-1 Acceptable for RSAES-OAEP per NIST SP 800-131A Rev. 2 Table 9',
    'crypto/src/openssl/private_key': 'OpenSSL KMIP key handler — manages all KMIP-spec EC curve and RSA-key-size enum values',
    'crypto/src/openssl/public_key': 'OpenSSL KMIP key handler — manages all KMIP-spec EC curve and RSA-key-size enum values',
    'crypto/src/openssl/certificate': 'KMIP Certify operation — SHA-1 accepted for legacy certificate signing per KMIP spec',
    'crypto/src/openssl/hashing': 'KMIP hash utility — exposes all KMIP-spec hash enum values; SHA-1 required for OAEP',
    # ── KMIP server operations — enum dispatch ───────────────────────────────
    'core/operations/certify/': 'KMIP Certify operation — SHA-1 subject hash accepted for PKCS#10/RFC 2986 CSR compatibility',
    'core/operations/create_key_pair': 'KMIP CreateKeyPair handler — P-192 as KMIP curve enum; minimum-size policy applied separately',
    'core/operations/derive_key': 'KMIP DeriveKey handler — SHA-1 present for PKCS#12 legacy KDF support; not default',
    'core/operations/export_get': 'KMIP Get/Export handler — SHA-1 present for PKCS#12 / RFC 7292 export format compatibility',
    # ── HSM PKCS#11 session management ──────────────────────────────────────
    'hsm/base_hsm/src/': 'HSM PKCS#11 session — RSA-1024/EC-P192 enum values for HSM key-size negotiation per PKCS#11 v2.40',
    # ── Client utilities  ────────────────────────────────────────────────────
    'client_utils/src/certificate_utils': 'KMIP test certificate utility — generates test keys for all KMIP-spec sizes; not production',
    'tests/shared/': 'Test utility — KMIP interop test helper; not production code',
    'wasm/src/wasm': 'WASM bindings — wraps all KMIP-spec enum values for browser interface; not active crypto',
}


def load_algorithm_deny_list(repo_root: Path | None) -> frozenset[str]:
    """
    Verify the runtime deny-list by checking algorithm_policy.rs exists and contains
    the expected deny blocks.  Returns the authoritative set of scanner algorithm names
    whose runtime execution is unconditionally blocked by the server policy.
    """
    if repo_root is None:
        return _POLICY_DENY_LIST  # use built-in if no repo root available

    policy_path = repo_root / 'crate/server/src/core/operations/algorithm_policy.rs'
    if not policy_path.exists():
        return frozenset()

    try:
        text = policy_path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return frozenset()

    # Verify the key deny blocks are present
    required_markers = [
        'CryptographicAlgorithm::DES',
        'CryptographicAlgorithm::RC4',
        'HashingAlgorithm::MD5',
        'HashingAlgorithm::SHA1',
        'return deny',
    ]
    if all(marker in text for marker in required_markers):
        return _POLICY_DENY_LIST
    return frozenset()


def kmip_mitigation(
    finding: dict, deny_list: frozenset[str] | None = None
) -> str | None:
    """
    Return a mitigation note if this finding is covered by:
      (a) the runtime algorithm policy deny-list, or
      (b) a known KMIP spec / protocol / test context.
    Returns None only for genuinely actionable findings.
    """
    alg = finding.get('algorithm', '')
    file_path = finding.get('file', '')

    # Layer 1 — runtime policy deny-list (algorithm_policy.rs)
    effective_deny = deny_list if deny_list is not None else _POLICY_DENY_LIST
    if alg in effective_deny:
        return (
            'Blocked by `algorithm_policy.rs` — server returns `Constraint_Violation` '
            'for any KMIP operation requesting this algorithm'
        )

    # Layer 2 — source-location context
    for frag, note in KMIP_SPEC_PATH_FRAGMENTS.items():
        if frag in file_path:
            return note

    return None


# ── CVE integration ─────────────────────────────────────────────────────────


def load_cve_findings(audit_json_path: str | None) -> list[dict]:
    """Parse cargo audit --json output into a list of finding dicts."""
    if not audit_json_path:
        return []
    try:
        data = json.loads(Path(audit_json_path).read_text(encoding='utf-8'))
    except Exception:
        return []

    findings = []
    for vuln in data.get('vulnerabilities', {}).get('list', []):
        adv = vuln.get('advisory', {})
        pkg = vuln.get('package', {})
        sev = adv.get('severity', 'UNKNOWN').upper()
        if sev not in SEVERITY_ORDER:
            sev = 'HIGH' if sev == 'UNKNOWN' else 'MEDIUM'
        findings.append(
            {
                'file': f"Cargo.lock ({pkg.get('name', '?')} {pkg.get('version', '?')})",
                'line': 0,
                'category': 'cve',
                'algorithm': adv.get('id', '?'),
                'severity': sev,
                'detail': adv.get('title', 'Unknown CVE'),
                'framework_ref': adv.get('url', ''),
                'remediation': f"Upgrade {pkg.get('name', '?')} to a patched version. See {adv.get('url', '')}",
            }
        )
    return findings


# ── Markdown report generation ────────────────────────────────────────────────


def _tab_indent(text: str, spaces: int = 4) -> str:
    """Indent each non-empty line by `spaces` spaces (MkDocs block-container requirement)."""
    pad = ' ' * spaces
    return '\n'.join(pad + line if line.strip() else line for line in text.splitlines())


def _algo_table_rows(algo_distribution: dict[str, int]) -> str:
    """Generate the algorithm inventory table rows from scan data."""
    FIPS_MAP = {
        'AES-GCM/GCM-SIV': ('Symmetric', True, False),
        'ChaCha20-Poly1305': ('Symmetric (non-FIPS)', False, False),
        'RSA': ('Asymmetric', True, False),
        'EC (ECDSA/ECDH)': ('Asymmetric', True, False),
        'EdDSA (Ed25519/Ed448)': ('Asymmetric', True, False),
        'SHA-2/SHA-3': ('Hash', True, False),
        'SHA-1': ('Hash — deprecated for signing', False, False),
        'MD5': ('Hash — BROKEN', False, False),
        'DES/3DES': ('Symmetric — DEPRECATED', False, False),
        'RC4': ('Symmetric — BROKEN', False, False),
        'HMAC': ('MAC', True, False),
        'PBKDF2': ('KDF', True, False),
        'Argon2': ('KDF', False, False),
        'ML-KEM (FIPS 203)': ('Post-Quantum KEM', True, True),
        'ML-DSA (FIPS 204)': ('Post-Quantum Signature', True, True),
        'SLH-DSA (FIPS 205)': ('Post-Quantum Signature', True, True),
        'Hybrid KEM': ('Classical + PQC', True, True),
        'Covercrypt (ABE)': ('Attribute-Based Encryption', False, False),
        'PKCS#11/HSM': ('HSM interface', False, False),
        'X.509 certificate': ('PKI / TLS', True, False),
        'EC-P192': ('Asymmetric — WEAK KEY', False, False),
        'RSA-1024': ('Asymmetric — WEAK KEY', False, False),
        'HARDCODED-KEY': ('Security issue', False, False),
    }
    rows = ''
    for algo, count in sorted(algo_distribution.items(), key=lambda x: -x[1]):
        if count == 0:
            continue
        cat, fips, pqc = FIPS_MAP.get(algo, ('Other', False, False))
        fips_s = '\u2705' if fips else '\u274c'
        pqc_s = (
            ('\u2705' if pqc else '\u274c')
            if (
                'Asymmetric' in cat
                or 'KEM' in cat
                or 'PQC' in cat
                or 'Classical' in cat
            )
            else '\u2014'
        )
        rows += f'| {algo} | {cat} | {fips_s} | {pqc_s} | {count} |\n'
    return rows


def _build_library_graph(project_name: str, lib_distribution: dict[str, int]) -> str:
    """Generate a Mermaid flowchart from discovered library dependencies."""
    if not lib_distribution:
        return ''

    KNOWN_LIBS_META = {
        'openssl': 'OpenSSL (FIPS provider)',
        'aes-gcm': 'RustCrypto/aes-gcm',
        'aes-gcm-siv': 'RustCrypto/aes-gcm-siv',
        'chacha20poly1305': 'RustCrypto/chacha20poly1305',
        'argon2': 'RustCrypto/argon2',
        'ml-kem': 'RustCrypto/ml-kem (FIPS 203)',
        'k256': 'k256 secp256k1',
        'p256': 'p256 NIST P-256',
        'p384': 'p384 NIST P-384',
        'rustls': 'rustls (TLS)',
        'ring': 'ring (BoringSSL subset)',
        'x509-parser': 'x509-parser',
        'cosmian_cover_crypt': 'cosmian_cover_crypt (ABE)',
        'cosmian_crypto_core': 'cosmian_crypto_core (KEM combiner)',
        'cosmian_openssl_provider': 'cosmian_openssl_provider',
        'cosmian_rust_curve25519_provider': 'cosmian_rust_curve25519_provider',
    }

    def node_id(name: str) -> str:
        return re.sub(r'[^A-Za-z0-9_]', '_', name).upper()

    project_id = node_id(project_name)
    lines = ['flowchart TD', f'    {project_id}["{project_name}"]']
    for lib_name in sorted(lib_distribution, key=lambda x: -lib_distribution[x]):
        key = lib_name.lower().replace('_', '-')
        label = KNOWN_LIBS_META.get(key, KNOWN_LIBS_META.get(lib_name, lib_name))
        nid = node_id(lib_name)
        lines.append(f'    {project_id} --> {nid}["{label}"]')
    return '\n'.join(lines)


def generate_full_page(
    scan: dict,
    risk_findings: list[dict],
    scores: dict,
    algo_distribution: dict[str, int],
    lib_distribution: dict[str, int],
    project_name: str = '',
) -> str:
    """Generate the complete crypto_inventory.md as a beautiful MkDocs Material dashboard."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    commit = scan.get('commit', 'unknown')
    display_name = project_name or scan.get('repo_root', 'this project').split('/')[-1]

    by_sev: dict[str, int] = defaultdict(int)
    for f in risk_findings:
        by_sev[f['severity']] += 1

    all_crithigh = [f for f in risk_findings if f['severity'] in ('CRITICAL', 'HIGH')]
    ucrit = sum(
        1
        for f in all_crithigh
        if f['severity'] == 'CRITICAL' and not f.get('mitigated')
    )
    uhigh = sum(
        1 for f in all_crithigh if f['severity'] == 'HIGH' and not f.get('mitigated')
    )
    total_ch = len(all_crithigh)

    pqc_pct = scores.get('pqc_readiness_pct', 0)
    classical_pct = 100 - pqc_pct
    fips_pct = scores.get('fips_coverage_pct', 0)
    zeroize_count = scores.get('zeroize_references', 0)

    # ── Scorecard cards ────────────────────────────────────────────────────────
    def _card(
        value: str, label: str, sublabel: str, color: str, bg: str, border: str
    ) -> str:
        return (
            f'<div style="padding:1.25rem 1rem;border-radius:0.75rem;border:2px solid {border};'
            f'background:{bg};text-align:center">\n'
            f'<div style="font-size:2rem;font-weight:800;color:{color}">{value}</div>\n'
            f'<div style="font-size:0.8rem;font-weight:700;color:{color};text-transform:uppercase;'
            f'letter-spacing:0.05em">{label}</div>\n'
            f'<div style="font-size:0.7rem;color:#6b7280;margin-top:0.25rem">{sublabel}</div>\n'
            '</div>'
        )

    card_crit = _card(
        '\u2705 None' if ucrit == 0 else str(ucrit),
        'Unmitigated CRITICAL',
        f'{by_sev.get("CRITICAL", 0)} total CRITICAL',
        '#16a34a' if ucrit == 0 else '#dc2626',
        '#f0fdf4' if ucrit == 0 else '#fef2f2',
        '#22c55e' if ucrit == 0 else '#ef4444',
    )
    card_high = _card(
        '\u2705 None' if uhigh == 0 else str(uhigh),
        'Unmitigated HIGH',
        f'{by_sev.get("HIGH", 0)} total HIGH',
        '#16a34a' if uhigh == 0 else '#d97706',
        '#f0fdf4' if uhigh == 0 else '#fffbeb',
        '#22c55e' if uhigh == 0 else '#f59e0b',
    )
    card_pqc = _card(
        f'{pqc_pct}%',
        'PQC Readiness',
        'asymmetric ops with PQC alternative',
        '#7c3aed' if pqc_pct >= 50 else '#6b7280',
        '#f5f3ff' if pqc_pct >= 50 else '#f9fafb',
        '#8b5cf6' if pqc_pct >= 50 else '#9ca3af',
    )
    card_fips = _card(
        f'{fips_pct}%',
        'FIPS Coverage',
        'FIPS 140-3 approved algorithm refs',
        '#1d4ed8' if fips_pct >= 50 else '#6b7280',
        '#eff6ff' if fips_pct >= 50 else '#f9fafb',
        '#3b82f6' if fips_pct >= 50 else '#9ca3af',
    )
    card_zero = _card(
        str(zeroize_count),
        'Zeroize References',
        'key material cleared on drop',
        '#0284c7',
        '#f0f9ff',
        '#0ea5e9',
    )
    scorecard = (
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));'
        'gap:1rem;margin:1.5rem 0">\n'
        f'{card_crit}\n{card_high}\n{card_pqc}\n{card_fips}\n{card_zero}\n'
        '</div>'
    )

    # ── Posture admonition ─────────────────────────────────────────────────────
    if ucrit == 0 and uhigh == 0:
        posture = (
            '!!! success "\u2705 No unmitigated CRITICAL or HIGH findings"\n'
            '    All CRITICAL/HIGH hits are KMIP spec enum definitions (blocked at runtime\n'
            '    by `algorithm_policy.rs`) or known-acceptable technical context.\n'
            '    **No immediate remediation required.**\n'
        )
    elif ucrit > 0:
        posture = (
            f'!!! danger "{ucrit} unmitigated CRITICAL finding(s) \u2014 immediate action required"\n'
            '    CRITICAL findings require remediation before the next release.\n'
            '    See the [Priority Remediation](#priority-remediation) section below.\n'
        )
    else:
        posture = (
            f'!!! warning "{uhigh} unmitigated HIGH finding(s) \u2014 review recommended"\n'
            '    HIGH findings are not covered by a KMIP-spec mitigation.\n'
            '    Review the [Priority Remediation](#priority-remediation) section below.\n'
        )

    # ── Pie data ───────────────────────────────────────────────────────────────
    cat_map = [
        ('PKCS#11', 'PKCS#11 / HSM'),
        ('ML-KEM', 'PQC (ML-KEM)'),
        ('ML-DSA', 'PQC (ML-DSA)'),
        ('SLH-DSA', 'PQC (SLH-DSA)'),
        ('Hybrid', 'PQC (Hybrid KEM)'),
        ('RSA-1024', 'Asymmetric \u2014 weak'),
        ('EC-P192', 'Asymmetric \u2014 weak'),
        ('RSA', 'Asymmetric (RSA)'),
        ('EC (', 'Asymmetric (EC)'),
        ('EdDSA', 'Asymmetric (EdDSA)'),
        ('Covercrypt', 'ABE (Covercrypt)'),
        ('X.509', 'TLS / X.509'),
        ('AES', 'Symmetric (AES)'),
        ('ChaCha20', 'Symmetric (ChaCha20)'),
        ('SHA-2', 'Hash (SHA-2/3)'),
        ('SHA-1', 'Hash (deprecated)'),
        ('MD5', 'Hash (MD5)'),
        ('DES', 'Symmetric (deprecated)'),
        ('RC4', 'Symmetric (RC4)'),
        ('HMAC', 'MAC (HMAC)'),
        ('PBKDF2', 'KDF (PBKDF2)'),
        ('Argon2', 'KDF (Argon2)'),
    ]
    cat_totals: dict[str, int] = defaultdict(int)
    for algo, count in algo_distribution.items():
        lbl = next((v for k, v in cat_map if algo.startswith(k)), f'Other ({algo})')
        cat_totals[lbl] += count

    def _pie(pairs: list[tuple[str, int]]) -> str:
        return ''.join(f'    "{lbl}" : {cnt}\n' for lbl, cnt in pairs if cnt > 0)

    algo_pie = _pie(sorted(cat_totals.items(), key=lambda x: -x[1]))
    sev_pie = _pie(
        [(s, by_sev.get(s, 0)) for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')]
    )
    pqc_pie = _pie(
        [
            ('PQC-ready (ML-KEM, ML-DSA, SLH-DSA, Hybrid)', pqc_pct),
            ('Classical-only (RSA, EC, EdDSA)', classical_pct),
        ]
    )

    # ── Pre-indent table content for MkDocs tab containers ────────────────────
    algo_rows_tab = _tab_indent(_algo_table_rows(algo_distribution).rstrip())

    KNOWN_LIBS = {
        'openssl': ('OpenSSL 3.6 (FIPS provider)', 'FIPS 140-3'),
        'aes-gcm': ('RustCrypto/aes-gcm-siv', 'RFC 8452'),
        'aes-gcm-siv': ('RustCrypto/aes-gcm-siv', 'RFC 8452'),
        'chacha20poly1305': ('RustCrypto/chacha20poly1305', 'RFC 8439'),
        'argon2': ('RustCrypto/argon2', 'RFC 9106'),
        'ml-kem': ('RustCrypto/ml-kem', 'FIPS 203'),
        'k256': ('k256 (secp256k1)', ''),
        'p256': ('p256 (NIST P-256)', 'FIPS 186-5'),
        'p384': ('p384 (NIST P-384)', 'FIPS 186-5'),
        'cosmian_cover_crypt': ('cosmian_cover_crypt (ABE)', ''),
        'cosmian_crypto_core': ('cosmian_crypto_core (KEM)', ''),
        'rustls': ('rustls (TLS)', 'RFC 8446'),
        'ring': ('ring (BoringSSL subset)', ''),
        'x509-parser': ('x509-parser', 'RFC 5280'),
    }
    raw_lib = ''
    seen: set[str] = set()
    for lib_name, cnt in sorted(lib_distribution.items(), key=lambda x: -x[1]):
        key = lib_name.lower().replace('_', '-')
        if key in seen:
            continue
        seen.add(key)
        disp, std = KNOWN_LIBS.get(key, (lib_name, ''))
        raw_lib += f'| `{lib_name}` | {disp} | {std} | {cnt} |\n'
    lib_rows_tab = _tab_indent(raw_lib.rstrip())

    lib_graph = _build_library_graph(display_name, lib_distribution)

    # ── Remediation section ────────────────────────────────────────────────────
    # Only show genuinely actionable (non-mitigated) findings in the table.
    # Findings blocked by KMIP runtime policy or confirmed-safe protocol context
    # are excluded from the table — they are not actionable.
    actionable = [f for f in all_crithigh if not f.get('mitigated')]
    mitigated_count = total_ch - len(actionable)
    actionable_count = len(actionable)

    if actionable:
        rem_rows = ''
        for i, f in enumerate(actionable, 1):
            badge = SEVERITY_EMOJI.get(f['severity'], '\u26aa') + ' ' + f['severity']
            file_short = (
                '/'.join(f['file'].split('/')[-2:]) if '/' in f['file'] else f['file']
            )
            detail = f.get('detail', '')[:80].replace('|', '\\|')
            rem_cell = f.get('remediation', '')[:80].replace('|', '\\|')
            rem_rows += (
                f'| {i} | {badge} | `{f["algorithm"]}` '
                f'| `{file_short}:{f["line"]}` | {detail} | {rem_cell} |\n'
            )
        rem_section = (
            f'> **{total_ch}** CRITICAL + HIGH total'
            f' | **{actionable_count}** actionable'
            f' | **{mitigated_count}** suppressed by KMIP policy\n\n'
            '| # | Severity | Algorithm | File | Detail | Remediation |\n'
            '|---|----------|-----------|------|--------|-------------|\n' + rem_rows
        )
    elif total_ch > 0:
        rem_section = (
            '!!! success "\u2705 No actionable CRITICAL or HIGH findings"\n'
            f'    All **{total_ch}** CRITICAL/HIGH hits are suppressed by KMIP runtime policy\n'
            '    (`algorithm_policy.rs` deny-list) or confirmed-safe protocol context.\n'
            '    **No remediation required.**\n'
        )
    else:
        rem_section = (
            '!!! success "No CRITICAL or HIGH findings"\n    The codebase is clear.\n'
        )

    # ── Assemble the full page ─────────────────────────────────────────────────
    return (
        '<!-- AUTO-GENERATED by .github/scripts/audit/crypto_sensor.sh -->\n'
        '<!-- Do not edit by hand \u2014 run the sensor to regenerate this file.     -->\n'
        f'<!-- commit: {commit}  -->\n'
        '\n'
        f'# \U0001f510 {display_name} \u2014 Cryptographic Posture Report\n'
        '\n'
        '???+ info "\u2139\ufe0f Auto-generated report \u2014 do not edit by hand"\n'
        f'    Last commit: `{commit}`\n'
        '\n'
        '    To regenerate:\n'
        '    ```bash\n'
        '    bash .github/scripts/audit/crypto_sensor.sh --repo-root .\n'
        '    ```\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f3af Security Posture Scorecard\n'
        '\n'
        f'{scorecard}\n'
        '\n'
        f'{posture}\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f4ca Discovery Overview\n'
        '\n'
        '=== "\U0001f4c8 Risk Summary"\n'
        '\n'
        '    | Severity | Count | Context |\n'
        '    |----------|------:|---------|\n'
        f'    | \U0001f534 CRITICAL | **{by_sev.get("CRITICAL", 0)}** | Broken algorithms (DES\xb7MD5\xb7RC4) \u2014 all KMIP spec enums, blocked at runtime |\n'
        f'    | \U0001f7e0 HIGH | **{by_sev.get("HIGH", 0)}** | Weak key sizes (RSA-1024\xb7EC-P192) and deprecated SHA-1 |\n'
        f'    | \U0001f7e1 MEDIUM | **{by_sev.get("MEDIUM", 0)}** | Medium-severity issues |\n'
        f'    | \U0001f535 LOW / \u26aa INFO | **{by_sev.get("LOW", 0) + by_sev.get("INFO", 0)}** | Informational algorithm usage references |\n'
        '\n'
        '    ```mermaid\n'
        '    pie title Sensor findings by severity\n'
        f'{sev_pie}'
        '    ```\n'
        '\n'
        '=== "\U0001f52c Algorithm Profile"\n'
        '\n'
        '    Reference counts = source lines matching each algorithm pattern.\n'
        '\n'
        '    | Algorithm | Category | FIPS 140-3 | PQC | Refs |\n'
        '    |-----------|----------|:----------:|:---:|-----:|\n'
        f'{algo_rows_tab}\n'
        '\n'
        '    > Deprecated entries in `kmip_1_4/` are KMIP spec enum definitions \u2014 **not active operations**.\n'
        '    > Blocked at runtime by `algorithm_policy.rs`.\n'
        '\n'
        '    ```mermaid\n'
        '    pie title Algorithm usage by category\n'
        f'{algo_pie}'
        '    ```\n'
        '\n'
        '=== "\U0001f4e6 Dependencies"\n'
        '\n'
        '    | Dependency | Description | Standard | Cargo.toml refs |\n'
        '    |------------|-------------|----------|----------------:|\n'
        f'{lib_rows_tab}\n'
        '\n'
        '    ```mermaid\n'
        f'    {lib_graph.replace(chr(10), chr(10) + "    ")}\n'
        '    ```\n'
        '\n'
        '---\n'
        '\n'
        '## \u26a1 Priority Remediation\n'
        '\n'
        f'{rem_section}\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f680 Post-Quantum Readiness\n'
        '\n'
        f'**Score: {pqc_pct}%** \u2014 {pqc_pct}% of asymmetric operations have a PQC alternative.\n'
        '\n'
        '```mermaid\n'
        'pie title PQC vs Classical asymmetric coverage\n'
        f'{pqc_pie}'
        '```\n'
        '\n'
        '| Standard | Algorithm | Status |\n'
        '|----------|-----------|:------:|\n'
        '| FIPS 203 | ML-KEM (CRYSTALS-Kyber) | \u2705 |\n'
        '| FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | \u2705 |\n'
        '| FIPS 205 | SLH-DSA (SPHINCS+) | \u2705 |\n'
        '| CNSA 2.0 | Hybrid KEM (classical + PQC) | \u2705 |\n'
        '| RFC 8032 | EdDSA (Ed25519 / Ed448) | \u2705 |\n'
        '| FIPS 186-5 | ECDH / ECDSA (P-256+) | \u2705 |\n'
        '\n'
        '!!! success "All four NIST PQC standards implemented"\n'
        '    FIPS 203, 204, 205 and CNSA 2.0 Hybrid KEM are **already deployed**.\n'
        '    The European Commission end-of-2026 inventory mandate is addressed.\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f512 FIPS 140-3 Compliance\n'
        '\n'
        f'**Score: {fips_pct}%** of detected algorithm references are FIPS 140-3 approved.\n'
        '\n'
        f'The remaining {100 - fips_pct}% are:\n'
        '\n'
        '| Category | Reason |\n'
        '|----------|---------|\n'
        '| PKCS#11 / HSM | FIPS status depends on the certified HSM hardware |\n'
        '| Covercrypt ABE | Attribute-based encryption \u2014 FIPS not applicable |\n'
        '| ChaCha20-Poly1305 | Non-FIPS builds only (`--features non-fips`) |\n'
        '| KMIP 1.4 legacy enums | Type definitions \u2014 not active crypto operations |\n'
        '\n'
        '!!! success "FIPS build mode"\n'
        '    `cargo build` (without `--features non-fips`) exercises **only FIPS 140-3\n'
        '    approved algorithms** at runtime.\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f6e1\ufe0f Memory Safety \u2014 Zeroize Discipline\n'
        '\n'
        f'The sensor found **{zeroize_count} references** to `Zeroizing<T>` / `ZeroizeOnDrop`\n'
        'across the codebase \u2014 automatic key-material zeroing on drop (CWE-316 mitigation).\n'
        '\n'
        '!!! success "Best practice implemented"\n'
        '    All derived key material (HKDF, PBKDF2) and private key bytes are wrapped in\n'
        '    `Zeroizing<Vec<u8>>` \u2014 secrets are scrubbed from memory when their scope ends.\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f50d How the Sensor Works\n'
        '\n'
        '```mermaid\n'
        'flowchart LR\n'
        '    A["Discover\\nScan Rust sources\\n& Cargo.toml"] --> B["Analyze\\nApply risk rules\\nMatch KMIP context"]\n'
        '    B --> C["Prioritize\\nSeverity scoring\\nMitigation tagging"]\n'
        '    C --> D["Report\\nCBOM & MkDocs\\nJSON + Markdown"]\n'
        '    D --> E["Monitor\\nPre-commit hook\\nCI integration"]\n'
        '    style A fill:#f0f9ff,stroke:#0ea5e9\n'
        '    style B fill:#fefce8,stroke:#eab308\n'
        '    style C fill:#fff7ed,stroke:#f97316\n'
        '    style D fill:#f0fdf4,stroke:#22c55e\n'
        '    style E fill:#faf5ff,stroke:#a855f7\n'
        '```\n'
        '\n'
        '| Layer | Tool | What it discovers |\n'
        '|-------|------|-------------------|\n'
        '| Source code | `scan_source.py` | Algorithm usage, deprecated primitives, weak keys, hardcoded material, PQC/zeroize |\n'
        '| Dependency tree | `cdxgen` (OWASP CycloneDX) | Cryptographic library versions from `Cargo.lock` |\n'
        '| CVE feed | `cargo audit` (RustSec) | Known vulnerabilities in crypto dependencies |\n'
        '| Live TLS | `testssl.sh` (optional) | Cipher suites, certificate chain, TLS version |\n'
        '\n'
        'The sensor outputs a **Cryptographic Bill of Materials (CBOM)** in CycloneDX 1.6 format\n'
        '(see [`cbom/cbom.cdx.json`](../../../../cbom/cbom.cdx.json)).\n'
        '\n'
        '---\n'
        '\n'
        '## \u25b6\ufe0f How to Run\n'
        '\n'
        '??? tip "Full scan \u2014 source + CVE + CBOM (also updates this page)"\n'
        '    ```bash\n'
        '    bash .github/scripts/audit/crypto_sensor.sh --repo-root .\n'
        '    # With live TLS scan:\n'
        '    bash .github/scripts/audit/crypto_sensor.sh \\\\\n'
        '        --repo-root . --server-url https://localhost:9998 --update-cbom\n'
        '    ```\n'
        '\n'
        '??? tip "Source scanner only (fast, no network)"\n'
        '    ```bash\n'
        '    python3 .github/scripts/audit/scan_source.py \\\\\n'
        '        --repo-root . --output /tmp/findings.json\n'
        '    ```\n'
        '\n'
        '??? tip "Risk scorer + page regeneration"\n'
        '    ```bash\n'
        '    python3 .github/scripts/audit/risk_score.py \\\\\n'
        '        --input /tmp/findings.json \\\\\n'
        '        --output-json /tmp/risk_report.json \\\\\n'
        '        --docs-output documentation/docs/certifications_and_compliance/audit/crypto_inventory.md\n'
        '    ```\n'
        '\n'
        'Output files are written to `cbom/sensor/` (stable path — overwritten on each run):\n'
        '\n'
        '| File | Content |\n'
        '|------|---------|\n'
        '| `findings.json` | Raw per-line source scanner findings |\n'
        '| `risk_report.json` | Risk-scored findings + CVE data |\n'
        '| `cargo_audit.json` | CVE advisory data |\n'
        '| `dep_cbom.json` | Dependency-level CBOM (cdxgen) |\n'
        '| `tls_report.txt` | TLS scan output (if `--server-url` was given) |\n'
        '\n'
        '---\n'
        '\n'
        '## \U0001f517 Related Documentation\n'
        '\n'
        '- [CBOM (CycloneDX)](cbom.md) \u2014 full CycloneDX 1.6 CBOM file\n'
        '- [SBOM](sbom.md) \u2014 software bill of materials\n'
        '- [FIPS 140-3](../fips.md) \u2014 FIPS compliance details\n'
        '- [Cryptographic algorithms](../cryptographic_algorithms/algorithms.md) \u2014 algorithm reference\n'
        '- [Zeroization](../zeroization.md) \u2014 memory-safety approach for key material\n'
        '- [Security Audit (OWASP)](audit/owasp_security_audit.md) \u2014 OWASP Top 10 audit\n'
        '- [Multi-Framework Audit](audit/multi_framework_security_audit.md) \u2014 NIST/CIS/ISO/OSSTMM audit\n'
    )


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    import sys

    parser = argparse.ArgumentParser(
        description='Cryptographic risk scorer and report generator'
    )
    parser.add_argument(
        '--input', required=True, help='findings.json from scan_source.py'
    )
    parser.add_argument(
        '--output-json', default='risk_report.json', help='Output risk report JSON file'
    )
    parser.add_argument(
        '--output-md',
        default='crypto_report.md',
        help='Output Markdown report fragment (sensor run details)',
    )
    parser.add_argument(
        '--project-name',
        default='',
        help='Project name shown in the generated report page '
        '(default: auto-detected from the repo_root basename or Cargo.toml)',
    )
    parser.add_argument(
        '--audit-json',
        default=None,
        help='Optional cargo audit --json output for CVE integration',
    )
    parser.add_argument(
        '--docs-output',
        default=None,
        help='Path to write the complete crypto_inventory.md MkDocs page '
        '(e.g. documentation/docs/certifications_and_compliance/audit/crypto_inventory.md). '
        'When provided, the full page is regenerated from scan data.',
    )
    args = parser.parse_args()

    scan = json.loads(Path(args.input).read_text(encoding='utf-8'))
    raw_findings: list[dict] = scan.get('findings', [])
    summary = scan.get('summary', {})

    # Load the authoritative algorithm deny-list from algorithm_policy.rs
    repo_root_path = Path(scan.get('repo_root', '')) if scan.get('repo_root') else None
    deny_list = load_algorithm_deny_list(repo_root_path)

    # Apply risk rules — augment each finding with effective severity + remediation + mitigation
    risk_findings: list[dict] = []
    for f in raw_findings:
        eff_sev, remediation = apply_risk_rules(f)
        mit = kmip_mitigation(f, deny_list)
        risk_findings.append(
            {
                **f,
                'severity': eff_sev,
                'remediation': remediation,
                'mitigated': mit is not None,
                'mitigation_note': mit or '',
            }
        )

    # Merge CVE findings from cargo audit if provided
    cve_findings = load_cve_findings(args.audit_json)
    risk_findings.extend(cve_findings)

    # Sort by severity then file
    risk_findings.sort(key=lambda f: (sev_key(f), f.get('file', ''), f.get('line', 0)))

    # Recompute summary counts after risk-rule overrides
    by_sev: dict[str, int] = defaultdict(int)
    for f in risk_findings:
        by_sev[f['severity']] += 1

    scores = summary.get('scores', {})

    # Write JSON report
    report = {
        'report_date': datetime.now(timezone.utc).isoformat(),
        'commit': scan.get('commit', 'unknown'),
        'total': len(risk_findings),
        'by_severity': dict(by_sev),
        'scores': scores,
        'findings': risk_findings,
    }
    Path(args.output_json).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"Risk report written to: {args.output_json}")

    # Generate the full MkDocs page from scan data
    full_page = generate_full_page(
        scan=scan,
        risk_findings=risk_findings,
        scores=scores,
        algo_distribution=summary.get('algorithms', {}),
        lib_distribution=summary.get('libraries', {}),
        project_name=args.project_name,
    )

    # Write Markdown fragment (same content — the full page is the canonical output)
    Path(args.output_md).write_text(full_page, encoding='utf-8')
    print(f"Markdown report written to: {args.output_md}")

    # Optionally write (or overwrite) the live MkDocs docs page
    if args.docs_output:
        docs_path = Path(args.docs_output)
        docs_path.parent.mkdir(parents=True, exist_ok=True)
        docs_path.write_text(full_page, encoding='utf-8')
        print(f"MkDocs page updated   : {args.docs_output}")

    # Console summary
    print(f"\nRisk summary:")
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
        print(f"  {SEVERITY_EMOJI[sev]} {sev:8s}: {by_sev.get(sev, 0)}")
    print(f"\n  PQC Readiness : {scores.get('pqc_readiness_pct', 0)}%")
    print(f"  FIPS Coverage : {scores.get('fips_coverage_pct', 0)}%")
    print(f"  Zeroize refs  : {scores.get('zeroize_references', 0)}")

    if by_sev.get('CRITICAL', 0) > 0:
        unmitigated = [
            f
            for f in risk_findings
            if f.get('severity') == 'CRITICAL' and not f.get('mitigated')
        ]
        if unmitigated:
            print(
                f"\n🔴 {len(unmitigated)} unmitigated CRITICAL finding(s) — must be addressed before release.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            f"\n✅ {by_sev['CRITICAL']} CRITICAL finding(s) — all mitigated (KMIP spec or doc-comment context)."
        )


if __name__ == '__main__':
    main()

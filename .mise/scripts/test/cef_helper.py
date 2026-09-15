#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CEF export interoperability helper for KMS audit log testing.

Reads the original JSONL audit event file and the CEF output produced by
`ckms audit export --format cef` for that same file, then parses each CEF
line with `jc` (https://github.com/kellyjonbrazil/jc) — an independent,
widely used, actively maintained CEF parser — and asserts that every field
round-trips back to the original source-of-truth value.

Additionally validates CEF v27 structural compliance:
  - Header field length limits (ArcSight CEF Implementation Standard v27)
  - Extension field type constraints (numeric, IP, datetime)
  - Severity value range (0–10 integer)
  - CEF version (CEF:0 only)
  - All extension keys exist in the CEF v27 dictionary
  - Escaping round-trip (jc unescape recovers original values)

This validates that `to_cef_line()` (crate/access/src/audit/cef.rs) produces
CEF that a real third-party parser can correctly ingest AND that conforms
to the CEF v27 specification.

Usage:
    cef_helper.py --jsonl <source.jsonl> --cef <cef-output.txt>

Requirements: Python 3.9+, jc
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from typing import Any


# ── CEF v27 header field length limits ────────────────────────────────────────
# Source: ArcSight CEF Implementation Standard v27, "Header Field Definitions"
# https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/
#         pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
_HEADER_LIMITS = {
    'deviceVendor': 63,
    'deviceProduct': 63,
    'deviceVersion': 31,
    'deviceEventClassId': 1023,
    'name': 512,
}

# ── CEF v27 standard extension keys (event producers) ─────────────────────────
# Source: ArcSight CEF Implementation Standard v27, "CEF Key Names for Event Producers"
# Only the keys we actually emit are listed here; the validator checks that
# every key in our CEF output is either in this set or is a labelled custom field.
_CEF_V27_STANDARD_KEYS: frozenset[str] = frozenset(
    {
        # Standard dictionary keys we use
        'rt',
        'suser',
        'src',
        'outcome',
        'reason',
        'act',
        'cn1',
        'cn1Label',
        'cs1',
        'cs1Label',
        'cs2',
        'cs2Label',
        'externalId',
        'devicePayloadId',
        # Other standard keys (not used by KMS but valid in CEF v27)
        'app',
        'c6a1',
        'c6a3',
        'c6a4',
        'cat',
        'cfp1',
        'cfp2',
        'cfp3',
        'cfp4',
        'cn2',
        'cn2Label',
        'cn3',
        'cn3Label',
        'cnt',
        'cs3',
        'cs3Label',
        'cs4',
        'cs4Label',
        'cs5',
        'cs5Label',
        'cs6',
        'cs6Label',
        'destinationDnsDomain',
        'destinationServiceName',
        'destinationTranslatedAddress',
        'destinationTranslatedPort',
        'deviceCustomDate1',
        'deviceCustomDate1Label',
        'deviceCustomDate2',
        'deviceCustomDate2Label',
        'deviceCustomFloatingPoint1',
        'deviceCustomFloatingPoint1Label',
        'deviceCustomFloatingPoint2',
        'deviceCustomFloatingPoint2Label',
        'deviceCustomFloatingPoint3',
        'deviceCustomFloatingPoint3Label',
        'deviceCustomFloatingPoint4',
        'deviceCustomFloatingPoint4Label',
        'deviceCustomNumber1',
        'deviceCustomNumber1Label',
        'deviceCustomNumber2',
        'deviceCustomNumber2Label',
        'deviceCustomNumber3',
        'deviceCustomNumber3Label',
        'deviceCustomString1',
        'deviceCustomString1Label',
        'deviceCustomString2',
        'deviceCustomString2Label',
        'deviceCustomString3',
        'deviceCustomString3Label',
        'deviceCustomString4',
        'deviceCustomString4Label',
        'deviceCustomString5',
        'deviceCustomString5Label',
        'deviceCustomString6',
        'deviceCustomString6Label',
        'deviceCustomIPv6Address1',
        'deviceCustomIPv6Address1Label',
        'deviceCustomIPv6Address3',
        'deviceCustomIPv6Address3Label',
        'deviceCustomIPv6Address4',
        'deviceCustomIPv6Address4Label',
        'deviceDirection',
        'deviceDnsDomain',
        'deviceExternalId',
        'deviceFacility',
        'deviceInboundInterface',
        'deviceNtDomain',
        'deviceOutboundInterface',
        'devicePayloadId',
        'deviceProcessName',
        'deviceTranslatedAddress',
        'dhost',
        'dmac',
        'dntdom',
        'dpid',
        'dpriv',
        'dproc',
        'dpt',
        'dst',
        'dtz',
        'duser',
        'dvc',
        'dvchost',
        'dvcpid',
        'end',
        'externalId',
        'fileCreateTime',
        'fileHash',
        'fileId',
        'fileModificationTime',
        'fileName',
        'filePath',
        'filePermission',
        'fileSize',
        'fileType',
        'flexDate1',
        'flexDate1Label',
        'flexString1',
        'flexString1Label',
        'flexString2',
        'flexString2Label',
        'fname',
        'fsize',
        'in',
        'msg',
        'oldFileCreateTime',
        'oldFileHash',
        'oldFileId',
        'oldFileModificationTime',
        'oldFileName',
        'oldFilePath',
        'oldFilePermission',
        'oldFileSize',
        'oldFileType',
        'out',
        'outcome',
        'proto',
        'reason',
        'request',
        'requestClientApplication',
        'requestContext',
        'requestCookies',
        'requestMethod',
        'rt',
        'shost',
        'smac',
        'sntdom',
        'sourceDnsDomain',
        'sourceServiceName',
        'sourceTranslatedAddress',
        'sourceTranslatedPort',
        'spid',
        'spriv',
        'sproc',
        'spt',
        'src',
        'start',
        'suid',
        'suser',
        'type',
    }
)


def _expected_severity(result: Any) -> int:
    """Mirror cef_severity() in crate/access/src/audit/cef.rs."""
    if result == 'Success':
        return 5
    if isinstance(result, dict) and 'Failure' in result:
        msg = result['Failure']
        if any(needle in msg for needle in ('401', '403', 'Unauthorized', 'Forbidden')):
            return 7
        return 6
    raise ValueError(f"Unrecognised AuditResult shape: {result!r}")


def _validate_cef_v27_structure(line_no: int, cef_line: str, cef: dict) -> list[str]:
    """Validate CEF v27 structural compliance beyond field round-trip.

    Returns a list of violation strings (empty = all OK).
    """
    violations: list[str] = []

    # ── 1. CEF version must be 0 ──────────────────────────────────────────
    if not cef_line.startswith('CEF:0|'):
        violations.append(
            f"line {line_no}: CEF version must be 0, got: {cef_line[:10]!r}"
        )

    # ── 2. Header field length limits ─────────────────────────────────────
    for key, max_len in _HEADER_LIMITS.items():
        val = cef.get(key, '')
        if len(val) > max_len:
            violations.append(
                f"line {line_no}: {key} length {len(val)} exceeds CEF v27 limit {max_len}"
            )

    # ── 3. Severity must be integer 0–10 ──────────────────────────────────
    sev = cef.get('agentSeverity', '')
    try:
        sev_int = int(sev)
        if not (0 <= sev_int <= 10):
            violations.append(
                f"line {line_no}: severity {sev_int} outside CEF v27 range 0–10"
            )
    except ValueError:
        valid_strings = {'Unknown', 'Low', 'Medium', 'High', 'Very-High'}
        if sev not in valid_strings:
            violations.append(
                f"line {line_no}: severity {sev!r} is not a valid CEF v27 value"
            )

    # ── 4. Extension field type validation ────────────────────────────────
    # rt must be a valid epoch-millisecond integer
    rt_val = cef.get('rt', '')
    try:
        rt_int = int(rt_val)
        if rt_int < 0:
            violations.append(f"line {line_no}: rt must be non-negative, got {rt_int}")
    except ValueError:
        violations.append(
            f"line {line_no}: rt must be an integer (epoch ms), got {rt_val!r}"
        )

    # cn1 must be a valid integer
    cn1_val = cef.get('cn1', '')
    try:
        int(cn1_val)
    except ValueError:
        violations.append(f"line {line_no}: cn1 must be an integer, got {cn1_val!r}")

    # src must be a valid IP address (if present)
    src_val = cef.get('src')
    if src_val is not None:
        try:
            ipaddress.ip_address(src_val)
        except ValueError:
            violations.append(
                f"line {line_no}: src must be a valid IP address, got {src_val!r}"
            )

    # ── 5. All extension keys must be in CEF v27 dictionary ───────────────
    # jc returns header fields + extension fields in one dict.
    # Header fields have fixed names; extension keys must be standard or labelled custom.
    _header_field_names = {
        'CEFVersion',
        'deviceVendor',
        'deviceProduct',
        'deviceVersion',
        'deviceEventClassId',
        'name',
        'agentSeverity',
    }
    for key in cef:
        if key in _header_field_names:
            continue
        if key not in _CEF_V27_STANDARD_KEYS:
            violations.append(
                f"line {line_no}: extension key {key!r} is not in the CEF v27 dictionary"
            )

    # ── 6. No raw newlines or carriage returns in the CEF line ────────────
    if '\n' in cef_line or '\r' in cef_line:
        violations.append(
            f"line {line_no}: CEF line contains raw newline/CR (injection risk)"
        )

    return violations


def _validate_escaping_roundtrip(line_no: int, event: dict, cef_line: str) -> list[str]:
    """Verify that jc correctly unescapes CEF values back to the originals.

    This catches bugs where our Rust escape function produces output that jc
    cannot correctly round-trip (e.g. double-escaping, missed escape sequences).
    """
    import jc

    violations: list[str] = []
    records = jc.parse('cef', cef_line, raw=True)
    if not records:
        return violations  # structural parse failure caught elsewhere

    cef = records[0]

    # Fields that go through escape_ext_value() in Rust and must round-trip
    roundtrip_checks = [
        ('suser', event['user'], 'user'),
        ('act', event['operation'], 'operation'),
    ]
    if event['client_ip'] is not None:
        roundtrip_checks.append(('src', event['client_ip'], 'client_ip'))
    if event['object_uid'] is not None:
        roundtrip_checks.append(('cs1', event['object_uid'], 'object_uid'))
    if event['algorithm'] is not None:
        roundtrip_checks.append(('cs2', event['algorithm'], 'algorithm'))
    if isinstance(event['result'], dict) and 'Failure' in event['result']:
        roundtrip_checks.append(
            ('reason', event['result']['Failure'], 'failure reason')
        )

    for cef_key, expected_val, label in roundtrip_checks:
        got = cef.get(cef_key)
        if got != expected_val:
            violations.append(
                f"line {line_no}: escaping round-trip failed for {label}: "
                f"expected {expected_val!r}, got {got!r}"
            )

    return violations


def _check_line(line_no: int, event: dict, cef_line: str) -> list[str]:
    """Run all validations on a single CEF line. Returns list of violations."""
    import jc

    violations: list[str] = []

    # ── Structural parse ──────────────────────────────────────────────────
    try:
        records = jc.parse('cef', cef_line, raw=True)
    except Exception as e:
        return [f"line {line_no}: jc parse raised {type(e).__name__}: {e}"]

    if len(records) != 1:
        return [
            f"line {line_no}: expected exactly 1 parsed CEF record, got {len(records)} "
            f"(possible record injection / line-splitting bug): {cef_line!r}"
        ]

    cef = records[0]

    # ── CEF v27 structural compliance ─────────────────────────────────────
    violations.extend(_validate_cef_v27_structure(line_no, cef_line, cef))

    # ── Escaping round-trip ───────────────────────────────────────────────
    violations.extend(_validate_escaping_roundtrip(line_no, event, cef_line))

    # If structural violations found, skip field-level checks
    if violations:
        return violations

    # ── Field-level round-trip ────────────────────────────────────────────
    def expect(key: str, value: str, label: str) -> None:
        got = cef.get(key)
        if got != value:
            violations.append(
                f"line {line_no} ({label}): expected {key}={value!r}, got {got!r}"
            )

    def expect_absent(key: str, label: str) -> None:
        if key in cef:
            violations.append(
                f"line {line_no} ({label}): expected {key} to be absent, got {cef[key]!r}"
            )

    expect('deviceVendor', 'Cosmian', 'vendor')
    expect('deviceProduct', 'KMS', 'product')
    expect('deviceEventClassId', event['operation'], 'class id')
    expect('name', event['operation'], 'name')
    expect('agentSeverity', str(_expected_severity(event['result'])), 'severity')

    expect('rt', str(int(event['_rt_ms'])), 'rt')
    expect('suser', event['user'], 'suser')
    if event['client_ip'] is not None:
        expect('src', event['client_ip'], 'client ip')
    else:
        expect_absent('src', 'client ip')

    result = event['result']
    if result == 'Success':
        expect('outcome', 'Success', 'outcome')
        expect_absent('reason', 'reason')
    else:
        expect('outcome', 'Failure', 'outcome')
        expect('reason', result['Failure'], 'failure reason')

    expect('act', event['operation'], 'act')
    expect('cn1', str(event['duration_ms']), 'duration value')
    expect('cn1Label', 'durationMs', 'duration label')

    if event['object_uid'] is not None:
        expect('cs1', event['object_uid'], 'object uid')
        expect('cs1Label', 'objectUID', 'object uid label')
    else:
        expect_absent('cs1', 'object uid')

    if event['algorithm'] is not None:
        expect('cs2', event['algorithm'], 'algorithm')
        expect('cs2Label', 'algorithm', 'algorithm label')
    else:
        expect_absent('cs2', 'algorithm')

    # Standard CEF keys (CEF v27 dictionary) — no custom csN labels for auditId/timestamp/requestId
    expect('externalId', str(event['id']), 'audit id (externalId)')

    if event.get('request_id') is not None:
        expect('devicePayloadId', event['request_id'], 'request id (devicePayloadId)')
    else:
        expect_absent('devicePayloadId', 'request id (devicePayloadId)')

    # Verify non-standard custom labels are absent
    expect_absent('cs3Label', 'cs3Label (non-standard)')
    expect_absent('cs4Label', 'cs4Label (non-standard)')
    expect_absent('cs5Label', 'cs5Label (non-standard)')

    return violations


# ── JSONL AuditEvent schema validation ────────────────────────────────────────

# Required fields (always present in every event)
_JSONL_REQUIRED_FIELDS: dict[str, type | tuple[type, ...]] = {
    'id': int,
    'timestamp': str,
    'operation': str,
    'user': str,
    'result': (str, dict),  # "Success" or {"Failure": "..."}
    'duration_ms': int,
    'prev_hash': str,
    'row_hash': str,
}

# Optional fields (may be null or absent)
_JSONL_OPTIONAL_FIELDS: dict[str, type | tuple[type, ...]] = {
    'object_uid': (str, type(None)),
    'algorithm': (str, type(None)),
    'client_ip': (str, type(None)),
    'request_id': (str, type(None)),
}


def _validate_jsonl_schema(events: list[dict]) -> list[str]:
    """Validate that every JSONL event conforms to the AuditEvent schema.

    This catches accidental schema changes (field renames, type changes, removed
    fields) that would break SIEM ingestion or hash-chain verification.
    """
    violations: list[str] = []

    for i, event in enumerate(events):
        prefix = f"JSONL event {i}"

        # Check required fields are present with correct types
        for field, expected_type in _JSONL_REQUIRED_FIELDS.items():
            if field not in event:
                violations.append(f"{prefix}: missing required field {field!r}")
            elif not isinstance(event[field], expected_type):
                violations.append(
                    f"{prefix}: field {field!r} has type {type(event[field]).__name__}, "
                    f"expected {expected_type}"
                )

        # Check optional fields have correct types when present
        for field, expected_type in _JSONL_OPTIONAL_FIELDS.items():
            if field in event and not isinstance(event[field], expected_type):
                violations.append(
                    f"{prefix}: field {field!r} has type {type(event[field]).__name__}, "
                    f"expected {expected_type}"
                )

        # Validate hash fields are 64-char hex strings
        for hash_field in ('prev_hash', 'row_hash'):
            val = event.get(hash_field, '')
            if isinstance(val, str) and (
                len(val) != 64 or not all(c in '0123456789abcdef' for c in val)
            ):
                violations.append(
                    f"{prefix}: {hash_field!r} must be 64 hex chars, got {len(val)} chars"
                )

        # Validate timestamp is RFC 3339
        ts = event.get('timestamp', '')
        if isinstance(ts, str) and not re.match(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', ts
        ):
            violations.append(f"{prefix}: timestamp {ts!r} is not RFC 3339")

        # Validate result shape
        result = event.get('result')
        if isinstance(result, dict):
            if 'Failure' not in result:
                violations.append(
                    f"{prefix}: result dict must have 'Failure' key, got {list(result.keys())}"
                )
        elif isinstance(result, str) and result != 'Success':
            violations.append(
                f"{prefix}: result string must be 'Success', got {result!r}"
            )

        # Validate id is non-negative and monotonically increasing
        eid = event.get('id', -1)
        if isinstance(eid, int) and eid != i:
            violations.append(
                f"{prefix}: id={eid} but expected {i} (must be 0-indexed sequential)"
            )

    return violations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--jsonl', required=True, help='Path to the original AuditEvent JSONL file'
    )
    parser.add_argument(
        '--cef',
        required=True,
        help='Path to the CEF output produced by ckms audit export',
    )
    args = parser.parse_args()

    with open(args.jsonl, encoding='utf-8') as f:
        events = [json.loads(line) for line in f if line.strip()]
    with open(args.cef, encoding='utf-8') as f:
        cef_lines = [line.rstrip('\n') for line in f if line.strip()]

    if len(events) != len(cef_lines):
        print(
            f"FATAL: source has {len(events)} events but CEF output has {len(cef_lines)} lines",
            file=sys.stderr,
        )
        sys.exit(1)

    # Rust computes rt as unix_timestamp*1000 + millisecond(); derive the same
    # value here from the RFC3339 timestamp so we don't need a datetime dep.
    # datetime.fromisoformat() only accepts up to microsecond (6-digit)
    # fractional seconds, so truncate any nanosecond-precision input first.
    import datetime

    for event in events:
        ts = re.sub(r'(\.\d{6})\d*Z$', r'\1Z', event['timestamp'])
        dt = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))
        event['_rt_ms'] = int(dt.timestamp() * 1000)

    # ── Phase 1: JSONL schema validation ────────────────────────────────────
    print('==> Validating JSONL AuditEvent schema...')
    jsonl_viols = _validate_jsonl_schema(events)
    if jsonl_viols:
        for v in jsonl_viols:
            print(f"FAIL: {v}", file=sys.stderr)
        print(f"\n{len(jsonl_viols)} JSONL schema violation(s).", file=sys.stderr)
        sys.exit(1)
    print(
        f"    JSONL schema OK ({len(events)} events, {len(_JSONL_REQUIRED_FIELDS)} required + {len(_JSONL_OPTIONAL_FIELDS)} optional fields)"
    )

    # ── Phase 2: CEF v27 interop validation ─────────────────────────────────
    print('\n==> Validating CEF v27 interop via jc...')
    total_violations = 0
    for i, (event, cef_line) in enumerate(zip(events, cef_lines), start=1):
        viols = _check_line(i, event, cef_line)
        if viols:
            for v in viols:
                print(f"FAIL: {v}", file=sys.stderr)
            total_violations += len(viols)
        else:
            print(f"PASS: line {i} ({event['operation']}, id={event['id']})")

    if total_violations:
        print(
            f"\n{total_violations} violation(s) across {len(events)} CEF line(s).",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"\nAll {len(events)} lines validated OK (JSONL schema + CEF v27 via jc).")


if __name__ == '__main__':
    main()

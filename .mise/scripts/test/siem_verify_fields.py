#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared helper for KMS SIEM integration tests.

Provides:
  1. ``verify_jsonl_fields`` — asserts required audit fields are present and
     correctly typed in a list of parsed JSONL objects.
  2. ``verify_fluent_bit_output`` — parses Fluent Bit output (JSONL format) and
     checks that each record contains the expected KMS audit fields.
  3. ``SyslogUDPReceiver`` — minimal UDP syslog listener that collects messages
     for the CEF-over-syslog integration test.
  4. ``verify_cef_syslog_messages`` — asserts CEF header structure AND optionally
     cross-validates field values against source JSONL events.
  5. ``verify_es_fields`` — verifies Elasticsearch documents produced by the
     kms-audit-normalize ingest pipeline (result_status / result_error fields).
  6. CLI entry-point for sub-commands:
       python siem_verify_fields.py jsonl   <file>
       python siem_verify_fields.py fluent  <file> [--exact N]
       python siem_verify_fields.py syslog  --port <N> --count <N> [--timeout <s>]
                                            [--source <audit.jsonl>]
       python siem_verify_fields.py es      <file> [--exact N]

All verification routines print a summary line and exit non-zero on first
failure, so they can be used directly in ``set -e`` shell scripts.

Design principle: **100 % success is the only acceptable outcome.**
- Exact event counts are always enforced — partial ingestion is a hard failure.
- Field *values* (not just presence) are checked wherever the source is available.
- Every failure path calls ``_fail()`` which exits with code 1 immediately.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any


# ── Required KMS audit fields ─────────────────────────────────────────────────

# Fields that MUST be present and non-null in every audit event.
_REQUIRED_FIELDS: tuple[str, ...] = (
    'id',
    'timestamp',
    'operation',
    'user',
    'result',
    'duration_ms',
    'prev_hash',
    'row_hash',
)

# Fields that must be present (may be null/None).
_OPTIONAL_FIELDS: tuple[str, ...] = (
    'object_uid',
    'algorithm',
    'client_ip',
    'request_id',
)

# All expected schema fields.
_ALL_FIELDS: frozenset[str] = frozenset(_REQUIRED_FIELDS) | frozenset(_OPTIONAL_FIELDS)

# Valid KMIP operation names emitted by KMS.
# Includes both KMIP operation names (injected by operation handlers) and
# HTTP-route-level fallback names (extracted from the request path when a
# KMIP request fails before operation dispatch — see middlewares/audit.rs).
_VALID_OPERATIONS: frozenset[str] = frozenset(
    {
        # ── HTTP route fallbacks (pre-dispatch failures) ──────────────────────
        'kmip',
        'google_cse',
        'ms_dke',
        'azure_ekm',
        'aws_xks',
        # ── KMIP 2.1 operations ───────────────────────────────────────────────
        'CreateKey',
        'Create',
        'CreateKeyPair',
        'Destroy',
        'Encrypt',
        'Decrypt',
        'Get',
        'GetAttributes',
        'Locate',
        'Revoke',
        'Import',
        'Export',
        'MAC',
        'Register',
        'Query',
        'Validate',
        'Sign',
        'Verify',
        'SetAttribute',
        'DeleteAttribute',
        'ObtainLease',
        'RekeyKeyPair',
    }
)

# 64-hex hash pattern (SHA-256 hex-encoded).
_HEX64_RE = re.compile(r'^[0-9a-f]{64}$')

# RFC 3339 / ISO 8601 timestamp pattern.
_TIMESTAMP_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
)


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


# ── 1. JSONL verification ─────────────────────────────────────────────────────


def verify_jsonl_fields(
    events: list[dict[str, Any]],
    *,
    label: str = 'event',
    exact: int | None = None,
) -> None:
    """Assert that each event dict has the required KMS audit fields.

    When ``exact`` is set, the list must contain *exactly* that many events.
    Raises SystemExit on first failure.
    """
    if exact is not None and len(events) != exact:
        _fail(
            f"Expected exactly {exact} {label} record(s), got {len(events)}. "
            'All audit events must be ingested — partial ingestion is not acceptable.'
        )

    if not events:
        _fail(f"No {label} records found — expected at least one audit event.")

    for i, ev in enumerate(events):
        for field in _REQUIRED_FIELDS:
            if field not in ev:
                _fail(f"{label}[{i}]: missing required field '{field}'")
            if ev[field] is None and field not in _OPTIONAL_FIELDS:
                _fail(f"{label}[{i}]: required field '{field}' is null")

        # id: positive integer sequence number
        ev_id = ev.get('id')
        if not isinstance(ev_id, (int, float)) or ev_id < 0:
            _fail(f"{label}[{i}]: 'id' must be a non-negative number, got {ev_id!r}")

        # duration_ms: non-negative integer
        dur = ev.get('duration_ms')
        if not isinstance(dur, (int, float)) or dur < 0:
            _fail(f"{label}[{i}]: 'duration_ms' must be >= 0, got {dur!r}")

        # timestamp: RFC 3339 string
        ts = ev.get('timestamp', '')
        if not isinstance(ts, str) or not _TIMESTAMP_RE.match(ts):
            _fail(f"{label}[{i}]: 'timestamp' is not a valid RFC 3339 string: {ts!r}")

        # operation: known KMIP operation name
        op = ev.get('operation', '')
        if not isinstance(op, str) or not op:
            _fail(f"{label}[{i}]: 'operation' must be a non-empty string")
        if op not in _VALID_OPERATIONS:
            _fail(
                f"{label}[{i}]: 'operation' value {op!r} is not a known KMS operation. "
                f"Expected one of: {sorted(_VALID_OPERATIONS)}"
            )

        # user: non-empty string
        user = ev.get('user', '')
        if not isinstance(user, str) or not user:
            _fail(f"{label}[{i}]: 'user' must be a non-empty string")

        # result: "Success" | {"Failure": "<msg>"}
        result = ev.get('result')
        if result != 'Success' and not (
            isinstance(result, dict)
            and 'Failure' in result
            and isinstance(result['Failure'], str)
        ):
            _fail(
                f"{label}[{i}]: 'result' must be 'Success' or {{\"Failure\": \"...\"}}, "
                f"got {result!r}"
            )

        # prev_hash / row_hash: 64-hex strings
        for hash_field in ('prev_hash', 'row_hash'):
            h = ev.get(hash_field, '')
            if not isinstance(h, str) or not _HEX64_RE.match(h):
                _fail(
                    f"{label}[{i}]: '{hash_field}' must be a 64-character hex string, "
                    f"got {h!r}"
                )

    print(f"OK: {len(events)} {label} record(s) passed schema validation.")


# ── ES normalized-field verification ─────────────────────────────────────────

# Fields required in every Elasticsearch-indexed audit document.
# The `result` field is replaced by `result_status` (always a string keyword)
# via the kms-audit-normalize ingest pipeline.
_ES_REQUIRED_FIELDS: tuple[str, ...] = (
    'id',
    'timestamp',
    'operation',
    'user',
    'result_status',
    'duration_ms',
    'prev_hash',
    'row_hash',
)


def verify_es_fields(
    events: list[dict[str, Any]],
    *,
    label: str = 'ES document',
    exact: int | None = None,
) -> None:
    """Assert that each Elasticsearch-indexed document has the expected fields.

    This verifies documents that have been processed by the kms-audit-normalize
    ingest pipeline, which replaces the polymorphic ``result`` field with:
    - ``result_status``: always a string ("Success" or "Failure")
    - ``result_error``: present only for Failure events, contains the error message

    When ``exact`` is set, the list must contain *exactly* that many events.
    Raises SystemExit on first failure.
    """
    if exact is not None and len(events) != exact:
        _fail(
            f"Expected exactly {exact} {label} record(s), got {len(events)}. "
            'All audit events must be indexed — partial ingestion is not acceptable.'
        )

    if not events:
        _fail(
            f"No {label} records found — expected at least one indexed audit document."
        )

    success_count = 0
    failure_count = 0

    for i, ev in enumerate(events):
        for field in _ES_REQUIRED_FIELDS:
            if field not in ev:
                _fail(f"{label}[{i}]: missing required field '{field}'")
            if ev[field] is None:
                _fail(f"{label}[{i}]: required field '{field}' is null")

        # id: non-negative number
        ev_id = ev.get('id')
        if not isinstance(ev_id, (int, float)) or ev_id < 0:
            _fail(f"{label}[{i}]: 'id' must be a non-negative number, got {ev_id!r}")

        # duration_ms: non-negative number
        dur = ev.get('duration_ms')
        if not isinstance(dur, (int, float)) or dur < 0:
            _fail(f"{label}[{i}]: 'duration_ms' must be >= 0, got {dur!r}")

        # timestamp: non-empty string (ES re-formats to ISO but still a string)
        if not isinstance(ev.get('timestamp'), str) or not ev['timestamp']:
            _fail(f"{label}[{i}]: 'timestamp' must be a non-empty string")

        # operation: non-empty string (known KMIP operation)
        op = ev.get('operation', '')
        if not isinstance(op, str) or not op:
            _fail(f"{label}[{i}]: 'operation' must be a non-empty string")
        if op not in _VALID_OPERATIONS:
            _fail(
                f"{label}[{i}]: 'operation' value {op!r} is not a known KMS operation"
            )

        # user: non-empty string
        if not isinstance(ev.get('user'), str) or not ev['user']:
            _fail(f"{label}[{i}]: 'user' must be a non-empty string")

        # result_status: exactly "Success" or "Failure"
        result_status = ev.get('result_status')
        if result_status not in ('Success', 'Failure'):
            _fail(
                f"{label}[{i}]: 'result_status' must be 'Success' or 'Failure', "
                f"got {result_status!r}"
            )
        if result_status == 'Success':
            success_count += 1
            # Failure events must have result_error
        else:
            failure_count += 1
            if not ev.get('result_error'):
                _fail(f"{label}[{i}]: Failure event is missing 'result_error' field")

        # prev_hash / row_hash: 64-hex strings
        for hash_field in ('prev_hash', 'row_hash'):
            h = ev.get(hash_field, '')
            if not isinstance(h, str) or not _HEX64_RE.match(h):
                _fail(
                    f"{label}[{i}]: '{hash_field}' must be a 64-character hex string, "
                    f"got {h!r}"
                )

    print(
        f"OK: {len(events)} {label} record(s) passed ES schema validation "
        f"({success_count} Success, {failure_count} Failure)."
    )


def verify_es_result_coverage(
    events: list[dict[str, Any]], *, label: str = 'ES document'
) -> None:
    """Assert that the indexed documents include BOTH Success and Failure events.

    This proves the kms-audit-normalize ingest pipeline correctly handles the
    polymorphic ``result`` field for both result types.
    Raises SystemExit if either type is absent.
    """
    statuses = {ev.get('result_status') for ev in events}
    if 'Success' not in statuses:
        _fail(
            f"{label}: no 'Success' events found — the ingest pipeline must handle "
            "result='Success' events."
        )
    if 'Failure' not in statuses:
        _fail(
            f"{label}: no 'Failure' events found — the ingest pipeline must handle "
            "result={{\"Failure\":\"...\"}} events. Add an operation that produces "
            'a Failure result to the test.'
        )
    print(
        f"OK: result coverage verified — both 'Success' and 'Failure' events are "
        f"present in the {len(events)} indexed document(s)."
    )


def load_jsonl(path: str, *, strict: bool = False) -> list[dict[str, Any]]:
    """Parse a JSONL (newline-delimited JSON) file into a list of dicts.

    When ``strict=True`` (used for audit file validation), any non-JSON line
    causes a hard failure. When ``strict=False`` (used for tool output that
    may contain banner/log lines), non-JSON lines are silently skipped.
    """
    records: list[dict[str, Any]] = []
    with open(path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith('{'):
                if strict:
                    _fail(
                        f"{path}:{lineno}: line does not start with '{{' — not a JSON object"
                    )
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if strict:
                    _fail(f"{path}:{lineno}: invalid JSON — {exc}")
                # Non-JSON line (Fluent Bit banner, log message, etc.) — skip
    return records


# ── 2. Fluent Bit output verification ────────────────────────────────────────


def verify_fluent_bit_output(
    output_path: str,
    *,
    exact: int | None = None,
    source_events: list[dict[str, Any]] | None = None,
) -> None:
    """Verify Fluent Bit parsed and forwarded KMS audit events correctly.

    Fluent Bit with the ``stdout`` output plugin (json_lines format) writes one
    JSON object per line. Each object may carry the audit fields at the top level
    or wrapped in a ``message`` envelope.

    Guards:
    - If ``exact`` is set, the extracted event count must match *exactly*.
    - If ``source_events`` is provided, the operation set in the Fluent Bit output
      must exactly match the operation set in the source JSONL.
    """
    records = load_jsonl(output_path)
    if not records:
        _fail(f"Fluent Bit output file is empty: {output_path}")

    # Unwrap envelope if present.
    audit_events: list[dict[str, Any]] = []
    for r in records:
        if 'message' in r and isinstance(r['message'], dict):
            audit_events.append(r['message'])
        elif 'operation' in r:
            audit_events.append(r)
        # else: skip internal Fluent Bit records

    if exact is not None and len(audit_events) != exact:
        _fail(
            f"Fluent Bit: expected exactly {exact} audit event(s), "
            f"got {len(audit_events)} (total records in file: {len(records)}). "
            'All audit events must be forwarded — partial ingestion is not acceptable.'
        )
    elif not audit_events:
        _fail('Fluent Bit: no audit events found in output file.')

    verify_jsonl_fields(audit_events, label='fluent-bit record', exact=exact)

    # Cross-validate operation set against source JSONL if provided.
    if source_events:
        src_ops = sorted(e.get('operation', '') for e in source_events)
        fb_ops = sorted(e.get('operation', '') for e in audit_events)
        if src_ops != fb_ops:
            _fail(
                f"Fluent Bit operation set does not match source JSONL.\n"
                f"  Source: {src_ops}\n"
                f"  Fluent Bit: {fb_ops}"
            )
        print(f"OK: Fluent Bit operations match source JSONL: {src_ops}")

    print(
        f"OK: Fluent Bit output contains {len(audit_events)} audit event(s) "
        f"with all required fields."
    )


# ── 3. UDP syslog receiver ────────────────────────────────────────────────────


class SyslogUDPReceiver:
    """Minimal UDP syslog receiver for CEF integration testing.

    Binds to localhost on the given port, collects UDP datagrams, and stores
    them as strings. The ``collect`` method blocks until ``count`` messages
    arrive or ``timeout`` seconds elapse.
    """

    def __init__(self, port: int, *, bind_host: str = '127.0.0.1') -> None:
        self.port = port
        self.bind_host = bind_host
        self._sock: socket.socket | None = None

    def __enter__(self) -> 'SyslogUDPReceiver':
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_host, self.port))
        return self

    def __exit__(self, *_: object) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def collect(self, count: int, *, timeout: float = 30.0) -> list[str]:
        """Collect exactly ``count`` UDP messages, waiting at most ``timeout`` seconds."""
        assert self._sock is not None, 'Call __enter__ first'
        messages: list[str] = []
        deadline = time.monotonic() + timeout
        while len(messages) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._sock.settimeout(remaining)
            try:
                data, _ = self._sock.recvfrom(65535)
                messages.append(data.decode('utf-8', errors='replace'))
            except (TimeoutError, OSError):
                break
        return messages


def verify_cef_syslog_messages(
    messages: list[str],
    *,
    exact: int,
    source_events: list[dict[str, Any]] | None = None,
) -> None:
    """Assert that syslog messages contain valid CEF:0 lines.

    Guards:
    - Exact count: received CEF line count must equal ``exact``.
    - CEF header structure: all 8 pipe-delimited fields present, correct vendor/product.
    - Mandatory extension keys: ``act`` (operation), ``suser`` (user), ``outcome``
      (result), ``durationMs``.
    - If ``source_events`` is provided, the ``act`` (operation) values in the CEF
      lines are cross-checked against the source JSONL operations.
    """
    cef_lines: list[str] = []
    for msg in messages:
        idx = msg.find('CEF:0|')
        if idx >= 0:
            cef_lines.append(msg[idx:].strip())

    if len(cef_lines) != exact:
        _fail(
            f"Expected exactly {exact} CEF line(s) in received syslog messages, "
            f"got {len(cef_lines)}. "
            f"Received {len(messages)} raw UDP message(s). "
            'All audit events must be forwarded — partial ingestion is not acceptable.\n'
            'Raw messages:\n' + '\n'.join(messages[:5])
        )

    for i, line in enumerate(cef_lines):
        # ── CEF header structure ──────────────────────────────────────────────
        parts = line.split('|', 7)
        if len(parts) < 8:
            _fail(f"CEF line[{i}] has fewer than 8 pipe-delimited fields: {line!r}")
        if parts[0] != 'CEF:0':
            _fail(f"CEF line[{i}] does not start with 'CEF:0': {line!r}")
        if parts[1] != 'Cosmian':
            _fail(f"CEF line[{i}] deviceVendor != 'Cosmian': got {parts[1]!r}")
        if parts[2] != 'KMS':
            _fail(f"CEF line[{i}] deviceProduct != 'KMS': got {parts[2]!r}")
        version = parts[3]
        if not version:
            _fail(f"CEF line[{i}] deviceVersion is empty")
        sig_id = parts[4]
        if not sig_id:
            _fail(f"CEF line[{i}] signatureID (operation) is empty")
        name = parts[5]
        if not name:
            _fail(f"CEF line[{i}] name field is empty")
        try:
            severity = int(parts[6])
        except ValueError:
            _fail(f"CEF line[{i}] severity is not an integer: {parts[6]!r}")
        if not 0 <= severity <= 10:
            _fail(f"CEF line[{i}] severity {severity} is outside 0–10 range")

        # ── Extension key presence ────────────────────────────────────────────
        ext = parts[7] if len(parts) == 8 else ''
        # Mandatory extension keys per KMS CEF ADR (2026-07-09-005):
        #   suser  — source user identity
        #   outcome — operation result ("Success" or "Failure")
        #   act    — KMIP operation name (may be "kmip" for pre-dispatch failures)
        #   cn1    — duration in milliseconds (CEF standard custom number field)
        #   cn1Label=durationMs — label for cn1 (must appear verbatim)
        for key in ('suser=', 'outcome=', 'act=', 'cn1=', 'cn1Label=durationMs'):
            if key not in ext:
                _fail(
                    f"CEF line[{i}] extension is missing mandatory key '{key.rstrip('=')}': "
                    f"ext={ext!r}"
                )

        # outcome must be "Success" or "Failure"
        outcome_m = re.search(r'\boutcome=(\S+)', ext)
        if outcome_m:
            outcome_val = outcome_m.group(1)
            if outcome_val not in ('Success', 'Failure'):
                _fail(
                    f"CEF line[{i}] outcome={outcome_val!r} is not 'Success' or 'Failure'"
                )

    # ── Cross-validate outcome distribution against source JSONL ─────────────────
    if source_events:
        # Count Success/Failure outcomes in CEF lines
        def _extract_ext_value(ext_str: str, key: str) -> str:
            m = re.search(rf"\b{re.escape(key)}=(\S+)", ext_str)
            return m.group(1) if m else ''

        cef_outcomes = sorted(
            _extract_ext_value(line.split('|', 7)[-1], 'outcome') for line in cef_lines
        )

        # Map source JSONL results to CEF outcome values
        def _src_outcome(result: Any) -> str:
            if result == 'Success':
                return 'Success'
            if isinstance(result, dict) and 'Failure' in result:
                return 'Failure'
            return 'Unknown'

        src_outcomes = sorted(_src_outcome(e.get('result')) for e in source_events)
        if cef_outcomes != src_outcomes:
            _fail(
                f"CEF outcome distribution does not match source JSONL.\n"
                f"  Source outcomes: {src_outcomes}\n"
                f"  CEF outcome=   : {cef_outcomes}"
            )
        print(f"OK: CEF outcome distribution matches source JSONL: {cef_outcomes}")

    print(
        f"OK: received exactly {len(cef_lines)} CEF line(s) via syslog — "
        'all passed header and extension validation.'
    )


# ── CLI entry-point ───────────────────────────────────────────────────────────


def _cmd_jsonl(args: argparse.Namespace) -> None:
    events = load_jsonl(args.file, strict=True)
    verify_jsonl_fields(events)


def _cmd_es(args: argparse.Namespace) -> None:
    """Verify Elasticsearch-indexed documents (after kms-audit-normalize pipeline)."""
    events = load_jsonl(args.file, strict=False)
    exact = args.exact if hasattr(args, 'exact') else None
    verify_es_fields(events, exact=exact)
    verify_es_result_coverage(events)


def _cmd_fluent(args: argparse.Namespace) -> None:
    events = load_jsonl(args.file, strict=False)
    source: list[dict[str, Any]] | None = None
    if args.source:
        source = load_jsonl(args.source, strict=True)
    # Re-use the full verification function
    verify_fluent_bit_output(
        args.file,
        exact=args.exact,
        source_events=source,
    )


def _cmd_syslog(args: argparse.Namespace) -> None:
    print(
        f"Listening for UDP syslog messages on port {args.port} "
        f"(expecting exactly {args.count}, timeout {args.timeout}s)..."
    )
    source: list[dict[str, Any]] | None = None
    if args.source:
        source = load_jsonl(args.source, strict=True)
    with SyslogUDPReceiver(args.port) as recv:
        messages = recv.collect(args.count, timeout=args.timeout)
    verify_cef_syslog_messages(messages, exact=args.count, source_events=source)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='KMS SIEM integration test helper — 100% ingestion is the only success'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_jsonl = sub.add_parser('jsonl', help='Verify a JSONL audit file')
    p_jsonl.add_argument('file', help='Path to the JSONL audit file')

    p_es = sub.add_parser(
        'es', help='Verify Elasticsearch-indexed documents (normalized)'
    )
    p_es.add_argument('file', help='Path to JSONL file containing ES _source documents')
    p_es.add_argument(
        '--exact',
        type=int,
        default=None,
        help='Required exact document count (fail if not matched)',
    )

    p_fluent = sub.add_parser('fluent', help='Verify Fluent Bit output file')
    p_fluent.add_argument('file', help='Path to the Fluent Bit output file')
    p_fluent.add_argument(
        '--exact',
        type=int,
        default=None,
        help='Required exact event count (fail if not matched)',
    )
    p_fluent.add_argument(
        '--source',
        default=None,
        help='Path to source JSONL audit file — enables operation cross-validation',
    )

    p_syslog = sub.add_parser('syslog', help='Receive and verify CEF via UDP syslog')
    p_syslog.add_argument(
        '--port', type=int, required=True, help='UDP port to listen on'
    )
    p_syslog.add_argument(
        '--count',
        type=int,
        required=True,
        help='Exact number of CEF messages expected (hard failure if not reached)',
    )
    p_syslog.add_argument(
        '--timeout', type=float, default=60.0, help='Receive timeout in seconds'
    )
    p_syslog.add_argument(
        '--source',
        default=None,
        help='Path to source JSONL audit file — enables CEF operation cross-validation',
    )

    args = parser.parse_args()
    dispatch = {
        'jsonl': _cmd_jsonl,
        'es': _cmd_es,
        'fluent': _cmd_fluent,
        'syslog': _cmd_syslog,
    }
    dispatch[args.cmd](args)


if __name__ == '__main__':
    main()

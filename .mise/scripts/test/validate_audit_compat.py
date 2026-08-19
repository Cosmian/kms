#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate that a KMS JSONL audit file ingests cleanly into an external SIEM.

Reads a KMS audit trail (one JSON object per line, see
schemas/kms-audit-fields.json), validates every line against the expected
field schema, then ingests it into either OpenSearch or Splunk and checks
that the ingested event count matches the source line count.

This script never persists data itself: it only talks to an ephemeral
backend (started with `docker run --rm`, no volume) provided by the caller.

Usage:
    python3 .mise/scripts/test/validate_audit_compat.py --backend opensearch --file audit.jsonl
    python3 .mise/scripts/test/validate_audit_compat.py --backend splunk --file audit.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

DEFAULT_FIELDS_FILE = 'schemas/kms-audit-fields.json'
DEFAULT_MAPPING_FILE = 'schemas/kms-audit-mapping.json'


def log_error(message: str) -> None:
    """Print an error line to stderr, prefixed for easy grepping in CI logs."""
    print(f"ERROR: {message}", file=sys.stderr)


def load_json_file(path: str) -> dict[str, Any]:
    """Load and parse a JSON file, exiting on failure."""
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        log_error(f"failed to load {path}: {exc}")
        sys.exit(1)


def load_jsonl_lines(path: str) -> list[tuple[int, str]]:
    """Read a JSONL file, returning (1-based line number, raw line) pairs."""
    try:
        raw = Path(path).read_text(encoding='utf-8')
    except OSError as exc:
        log_error(f"failed to read audit file {path}: {exc}")
        sys.exit(1)
    lines = [line for line in raw.splitlines() if line.strip()]
    return list(enumerate(lines, start=1))


def parse_records(
    lines: list[tuple[int, str]],
) -> tuple[list[tuple[int, dict[str, Any]]], list[str]]:
    """Parse each JSONL line, collecting per-line JSON errors."""
    records: list[tuple[int, dict[str, Any]]] = []
    errors: list[str] = []
    for lineno, raw in lines:
        try:
            records.append((lineno, json.loads(raw)))
        except json.JSONDecodeError as exc:
            errors.append(f"line {lineno}: invalid JSON ({exc})")
    return records, errors


def validate_record(
    lineno: int, record: dict[str, Any], fields_spec: dict[str, Any]
) -> list[str]:
    """Check one record against the expected field schema, returning error strings."""
    errors: list[str] = []
    known_names = {f['name'] for f in fields_spec['fields']}
    for extra in set(record) - known_names:
        errors.append(f"line {lineno}: unexpected field '{extra}'")
    for field in fields_spec['fields']:
        name = field['name']
        if name not in record:
            if field['required']:
                errors.append(f"line {lineno}: missing required field '{name}'")
            continue
        if record[name] is None and not field.get('nullable', False):
            errors.append(f"line {lineno}: field '{name}' is null but not nullable")
    return errors


def validate_records(
    records: list[tuple[int, dict[str, Any]]], fields_spec: dict[str, Any]
) -> list[str]:
    """Validate every record, returning the full list of error strings."""
    errors: list[str] = []
    for lineno, record in records:
        errors.extend(validate_record(lineno, record, fields_spec))
    return errors


def normalize_result(record: dict[str, Any]) -> tuple[str, str | None]:
    """Split the polymorphic 'result' field into (status, detail) for OpenSearch."""
    result = record.get('result')
    if isinstance(result, str):
        return result, None
    if isinstance(result, dict) and 'Failure' in result:
        return 'Failure', str(result['Failure'])
    return 'Unknown', json.dumps(result)


def build_opensearch_bulk_body(
    records: list[tuple[int, dict[str, Any]]], index: str
) -> str:
    """Build a NDJSON bulk body, normalizing 'result' into result_status/result_detail."""
    lines: list[str] = []
    for _, record in records:
        status, detail = normalize_result(record)
        doc = {k: v for k, v in record.items() if k != 'result'}
        doc['result_status'] = status
        doc['result_detail'] = detail
        lines.append(json.dumps({'index': {'_index': index}}))
        lines.append(json.dumps(doc))
    return '\n'.join(lines) + '\n'


def run_opensearch(
    args: argparse.Namespace, records: list[tuple[int, dict[str, Any]]]
) -> int:
    """Create the index, bulk-load records, and verify the ingested count."""
    base_url = f"{args.scheme}://{args.host}:{args.port}"
    mapping = load_json_file(args.mapping_file)

    requests.delete(
        f"{base_url}/{args.index}", timeout=args.timeout, verify=not args.insecure
    )
    resp = requests.put(
        f"{base_url}/{args.index}",
        json=mapping,
        timeout=args.timeout,
        verify=not args.insecure,
    )
    if not resp.ok:
        log_error(
            f"failed to create index '{args.index}': {resp.status_code} {resp.text}"
        )
        return 1

    bulk_body = build_opensearch_bulk_body(records, args.index)
    resp = requests.post(
        f"{base_url}/_bulk?refresh=true",
        data=bulk_body.encode('utf-8'),
        headers={'Content-Type': 'application/x-ndjson'},
        timeout=args.timeout,
        verify=not args.insecure,
    )
    if not resp.ok:
        log_error(f"bulk request failed: {resp.status_code} {resp.text}")
        return 1

    bulk_result = resp.json()
    if bulk_result.get('errors'):
        for i, item in enumerate(bulk_result.get('items', [])):
            outcome = item.get('index', {})
            if 'error' in outcome:
                lineno = records[i][0]
                reason = outcome['error'].get('reason', outcome['error'])
                log_error(f"line {lineno}: OpenSearch rejected document: {reason}")
        return 1

    count_resp = requests.get(
        f"{base_url}/{args.index}/_count",
        timeout=args.timeout,
        verify=not args.insecure,
    )
    if not count_resp.ok:
        log_error(f"count request failed: {count_resp.status_code} {count_resp.text}")
        return 1
    indexed_count = count_resp.json()['count']
    if indexed_count != len(records):
        log_error(
            f"indexed count mismatch: expected {len(records)}, got {indexed_count}"
        )
        return 1

    print(
        f"OpenSearch: {indexed_count}/{len(records)} events ingested and counted correctly."
    )
    return 0


def send_splunk_hec_events(
    args: argparse.Namespace, records: list[tuple[int, dict[str, Any]]]
) -> int:
    """Send every record to the Splunk HEC /services/collector/event endpoint.

    Splunk's default sourcetype=_json extraction does not reliably expose a
    top-level field when its JSON value is itself an object (our polymorphic
    'result': "Success" | {"Failure": "..."}). Normalize it the same way as
    for OpenSearch (result_status/result_detail) so both backends are checked
    against the same, unambiguous field set.
    """
    hec_url = f"{args.scheme}://{args.host}:{args.port}/services/collector/event"
    headers = {'Authorization': f"Splunk {args.hec_token}"}
    body_parts = []
    for _, record in records:
        status, detail = normalize_result(record)
        event = {k: v for k, v in record.items() if k != 'result'}
        event['result_status'] = status
        event['result_detail'] = detail
        body_parts.append(
            json.dumps({'event': event, 'sourcetype': '_json', 'index': args.index})
        )
    resp = requests.post(
        hec_url,
        data='\n'.join(body_parts).encode('utf-8'),
        headers=headers,
        timeout=args.timeout,
        verify=not args.insecure,
    )
    if not resp.ok:
        log_error(f"HEC ingestion failed: {resp.status_code} {resp.text}")
        return 1
    return 0


def run_splunk_search(args: argparse.Namespace, query: str) -> int | None:
    """Run a blocking Splunk search job and return the numeric 'count' stat, or None."""
    mgmt_base = f"{args.scheme}://{args.host}:{args.mgmt_port}"
    auth = (args.username, args.password)
    resp = requests.post(
        f"{mgmt_base}/services/search/jobs",
        data={'search': query, 'output_mode': 'json', 'exec_mode': 'blocking'},
        auth=auth,
        timeout=args.timeout,
        verify=not args.insecure,
    )
    if not resp.ok:
        log_error(f"failed to start Splunk search job: {resp.status_code} {resp.text}")
        return None
    sid = resp.json()['sid']

    results_resp = requests.get(
        f"{mgmt_base}/services/search/jobs/{sid}/results",
        params={'output_mode': 'json'},
        auth=auth,
        timeout=args.timeout,
        verify=not args.insecure,
    )
    if not results_resp.ok:
        log_error(
            f"failed to fetch Splunk search results: {results_resp.status_code} {results_resp.text}"
        )
        return None
    rows = results_resp.json().get('results', [])
    if not rows or 'count' not in rows[0]:
        return 0
    return int(rows[0]['count'])


def run_splunk(
    args: argparse.Namespace,
    records: list[tuple[int, dict[str, Any]]],
    fields_spec: dict[str, Any],
) -> int:
    """Send events over HEC, wait for indexing, then verify count and required keys via search."""
    if send_splunk_hec_events(args, records) != 0:
        return 1

    # Splunk indexing is asynchronous; poll the count until it stabilizes or times out.
    expected = len(records)
    count_query = f"search index={args.index} sourcetype=_json | stats count"
    deadline = time.monotonic() + args.timeout
    count = 0
    while time.monotonic() < deadline:
        count = run_splunk_search(args, count_query) or 0
        if count >= expected:
            break
        time.sleep(2)
    if count != expected:
        log_error(f"Splunk indexed count mismatch: expected {expected}, got {count}")
        return 1

    no_ts_query = (
        f"search index={args.index} sourcetype=_json_no_timestamp | stats count"
    )
    no_ts_count = run_splunk_search(args, no_ts_query) or 0
    if no_ts_count:
        log_error(
            f"{no_ts_count} event(s) landed in sourcetype=_json_no_timestamp (timestamp parsing failed)"
        )
        return 1

    required_keys = fields_spec.get('splunk_required_keys_check', [])
    missing_clause = ' OR '.join(f"NOT {key}=*" for key in required_keys)
    missing_query = (
        f"search index={args.index} sourcetype=_json ({missing_clause}) | stats count"
    )
    missing_count = run_splunk_search(args, missing_query) or 0
    if missing_count:
        log_error(
            f"{missing_count} event(s) missing one of required keys: {required_keys}"
        )
        return 1

    print(
        f"Splunk: {count}/{expected} events ingested, no timestamp failures, no missing keys."
    )
    return 0


def parse_args() -> argparse.Namespace:
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=['opensearch', 'splunk'], required=True)
    parser.add_argument(
        '--file', required=True, help='Path to the KMS JSONL audit file'
    )
    parser.add_argument('--fields-file', default=DEFAULT_FIELDS_FILE)
    parser.add_argument(
        '--mapping-file', default=DEFAULT_MAPPING_FILE, help='OpenSearch mapping file'
    )
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--scheme', default='http')
    parser.add_argument(
        '--port',
        type=int,
        default=None,
        help='Defaults to 9200 (opensearch) or 8088 (splunk HEC)',
    )
    parser.add_argument(
        '--mgmt-port', type=int, default=8089, help='Splunk management API port'
    )
    parser.add_argument(
        '--index',
        default=None,
        help='Defaults to kms-audit-compat-test (opensearch) or main (splunk)',
    )
    parser.add_argument(
        '--username', default='admin', help='Splunk management API username'
    )
    parser.add_argument(
        '--password',
        default=os.environ.get('SPLUNK_PASSWORD'),
        help='Splunk management API password (env SPLUNK_PASSWORD)',
    )
    parser.add_argument(
        '--hec-token',
        default=os.environ.get('SPLUNK_HEC_TOKEN'),
        help='Splunk HEC token (env SPLUNK_HEC_TOKEN)',
    )
    parser.add_argument(
        '--insecure', action='store_true', help='Skip TLS certificate verification'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=60.0,
        help='Per-request / polling timeout in seconds',
    )
    args = parser.parse_args()
    if args.port is None:
        args.port = 9200 if args.backend == 'opensearch' else 8088
    if args.index is None:
        args.index = 'kms-audit-compat-test' if args.backend == 'opensearch' else 'main'
    return args


def main() -> int:
    args = parse_args()
    if args.insecure:
        # --insecure is an explicit opt-in for the ephemeral, self-signed test containers.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if args.backend == 'splunk' and not args.hec_token:
        log_error('Splunk backend requires --hec-token or SPLUNK_HEC_TOKEN env var')
        return 1

    fields_spec = load_json_file(args.fields_file)
    lines = load_jsonl_lines(args.file)
    records, parse_errors = parse_records(lines)
    if parse_errors:
        for err in parse_errors:
            log_error(err)
        return 1

    schema_errors = validate_records(records, fields_spec)
    if schema_errors:
        for err in schema_errors:
            log_error(err)
        return 1

    if args.backend == 'opensearch':
        return run_opensearch(args, records)
    return run_splunk(args, records, fields_spec)


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CEF export interoperability helper for KMS audit log testing.

Reads the original JSONL audit event file and the CEF output produced by
`ckms audit export --format cef` for that same file, then parses each CEF
line with `jc` (https://github.com/kellyjonbrazil/jc) — an independent,
widely used, actively maintained CEF parser — and asserts that every field
round-trips back to the original source-of-truth value.

This validates that `to_cef_line()` (crate/access/src/audit/cef.rs) produces
CEF that a real third-party parser can correctly ingest, not just that our
own Rust unit tests agree with themselves.

Usage:
    cef_interop_helper.py --jsonl <source.jsonl> --cef <cef-output.txt> --kms-version <version>

Requirements: Python 3.9+, jc
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _expected_severity(result: Any) -> int:
    """Mirror cef_severity() in crate/access/src/audit/cef.rs."""
    if result == "Success":
        return 5
    if isinstance(result, dict) and "Failure" in result:
        msg = result["Failure"]
        if any(needle in msg for needle in ("401", "403", "Unauthorized", "Forbidden")):
            return 7
        return 6
    raise ValueError(f"Unrecognised AuditResult shape: {result!r}")


def _check_line(line_no: int, event: dict, cef_line: str) -> None:
    import jc

    records = jc.parse("cef", cef_line, raw=True)
    if len(records) != 1:
        raise AssertionError(
            f"line {line_no}: expected exactly 1 parsed CEF record, got {len(records)} "
            f"(possible record injection / line-splitting bug): {cef_line!r}"
        )
    cef = records[0]

    def expect(key: str, value: str, label: str) -> None:
        got = cef.get(key)
        if got != value:
            raise AssertionError(
                f"line {line_no} ({label}): expected {key}={value!r}, got {got!r}"
            )

    def expect_absent(key: str, label: str) -> None:
        if key in cef:
            raise AssertionError(
                f"line {line_no} ({label}): expected {key} to be absent, got {cef[key]!r}"
            )

    expect("deviceVendor", "Cosmian", "vendor")
    expect("deviceProduct", "KMS", "product")
    expect("deviceEventClassId", event["operation"], "class id")
    expect("name", event["operation"], "name")
    expect("agentSeverity", str(_expected_severity(event["result"])), "severity")

    expect("rt", str(int(event["_rt_ms"])), "rt")
    expect("suser", event["user"], "suser")
    if event["client_ip"] is not None:
        expect("src", event["client_ip"], "client ip")
    else:
        expect_absent("src", "client ip")

    result = event["result"]
    if result == "Success":
        expect("outcome", "Success", "outcome")
        expect_absent("reason", "reason")
    else:
        expect("outcome", "Failure", "outcome")
        expect("reason", result["Failure"], "failure reason")

    expect("act", event["operation"], "act")
    expect("cn1", str(event["duration_ms"]), "duration value")
    expect("cn1Label", "durationMs", "duration label")

    if event["object_uid"] is not None:
        expect("cs1", event["object_uid"], "object uid")
        expect("cs1Label", "objectUID", "object uid label")
    else:
        expect_absent("cs1", "object uid")

    if event["algorithm"] is not None:
        expect("cs2", event["algorithm"], "algorithm")
        expect("cs2Label", "algorithm", "algorithm label")
    else:
        expect_absent("cs2", "algorithm")

    expect("cs3", str(event["id"]), "audit id")
    expect("cs3Label", "auditId", "audit id label")

    expect("cs4", event["timestamp"], "rfc3339 timestamp")
    expect("cs4Label", "timestamp", "timestamp label")

    if event.get("request_id") is not None:
        expect("cs5", event["request_id"], "request id")
        expect("cs5Label", "requestId", "request id label")
    else:
        expect_absent("cs5", "request id")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl", required=True, help="Path to the original AuditEvent JSONL file")
    parser.add_argument("--cef", required=True, help="Path to the CEF output produced by ckms audit export")
    args = parser.parse_args()

    with open(args.jsonl, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    with open(args.cef, encoding="utf-8") as f:
        cef_lines = [line.rstrip("\n") for line in f if line.strip()]

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
    import re

    for event in events:
        ts = re.sub(r"(\.\d{6})\d*Z$", r"\1Z", event["timestamp"])
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        event["_rt_ms"] = int(dt.timestamp() * 1000)

    failures = 0
    for i, (event, cef_line) in enumerate(zip(events, cef_lines), start=1):
        try:
            _check_line(i, event, cef_line)
        except AssertionError as e:
            print(f"FAIL: {e}", file=sys.stderr)
            failures += 1
        else:
            print(f"PASS: line {i} ({event['operation']}, id={event['id']})")

    if failures:
        print(f"\n{failures}/{len(events)} CEF line(s) failed interop validation.", file=sys.stderr)
        sys.exit(1)

    print(f"\nAll {len(events)} CEF lines validated OK via jc.")


if __name__ == "__main__":
    main()

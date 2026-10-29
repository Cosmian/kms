#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check the KMS log of the OpenBao KMIP seal scenario.

Usage: check_kmip_seal_audit.py <kms.log> <client-cn> <key-uid>

The binary KMIP listener logs one line per request with the authenticated user and, at debug
level, the raw TTLV request in hex. The script asserts that:
  * Encrypt and Decrypt were served for the OpenBao client certificate identity, and for nobody else;
  * those requests are KMIP 1.4, target the wrapping key and use AES in GCM mode.
"""

import re
import sys

# TTLV items: tag, type, length, value (padded to 8 bytes). Only fixed-size items are matched.
PROTOCOL_VERSION_1_4 = (
    '42006a0200000004' + '0000000100000000' + '42006b0200000004' + '0000000400000000'
)
AES_ALGORITHM = '4200280500000004' + '0000000300000000'
GCM_MODE = '4200110500000004' + '0000000900000000'

OPERATION_RE = re.compile(
    r"KMIP Request message with \d+ operation\(s\): \[(\w+)\] user=\"([^\"]*)\""
)
REQUEST_RE = re.compile(r'socket server: received request: ([0-9a-f]+)')


def main() -> int:
    log_path, client_cn, key_uid = sys.argv[1:4]
    with open(log_path, encoding='utf-8') as handle:
        lines = handle.read().splitlines()

    crypto_users: dict[str, set[str]] = {}
    errors: list[str] = []
    checked_requests = 0
    key_uid_hex = key_uid.encode().hex()

    for index, line in enumerate(lines):
        operation = OPERATION_RE.search(line)
        if operation and operation.group(1) in ('Encrypt', 'Decrypt'):
            crypto_users.setdefault(operation.group(1), set()).add(operation.group(2))

        request = REQUEST_RE.search(line)
        if not request:
            continue
        # The operation is only named on the line that follows the hex dump.
        next_line = lines[index + 1] if index + 1 < len(lines) else ''
        named = OPERATION_RE.search(next_line)
        if not named or named.group(1) not in ('Encrypt', 'Decrypt'):
            continue
        checked_requests += 1
        hex_request = request.group(1)
        for label, needle in (
            ('KMIP 1.4 protocol version', PROTOCOL_VERSION_1_4),
            ('AES algorithm', AES_ALGORITHM),
            ('GCM block cipher mode', GCM_MODE),
            ('the wrapping key identifier', key_uid_hex),
        ):
            if needle not in hex_request:
                errors.append(f"{named.group(1)} request without {label}")

    for operation in ('Encrypt', 'Decrypt'):
        users = crypto_users.get(operation)
        if not users:
            errors.append(f"no KMIP {operation} served")
        elif users != {client_cn}:
            errors.append(
                f"KMIP {operation} served for {sorted(users)}, expected only {client_cn}"
            )
    if checked_requests == 0:
        errors.append(
            'no Encrypt/Decrypt request dump found (is the KMS log level debug?)'
        )

    if errors:
        for error in sorted(set(errors)):
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"OK: Encrypt and Decrypt served for {client_cn} only; "
        f"{checked_requests} request(s) are KMIP 1.4, AES-GCM, key {key_uid}"
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())

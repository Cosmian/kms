#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check what the OpenBao KMIP seal scenario sent to and got served by the KMS.

Usage: check_kmip_seal_audit.py <kms.log> <tap.log> <client-cn> <key-uid>

`kms.log` is the KMS log: one line per KMIP request with the authenticated user. `tap.log` is
written by `kmip_tap_proxy.py`, which sits between OpenBao and the KMS and records every raw
TTLV request in hex (the KMS does not log request contents). The script asserts that:
  * Encrypt and Decrypt were served for the OpenBao client certificate identity, and for nobody else;
  * OpenBao sent Encrypt and Decrypt requests that are KMIP 1.4, target the wrapping key and use
    AES in GCM mode.
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
REQUEST_RE = re.compile(r'^request: ([0-9a-f]+)$')
# Operation tag, Enumeration, length 4, then the KMIP 1.4 Operation value (Encrypt 0x1F, Decrypt 0x20).
OPERATION_TTLV = {
    'Encrypt': '42005c0500000004' + '0000001f00000000',
    'Decrypt': '42005c0500000004' + '0000002000000000',
}


def main() -> int:
    kms_log_path, tap_log_path, client_cn, key_uid = sys.argv[1:5]
    with open(kms_log_path, encoding='utf-8') as handle:
        kms_lines = handle.read().splitlines()
    with open(tap_log_path, encoding='utf-8') as handle:
        tap_lines = handle.read().splitlines()

    crypto_users: dict[str, set[str]] = {}
    errors: list[str] = []
    checked: dict[str, int] = {'Encrypt': 0, 'Decrypt': 0}
    key_uid_hex = key_uid.encode().hex()

    for line in kms_lines:
        operation = OPERATION_RE.search(line)
        if operation and operation.group(1) in ('Encrypt', 'Decrypt'):
            crypto_users.setdefault(operation.group(1), set()).add(operation.group(2))

    for line in tap_lines:
        request = REQUEST_RE.search(line)
        if not request:
            continue
        hex_request = request.group(1)
        named = [
            name for name, needle in OPERATION_TTLV.items() if needle in hex_request
        ]
        if len(named) != 1:
            continue
        checked[named[0]] += 1
        for label, needle in (
            ('KMIP 1.4 protocol version', PROTOCOL_VERSION_1_4),
            ('AES algorithm', AES_ALGORITHM),
            ('GCM block cipher mode', GCM_MODE),
            ('the wrapping key identifier', key_uid_hex),
        ):
            if needle not in hex_request:
                errors.append(f"{named[0]} request without {label}")

    for operation in ('Encrypt', 'Decrypt'):
        users = crypto_users.get(operation)
        if not users:
            errors.append(f"no KMIP {operation} served")
        elif users != {client_cn}:
            errors.append(
                f"KMIP {operation} served for {sorted(users)}, expected only {client_cn}"
            )
    for operation, count in checked.items():
        if count == 0:
            errors.append(f"no {operation} request recorded by the KMIP tap")

    if errors:
        for error in sorted(set(errors)):
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        f"OK: Encrypt and Decrypt served for {client_cn} only; "
        f"{checked['Encrypt']} Encrypt and {checked['Decrypt']} Decrypt request(s) are "
        f"KMIP 1.4, AES-GCM, key {key_uid}"
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())

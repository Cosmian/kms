#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check what the OpenBao KMIP seal scenario sent to and got served by the KMS.

Usage: check_kmip_seal_audit.py <kms.log> <client-cn> <key-uid>

`kms.log` is the KMS log written with `cosmian_kms_server=debug`. It holds, per KMIP request
message, an info line with the operations and the authenticated user, and debug lines with the
protocol version, operation and, for Encrypt and Decrypt, the target key identifier, the cryptographic
algorithm and the block cipher mode (never the data or the IV). The script asserts that:
  * Encrypt and Decrypt were served for the OpenBao client certificate identity, and for nobody else;
  * OpenBao sent Encrypt and Decrypt requests that are KMIP 1.4, target the wrapping key and use
    AES in GCM mode.
"""

import re
import sys

OPERATION_RE = re.compile(
    r"KMIP Request message with \d+ operation\(s\): \[(\w+)\] user=\"([^\"]*)\""
)
DETAILS_RE = re.compile(
    r'KMIP request \[(Encrypt|Decrypt)\] protocol_version=(\S+) unique_identifier=(\S+) '
    r'cryptographic_algorithm=(\S+) block_cipher_mode=(\S+) user="([^"]*)"'
)


def main() -> int:
    kms_log_path, client_cn, key_uid = sys.argv[1:4]
    with open(kms_log_path, encoding='utf-8') as handle:
        kms_lines = handle.read().splitlines()

    crypto_users: dict[str, set[str]] = {}
    checked: dict[str, int] = {'Encrypt': 0, 'Decrypt': 0}
    errors: list[str] = []

    for line in kms_lines:
        operation = OPERATION_RE.search(line)
        if operation and operation.group(1) in ('Encrypt', 'Decrypt'):
            crypto_users.setdefault(operation.group(1), set()).add(operation.group(2))
        details = DETAILS_RE.search(line)
        if details:
            name, version, uid, algorithm, mode, user = details.groups()
            if user != client_cn:
                continue
            checked[name] += 1
            if version != '1.4':
                errors.append(f"{name} request uses KMIP {version}, expected 1.4")
            if uid != key_uid:
                errors.append(
                    f"{name} request targets {uid}, expected the wrapping key {key_uid}"
                )
            if algorithm != 'AES':
                errors.append(
                    f"{name} request uses algorithm {algorithm}, expected AES"
                )
            if mode != 'GCM':
                errors.append(
                    f"{name} request uses block cipher mode {mode}, expected GCM"
                )

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
            errors.append(f"no {operation} request details found in the KMS debug log")

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

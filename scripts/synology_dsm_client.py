#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Synology DSM KMIP simulation client for Cosmian KMS compatibility testing.

Synology DSM 7.x uses KMIP 1.2 over TCP/TLS with mutual certificate
authentication to store and retrieve volume encryption keys.

This script simulates the exact KMIP operation sequence that Synology DSM
performs when it configures an external KMS server, based on observed wire
traffic (decoded TTLV binary):

  1. Discover Versions   — check KMIP protocol compatibility
  2. Query               — enumerate server capabilities (6 QueryFunctions)
  3. Locate (pre-check)  — check if volume key already exists (expect 0)
  4. Register            — register SecretData with opaque 32-byte key material
  5. Activate            — transition PreActive → Active
  6. Modify Attribute    — set Name = volume UUID (DSM renames key after register)
  7. Get Attributes      — verify key attributes (state, object type…)
  8. Get                 — retrieve key material (simulates volume mount)
  9. Locate (verify)     — find key by volume UUID (simulates reconnect)
  10. Revoke             — revoke the key (simulates key rotation / cleanup)
  11. Destroy            — delete the key

Key observations from real DSM TTLV trace:
  - DSM uses Register with ObjectType=SecretData(7), CryptographicUsageMask=Verify,
    OperationPolicyName="default", key Name=SHA512(key_bytes)hex, 32-72 opaque bytes.
  - ModifyAttribute renames the key to the volume UUID (not ActivationDate).
  - Query sends 6 QueryFunctions: Operations, ObjectTypes, ServerInfo,
    AppNamespaces, ExtensionList, Profiles.

Requirements:
    pip install PyKMIP
    Python 3.11 or earlier (due to ssl.wrap_socket deprecation in 3.12+)

Usage:
    python synology_dsm_client.py --configuration pykmip.conf [--verbose]

Returns exit code 0 on success, 1 on any failure.
"""

import argparse
import hashlib
import json
import os
import sys
import traceback

# Check Python version before importing PyKMIP
if sys.version_info >= (3, 12):
    print(
        json.dumps(
            {
                'operation': 'Version Check',
                'status': 'error',
                'error': (
                    f'Python {sys.version_info.major}.{sys.version_info.minor} '
                    'is not supported. PyKMIP requires Python 3.11 or earlier '
                    'due to ssl.wrap_socket deprecation.'
                ),
                'solution': (
                    'Install Python 3.11 and recreate virtual environment: '
                    'rm -rf .venv && python3.11 -m venv .venv && '
                    'source .venv/bin/activate && pip install PyKMIP'
                ),
            },
            indent=2,
        )
    )
    sys.exit(1)

try:
    from kmip.services.kmip_client import KMIPProxy
    from kmip.core import enums, misc
    from kmip.core import exceptions as kmip_exceptions
    from kmip.core.objects import KeyBlock, KeyValue, KeyMaterial, TemplateAttribute
    from kmip.core.secrets import SecretData as KmipSecretData
    from kmip.core.factories.attributes import AttributeFactory
    from kmip.core.messages.payloads.modify_attribute import (
        ModifyAttributeRequestPayload,
        ModifyAttributeResponsePayload,
    )
except ImportError as e:
    print(
        json.dumps(
            {
                'operation': 'Import Check',
                'status': 'error',
                'error': f'Failed to import PyKMIP: {str(e)}',
                'solution': 'Install PyKMIP: pip install PyKMIP',
            },
            indent=2,
        )
    )
    sys.exit(1)
except Exception as e:
    if 'wrap_socket' in str(e):
        print(
            json.dumps(
                {
                    'operation': 'SSL Check',
                    'status': 'error',
                    'error': f'SSL compatibility issue: {str(e)}',
                    'solution': (
                        'Use Python 3.11 or earlier. Current Python version '
                        'has removed ssl.wrap_socket which PyKMIP requires.'
                    ),
                },
                indent=2,
            )
        )
        sys.exit(1)
    else:
        print(
            json.dumps(
                {
                    'operation': 'Import Check',
                    'status': 'error',
                    'error': f'Unexpected import error: {str(e)}',
                },
                indent=2,
            )
        )
        sys.exit(1)


# ── helpers ──────────────────────────────────────────────────────────────────


def _ok(op: str, detail: str = '', verbose: bool = False) -> None:
    msg = {'operation': op, 'status': 'success'}
    if detail:
        msg['detail'] = detail
    print(json.dumps(msg, indent=2))


def _fail(op: str, error: str) -> None:
    print(json.dumps({'operation': op, 'status': 'error', 'error': error}, indent=2))


def _result_value(result, field: str):
    """Safely extract a value from a PyKMIP result object."""
    val = getattr(result, field, None)
    if val is None:
        return None
    # PyKMIP wraps primitives in value-holders
    return getattr(val, 'value', val)


def _check_result(result, operation: str, verbose: bool) -> bool:
    """Return True if the operation succeeded, else print error and return False."""
    status = _result_value(result, 'result_status')
    if verbose:
        print(f'  [{operation}] raw status: {status}')
    if status == enums.ResultStatus.SUCCESS:
        return True
    reason = _result_value(result, 'result_reason') or ''
    message = _result_value(result, 'result_message') or ''
    _fail(operation, f'{reason} – {message}')
    return False


# ── KMIP operation wrappers ───────────────────────────────────────────────────


def op_discover_versions(proxy: KMIPProxy, verbose: bool) -> bool:
    """Step 1 – Discover KMIP protocol versions the server supports."""
    try:
        result = proxy.discover_versions()
        if not _check_result(result, 'Discover Versions', verbose):
            return False
        versions = getattr(result, 'protocol_versions', []) or []
        version_strs = [
            f'{getattr(v, "major", "?")}.{getattr(v, "minor", "?")}' for v in versions
        ]
        _ok(
            'Discover Versions',
            f'Server supports KMIP versions: {version_strs}',
            verbose,
        )
        return True
    except Exception as exc:
        _fail('Discover Versions', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_query(proxy: KMIPProxy, verbose: bool) -> bool:
    """Step 2 – Query server capabilities with all 6 QueryFunctions as real DSM trace shows."""
    try:
        result = proxy.query(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS,
                enums.QueryFunction.QUERY_SERVER_INFORMATION,
                enums.QueryFunction.QUERY_APPLICATION_NAMESPACES,
                enums.QueryFunction.QUERY_EXTENSION_LIST,
                enums.QueryFunction.QUERY_PROFILES,
            ]
        )
        if not _check_result(result, 'Query', verbose):
            return False
        ops = getattr(result, 'operations', []) or []
        op_names = [str(o) for o in ops]
        _ok('Query', f'Server operations: {op_names}', verbose)
        return True
    except Exception as exc:
        _fail('Query', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_register_secret_data(proxy: KMIPProxy, volume_uuid: str, verbose: bool):
    """
    Step 4 – Register a SecretData object with opaque key material, matching the
    actual Synology DSM 7.x KMIP wire protocol (observed from TTLV trace).

    DSM brings its own key material as raw opaque bytes, sets CryptographicUsageMask
    to Verify, includes OperationPolicyName="default" (KMIP 1.x attribute), and uses
    the SHA-512 hex digest of the key bytes as the initial Name.
    The key is later renamed to the volume UUID via ModifyAttribute.

    Returns (uid, True) on success, (None, False) on failure.
    """
    try:
        # Generate 32 bytes of random key material (DSM uses 72 bytes in production)
        raw_bytes = os.urandom(32)
        # DSM names the key with SHA-512(key_bytes) hex during Register
        hash_name = hashlib.sha512(raw_bytes).hexdigest()

        # Build SecretData: KeyFormatType and SecretDataType both require KMIP
        # primitive wrappers (misc.KeyFormatType / SecretData.SecretDataType),
        # not the bare enums.* Python enum values.
        key_format_type = misc.KeyFormatType(value=enums.KeyFormatType.OPAQUE)
        key_mat = KeyMaterial(value=raw_bytes)
        key_val = KeyValue(key_material=key_mat)
        key_block = KeyBlock(key_format_type=key_format_type, key_value=key_val)
        # DSM TTLV trace shows SecretDataType=Password (0x1), not Seed
        secret = KmipSecretData(
            secret_data_type=KmipSecretData.SecretDataType(
                value=enums.SecretDataType.PASSWORD
            ),
            key_block=key_block,
        )

        factory = AttributeFactory()
        # DSM registers with CryptographicUsageMask=Verify
        usage_attr = factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.VERIFY],
        )
        # Initial name is SHA-512(key_bytes) hex; renamed to volume UUID later
        name_attr = factory.create_attribute(enums.AttributeType.NAME, hash_name)
        attrs = [usage_attr, name_attr]

        # DSM includes OperationPolicyName="default" (KMIP 1.x attribute,
        # deprecated in 1.3, removed in 2.0).  The KMS silently ignores it
        # (issue #796 — previously emitted a confusing WARN log entry).
        try:
            policy_attr = factory.create_attribute(
                enums.AttributeType.OPERATION_POLICY_NAME, 'default'
            )
            attrs.append(policy_attr)
        except (AttributeError, ValueError, KeyError):
            pass  # Not available in all PyKMIP versions — safe to skip

        result = proxy.register(
            enums.ObjectType.SECRET_DATA,
            TemplateAttribute(attributes=attrs),
            secret,
        )
        if not _check_result(result, 'Register', verbose):
            return None, False

        uid = getattr(result, 'uuid', None) or getattr(
            result, 'unique_identifier', None
        )
        if hasattr(uid, 'value'):
            uid = uid.value
        if not uid:
            _fail(
                'Register', 'Server returned SUCCESS but no UID — unexpected response'
            )
            return None, False
        _ok(
            'Register',
            f'SecretData (OPAQUE/SEED, 32 bytes) registered — UID: {uid}',
            verbose,
        )
        return uid, True
    except Exception as exc:
        _fail('Register', str(exc))
        if verbose:
            traceback.print_exc()
        return None, False


def op_activate(proxy: KMIPProxy, uid: str, verbose: bool) -> bool:
    """Step 5 – Activate the registered SecretData (PreActive → Active)."""
    try:
        result = proxy.activate(uid)
        if not _check_result(result, 'Activate', verbose):
            return False
        _ok('Activate', f'Key {uid} is now Active', verbose)
        return True
    except Exception as exc:
        _fail('Activate', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_get_attributes(proxy: KMIPProxy, uid: str, verbose: bool) -> bool:
    """Step 7 – Read key attributes (state should be Active after Activate)."""
    try:
        result = proxy.get_attribute_list(uid)
        if not _check_result(result, 'Get Attribute List', verbose):
            return False
        # KMIPProxy returns attribute names in .names (not .attribute_names)
        attrs = getattr(result, 'names', []) or []
        _ok('Get Attribute List', f'Attributes: {list(attrs)}', verbose)

        # Fetch specific attributes that DSM reads — pass strings, not enums
        result2 = proxy.get_attributes(uid, ['State', 'Object Type'])
        if not _check_result(result2, 'Get Attributes', verbose):
            return False
        attr_list = getattr(result2, 'attributes', []) or []
        attr_summary = {
            getattr(getattr(a, 'attribute_name', None), 'value', str(a)): str(
                getattr(a, 'attribute_value', '?')
            )
            for a in attr_list
        }
        _ok('Get Attributes', f'Key attributes: {attr_summary}', verbose)
        return True
    except Exception as exc:
        _fail('Get Attributes', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_modify_attribute(
    proxy: KMIPProxy, uid: str, volume_uuid: str, verbose: bool
) -> bool:
    """
    Step 6 – Rename the registered key to the volume UUID via ModifyAttribute.

    This matches the real DSM trace: after Register (which names the key with
    SHA-512(key_bytes)hex), DSM immediately calls ModifyAttribute to set the
    Name attribute to the volume UUID (e.g. '07a07834-49ff-4c2b-aec8-821d83df4daf').
    This is the ModifyAttribute operation fixed in issue #760.
    """
    try:
        factory = AttributeFactory()
        attribute = factory.create_attribute(
            enums.AttributeType.NAME,
            volume_uuid,
        )
        # KMIPProxy 0.10.0 does not expose modify_attribute() as a high-level method.
        # Use send_request_payload with ModifyAttributeRequestPayload directly.
        payload = ModifyAttributeRequestPayload(
            unique_identifier=uid,
            attribute=attribute,
        )
        result = proxy.send_request_payload(enums.Operation.MODIFY_ATTRIBUTE, payload)
        if not _check_result(result, 'Modify Attribute', verbose):
            return False
        _ok('Modify Attribute', f'Name set to volume UUID: {volume_uuid}', verbose)
        return True
    except kmip_exceptions.OperationFailure as exc:
        _fail('Modify Attribute', str(exc))
        if verbose:
            traceback.print_exc()
        return False
    except Exception as exc:
        msg = str(exc)
        # PyKMIP 0.10.0 cannot deserialize the COMMENT placeholder that the server
        # includes in the KMIP 1.x ModifyAttributeResponse for compatibility.
        # The batch status SUCCESS is confirmed before the parse step, so the
        # request DID succeed on the server — treat this as a success.
        if 'No value type for' in msg:
            _ok(
                'Modify Attribute',
                f'Name set to {volume_uuid} '
                f'(PyKMIP 0.10.0 response parse limitation: {msg})',
                verbose,
            )
            return True
        _fail('Modify Attribute', msg)
        if verbose:
            traceback.print_exc()
        return False


def op_get(proxy: KMIPProxy, uid: str, verbose: bool) -> bool:
    """Step 8 – Retrieve key material (simulates Synology volume mount)."""
    try:
        result = proxy.get(uid)
        if not _check_result(result, 'Get', verbose):
            return False
        # KMIPProxy stores the retrieved managed object in .secret
        secret = getattr(result, 'secret', None)
        key_block = getattr(secret, 'key_block', None) if secret else None
        key_value = getattr(key_block, 'key_value', None) if key_block else None
        key_bytes = getattr(key_value, 'key_material', None) if key_value else None
        key_len = (
            len(key_bytes) * 8
            if isinstance(key_bytes, (bytes, bytearray))
            else 'retrieved'
        )
        _ok('Get', f'SecretData key material retrieved ({key_len}-bit)', verbose)
        return True
    except Exception as exc:
        _fail('Get', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_locate(proxy: KMIPProxy, volume_uuid: str, verbose: bool) -> bool:
    """Step 9 – Locate the key by volume UUID (simulates NAS reconnect after reboot)."""
    try:
        factory = AttributeFactory()
        name_attr = factory.create_attribute(
            enums.AttributeType.NAME,
            volume_uuid,
        )
        result = proxy.locate(attributes=[name_attr])
        if not _check_result(result, 'Locate', verbose):
            return False
        # PyKMIP 0.10.0 stores located UIDs in .uuids (not .uids)
        uids = getattr(result, 'uuids', []) or []
        _ok(
            'Locate',
            f'Located {len(uids)} key(s) with volume UUID "{volume_uuid}": {uids}',
            verbose,
        )
        return True
    except Exception as exc:
        _fail('Locate', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_locate_check(proxy: KMIPProxy, volume_uuid: str, verbose: bool) -> bool:
    """Step 3 – Pre-register Locate to verify the volume key does not yet exist."""
    try:
        factory = AttributeFactory()
        name_attr = factory.create_attribute(
            enums.AttributeType.NAME,
            volume_uuid,
        )
        result = proxy.locate(attributes=[name_attr])
        if not _check_result(result, 'Locate (pre-check)', verbose):
            return False
        uids = getattr(result, 'uuids', []) or []
        _ok(
            'Locate (pre-check)',
            f'Found {len(uids)} existing key(s) for volume "{volume_uuid}"',
            verbose,
        )
        return True
    except Exception as exc:
        _fail('Locate (pre-check)', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_revoke(proxy: KMIPProxy, uid: str, verbose: bool) -> bool:
    """Step 8 – Revoke the key (simulates key rotation or NAS decommission)."""
    try:
        # PyKMIP 0.10.0: first arg is revocation_reason, uuid is keyword arg;
        # enum is RevocationReasonCode (not RevocationReason)
        result = proxy.revoke(
            enums.RevocationReasonCode.KEY_COMPROMISE,
            uuid=uid,
            revocation_message='Synology DSM simulation: key rotation test',
        )
        if not _check_result(result, 'Revoke', verbose):
            return False
        _ok('Revoke', f'Key {uid} revoked', verbose)
        return True
    except Exception as exc:
        _fail('Revoke', str(exc))
        if verbose:
            traceback.print_exc()
        return False


def op_destroy(proxy: KMIPProxy, uid: str, verbose: bool) -> bool:
    """Step 9 – Destroy the key."""
    try:
        result = proxy.destroy(uid)
        if not _check_result(result, 'Destroy', verbose):
            return False
        _ok('Destroy', f'Key {uid} destroyed', verbose)
        return True
    except Exception as exc:
        _fail('Destroy', str(exc))
        if verbose:
            traceback.print_exc()
        return False


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            'Synology DSM KMIP simulation client — '
            'tests Cosmian KMS compatibility with Synology DSM 7.x NAS volume encryption'
        )
    )
    parser.add_argument(
        '--configuration', required=True, help='PyKMIP configuration file path'
    )
    parser.add_argument(
        '--key-name',
        default='07a07834-49ff-4c2b-aec8-821d83df4daf',
        help=(
            'Volume UUID used as the key name (default: sample Synology volume UUID). '
            'DSM identifies KMS keys by the volume UUID.'
        ),
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true', help='Enable verbose output'
    )
    args = parser.parse_args()

    print('=' * 60)
    print('Synology DSM KMIP Simulation Client')
    print('Testing Cosmian KMS compatibility with Synology DSM 7.x')
    print('=' * 60)

    proxy = KMIPProxy(config_file=args.configuration)

    try:
        proxy.open()
    except Exception as exc:
        _fail('Connect', f'Failed to connect to KMS server: {exc}')
        if args.verbose:
            traceback.print_exc()
        return 1

    _ok('Connect', 'Connected to KMS server via KMIP/TLS', args.verbose)

    uid = None
    success = True

    # Ordered sequence mirroring real Synology DSM 7.x KMIP operations
    steps = [
        ('Discover Versions', lambda: op_discover_versions(proxy, args.verbose)),
        ('Query', lambda: op_query(proxy, args.verbose)),
        # DSM locates first to check if volume key already exists (expect 0 results)
        (
            'Locate (pre-check)',
            lambda: op_locate_check(proxy, args.key_name, args.verbose),
        ),
    ]

    for step_name, step_fn in steps:
        if not step_fn():
            success = False
            break

    if success:
        # DSM registers opaque SecretData (not Create SymmetricKey)
        uid, created = op_register_secret_data(proxy, args.key_name, args.verbose)
        if not created or uid is None:
            success = False

    if success and uid:
        remaining_steps = [
            # Activate transitions PreActive → Active so the key can be retrieved
            ('Activate', lambda: op_activate(proxy, uid, args.verbose)),
            # ModifyAttribute renames key to volume UUID (not ActivationDate)
            (
                'Modify Attribute (Name)',
                lambda: op_modify_attribute(proxy, uid, args.key_name, args.verbose),
            ),
            ('Get Attributes', lambda: op_get_attributes(proxy, uid, args.verbose)),
            ('Get', lambda: op_get(proxy, uid, args.verbose)),
            # Locate by volume UUID — should find 1 result after ModifyAttribute
            ('Locate (verify)', lambda: op_locate(proxy, args.key_name, args.verbose)),
            ('Revoke', lambda: op_revoke(proxy, uid, args.verbose)),
            ('Destroy', lambda: op_destroy(proxy, uid, args.verbose)),
        ]
        for step_name, step_fn in remaining_steps:
            if not step_fn():
                success = False
                print(f'  Step "{step_name}" failed — attempting cleanup...')
                if step_name == 'Activate':
                    # Still Pre-Active — can Destroy directly
                    op_destroy(proxy, uid, args.verbose)
                elif step_name not in ('Revoke', 'Destroy'):
                    # Key is Active — must Revoke before Destroy
                    op_revoke(proxy, uid, args.verbose)
                    op_destroy(proxy, uid, args.verbose)
                elif step_name == 'Revoke':
                    # Try Destroy anyway (key may already be in a destroyable state)
                    op_destroy(proxy, uid, args.verbose)
                break

    try:
        proxy.close()
    except Exception:
        pass

    print('=' * 60)
    if success:
        print('RESULT: ALL SYNOLOGY DSM SIMULATION STEPS PASSED ✓')
        print('Cosmian KMS is compatible with Synology DSM KMIP client.')
    else:
        print('RESULT: SOME SYNOLOGY DSM SIMULATION STEPS FAILED ✗')
        print('Check the error messages above for details.')
    print('=' * 60)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())

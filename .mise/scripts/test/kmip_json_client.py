#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure-stdlib KMIP 2.1 JSON client and TTLV request builders for upgrade testing."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_ACTIVATION_DATE = '2024-01-01T00:00:00Z'
FUTURE_ACTIVATION_DATE = '2099-01-01T00:00:00Z'


class KmipRequestError(Exception):
    """Structured error raised when a KMIP or REST call to the KMS server fails."""

    def __init__(
        self,
        *,
        operation: str,
        uid: str | None,
        http_status: int | None,
        result_status: str | None = None,
        result_reason: str | None = None,
        server_message: str = '',
    ) -> None:
        self.operation = operation
        self.uid = uid
        self.http_status = http_status
        self.result_status = result_status
        self.result_reason = result_reason
        self.server_message = server_message.strip()
        target = f' uid={uid}' if uid else ''
        status_part = f'http={http_status}' if http_status is not None else 'http=N/A'
        reason_part = f' reason={result_reason}' if result_reason else ''
        super().__init__(
            f'{operation}{target} failed ({status_part}{reason_part}): {self.server_message}'
        )


def is_unsupported_feature_error(error: KmipRequestError) -> bool:
    """Return True only when an older 5.x server rejects an optional feature as unsupported.

    Kept in one place so the skip-vs-fail boundary is auditable.
    """
    if error.http_status not in (400, 422, 500, 501):
        return False
    msg = error.server_message.lower()
    reason = (error.result_reason or '').lower()
    unsupported_markers = (
        'unknown variant',
        'not supported',
        'unsupported',
        'operation not supported',
        'cryptographic algorithm not supported',
        'invalid field',
        'invalid enumeration',
        'unknown enumeration',
        'feature is not enabled',
        'not implemented',
    )
    if any(marker in msg for marker in unsupported_markers):
        return True
    return reason in {
        'operationnotsupported',
        'cryptographicalgorithmnotsupported',
        'featurenotenabled',
    }


def make_mtls_context(
    ca_cert: str | Path,
    client_cert: str | Path,
    client_key: str | Path,
) -> ssl.SSLContext:
    """Create a TLS context that verifies the server certificate against `ca_cert` and presents client mTLS credentials."""
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    # test_data/certificates/client_server/server/kmserver.acme.com.crt carries CN=kmserver.acme.com
    # without a SubjectAltName extension; signature chain validation against ca.crt remains enforced.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


class KmipClient:
    """HTTP/HTTPS client for KMS `/kmip/2_1`, `/version`, and `/access/*` endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        ssl_context: ssl.SSLContext | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = base_url.rstrip('/')
        self.ssl_context = ssl_context
        self.headers = dict(headers) if headers else {}
        self.timeout = timeout

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        operation: str,
        uid: str | None = None,
    ) -> Any:
        url = f'{self.base_url}{path}'
        req_headers = dict(self.headers)
        data: bytes | None = None
        if payload is not None:
            req_headers['Content-Type'] = 'application/json'
            data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(
                req, context=self.ssl_context, timeout=self.timeout
            ) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
                if not raw.strip():
                    return {}
                try:
                    return json.loads(raw)
                except ValueError as exc:
                    raise KmipRequestError(
                        operation=operation,
                        uid=uid,
                        http_status=resp.status,
                        server_message=f'Invalid JSON response: {raw[:200]}',
                    ) from exc
        except urllib.error.HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')
            result_status, result_reason = _parse_kmip_error_fields(body)
            raise KmipRequestError(
                operation=operation,
                uid=uid,
                http_status=exc.code,
                result_status=result_status,
                result_reason=result_reason,
                server_message=body or str(exc.reason),
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, 'reason', exc)
            raise KmipRequestError(
                operation=operation,
                uid=uid,
                http_status=None,
                server_message=str(reason),
            ) from exc

    def get_version(self) -> str:
        """Query `GET /version` and return the normalized version string (e.g. `5.29.0`)."""
        raw = self._request_json('GET', '/version', operation='GET /version')
        text = str(raw).strip().strip('"')
        return text.split()[0] if text else 'unknown'

    def kmip(
        self, payload: dict[str, Any], *, uid: str | None = None
    ) -> dict[str, Any]:
        """Send a KMIP 2.1 JSON request to `POST /kmip/2_1`."""
        op = str(payload.get('tag', 'KMIP'))
        inferred_uid = uid or find_tag_value(payload, 'UniqueIdentifier')
        result = self._request_json(
            'POST',
            '/kmip/2_1',
            payload=payload,
            operation=op,
            uid=str(inferred_uid) if inferred_uid is not None else None,
        )
        if not isinstance(result, dict):
            raise KmipRequestError(
                operation=op,
                uid=uid,
                http_status=200,
                server_message=f'Expected JSON object from /kmip/2_1, got {type(result).__name__}',
            )
        if result.get('tag') == 'Error':
            reason = find_tag_value(result, 'ResultReason')
            message = find_tag_value(result, 'ResultMessage') or json.dumps(result)
            raise KmipRequestError(
                operation=op,
                uid=uid,
                http_status=200,
                result_status='OperationFailed',
                result_reason=str(reason) if reason else None,
                server_message=str(message),
            )
        return result

    def grant_access(
        self, uid: str, user_id: str, operations: list[str]
    ) -> dict[str, Any]:
        """Grant `operations` on `uid` to `user_id` via `POST /access/grant`."""
        payload = {
            'unique_identifier': uid,
            'user_id': user_id,
            'operation_types': operations,
        }
        res = self._request_json(
            'POST',
            '/access/grant',
            payload=payload,
            operation='GrantAccess',
            uid=uid,
        )
        return res if isinstance(res, dict) else {}

    def list_access(self, uid: str) -> list[dict[str, Any]]:
        """Return the access list for `uid` via `GET /access/list/{object_id}`."""
        encoded = urllib.parse.quote(uid, safe='')
        res = self._request_json(
            'GET',
            f'/access/list/{encoded}',
            operation='ListAccess',
            uid=uid,
        )
        if not isinstance(res, list):
            raise KmipRequestError(
                operation='ListAccess',
                uid=uid,
                http_status=200,
                server_message=f'Expected list from /access/list/{uid}, got {res!r}',
            )
        return res


def _parse_kmip_error_fields(body: str) -> tuple[str | None, str | None]:
    try:
        parsed = json.loads(body)
    except ValueError:
        return None, None
    status = find_tag_value(parsed, 'ResultStatus')
    reason = find_tag_value(parsed, 'ResultReason')
    return (
        str(status) if status is not None else None,
        str(reason) if reason is not None else None,
    )


def find_tag_value(node: Any, tag_name: str) -> Any:
    """Return the first scalar `value` of a TTLV item matching `tag_name`."""
    if isinstance(node, dict):
        if node.get('tag') == tag_name and 'value' in node:
            val = node['value']
            if not isinstance(val, (dict, list)):
                return val
        for child in node.values():
            found = find_tag_value(child, tag_name)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = find_tag_value(item, tag_name)
            if found is not None:
                return found
    return None


def find_all_tag_values(node: Any, tag_name: str) -> list[str]:
    """Return all scalar values of TTLV items matching `tag_name`."""
    results: list[str] = []
    _collect_tag_values(node, tag_name, results)
    return results


def _collect_tag_values(node: Any, tag_name: str, out: list[str]) -> None:
    if isinstance(node, dict):
        if node.get('tag') == tag_name and 'value' in node:
            val = node['value']
            if not isinstance(val, (dict, list)):
                out.append(str(val))
        for child in node.values():
            _collect_tag_values(child, tag_name, out)
    elif isinstance(node, list):
        for item in node:
            _collect_tag_values(item, tag_name, out)


def extract_all_tags(node: Any) -> list[str]:
    """Extract all sorted tags (including `_`-prefixed system tags) from a `GetAttributes` response."""
    tags: set[str] = set()
    _walk_vendor_tags(node, tags)
    return sorted(tags)


def extract_user_tags(node: Any) -> list[str]:
    """Extract sorted non-system tags (`not tag.startswith('_')`) from a `GetAttributes` response."""
    return [t for t in extract_all_tags(node) if not t.startswith('_')]


def _walk_vendor_tags(node: Any, out: set[str]) -> None:
    if isinstance(node, dict):
        if node.get('tag') == 'Attribute' and isinstance(node.get('value'), list):
            vendor = find_tag_value(node['value'], 'VendorIdentification')
            name = find_tag_value(node['value'], 'AttributeName')
            raw_val = find_tag_value(node['value'], 'AttributeValue')
            if vendor == 'cosmian' and name == 'tag' and isinstance(raw_val, str):
                try:
                    parsed = json.loads(raw_val)
                    if isinstance(parsed, list):
                        out.update(str(item) for item in parsed)
                except ValueError:
                    pass
        for child in node.values():
            _walk_vendor_tags(child, out)
    elif isinstance(node, list):
        for item in node:
            _walk_vendor_tags(item, out)


def tag_attribute(tags: list[str]) -> dict[str, Any]:
    """Build the Cosmian vendor `tag` attribute TTLV structure."""
    return vendor_attribute('tag', json.dumps(tags), value_type='TextString')


def vendor_attribute(
    name: str,
    value: str,
    *,
    value_type: str = 'TextString',
    vendor_id: str = 'cosmian',
) -> dict[str, Any]:
    """Build a KMIP 2.1 Vendor `Attribute` TTLV structure."""
    return {
        'tag': 'Attribute',
        'value': [
            {'tag': 'VendorIdentification', 'type': 'TextString', 'value': vendor_id},
            {'tag': 'AttributeName', 'type': 'TextString', 'value': name},
            {'tag': 'AttributeValue', 'type': value_type, 'value': value},
        ],
    }


def name_attribute(name_value: str) -> dict[str, Any]:
    """Build a KMIP 2.1 `Name` attribute structure."""
    return {
        'tag': 'Name',
        'value': [
            {'tag': 'NameValue', 'type': 'TextString', 'value': name_value},
            {
                'tag': 'NameType',
                'type': 'Enumeration',
                'value': 'UninterpretedTextString',
            },
        ],
    }


def link_attribute(link_type: str, linked_uid: str) -> dict[str, Any]:
    """Build a KMIP 2.1 `Link` attribute structure."""
    return {
        'tag': 'Link',
        'value': [
            {'tag': 'LinkType', 'type': 'Enumeration', 'value': link_type},
            {
                'tag': 'LinkedObjectIdentifier',
                'type': 'TextString',
                'value': linked_uid,
            },
        ],
    }


def build_create_symmetric_key(
    uid: str,
    *,
    algorithm: str = 'AES',
    length: int = 256,
    usage_mask: int = 2108,
    tags: list[str] | None = None,
    activation_date: str | None = DEFAULT_ACTIVATION_DATE,
    wrapping_key_uid: str | None = None,
    name: str | None = None,
    extra_attributes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a KMIP `Create` request for a `SymmetricKey`."""
    attrs: list[dict[str, Any]] = [
        {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
        {'tag': 'CryptographicAlgorithm', 'type': 'Enumeration', 'value': algorithm},
        {'tag': 'CryptographicLength', 'type': 'Integer', 'value': length},
        {'tag': 'CryptographicUsageMask', 'type': 'Integer', 'value': usage_mask},
        {
            'tag': 'KeyFormatType',
            'type': 'Enumeration',
            'value': 'TransparentSymmetricKey',
        },
        {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'SymmetricKey'},
    ]
    if activation_date is not None:
        attrs.append(
            {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date}
        )
    if name:
        attrs.append(name_attribute(name))
    if extra_attributes:
        attrs.extend(a for a in extra_attributes if a.get('tag') != 'Attribute')
    if tags:
        attrs.append(tag_attribute(tags))
    if wrapping_key_uid:
        attrs.append(vendor_attribute('wrapping_key_id', wrapping_key_uid))
    if extra_attributes:
        attrs.extend(a for a in extra_attributes if a.get('tag') == 'Attribute')
    return {
        'tag': 'Create',
        'value': [
            {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'SymmetricKey'},
            {'tag': 'Attributes', 'value': attrs},
        ],
    }


def build_create_key_pair(
    sk_uid: str,
    *,
    algorithm: str,
    length: int | None = None,
    curve: str | None = None,
    key_format_type: str | None = None,
    usage_mask: int = 12,
    private_usage_mask: int | None = None,
    public_usage_mask: int | None = None,
    tags: list[str] | None = None,
    activation_date: str | None = DEFAULT_ACTIVATION_DATE,
    extra_common_attributes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a KMIP `CreateKeyPair` request for RSA, ECDSA, Ed25519, CoverCrypt, or ML-DSA."""
    sk_mask = private_usage_mask if private_usage_mask is not None else usage_mask
    pk_mask = public_usage_mask if public_usage_mask is not None else usage_mask
    common: list[dict[str, Any]] = [
        {'tag': 'CryptographicAlgorithm', 'type': 'Enumeration', 'value': algorithm},
        {'tag': 'CryptographicUsageMask', 'type': 'Integer', 'value': sk_mask},
    ]
    if length is not None:
        common.append(
            {'tag': 'CryptographicLength', 'type': 'Integer', 'value': length}
        )
    if curve is not None:
        common.append(
            {
                'tag': 'CryptographicDomainParameters',
                'value': [
                    {'tag': 'RecommendedCurve', 'type': 'Enumeration', 'value': curve}
                ],
            }
        )
    if key_format_type is not None:
        common.append(
            {'tag': 'KeyFormatType', 'type': 'Enumeration', 'value': key_format_type}
        )
    if activation_date is not None:
        common.append(
            {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date}
        )
    if extra_common_attributes:
        non_vendor = [a for a in extra_common_attributes if a.get('tag') != 'Attribute']
        vendor = [a for a in extra_common_attributes if a.get('tag') == 'Attribute']
        common.extend(non_vendor)
        if tags:
            common.append(tag_attribute(tags))
        common.extend(vendor)
    elif tags:
        common.append(tag_attribute(tags))

    priv_attrs: list[dict[str, Any]] = [
        {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': sk_uid},
        {'tag': 'CryptographicUsageMask', 'type': 'Integer', 'value': sk_mask},
    ]
    pub_attrs: list[dict[str, Any]] = [
        {'tag': 'CryptographicUsageMask', 'type': 'Integer', 'value': pk_mask},
    ]
    if activation_date is not None:
        priv_attrs.append(
            {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date}
        )
        pub_attrs.append(
            {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date}
        )
    if tags:
        priv_attrs.append(tag_attribute(tags))
        pub_attrs.append(tag_attribute(tags))
    return {
        'tag': 'CreateKeyPair',
        'value': [
            {'tag': 'CommonAttributes', 'value': common},
            {'tag': 'PrivateKeyAttributes', 'value': priv_attrs},
            {'tag': 'PublicKeyAttributes', 'value': pub_attrs},
        ],
    }


def build_rekey(uid: str) -> dict[str, Any]:
    """Build a KMIP `ReKey` request for a symmetric key."""
    return {
        'tag': 'ReKey',
        'value': [{'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}],
    }


def build_certify(
    public_key_uid: str,
    cert_uid: str,
    *,
    subject_cn: str,
    tags: list[str] | None = None,
    activation_date: str = DEFAULT_ACTIVATION_DATE,
) -> dict[str, Any]:
    """Build a KMIP `Certify` request creating a self-signed X.509 certificate for `public_key_uid`."""
    empty_dn_tags = (
        'CertificateSubjectOu',
        'CertificateSubjectEmail',
        'CertificateSubjectSt',
        'CertificateSubjectL',
        'CertificateSubjectUid',
        'CertificateSubjectSerialNumber',
        'CertificateSubjectTitle',
        'CertificateSubjectDc',
        'CertificateSubjectDnQualifier',
        'CertificateIssuerCn',
        'CertificateIssuerO',
        'CertificateIssuerOu',
        'CertificateIssuerEmail',
        'CertificateIssuerC',
        'CertificateIssuerSt',
        'CertificateIssuerL',
        'CertificateIssuerUid',
        'CertificateIssuerSerialNumber',
        'CertificateIssuerTitle',
        'CertificateIssuerDc',
        'CertificateIssuerDnQualifier',
    )
    cert_attrs = [
        {'tag': 'CertificateSubjectCn', 'type': 'TextString', 'value': subject_cn},
        {'tag': 'CertificateSubjectO', 'type': 'TextString', 'value': 'Cosmian'},
        {'tag': 'CertificateSubjectC', 'type': 'TextString', 'value': 'FR'},
        *[{'tag': tag, 'type': 'TextString', 'value': ''} for tag in empty_dn_tags],
    ]
    attrs: list[dict[str, Any]] = [
        {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': cert_uid},
        {'tag': 'CertificateType', 'type': 'Enumeration', 'value': 'X509'},
        {'tag': 'CertificateAttributes', 'value': cert_attrs},
        {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date},
    ]
    if tags:
        attrs.append(tag_attribute(tags))
    return {
        'tag': 'Certify',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': public_key_uid},
            {'tag': 'Attributes', 'value': attrs},
        ],
    }


def build_import_certificate(
    uid: str,
    der_hex: str,
    *,
    tags: list[str] | None = None,
    activation_date: str = DEFAULT_ACTIVATION_DATE,
) -> dict[str, Any]:
    """Build a KMIP `Import` request for an X.509 `Certificate`."""
    attrs: list[dict[str, Any]] = [
        {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'Certificate'},
        {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date},
    ]
    if tags:
        attrs.append(tag_attribute(tags))
    return {
        'tag': 'Import',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'Certificate'},
            {'tag': 'ReplaceExisting', 'type': 'Boolean', 'value': False},
            {'tag': 'Attributes', 'value': attrs},
            {
                'tag': 'Certificate',
                'value': [
                    {'tag': 'CertificateType', 'type': 'Enumeration', 'value': 'X509'},
                    {'tag': 'CertificateValue', 'type': 'ByteString', 'value': der_hex},
                ],
            },
        ],
    }


def build_import_secret_data(
    uid: str,
    hex_bytes: str,
    *,
    tags: list[str] | None = None,
    activation_date: str = DEFAULT_ACTIVATION_DATE,
) -> dict[str, Any]:
    """Build a KMIP `Import` request for `SecretData`."""
    attrs: list[dict[str, Any]] = [
        {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'SecretData'},
        {'tag': 'CryptographicUsageMask', 'type': 'Integer', 'value': 2},
        {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date},
    ]
    if tags:
        attrs.append(tag_attribute(tags))
    return {
        'tag': 'Import',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'SecretData'},
            {'tag': 'ReplaceExisting', 'type': 'Boolean', 'value': False},
            {'tag': 'Attributes', 'value': attrs},
            {
                'tag': 'SecretData',
                'value': [
                    {
                        'tag': 'SecretDataType',
                        'type': 'Enumeration',
                        'value': 'Password',
                    },
                    {
                        'tag': 'KeyBlock',
                        'value': [
                            {
                                'tag': 'KeyFormatType',
                                'type': 'Enumeration',
                                'value': 'Opaque',
                            },
                            {
                                'tag': 'KeyValue',
                                'value': [
                                    {
                                        'tag': 'KeyMaterial',
                                        'type': 'ByteString',
                                        'value': hex_bytes,
                                    }
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    }


def build_import_opaque_object(
    uid: str,
    hex_bytes: str,
    *,
    tags: list[str] | None = None,
    activation_date: str = DEFAULT_ACTIVATION_DATE,
) -> dict[str, Any]:
    """Build a KMIP `Import` request for an `OpaqueObject`."""
    attrs: list[dict[str, Any]] = [
        {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'OpaqueObject'},
        {'tag': 'ActivationDate', 'type': 'DateTime', 'value': activation_date},
    ]
    if tags:
        attrs.append(tag_attribute(tags))
    return {
        'tag': 'Import',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'OpaqueObject'},
            {'tag': 'ReplaceExisting', 'type': 'Boolean', 'value': False},
            {'tag': 'Attributes', 'value': attrs},
            {
                'tag': 'OpaqueObject',
                'value': [
                    {
                        'tag': 'OpaqueDataType',
                        'type': 'Enumeration',
                        'value': 'Unknown',
                    },
                    {
                        'tag': 'OpaqueDataValue',
                        'type': 'ByteString',
                        'value': hex_bytes,
                    },
                ],
            },
        ],
    }


def build_revoke(uid: str, reason_code: str = 'CessationOfOperation') -> dict[str, Any]:
    """Build a KMIP `Revoke` request (`KeyCompromise` transitions to `Compromised`, others to `Deactivated`)."""
    return {
        'tag': 'Revoke',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {
                'tag': 'RevocationReason',
                'value': [
                    {
                        'tag': 'RevocationReasonCode',
                        'type': 'Enumeration',
                        'value': reason_code,
                    }
                ],
            },
        ],
    }


def build_destroy(uid: str) -> dict[str, Any]:
    """Build a KMIP `Destroy` request."""
    return {
        'tag': 'Destroy',
        'value': [{'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}],
    }


def build_get(uid: str) -> dict[str, Any]:
    """Build a KMIP `Get` request."""
    return {
        'tag': 'Get',
        'value': [{'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}],
    }


def build_export(uid: str) -> dict[str, Any]:
    """Build a KMIP `Export` request."""
    return {
        'tag': 'Export',
        'value': [{'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}],
    }


def build_get_attributes(uid: str, *, include_tags: bool = False) -> dict[str, Any]:
    """Build a KMIP `GetAttributes` request (all attributes, or specifically the Cosmian `tag` attribute)."""
    val: list[dict[str, Any]] = [
        {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}
    ]
    if include_tags:
        val.append(
            {
                'tag': 'AttributeReference',
                'value': [
                    {
                        'tag': 'VendorIdentification',
                        'type': 'TextString',
                        'value': 'cosmian',
                    },
                    {'tag': 'AttributeName', 'type': 'TextString', 'value': 'tag'},
                ],
            }
        )
    return {'tag': 'GetAttributes', 'value': val}


def build_set_attribute(uid: str, attribute: dict[str, Any]) -> dict[str, Any]:
    """Build a KMIP `SetAttribute` request."""
    return {
        'tag': 'SetAttribute',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {'tag': 'NewAttribute', 'value': [attribute]},
        ],
    }


def build_locate_by_tag(tag: str, *, object_type: str | None = None) -> dict[str, Any]:
    """Build a KMIP `Locate` request filtering by a single Cosmian tag."""
    attrs: list[dict[str, Any]] = [tag_attribute([tag])]
    if object_type is not None:
        attrs.insert(
            0, {'tag': 'ObjectType', 'type': 'Enumeration', 'value': object_type}
        )
    return {
        'tag': 'Locate',
        'value': [{'tag': 'Attributes', 'value': attrs}],
    }


def build_encrypt(
    uid: str,
    data_hex: str,
    *,
    algorithm: str = 'AES',
    mode: str = 'GCM',
) -> dict[str, Any]:
    """Build a KMIP `Encrypt` request."""
    return {
        'tag': 'Encrypt',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {
                'tag': 'CryptographicParameters',
                'value': [
                    {'tag': 'BlockCipherMode', 'type': 'Enumeration', 'value': mode},
                    {
                        'tag': 'CryptographicAlgorithm',
                        'type': 'Enumeration',
                        'value': algorithm,
                    },
                ],
            },
            {'tag': 'Data', 'type': 'ByteString', 'value': data_hex},
        ],
    }


def build_decrypt(
    uid: str,
    ciphertext_hex: str,
    iv_hex: str,
    auth_tag_hex: str,
    *,
    algorithm: str = 'AES',
    mode: str = 'GCM',
) -> dict[str, Any]:
    """Build a KMIP `Decrypt` request."""
    return {
        'tag': 'Decrypt',
        'value': [
            {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid},
            {
                'tag': 'CryptographicParameters',
                'value': [
                    {'tag': 'BlockCipherMode', 'type': 'Enumeration', 'value': mode},
                    {
                        'tag': 'CryptographicAlgorithm',
                        'type': 'Enumeration',
                        'value': algorithm,
                    },
                ],
            },
            {'tag': 'Data', 'type': 'ByteString', 'value': ciphertext_hex},
            {'tag': 'IVCounterNonce', 'type': 'ByteString', 'value': iv_hex},
            {
                'tag': 'AuthenticatedEncryptionTag',
                'type': 'ByteString',
                'value': auth_tag_hex,
            },
        ],
    }


def build_sign(
    uid: str,
    data_hex: str,
    *,
    digital_signature_algorithm: str | None = None,
    hashing_algorithm: str | None = None,
) -> dict[str, Any]:
    """Build a KMIP `Sign` request."""
    val: list[dict[str, Any]] = [
        {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}
    ]
    params: list[dict[str, Any]] = []
    if digital_signature_algorithm is not None:
        params.append(
            {
                'tag': 'DigitalSignatureAlgorithm',
                'type': 'Enumeration',
                'value': digital_signature_algorithm,
            }
        )
    if hashing_algorithm is not None:
        params.append(
            {
                'tag': 'HashingAlgorithm',
                'type': 'Enumeration',
                'value': hashing_algorithm,
            }
        )
    if params:
        val.append({'tag': 'CryptographicParameters', 'value': params})
    val.append({'tag': 'Data', 'type': 'ByteString', 'value': data_hex})
    return {'tag': 'Sign', 'value': val}


def build_signature_verify(
    uid: str,
    data_hex: str,
    signature_hex: str,
    *,
    digital_signature_algorithm: str | None = None,
    hashing_algorithm: str | None = None,
) -> dict[str, Any]:
    """Build a KMIP `SignatureVerify` request."""
    val: list[dict[str, Any]] = [
        {'tag': 'UniqueIdentifier', 'type': 'TextString', 'value': uid}
    ]
    params: list[dict[str, Any]] = []
    if digital_signature_algorithm is not None:
        params.append(
            {
                'tag': 'DigitalSignatureAlgorithm',
                'type': 'Enumeration',
                'value': digital_signature_algorithm,
            }
        )
    if hashing_algorithm is not None:
        params.append(
            {
                'tag': 'HashingAlgorithm',
                'type': 'Enumeration',
                'value': hashing_algorithm,
            }
        )
    if params:
        val.append({'tag': 'CryptographicParameters', 'value': params})
    val.extend(
        [
            {'tag': 'Data', 'type': 'ByteString', 'value': data_hex},
            {'tag': 'SignatureData', 'type': 'ByteString', 'value': signature_hex},
        ]
    )
    return {'tag': 'SignatureVerify', 'value': val}

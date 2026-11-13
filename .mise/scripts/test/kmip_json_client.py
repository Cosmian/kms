#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small stdlib KMIP JSON transport and payload helpers for the upgrade gate."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

JSON = dict[str, Any]
DEFAULT_ACTIVATION_DATE = '2024-01-01T00:00:00Z'
FUTURE_ACTIVATION_DATE = '2099-01-01T00:00:00Z'
SIGN, VERIFY, ENCRYPT, DECRYPT, WRAP, UNWRAP = 1, 2, 4, 8, 16, 32
AES_USAGE_MASK = ENCRYPT | DECRYPT | WRAP | UNWRAP | 0x800
# Keep the mask used by the historical Covercrypt images in the gate.
COVERCRYPT_USAGE_MASK = 4194304


class KmipRequestError(Exception):
    """A transport or KMIP failure, with enough context to replay the operation."""

    def __init__(
        self,
        *,
        operation: str,
        uid: str | None = None,
        http_status: int | None = None,
        result_reason: str | None = None,
        server_message: str = '',
    ) -> None:
        self.operation, self.uid = operation, uid
        self.http_status, self.result_reason = http_status, result_reason
        self.server_message = server_message
        super().__init__(
            f'{operation} uid={uid} http={http_status} reason={result_reason}: '
            f'{server_message}'
        )


def walk(node: Any, *, exclude: tuple[str, ...] = ()) -> Iterator[JSON]:
    """Walk TTLV structures without flattening their scalar values."""
    if isinstance(node, dict):
        if node.get('tag') not in exclude:
            yield node
            for child in node.values():
                yield from walk(child, exclude=exclude)
    elif isinstance(node, list):
        for child in node:
            yield from walk(child, exclude=exclude)


def find_all_tag_values(node: Any, tag: str) -> list[str]:
    return [
        str(item['value'])
        for item in walk(node)
        if item.get('tag') == tag
        and 'value' in item
        and not isinstance(item['value'], (dict, list))
    ]


def find_tag_value(node: Any, tag: str) -> str | None:
    return next(iter(find_all_tag_values(node, tag)), None)


def required_value(node: Any, tag: str) -> str:
    value = find_tag_value(node, tag)
    if value is None or not value:
        raise KmipRequestError(
            operation='DecodeResponse', server_message=f'Missing {tag} in response'
        )
    return value


def extract_all_tags(node: Any) -> list[str]:
    tags: set[str] = set()
    for item in walk(node):
        if (
            item.get('tag') != 'Attribute'
            or find_tag_value(item, 'VendorIdentification') != 'cosmian'
            or find_tag_value(item, 'AttributeName') != 'tag'
        ):
            continue
        try:
            values = json.loads(required_value(item, 'AttributeValue'))
        except ValueError as error:
            raise KmipRequestError(
                operation='GetAttributes', server_message='Malformed vendor tag JSON'
            ) from error
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise KmipRequestError(
                operation='GetAttributes',
                server_message='Expected a list of string tags',
            )
        tags.update(values)
    return sorted(tags)


def is_unsupported_feature_error(error: KmipRequestError) -> bool:
    if error.http_status not in (400, 422, 501):
        return False
    return (error.result_reason or '').lower() in (
        'operationnotsupported',
        'cryptographicalgorithmnotsupported',
        'featurenotenabled',
    ) or any(
        marker in error.server_message.lower()
        for marker in (
            'unknown variant',
            'not supported',
            'unsupported',
            'feature is not enabled',
        )
    )


def make_mtls_context(
    ca_cert: str | Path, client_cert: str | Path, client_key: str | Path
) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_cert))
    # The loopback test server's certificate has no IP SAN; still verify its CA chain.
    context.check_hostname = False
    context.load_cert_chain(str(client_cert), str(client_key))
    return context


class KmipClient:
    """Send raw TTLV JSON to either the old or candidate server, independently of Rust."""

    def __init__(
        self, base_url: str, *, ssl_context: ssl.SSLContext | None = None
    ) -> None:
        self.base_url, self.ssl_context = base_url.rstrip('/'), ssl_context

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        uid: str | None = None,
        payload: JSON | None = None,
    ) -> Any:
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(
                request, context=self.ssl_context, timeout=20
            ) as response:
                try:
                    return json.load(response)
                except ValueError as error:
                    raise KmipRequestError(
                        operation=operation,
                        uid=uid,
                        http_status=response.status,
                        server_message='Empty or invalid JSON response',
                    ) from error
        except urllib.error.HTTPError as error:
            body = error.read().decode('utf-8', errors='replace')
            reason = None
            try:
                reason = find_tag_value(json.loads(body), 'ResultReason')
            except ValueError:
                pass  # Non-JSON HTTP failures are still reported with their body below.
            raise KmipRequestError(
                operation=operation,
                uid=uid,
                http_status=error.code,
                result_reason=reason,
                server_message=body,
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise KmipRequestError(
                operation=operation,
                uid=uid,
                server_message=str(error),
            ) from error

    def kmip(self, payload: JSON, *, uid: str | None = None) -> JSON:
        operation = payload['tag']
        uid = uid or find_tag_value(payload, 'UniqueIdentifier')
        response = self._request_json(
            'POST',
            '/kmip/2_1',
            operation=operation,
            uid=uid,
            payload=payload,
        )
        if not isinstance(response, dict) or response.get('tag') == 'Error':
            raise KmipRequestError(
                operation=operation,
                uid=uid,
                http_status=200,
                result_reason=find_tag_value(response, 'ResultReason'),
                server_message=find_tag_value(response, 'ResultMessage')
                or 'Invalid KMIP response',
            )
        return response

    def grant_access(self, uid: str, user_id: str, operations: list[str]) -> None:
        response = self._request_json(
            'POST',
            '/access/grant',
            operation='GrantAccess',
            uid=uid,
            payload={
                'unique_identifier': uid,
                'user_id': user_id,
                'operation_types': operations,
            },
        )
        if not isinstance(response, dict):
            raise KmipRequestError(
                operation='GrantAccess',
                uid=uid,
                server_message='Invalid access response',
            )

    def list_access(self, uid: str) -> list[JSON]:
        response = self._request_json(
            'GET',
            '/access/list/' + urllib.parse.quote(uid, safe=''),
            operation='ListAccess',
            uid=uid,
        )
        if not isinstance(response, list) or not all(
            isinstance(entry, dict) and 'user_id' in entry and 'operations' in entry
            for entry in response
        ):
            raise KmipRequestError(
                operation='ListAccess', uid=uid, server_message='Invalid access list'
            )
        return response


def ttlv(tag: str, value: Any, kind: str | None = None) -> JSON:
    # Older servers deserialize value using the preceding type field.
    return {'tag': tag, **({'type': kind} if kind else {}), 'value': value}


def request(operation: str, uid: str | None = None, *fields: JSON) -> JSON:
    return ttlv(
        operation,
        ([ttlv('UniqueIdentifier', uid, 'TextString')] if uid else []) + list(fields),
    )


def vendor_attribute(name: str, value: str, kind: str = 'TextString') -> JSON:
    return ttlv(
        'Attribute',
        [
            ttlv('VendorIdentification', 'cosmian', 'TextString'),
            ttlv('AttributeName', name, 'TextString'),
            ttlv('AttributeValue', value, kind),
        ],
    )


def tag_attribute(tags: list[str]) -> JSON:
    return vendor_attribute('tag', json.dumps(tags))


def name_attribute(name: str) -> JSON:
    return ttlv(
        'Name',
        [
            ttlv('NameValue', name, 'TextString'),
            ttlv('NameType', 'UninterpretedTextString', 'Enumeration'),
        ],
    )


def link_attribute(kind: str, uid: str) -> JSON:
    return ttlv(
        'Link',
        [
            ttlv('LinkType', kind, 'Enumeration'),
            ttlv('LinkedObjectIdentifier', uid, 'TextString'),
        ],
    )


def build_create_symmetric_key(
    uid: str,
    *,
    length: int = 256,
    tags: list[str],
    wrapping_key_uid: str | None = None,
    activation_date: str = DEFAULT_ACTIVATION_DATE,
    name: str | None = None,
) -> JSON:
    attributes = [
        ttlv('UniqueIdentifier', uid, 'TextString'),
        ttlv('CryptographicAlgorithm', 'AES', 'Enumeration'),
        ttlv('CryptographicLength', length, 'Integer'),
        ttlv(
            'CryptographicUsageMask',
            ENCRYPT | DECRYPT if wrapping_key_uid else AES_USAGE_MASK,
            'Integer',
        ),
        ttlv('KeyFormatType', 'TransparentSymmetricKey', 'Enumeration'),
        ttlv('ObjectType', 'SymmetricKey', 'Enumeration'),
        ttlv('ActivationDate', activation_date, 'DateTime'),
    ]
    if name:
        attributes.append(name_attribute(name))
    attributes.append(tag_attribute(tags))
    if wrapping_key_uid:
        attributes.append(vendor_attribute('wrapping_key_id', wrapping_key_uid))
    return request(
        'Create',
        None,
        ttlv('ObjectType', 'SymmetricKey', 'Enumeration'),
        ttlv('Attributes', attributes),
    )


def build_create_key_pair(
    uid: str,
    *,
    algorithm: str,
    tags: list[str],
    length: int = 2048,
    curve: str = 'P256',
    extra_attributes: list[JSON] | None = None,
) -> JSON:
    formats = {
        'RSA': 'TransparentRSAPrivateKey',
        'ECDSA': 'ECPrivateKey',
        'Ed25519': 'ECPrivateKey',
        'CoverCrypt': 'CoverCryptSecretKey',
    }
    private_mask, public_mask = {
        'RSA': (SIGN | DECRYPT | UNWRAP, VERIFY | ENCRYPT | WRAP),
        'ECDSA': (SIGN, VERIFY),
        'Ed25519': (ENCRYPT | DECRYPT, ENCRYPT | DECRYPT),
        'CoverCrypt': (COVERCRYPT_USAGE_MASK, COVERCRYPT_USAGE_MASK),
    }[algorithm]
    common = [
        ttlv('CryptographicAlgorithm', algorithm, 'Enumeration'),
        ttlv('CryptographicUsageMask', private_mask, 'Integer'),
        ttlv('KeyFormatType', formats[algorithm], 'Enumeration'),
        ttlv('ActivationDate', DEFAULT_ACTIVATION_DATE, 'DateTime'),
    ]
    if algorithm == 'RSA':
        common.append(ttlv('CryptographicLength', length, 'Integer'))
    elif algorithm in ('ECDSA', 'Ed25519'):
        common.append(
            ttlv(
                'CryptographicDomainParameters',
                [
                    ttlv(
                        'RecommendedCurve',
                        'CURVEED25519' if algorithm == 'Ed25519' else curve,
                        'Enumeration',
                    )
                ],
            )
        )
    common.extend(extra_attributes or [])
    common.append(tag_attribute(tags))
    private = [ttlv('UniqueIdentifier', uid, 'TextString')]
    for fields, mask in ((private, private_mask), (public := [], public_mask)):
        fields.extend(
            [
                ttlv('CryptographicUsageMask', mask, 'Integer'),
                ttlv('ActivationDate', DEFAULT_ACTIVATION_DATE, 'DateTime'),
                tag_attribute(tags),
            ]
        )
    return request(
        'CreateKeyPair',
        None,
        ttlv('CommonAttributes', common),
        ttlv('PrivateKeyAttributes', private),
        ttlv('PublicKeyAttributes', public),
    )


def build_certify(public_uid: str, uid: str, tags: list[str]) -> JSON:
    suffixes = 'Cn O Ou Email C St L Uid SerialNumber Title Dc DnQualifier'.split()
    dn = [
        ttlv('Certificate' + side + suffix, '', 'TextString')
        for side in ('Subject', 'Issuer')
        for suffix in suffixes
    ]
    dn[:2] = [
        ttlv('CertificateSubjectCn', uid, 'TextString'),
        ttlv('CertificateSubjectO', 'Cosmian', 'TextString'),
    ]
    dn[4] = ttlv('CertificateSubjectC', 'FR', 'TextString')
    return request(
        'Certify',
        public_uid,
        ttlv(
            'Attributes',
            [
                ttlv('UniqueIdentifier', uid, 'TextString'),
                ttlv('CertificateType', 'X509', 'Enumeration'),
                ttlv('CertificateAttributes', dn),
                ttlv('ActivationDate', DEFAULT_ACTIVATION_DATE, 'DateTime'),
                tag_attribute(tags),
            ],
        ),
    )


def build_import(uid: str, kind: str, data_hex: str, tags: list[str]) -> JSON:
    if kind == 'Certificate':
        payload = [
            ttlv('CertificateType', 'X509', 'Enumeration'),
            ttlv('CertificateValue', data_hex, 'ByteString'),
        ]
    elif kind == 'OpaqueObject':
        payload = [
            ttlv('OpaqueDataType', 'Unknown', 'Enumeration'),
            ttlv('OpaqueDataValue', data_hex, 'ByteString'),
        ]
    else:
        payload = [
            ttlv('SecretDataType', 'Password', 'Enumeration'),
            ttlv(
                'KeyBlock',
                [
                    ttlv('KeyFormatType', 'Opaque', 'Enumeration'),
                    ttlv('KeyValue', [ttlv('KeyMaterial', data_hex, 'ByteString')]),
                ],
            ),
        ]
    attributes = [
        ttlv('ObjectType', kind, 'Enumeration'),
        ttlv('ActivationDate', DEFAULT_ACTIVATION_DATE, 'DateTime'),
        tag_attribute(tags),
    ]
    if kind == 'SecretData':
        attributes.insert(1, ttlv('CryptographicUsageMask', VERIFY, 'Integer'))
    return request(
        'Import',
        uid,
        ttlv('ObjectType', kind, 'Enumeration'),
        ttlv('ReplaceExisting', False, 'Boolean'),
        ttlv('Attributes', attributes),
        ttlv(kind, payload),
    )


def build_get_attributes(uid: str, *, include_tags: bool = False) -> JSON:
    fields = (
        [
            ttlv(
                'AttributeReference',
                [
                    ttlv('VendorIdentification', 'cosmian', 'TextString'),
                    ttlv('AttributeName', 'tag', 'TextString'),
                ],
            )
        ]
        if include_tags
        else []
    )
    return request('GetAttributes', uid, *fields)


def build_cryptographic_request(
    operation: str,
    uid: str,
    data_hex: str,
    *,
    iv: str | None = None,
    auth_tag: str | None = None,
) -> JSON:
    fields = [
        ttlv(
            'CryptographicParameters',
            [
                ttlv('BlockCipherMode', 'GCM', 'Enumeration'),
                ttlv('CryptographicAlgorithm', 'AES', 'Enumeration'),
            ],
        ),
        ttlv('Data', data_hex, 'ByteString'),
    ]
    if iv is not None and auth_tag is not None:
        fields.extend(
            [
                ttlv('IVCounterNonce', iv, 'ByteString'),
                ttlv('AuthenticatedEncryptionTag', auth_tag, 'ByteString'),
            ]
        )
    return request(operation, uid, *fields)


def build_signature_request(
    uid: str,
    data_hex: str,
    *,
    signature: str | None = None,
    rsa: bool = False,
) -> JSON:
    fields = (
        [
            ttlv(
                'CryptographicParameters',
                [
                    ttlv('DigitalSignatureAlgorithm', 'RSASSAPSS', 'Enumeration'),
                    ttlv('HashingAlgorithm', 'SHA256', 'Enumeration'),
                ],
            )
        ]
        if rsa
        else []
    )
    fields.append(ttlv('Data', data_hex, 'ByteString'))
    if signature is not None:
        fields.append(ttlv('SignatureData', signature, 'ByteString'))
    return request('SignatureVerify' if signature is not None else 'Sign', uid, *fields)

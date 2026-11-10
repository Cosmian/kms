#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seeded random KMIP populator, pre-upgrade snapshotter, and post-upgrade verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any

from kmip_json_client import (
    DEFAULT_ACTIVATION_DATE,
    FUTURE_ACTIVATION_DATE,
    KmipClient,
    KmipRequestError,
    build_certify,
    build_create_key_pair,
    build_create_symmetric_key,
    build_decrypt,
    build_destroy,
    build_encrypt,
    build_export,
    build_get,
    build_get_attributes,
    build_import_certificate,
    build_import_opaque_object,
    build_import_secret_data,
    build_locate_by_tag,
    build_rekey,
    build_revoke,
    build_set_attribute,
    build_sign,
    build_signature_verify,
    extract_all_tags,
    extract_user_tags,
    find_all_tag_values,
    find_tag_value,
    is_unsupported_feature_error,
    make_mtls_context,
    name_attribute,
    vendor_attribute,
)
from populate_fixed_set import (
    COVERCRYPT_POLICY_HEX,
    GRANTEE_USER,
    _item_record,
    pem_cert_to_der_hex,
)

EXTRACTED_ATTR_KEYS = {
    'state',
    'namevalue',
    'cryptographicalgorithm',
    'cryptographiclength',
    'linkedobjectidentifier',
    'digestvalue',
    'objecttype',
    'keyformattype',
}

UNICODE_TAG_POOL = [
    'rnd-alpha',
    'équipe:sécurité-🔑',
    'region/eu-west/1',
    'app:billing#v2',
    'tenant_Δ_42',
    'env:staging/fr',
]


class UpgradeVerificationFailure(Exception):
    """Structured failure raised when a snapshot or post-upgrade check fails."""

    def __init__(
        self,
        *,
        uid: str,
        check: str,
        expected: Any,
        actual: Any,
    ) -> None:
        self.uid = uid
        self.check = check
        self.expected = expected
        self.actual = actual
        super().__init__(f'[{uid}] {check}: expected={expected!r} actual={actual!r}')


def _norm_key(key: str) -> str:
    return str(key).lower().replace('_', '').replace(' ', '')


def extract_normalized_attributes(node: Any) -> dict[str, list[str]]:
    """Extract normalized KMIP attributes from a `GetAttributes` response.

    Ignores `RandomNumberGenerator`, which KMS 5.29.0 synthesizes on every object
    and 6.0+ no longer returns.
    """
    out: dict[str, list[str]] = {}
    _walk_attributes(node, out)
    return {k: sorted(set(v)) for k, v in out.items()}


def _walk_attributes(node: Any, out: dict[str, list[str]]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_attributes(item, out)
    elif isinstance(node, dict):
        tag_norm = _norm_key(node.get('tag', ''))
        if tag_norm == 'randomnumbergenerator':
            return
        if (
            'tag' in node
            and 'value' in node
            and tag_norm in EXTRACTED_ATTR_KEYS
            and not isinstance(node['value'], (dict, list))
        ):
            out.setdefault(tag_norm, []).append(str(node['value']))
        for k, v in node.items():
            k_norm = _norm_key(k)
            if k_norm in EXTRACTED_ATTR_KEYS and not isinstance(v, (dict, list)):
                out.setdefault(k_norm, []).append(str(v))
            _walk_attributes(v, out)


def extract_object_material_digest(get_response: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 digest of the cryptographic material in a `Get` response."""
    material_fields: list[str] = []
    for tag in (
        'KeyMaterial',
        'CertificateValue',
        'OpaqueDataValue',
        'Modulus',
        'PublicExponent',
        'PrivateExponent',
        'PrimeP',
        'PrimeQ',
        'D',
        'QString',
    ):
        vals = find_all_tag_values(get_response, tag)
        if vals:
            material_fields.append(f"{tag}:{','.join(vals)}")
    if not material_fields:
        material_fields.append(json.dumps(get_response, sort_keys=True))
    joined = '|'.join(material_fields)
    return hashlib.sha256(joined.encode('utf-8')).hexdigest()


def populate_random_layer(
    client: KmipClient,
    manifest: dict[str, Any],
    *,
    seed: int,
    count: int = 12,
    sample_cert_der_hex: str | None = None,
) -> dict[str, Any]:
    """Generate `count` seeded-random `rnd_*` objects and append them to `manifest`."""
    rng = random.Random(seed)
    variant = manifest.get('variant', 'fips')
    recipes = [
        'aes_active',
        'aes_wrapped',
        'ec_keypair',
        'rsa_cert',
        'secret_data',
        'opaque_object',
        'lifecycle',
    ]
    if variant == 'non-fips':
        recipes.extend(['ed25519', 'covercrypt'])

    chosen_recipes = [recipes[i % len(recipes)] for i in range(count)]
    rng.shuffle(chosen_recipes)

    available_keks = ['mig_kek', 'bulk_aes_256']
    items = manifest.setdefault('items', [])

    for idx, recipe in enumerate(chosen_recipes):
        uid = f'rnd_{seed}_{idx:02d}_{recipe}'
        picked_tags = ['rnd', f'rnd-seed-{seed}'] + rng.sample(
            UNICODE_TAG_POOL, k=rng.randint(1, 2)
        )
        try:
            new_items = _execute_random_recipe(
                client,
                rng,
                recipe=recipe,
                uid=uid,
                tags=picked_tags,
                available_keks=available_keks,
                sample_cert_der_hex=sample_cert_der_hex,
            )
            items.extend(new_items)
        except KmipRequestError as exc:
            optional = recipe in ('ed25519', 'covercrypt')
            status = (
                'skipped'
                if (optional and is_unsupported_feature_error(exc))
                else 'failed'
            )
            items.append(
                _item_record(
                    uid=uid,
                    layer='random',
                    status=status,
                    required=not optional,
                    object_type='PrivateKey' if optional else recipe,
                    algorithm=recipe if optional else None,
                    user_tags=picked_tags,
                    reason=str(exc),
                )
            )

    manifest['seed'] = seed
    return manifest


def _execute_random_recipe(
    client: KmipClient,
    rng: random.Random,
    *,
    recipe: str,
    uid: str,
    tags: list[str],
    available_keks: list[str],
    sample_cert_der_hex: str | None,
) -> list[dict[str, Any]]:
    if recipe == 'aes_active':
        bits = rng.choice([128, 192, 256])
        grant_grantee = rng.choice([True, False])
        name_val = f'name-{uid}'
        client.kmip(
            build_create_symmetric_key(
                uid,
                algorithm='AES',
                length=bits,
                usage_mask=2108,
                tags=tags,
                name=name_val,
            ),
            uid=uid,
        )
        grants: dict[str, list[str]] = {}
        if grant_grantee:
            ops = ['encrypt', 'decrypt', 'get']
            client.grant_access(uid, GRANTEE_USER, ops)
            grants[GRANTEE_USER] = sorted(ops)
        if bits == 256:
            available_keks.append(uid)
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='SymmetricKey',
                algorithm='AES',
                length=bits,
                user_tags=tags,
                grants=grants,
                usages=['encrypt', 'decrypt'],
            )
        ]

    if recipe == 'aes_wrapped':
        bits = rng.choice([128, 192, 256])
        kek_uid = rng.choice(available_keks)
        client.kmip(
            build_create_symmetric_key(
                uid,
                algorithm='AES',
                length=bits,
                usage_mask=12,
                tags=tags,
                wrapping_key_uid=kek_uid,
            ),
            uid=uid,
        )
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='SymmetricKey',
                algorithm='AES',
                length=bits,
                user_tags=tags,
                wrapping_key_uid=kek_uid,
                usages=['encrypt', 'decrypt'],
            )
        ]

    if recipe == 'ec_keypair':
        curve = rng.choice(['P256', 'P384'])
        resp = client.kmip(
            build_create_key_pair(
                uid,
                algorithm='ECDSA',
                curve=curve,
                key_format_type='ECPrivateKey',
                private_usage_mask=1,
                public_usage_mask=2,
                tags=tags,
            ),
            uid=uid,
        )
        pk_uid = str(find_tag_value(resp, 'PublicKeyUniqueIdentifier') or f'{uid}_pk')
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='PrivateKey',
                algorithm='ECDSA',
                user_tags=tags,
                links={'PublicKeyLink': pk_uid},
                usages=['sign_ecdsa'],
            ),
            _item_record(
                uid=pk_uid,
                layer='random',
                status='created',
                required=True,
                object_type='PublicKey',
                algorithm='ECDSA',
                user_tags=tags,
                links={'PrivateKeyLink': uid},
                usages=['verify_ecdsa'],
            ),
        ]

    if recipe == 'rsa_cert':
        resp = client.kmip(
            build_create_key_pair(
                uid,
                algorithm='RSA',
                length=2048,
                key_format_type='TransparentRSAPrivateKey',
                private_usage_mask=41,
                public_usage_mask=22,
                tags=tags,
            ),
            uid=uid,
        )
        pk_uid = str(find_tag_value(resp, 'PublicKeyUniqueIdentifier') or f'{uid}_pk')
        cert_uid = f'{uid}_cert'
        if sample_cert_der_hex and rng.choice([True, False]):
            client.kmip(
                build_import_certificate(cert_uid, sample_cert_der_hex, tags=tags),
                uid=cert_uid,
            )
        else:
            client.kmip(
                build_certify(
                    pk_uid,
                    cert_uid,
                    subject_cn=f'Random Cert {uid}',
                    tags=tags,
                ),
                uid=cert_uid,
            )
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='PrivateKey',
                algorithm='RSA',
                length=2048,
                user_tags=tags,
                links={'PublicKeyLink': pk_uid},
                usages=['sign_rsa_pss'],
            ),
            _item_record(
                uid=pk_uid,
                layer='random',
                status='created',
                required=True,
                object_type='PublicKey',
                algorithm='RSA',
                length=2048,
                user_tags=tags,
                links={'PrivateKeyLink': uid},
                usages=['verify_rsa_pss'],
            ),
            _item_record(
                uid=cert_uid,
                layer='random',
                status='created',
                required=True,
                object_type='Certificate',
                user_tags=tags,
            ),
        ]

    if recipe == 'secret_data':
        raw_hex = rng.randbytes(rng.randint(16, 128)).hex().upper()
        client.kmip(build_import_secret_data(uid, raw_hex, tags=tags), uid=uid)
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='SecretData',
                user_tags=tags,
            )
        ]

    if recipe == 'opaque_object':
        raw_hex = rng.randbytes(rng.randint(16, 256)).hex().upper()
        client.kmip(build_import_opaque_object(uid, raw_hex, tags=tags), uid=uid)
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='OpaqueObject',
                user_tags=tags,
            )
        ]

    if recipe == 'lifecycle':
        target_state = rng.choice(
            ['PreActive', 'Deactivated', 'Compromised', 'Destroyed']
        )
        act_date = (
            FUTURE_ACTIVATION_DATE
            if target_state == 'PreActive'
            else DEFAULT_ACTIVATION_DATE
        )
        client.kmip(
            build_create_symmetric_key(
                uid,
                algorithm='AES',
                length=256,
                usage_mask=12,
                tags=tags,
                activation_date=act_date,
            ),
            uid=uid,
        )
        if target_state == 'Deactivated':
            client.kmip(build_revoke(uid, 'CessationOfOperation'), uid=uid)
        elif target_state == 'Compromised':
            client.kmip(build_revoke(uid, 'KeyCompromise'), uid=uid)
        elif target_state == 'Destroyed':
            client.kmip(build_revoke(uid, 'Superseded'), uid=uid)
            client.kmip(build_destroy(uid), uid=uid)
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=True,
                object_type='SymmetricKey',
                algorithm='AES',
                length=256,
                expected_state=target_state,
                user_tags=tags,
            )
        ]

    if recipe == 'ed25519':
        resp = client.kmip(
            build_create_key_pair(
                uid,
                algorithm='Ed25519',
                curve='CURVEED25519',
                key_format_type='ECPrivateKey',
                usage_mask=12,
                tags=tags,
            ),
            uid=uid,
        )
        pk_uid = str(find_tag_value(resp, 'PublicKeyUniqueIdentifier') or f'{uid}_pk')
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=False,
                object_type='PrivateKey',
                algorithm='Ed25519',
                user_tags=tags,
                links={'PublicKeyLink': pk_uid},
            ),
            _item_record(
                uid=pk_uid,
                layer='random',
                status='created',
                required=False,
                object_type='PublicKey',
                algorithm='Ed25519',
                user_tags=tags,
                links={'PrivateKeyLink': uid},
            ),
        ]

    if recipe == 'covercrypt':
        resp = client.kmip(
            build_create_key_pair(
                uid,
                algorithm='CoverCrypt',
                key_format_type='CoverCryptSecretKey',
                usage_mask=4194304,
                tags=tags,
                extra_common_attributes=[
                    {'tag': 'ObjectType', 'type': 'Enumeration', 'value': 'PrivateKey'},
                    vendor_attribute(
                        'cover_crypt_access_structure',
                        COVERCRYPT_POLICY_HEX,
                        value_type='ByteString',
                    ),
                ],
            ),
            uid=uid,
        )
        pk_uid = str(find_tag_value(resp, 'PublicKeyUniqueIdentifier') or f'{uid}_pk')
        return [
            _item_record(
                uid=uid,
                layer='random',
                status='created',
                required=False,
                object_type='PrivateKey',
                algorithm='CoverCrypt',
                user_tags=tags,
                links={'PublicKeyLink': pk_uid},
            ),
            _item_record(
                uid=pk_uid,
                layer='random',
                status='created',
                required=False,
                object_type='PublicKey',
                algorithm='CoverCrypt',
                user_tags=tags,
                links={'PrivateKeyLink': uid},
            ),
        ]

    raise ValueError(f'Unknown random recipe: {recipe}')


def take_snapshot(
    owner_client: KmipClient,
    grantee_client: KmipClient | None,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Capture a full KMIP snapshot (attributes, tags, material digests, grants, locate sets, ciphertexts, signatures) from the old server."""
    seed = int(manifest.get('seed', 0))
    created_items = [
        item for item in manifest.get('items', []) if item.get('status') == 'created'
    ]
    objects_snap: dict[str, Any] = {}
    ciphertexts: list[dict[str, Any]] = []
    signatures: list[dict[str, Any]] = []
    all_tags: set[str] = set()

    for item in created_items:
        uid = item['uid']
        expected_state = item['expected_state']
        expected_tags = sorted(item.get('user_tags', []))
        all_tags.update(expected_tags)

        try:
            raw_attrs = owner_client.kmip(build_get_attributes(uid), uid=uid)
            raw_tags = owner_client.kmip(
                build_get_attributes(uid, include_tags=True), uid=uid
            )
        except KmipRequestError as exc:
            raise UpgradeVerificationFailure(
                uid=uid,
                check='pre-upgrade GetAttributes',
                expected='Success',
                actual=str(exc),
            ) from exc

        norm_attrs = extract_normalized_attributes(raw_attrs)
        actual_states = norm_attrs.get('state', [])
        if expected_state not in actual_states:
            raise UpgradeVerificationFailure(
                uid=uid,
                check='pre-upgrade State',
                expected=expected_state,
                actual=actual_states,
            )

        user_tags = extract_user_tags(raw_tags)
        if not set(expected_tags) <= set(user_tags):
            raise UpgradeVerificationFailure(
                uid=uid,
                check='pre-upgrade user tags',
                expected=expected_tags,
                actual=user_tags,
            )

        material_digest: str | None = None
        if expected_state == 'Active':
            try:
                get_resp = owner_client.kmip(build_get(uid), uid=uid)
                material_digest = extract_object_material_digest(get_resp)
            except KmipRequestError as exc:
                raise UpgradeVerificationFailure(
                    uid=uid,
                    check='pre-upgrade Get material',
                    expected='readable object material',
                    actual=str(exc),
                ) from exc

        grants_list = owner_client.list_access(uid)
        actual_grants = {
            entry['user_id']: sorted(entry.get('operations', []))
            for entry in grants_list
            if 'user_id' in entry
        }
        expected_grants = item.get('grants', {})
        if actual_grants != expected_grants:
            raise UpgradeVerificationFailure(
                uid=uid,
                check='pre-upgrade access grants',
                expected=expected_grants,
                actual=actual_grants,
            )

        objects_snap[uid] = {
            'expected_state': expected_state,
            'attributes': norm_attrs,
            'user_tags': user_tags,
            'material_digest': material_digest,
            'grants': actual_grants,
            'wrapping_key_uid': item.get('wrapping_key_uid'),
        }

        usages = item.get('usages', [])
        if expected_state == 'Active' and 'encrypt' in usages:
            plain_hex = f'kms-upgrade-plain-{seed}-{uid}'.encode('utf-8').hex().upper()
            enc_resp = owner_client.kmip(build_encrypt(uid, plain_hex), uid=uid)
            ct_hex = str(find_tag_value(enc_resp, 'Data') or '')
            iv_hex = str(find_tag_value(enc_resp, 'IVCounterNonce') or '')
            tag_hex = str(find_tag_value(enc_resp, 'AuthenticatedEncryptionTag') or '')
            dec_resp = owner_client.kmip(
                build_decrypt(uid, ct_hex, iv_hex, tag_hex), uid=uid
            )
            if str(find_tag_value(dec_resp, 'Data') or '').upper() != plain_hex:
                raise UpgradeVerificationFailure(
                    uid=uid,
                    check='pre-upgrade owner Encrypt/Decrypt roundtrip',
                    expected=plain_hex,
                    actual=find_tag_value(dec_resp, 'Data'),
                )
            ciphertexts.append(
                {
                    'uid': uid,
                    'actor': 'owner',
                    'plaintext_hex': plain_hex,
                    'ciphertext_hex': ct_hex,
                    'iv_hex': iv_hex,
                    'auth_tag_hex': tag_hex,
                }
            )
            if (
                grantee_client is not None
                and 'encrypt' in actual_grants.get(GRANTEE_USER, [])
                and 'decrypt' in actual_grants.get(GRANTEE_USER, [])
            ):
                g_enc = grantee_client.kmip(build_encrypt(uid, plain_hex), uid=uid)
                g_ct = str(find_tag_value(g_enc, 'Data') or '')
                g_iv = str(find_tag_value(g_enc, 'IVCounterNonce') or '')
                g_tag = str(find_tag_value(g_enc, 'AuthenticatedEncryptionTag') or '')
                g_dec = grantee_client.kmip(
                    build_decrypt(uid, g_ct, g_iv, g_tag), uid=uid
                )
                if str(find_tag_value(g_dec, 'Data') or '').upper() != plain_hex:
                    raise UpgradeVerificationFailure(
                        uid=uid,
                        check='pre-upgrade grantee Encrypt/Decrypt roundtrip',
                        expected=plain_hex,
                        actual=find_tag_value(g_dec, 'Data'),
                    )
                ciphertexts.append(
                    {
                        'uid': uid,
                        'actor': 'grantee',
                        'plaintext_hex': plain_hex,
                        'ciphertext_hex': g_ct,
                        'iv_hex': g_iv,
                        'auth_tag_hex': g_tag,
                    }
                )

        if expected_state == 'Active' and 'sign_rsa_pss' in usages:
            pk_uid = item.get('links', {}).get('PublicKeyLink')
            if pk_uid:
                msg_hex = f'kms-rsa-sign-{seed}-{uid}'.encode('utf-8').hex().upper()
                sig_resp = owner_client.kmip(
                    build_sign(
                        uid,
                        msg_hex,
                        digital_signature_algorithm='RSASSAPSS',
                        hashing_algorithm='SHA256',
                    ),
                    uid=uid,
                )
                sig_hex = str(find_tag_value(sig_resp, 'SignatureData') or '')
                ver_resp = owner_client.kmip(
                    build_signature_verify(
                        pk_uid,
                        msg_hex,
                        sig_hex,
                        digital_signature_algorithm='RSASSAPSS',
                        hashing_algorithm='SHA256',
                    ),
                    uid=pk_uid,
                )
                if find_tag_value(ver_resp, 'ValidityIndicator') != 'Valid':
                    raise UpgradeVerificationFailure(
                        uid=pk_uid,
                        check='pre-upgrade RSA SignatureVerify',
                        expected='Valid',
                        actual=find_tag_value(ver_resp, 'ValidityIndicator'),
                    )
                signatures.append(
                    {
                        'kind': 'rsa_pss',
                        'private_uid': uid,
                        'public_uid': pk_uid,
                        'data_hex': msg_hex,
                        'signature_hex': sig_hex,
                    }
                )

        if expected_state == 'Active' and 'sign_ecdsa' in usages:
            pk_uid = item.get('links', {}).get('PublicKeyLink')
            if pk_uid:
                msg_hex = f'kms-ecdsa-sign-{seed}-{uid}'.encode('utf-8').hex().upper()
                sig_resp = owner_client.kmip(build_sign(uid, msg_hex), uid=uid)
                sig_hex = str(find_tag_value(sig_resp, 'SignatureData') or '')
                ver_resp = owner_client.kmip(
                    build_signature_verify(pk_uid, msg_hex, sig_hex), uid=pk_uid
                )
                if find_tag_value(ver_resp, 'ValidityIndicator') != 'Valid':
                    raise UpgradeVerificationFailure(
                        uid=pk_uid,
                        check='pre-upgrade ECDSA SignatureVerify',
                        expected='Valid',
                        actual=find_tag_value(ver_resp, 'ValidityIndicator'),
                    )
                signatures.append(
                    {
                        'kind': 'ecdsa',
                        'private_uid': uid,
                        'public_uid': pk_uid,
                        'data_hex': msg_hex,
                        'signature_hex': sig_hex,
                    }
                )

    locate_by_tag: dict[str, list[str]] = {}
    for tag in sorted(all_tags):
        loc_resp = owner_client.kmip(build_locate_by_tag(tag))
        located = sorted(set(find_all_tag_values(loc_resp, 'UniqueIdentifier')))
        locate_by_tag[tag] = located

    if grantee_client is not None:
        _assert_grantee_denials(owner_client, grantee_client)

    return {
        'snapshot_version': 1,
        'server_version': manifest.get('server_version', 'unknown'),
        'variant': manifest.get('variant', 'fips'),
        'seed': seed,
        'objects': objects_snap,
        'ciphertexts': ciphertexts,
        'signatures': signatures,
        'locate_by_tag': locate_by_tag,
    }


def _assert_kmip_rejected(exc: KmipRequestError, *, uid: str, check: str) -> None:
    """Ensure a negative check failed with a client-side KMIP denial/not-found, not a server crash or outage."""
    msg = f"{exc.result_reason or ''} {exc.server_message}".lower()
    expected_markers = (
        'not_found',
        'not found',
        'permission',
        'denied',
        'unauthori',
        'forbidden',
    )
    if exc.http_status not in (400, 401, 403, 404, 422) or not any(
        m in msg for m in expected_markers
    ):
        raise UpgradeVerificationFailure(
            uid=uid,
            check=check,
            expected='HTTP 4xx denial / object-not-found',
            actual=f'http={exc.http_status} message={exc.server_message!r}',
        )


def _assert_grantee_denials(
    owner_client: KmipClient, grantee_client: KmipClient
) -> None:
    """Verify grantee is denied Export on `bulk_aes_256` (granted encrypt/decrypt only) and Encrypt on `mig_wrapped`."""
    try:
        grantee_client.kmip(build_export('bulk_aes_256'), uid='bulk_aes_256')
        raise UpgradeVerificationFailure(
            uid='bulk_aes_256',
            check='grantee Export denial',
            expected='permission denied error',
            actual='Export succeeded for grantee',
        )
    except KmipRequestError as exc:
        _assert_kmip_rejected(exc, uid='bulk_aes_256', check='grantee Export denial')

    try:
        grantee_client.kmip(
            build_encrypt('mig_wrapped', '48656C6C6F'), uid='mig_wrapped'
        )
        raise UpgradeVerificationFailure(
            uid='mig_wrapped',
            check='grantee ungranted key Encrypt denial',
            expected='permission denied / not found error',
            actual='Encrypt succeeded for grantee on ungranted key',
        )
    except KmipRequestError as exc:
        _assert_kmip_rejected(
            exc, uid='mig_wrapped', check='grantee ungranted key Encrypt denial'
        )

    owner_client.kmip(build_get_attributes('mig_kek'), uid='mig_kek')


def _compare_attributes(
    uid: str, baseline: dict[str, list[str]], current: dict[str, list[str]]
) -> None:
    for key, base_vals in baseline.items():
        cur_vals = current.get(key, [])
        if key == 'digestvalue':
            if not set(base_vals) <= set(cur_vals):
                raise UpgradeVerificationFailure(
                    uid=uid,
                    check='attribute digestvalue preservation',
                    expected=base_vals,
                    actual=cur_vals,
                )
        elif base_vals != cur_vals:
            raise UpgradeVerificationFailure(
                uid=uid,
                check=f"attribute '{key}' preservation",
                expected=base_vals,
                actual=cur_vals,
            )


def verify_against_snapshot(
    owner_client: KmipClient,
    grantee_client: KmipClient | None,
    snapshot: dict[str, Any],
    *,
    phase: str,
    backend: str = 'sqlite',
    mutate: bool = False,
    canary_file: Path | None = None,
) -> None:
    """Verify that the target server preserves all snapshot invariants."""
    if phase in ('candidate-restart', 'restore') and canary_file is not None:
        if not canary_file.is_file():
            raise UpgradeVerificationFailure(
                uid='canary',
                check=f'{phase} canary file presence',
                expected=str(canary_file),
                actual='missing',
            )

    expected_objects: dict[str, Any] = json.loads(json.dumps(snapshot['objects']))
    if (
        phase == 'candidate-restart'
        and canary_file is not None
        and canary_file.is_file()
    ):
        canary_info = json.loads(canary_file.read_text(encoding='utf-8'))
        mutated_uid = canary_info.get('mutated_uid')
        mutated_name = canary_info.get('mutated_name')
        if mutated_uid and mutated_name and mutated_uid in expected_objects:
            prev_names = expected_objects[mutated_uid]['attributes'].get(
                'namevalue', []
            )
            expected_objects[mutated_uid]['attributes']['namevalue'] = sorted(
                set(prev_names + [mutated_name])
            )

    for uid, snap_obj in expected_objects.items():
        try:
            raw_attrs = owner_client.kmip(build_get_attributes(uid), uid=uid)
            raw_tags = owner_client.kmip(
                build_get_attributes(uid, include_tags=True), uid=uid
            )
        except KmipRequestError as exc:
            raise UpgradeVerificationFailure(
                uid=uid,
                check=f'{phase} GetAttributes',
                expected='Success',
                actual=str(exc),
            ) from exc

        cur_attrs = extract_normalized_attributes(raw_attrs)
        _compare_attributes(uid, snap_obj['attributes'], cur_attrs)

        all_tags = extract_all_tags(raw_tags)
        cur_user_tags = [t for t in all_tags if not t.startswith('_')]
        if cur_user_tags != snap_obj['user_tags']:
            raise UpgradeVerificationFailure(
                uid=uid,
                check=f"{phase} user tags (system '_' tags ignored)",
                expected=snap_obj['user_tags'],
                actual=cur_user_tags,
            )

        if (
            phase in ('candidate', 'candidate-restart')
            and backend != 'redis'
            and 'Certificate' in cur_attrs.get('objecttype', [])
        ):
            serial_tags = [t for t in all_tags if t.startswith('_serial=')]
            if len(serial_tags) != 1:
                raise UpgradeVerificationFailure(
                    uid=uid,
                    check=f'{phase} 5.29 certificate _serial= tag backfill',
                    expected='exactly 1 _serial=<HEX> system tag',
                    actual=serial_tags,
                )

        if snap_obj['expected_state'] == 'Active':
            try:
                get_resp = owner_client.kmip(build_get(uid), uid=uid)
            except KmipRequestError as exc:
                raise UpgradeVerificationFailure(
                    uid=uid,
                    check=f"{phase} Get material (unwrap={snap_obj.get('wrapping_key_uid')})",
                    expected='readable object material',
                    actual=str(exc),
                ) from exc
            cur_digest = extract_object_material_digest(get_resp)
            if cur_digest != snap_obj['material_digest']:
                raise UpgradeVerificationFailure(
                    uid=uid,
                    check=f'{phase} object material SHA-256 digest',
                    expected=snap_obj['material_digest'],
                    actual=cur_digest,
                )

        grants_list = owner_client.list_access(uid)
        cur_grants = {
            entry['user_id']: sorted(entry.get('operations', []))
            for entry in grants_list
            if 'user_id' in entry
        }
        if cur_grants != snap_obj['grants']:
            raise UpgradeVerificationFailure(
                uid=uid,
                check=f'{phase} access grants',
                expected=snap_obj['grants'],
                actual=cur_grants,
            )

    for ct in snapshot.get('ciphertexts', []):
        uid = ct['uid']
        actor = ct['actor']
        client = owner_client if actor == 'owner' else grantee_client
        if client is None:
            continue
        try:
            dec_resp = client.kmip(
                build_decrypt(
                    uid,
                    ct['ciphertext_hex'],
                    ct['iv_hex'],
                    ct['auth_tag_hex'],
                ),
                uid=uid,
            )
        except KmipRequestError as exc:
            raise UpgradeVerificationFailure(
                uid=uid,
                check=f'{phase} Decrypt old ciphertext ({actor})',
                expected=ct['plaintext_hex'],
                actual=str(exc),
            ) from exc
        actual_plain = str(find_tag_value(dec_resp, 'Data') or '').upper()
        if actual_plain != ct['plaintext_hex']:
            raise UpgradeVerificationFailure(
                uid=uid,
                check=f'{phase} Decrypt plaintext match ({actor})',
                expected=ct['plaintext_hex'],
                actual=actual_plain,
            )

    for sig in snapshot.get('signatures', []):
        pk_uid = sig['public_uid']
        kind = sig['kind']
        try:
            if kind == 'rsa_pss':
                ver_resp = owner_client.kmip(
                    build_signature_verify(
                        pk_uid,
                        sig['data_hex'],
                        sig['signature_hex'],
                        digital_signature_algorithm='RSASSAPSS',
                        hashing_algorithm='SHA256',
                    ),
                    uid=pk_uid,
                )
            else:
                ver_resp = owner_client.kmip(
                    build_signature_verify(
                        pk_uid, sig['data_hex'], sig['signature_hex']
                    ),
                    uid=pk_uid,
                )
        except KmipRequestError as exc:
            raise UpgradeVerificationFailure(
                uid=pk_uid,
                check=f'{phase} SignatureVerify ({kind})',
                expected='Valid',
                actual=str(exc),
            ) from exc
        validity = find_tag_value(ver_resp, 'ValidityIndicator')
        if validity != 'Valid':
            raise UpgradeVerificationFailure(
                uid=pk_uid,
                check=f'{phase} SignatureVerify ValidityIndicator ({kind})',
                expected='Valid',
                actual=validity,
            )

    for tag, expected_uids in snapshot.get('locate_by_tag', {}).items():
        loc_resp = owner_client.kmip(build_locate_by_tag(tag))
        actual_uids = sorted(set(find_all_tag_values(loc_resp, 'UniqueIdentifier')))
        if not set(expected_uids) <= set(actual_uids):
            raise UpgradeVerificationFailure(
                uid=f'tag:{tag}',
                check=f"{phase} Locate by tag '{tag}'",
                expected=expected_uids,
                actual=actual_uids,
            )

    if grantee_client is not None:
        _assert_grantee_denials(owner_client, grantee_client)

    if phase == 'candidate' and mutate and canary_file is not None:
        _perform_post_upgrade_mutations(owner_client, canary_file)
    elif phase == 'candidate-restart' and canary_file is not None:
        _verify_post_upgrade_mutations(owner_client, snapshot, canary_file)
    elif phase == 'restore' and canary_file is not None:
        _verify_restore_isolation(owner_client, canary_file)


def _perform_post_upgrade_mutations(
    owner_client: KmipClient, canary_file: Path
) -> None:
    mutated_uid = 'bulk_aes_256'
    mutated_name = 'bulk-shared-aes-256-candidate'
    canary_uid = 'upgrade_post_migration_canary'
    canary_plain_hex = '504F53545F555047524144455F43414E415259'

    owner_client.kmip(
        build_set_attribute(mutated_uid, name_attribute(mutated_name)),
        uid=mutated_uid,
    )
    owner_client.kmip(
        build_create_symmetric_key(
            canary_uid,
            algorithm='AES',
            length=256,
            usage_mask=12,
            tags=['canary'],
        ),
        uid=canary_uid,
    )
    enc_resp = owner_client.kmip(
        build_encrypt(canary_uid, canary_plain_hex), uid=canary_uid
    )
    canary_data = {
        'mutated_uid': mutated_uid,
        'mutated_name': mutated_name,
        'canary_uid': canary_uid,
        'plaintext_hex': canary_plain_hex,
        'ciphertext_hex': str(find_tag_value(enc_resp, 'Data') or ''),
        'iv_hex': str(find_tag_value(enc_resp, 'IVCounterNonce') or ''),
        'auth_tag_hex': str(
            find_tag_value(enc_resp, 'AuthenticatedEncryptionTag') or ''
        ),
    }
    canary_file.parent.mkdir(parents=True, exist_ok=True)
    canary_file.write_text(json.dumps(canary_data, indent=2) + '\n', encoding='utf-8')


def _verify_post_upgrade_mutations(
    owner_client: KmipClient, snapshot: dict[str, Any], canary_file: Path
) -> None:
    canary = json.loads(canary_file.read_text(encoding='utf-8'))
    canary_uid = canary['canary_uid']
    dec_resp = owner_client.kmip(
        build_decrypt(
            canary_uid,
            canary['ciphertext_hex'],
            canary['iv_hex'],
            canary['auth_tag_hex'],
        ),
        uid=canary_uid,
    )
    actual_plain = str(find_tag_value(dec_resp, 'Data') or '').upper()
    if actual_plain != canary['plaintext_hex']:
        raise UpgradeVerificationFailure(
            uid=canary_uid,
            check='candidate-restart post-upgrade canary Decrypt',
            expected=canary['plaintext_hex'],
            actual=actual_plain,
        )

    # Exercise the 5.25.0 wrapping_key_id column backfill: rotating mig_kek calls
    # find_wrapped_by("mig_kek") and re-wraps mig_wrapped under the new KEK.
    rekey_resp = owner_client.kmip(build_rekey('mig_kek'), uid='mig_kek')
    new_kek_uid = str(find_tag_value(rekey_resp, 'UniqueIdentifier') or '')
    if not new_kek_uid or new_kek_uid == 'mig_kek':
        raise UpgradeVerificationFailure(
            uid='mig_kek',
            check='candidate-restart ReKey wrapping key',
            expected='new KEK UniqueIdentifier != mig_kek',
            actual=new_kek_uid,
        )
    wrapped_attrs = extract_normalized_attributes(
        owner_client.kmip(build_get_attributes('mig_wrapped'), uid='mig_wrapped')
    )
    if new_kek_uid not in wrapped_attrs.get('linkedobjectidentifier', []):
        raise UpgradeVerificationFailure(
            uid='mig_wrapped',
            check='candidate-restart wrapping_key_id backfill rewrap_dependants link',
            expected=new_kek_uid,
            actual=wrapped_attrs.get('linkedobjectidentifier', []),
        )
    for ct in snapshot.get('ciphertexts', []):
        if ct['uid'] == 'mig_wrapped' and ct['actor'] == 'owner':
            rewrapped_dec = owner_client.kmip(
                build_decrypt(
                    'mig_wrapped',
                    ct['ciphertext_hex'],
                    ct['iv_hex'],
                    ct['auth_tag_hex'],
                ),
                uid='mig_wrapped',
            )
            if (
                str(find_tag_value(rewrapped_dec, 'Data') or '').upper()
                != ct['plaintext_hex']
            ):
                raise UpgradeVerificationFailure(
                    uid='mig_wrapped',
                    check='candidate-restart Decrypt after KEK ReKey',
                    expected=ct['plaintext_hex'],
                    actual=find_tag_value(rewrapped_dec, 'Data'),
                )


def _verify_restore_isolation(owner_client: KmipClient, canary_file: Path) -> None:
    canary = json.loads(canary_file.read_text(encoding='utf-8'))
    canary_uid = canary['canary_uid']
    try:
        owner_client.kmip(build_get_attributes(canary_uid), uid=canary_uid)
        raise UpgradeVerificationFailure(
            uid=canary_uid,
            check='restore backup isolation',
            expected='canary object absent from pre-upgrade backup',
            actual=f'{canary_uid} exists in restored backup',
        )
    except KmipRequestError as exc:
        _assert_kmip_rejected(exc, uid=canary_uid, check='restore backup isolation')


def emit_failure_report(
    failure: UpgradeVerificationFailure,
    *,
    old_version: str,
    new_version: str,
    backend: str,
    variant: str,
    phase: str,
    seed: int,
    replay_cmd: str,
) -> None:
    """Write a concise, human-readable failure report to stderr and `$GITHUB_STEP_SUMMARY`."""
    banner = (
        '\n========================================================================\n'
        'DB UPGRADE GATE FAILURE\n'
        f'  Upgrade path : {old_version} -> {new_version}\n'
        f'  Backend      : {backend} ({variant})\n'
        f'  Phase        : {phase}\n'
        f'  Random seed  : {seed}\n'
        f'  Object UID   : {failure.uid}\n'
        f'  Failed check : {failure.check}\n'
        f'  Expected     : {failure.expected}\n'
        f'  Actual       : {failure.actual}\n'
        f'  Replay cmd   : {replay_cmd}\n'
        '========================================================================\n'
    )
    print(banner, file=sys.stderr)

    summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary_path:
        md = (
            f'### DB Upgrade Gate Failure (`{old_version}` -> `{new_version}`, `{backend}`, `{variant}`)\n\n'
            '| Field | Value |\n'
            '|---|---|\n'
            f'| **Upgrade path** | `{old_version}` -> `{new_version}` |\n'
            f'| **Backend / Variant** | `{backend}` / `{variant}` |\n'
            f'| **Phase** | `{phase}` |\n'
            f'| **Random seed** | `{seed}` |\n'
            f'| **Object UID** | `{failure.uid}` |\n'
            f'| **Failed check** | `{failure.check}` |\n'
            f'| **Expected** | `{failure.expected}` |\n'
            f'| **Actual** | `{failure.actual}` |\n\n'
            '**Replay command:**\n'
            f'```bash\n{replay_cmd}\n```\n\n'
        )
        with Path(summary_path).open('a', encoding='utf-8') as handle:
            handle.write(md)


def _build_clients(
    args: argparse.Namespace,
) -> tuple[KmipClient, KmipClient | None]:
    owner_ctx = None
    grantee_ctx = None
    if args.ca_cert and args.client_cert and args.client_key:
        owner_ctx = make_mtls_context(args.ca_cert, args.client_cert, args.client_key)
    if args.ca_cert and args.grantee_cert and args.grantee_key:
        grantee_ctx = make_mtls_context(
            args.ca_cert, args.grantee_cert, args.grantee_key
        )
    owner_client = KmipClient(args.url, ssl_context=owner_ctx)
    grantee_client = (
        KmipClient(args.url, ssl_context=grantee_ctx) if grantee_ctx else None
    )
    return owner_client, grantee_client


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Seeded random KMIP populator, snapshotter, and post-upgrade verifier.'
    )
    sub = parser.add_subparsers(dest='subcommand', required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument('--url', required=True, help='KMS base URL')
        p.add_argument('--ca-cert', type=Path, default=None)
        p.add_argument('--client-cert', type=Path, default=None)
        p.add_argument('--client-key', type=Path, default=None)
        p.add_argument('--grantee-cert', type=Path, default=None)
        p.add_argument('--grantee-key', type=Path, default=None)
        p.add_argument('--old-version', default='unknown')
        p.add_argument('--new-version', default='candidate')
        p.add_argument('--backend', default='sqlite')
        p.add_argument('--variant', default='fips')
        p.add_argument('--replay-cmd', default='')

    p_rand = sub.add_parser(
        'populate-random', help='Add seeded random rnd_* objects to manifest'
    )
    add_common(p_rand)
    p_rand.add_argument('--manifest', required=True, type=Path)
    p_rand.add_argument('--seed', type=int, default=None)
    p_rand.add_argument('--count', type=int, default=12)
    p_rand.add_argument('--sample-cert', type=Path, default=None)

    p_snap = sub.add_parser(
        'snapshot', help='Capture pre-upgrade KMIP snapshot from old server'
    )
    add_common(p_snap)
    p_snap.add_argument('--manifest', required=True, type=Path)
    p_snap.add_argument('--snapshot', required=True, type=Path)

    p_ver = sub.add_parser(
        'verify', help='Verify server state against pre-upgrade snapshot'
    )
    add_common(p_ver)
    p_ver.add_argument('--snapshot', required=True, type=Path)
    p_ver.add_argument(
        '--phase',
        choices=('candidate', 'candidate-restart', 'restore'),
        default='candidate',
    )
    p_ver.add_argument('--mutate', action='store_true')
    p_ver.add_argument('--canary-file', type=Path, default=None)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    owner_client, grantee_client = _build_clients(args)

    if args.subcommand == 'populate-random':
        seed = (
            args.seed if args.seed is not None else int(time.time() * 1000) & 0x7FFFFFFF
        )
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        sample_der = (
            pem_cert_to_der_hex(args.sample_cert)
            if args.sample_cert and args.sample_cert.is_file()
            else None
        )
        populate_random_layer(
            owner_client,
            manifest,
            seed=seed,
            count=args.count,
            sample_cert_der_hex=sample_der,
        )
        args.manifest.write_text(
            json.dumps(manifest, indent=2) + '\n', encoding='utf-8'
        )
        failed = [
            item
            for item in manifest['items']
            if item.get('layer') == 'random' and item.get('status') == 'failed'
        ]
        created = [
            item
            for item in manifest['items']
            if item.get('layer') == 'random' and item.get('status') == 'created'
        ]
        if failed:
            first = failed[0]
            replay = (
                args.replay_cmd
                or f'mise run test:upgrade-db --variant {args.variant} --backend {args.backend} --old-version {args.old_version} --seed {seed}'
            )
            emit_failure_report(
                UpgradeVerificationFailure(
                    uid=first['uid'],
                    check='populate-random',
                    expected='created',
                    actual=first.get('reason'),
                ),
                old_version=args.old_version,
                new_version=args.new_version,
                backend=args.backend,
                variant=args.variant,
                phase='seed-random',
                seed=seed,
                replay_cmd=replay,
            )
            return 1
        print(f'Populated random layer (seed={seed}): created={len(created)}')
        return 0

    if args.subcommand == 'snapshot':
        manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
        seed = int(manifest.get('seed', 0))
        replay = (
            args.replay_cmd
            or f'mise run test:upgrade-db --variant {args.variant} --backend {args.backend} --old-version {args.old_version} --seed {seed}'
        )
        try:
            snap = take_snapshot(owner_client, grantee_client, manifest)
        except (UpgradeVerificationFailure, KmipRequestError) as exc:
            failure = (
                exc
                if isinstance(exc, UpgradeVerificationFailure)
                else UpgradeVerificationFailure(
                    uid=exc.uid or 'server',
                    check=f'seed-snapshot {exc.operation}',
                    expected='Success',
                    actual=str(exc),
                )
            )
            emit_failure_report(
                failure,
                old_version=args.old_version,
                new_version=args.new_version,
                backend=args.backend,
                variant=args.variant,
                phase='seed-snapshot',
                seed=seed,
                replay_cmd=replay,
            )
            return 1
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        args.snapshot.write_text(json.dumps(snap, indent=2) + '\n', encoding='utf-8')
        print(
            f'Captured pre-upgrade snapshot (seed={seed}): '
            f"objects={len(snap['objects'])} ciphertexts={len(snap['ciphertexts'])} "
            f"signatures={len(snap['signatures'])} tags={len(snap['locate_by_tag'])}"
        )
        return 0

    if args.subcommand == 'verify':
        snap = json.loads(args.snapshot.read_text(encoding='utf-8'))
        seed = int(snap.get('seed', 0))
        replay = (
            args.replay_cmd
            or f'mise run test:upgrade-db --variant {args.variant} --backend {args.backend} --old-version {args.old_version} --seed {seed}'
        )
        try:
            verify_against_snapshot(
                owner_client,
                grantee_client,
                snap,
                phase=args.phase,
                backend=args.backend,
                mutate=args.mutate,
                canary_file=args.canary_file,
            )
        except (UpgradeVerificationFailure, KmipRequestError) as exc:
            failure = (
                exc
                if isinstance(exc, UpgradeVerificationFailure)
                else UpgradeVerificationFailure(
                    uid=exc.uid or 'server',
                    check=f'{args.phase} {exc.operation}',
                    expected='Success',
                    actual=str(exc),
                )
            )
            emit_failure_report(
                failure,
                old_version=args.old_version,
                new_version=args.new_version,
                backend=args.backend,
                variant=args.variant,
                phase=args.phase,
                seed=seed,
                replay_cmd=replay,
            )
            return 1
        print(
            f'Verified {args.phase} against snapshot (seed={seed}): '
            f"objects={len(snap['objects'])} ciphertexts={len(snap['ciphertexts'])} "
            f"signatures={len(snap['signatures'])}"
        )
        return 0

    return 1


if __name__ == '__main__':
    sys.exit(main())

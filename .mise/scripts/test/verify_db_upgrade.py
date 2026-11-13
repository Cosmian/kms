#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seed, snapshot and verify live KMS upgrades using one shared set of recipes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kmip_json_client import (
    DEFAULT_ACTIVATION_DATE,
    FUTURE_ACTIVATION_DATE,
    JSON,
    KmipClient,
    KmipRequestError,
    build_certify,
    build_create_key_pair,
    build_create_symmetric_key,
    build_cryptographic_request,
    build_get_attributes,
    build_import,
    build_signature_request,
    extract_all_tags,
    find_all_tag_values,
    is_unsupported_feature_error,
    link_attribute,
    make_mtls_context,
    name_attribute,
    request,
    required_value,
    tag_attribute,
    ttlv,
    vendor_attribute,
    walk,
)

GRANTEE_USER = 'user.client@acme.com'
MUTATED_UID = 'bulk_aes_256'
MUTATED_NAME = 'bulk-shared-aes-256-candidate'
CANARY_UID = 'upgrade_post_migration_canary'
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
COVERCRYPT_POLICY_HEX = (
    json.dumps(
        {
            'Security Level::<': ['Protected', 'Confidential'],
            'Department': ['MKG', 'FIN'],
        },
        separators=(',', ':'),
    )
    .encode()
    .hex()
    .upper()
)


class UpgradeVerificationFailure(Exception):
    """An invariant failed, rather than a server or transport operation."""

    def __init__(self, *, uid: str, check: str, expected: Any, actual: Any) -> None:
        self.uid, self.check, self.expected, self.actual = uid, check, expected, actual
        super().__init__(f'{uid}: {check}: expected={expected!r}, actual={actual!r}')


def check(uid: str, label: str, expected: Any, actual: Any) -> None:
    if expected != actual:
        raise UpgradeVerificationFailure(
            uid=uid, check=label, expected=expected, actual=actual
        )


@dataclass(frozen=True)
class Recipe:
    """Object inputs shared by deterministic and seeded-random population."""

    uid: str
    kind: str = 'aes'
    bits: int = 256
    curve: str = 'P256'
    state: str = 'Active'
    tags: tuple[str, ...] = ()
    kek: str | None = None
    name: str | None = None
    cert_from: str | None = None
    cert_hex: str = ''
    with_cert: bool = False
    material_hex: str = ''
    grants: tuple[tuple[str, tuple[str, ...]], ...] = ()
    links: tuple[tuple[str, str], ...] = ()


def fixed_recipes(sample_hex: str, variant: str) -> list[Recipe]:
    recipes = [
        Recipe('mig_kek', grants=((GRANTEE_USER, ('get', 'encrypt', 'decrypt')),)),
        Recipe('mig_wrapped', kek='mig_kek'),
        Recipe('mig_rsa', 'rsa', bits=2048),
        Recipe('mig_cert', 'certificate', cert_from='mig_rsa'),
        Recipe('mig_revoked', state='Deactivated'),
        Recipe('bulk_aes_128', bits=128),
        Recipe('bulk_aes_192', bits=192),
        Recipe(
            'bulk_aes_256',
            name='bulk-shared-aes-256',
            tags=('bulk', 'env:prod/eu', 'émoji-🔐'),
            grants=(
                (GRANTEE_USER, ('encrypt', 'decrypt')),
                ('bulk_auditor', ('get', 'locate')),
            ),
            links=(('CertificateLink', 'mig_cert'),),
        ),
        Recipe('bulk_sym_wrapped', kek='mig_kek'),
        Recipe('bulk_wrapped_2', kek='bulk_aes_256'),
        Recipe('bulk_rsa_3072', 'rsa', bits=3072, with_cert=True),
        Recipe('bulk_ec_p256', 'ec'),
        Recipe('bulk_ec_p384', 'ec', curve='P384'),
        Recipe(
            'bulk_secret_data', 'secret', material_hex='DEADBEEFCAFE0123456789ABCDEF'
        ),
        Recipe('bulk_opaque', 'opaque', material_hex='48656C6C6F204F7061717565'),
        Recipe('bulk_preactive', state='PreActive'),
        Recipe('bulk_compromised', state='Compromised'),
        Recipe('bulk_destroyed', state='Destroyed'),
    ]
    if sample_hex:
        recipes.append(Recipe('mig_imported_cert', 'certificate', cert_hex=sample_hex))
    if variant == 'non-fips':
        recipes.extend(
            Recipe('bulk_' + kind, kind, tags=('bulk', 'non-fips'))
            for kind in ('ed25519', 'covercrypt')
        )
    return recipes


def random_recipes(
    seed: int, count: int, sample_hex: str, variant: str
) -> list[Recipe]:
    """Randomize recipe inputs, not a second implementation of their KMIP operations."""
    rng = random.Random(seed)
    kinds = [
        'aes_active',
        'aes_wrapped',
        'ec_keypair',
        'rsa_cert',
        'secret_data',
        'opaque_object',
        'lifecycle',
    ]
    if variant == 'non-fips':
        kinds += ['ed25519', 'covercrypt']
    chosen = [kinds[i % len(kinds)] for i in range(count)]
    rng.shuffle(chosen)
    keks = ['mig_kek', 'bulk_aes_256']
    recipes = []
    for i, kind in enumerate(chosen):
        uid = f'rnd_{seed}_{i:02d}_{kind}'
        tags = (
            'rnd',
            f'rnd-seed-{seed}',
            *rng.sample(UNICODE_TAG_POOL, rng.randint(1, 2)),
        )
        fields: JSON = {}
        if kind == 'aes_active':
            fields = {'bits': rng.choice([128, 192, 256]), 'name': f'name-{uid}'}
            if rng.choice([True, False]):
                fields['grants'] = ((GRANTEE_USER, ('encrypt', 'decrypt', 'get')),)
            if fields['bits'] == 256:
                keks.append(uid)
        elif kind == 'aes_wrapped':
            fields = {'bits': rng.choice([128, 192, 256]), 'kek': rng.choice(keks)}
        elif kind == 'ec_keypair':
            fields = {'kind': 'ec', 'curve': rng.choice(['P256', 'P384'])}
        elif kind == 'rsa_cert':
            fields = {
                'kind': 'rsa',
                'bits': 2048,
                'with_cert': True,
                'cert_hex': (
                    sample_hex if sample_hex and rng.choice([True, False]) else ''
                ),
            }
        elif kind in ('secret_data', 'opaque_object'):
            fields = {
                'kind': 'secret' if kind == 'secret_data' else 'opaque',
                'material_hex': rng.randbytes(
                    rng.randint(16, 128 if kind == 'secret_data' else 256)
                )
                .hex()
                .upper(),
            }
        elif kind == 'lifecycle':
            fields = {
                'state': rng.choice(
                    ['PreActive', 'Deactivated', 'Compromised', 'Destroyed']
                )
            }
        else:
            fields = {'kind': kind}
        recipes.append(Recipe(uid, tags=tags, **fields))
    return recipes


def object_record(recipe: Recipe, uid: str, object_type: str, tags: list[str]) -> JSON:
    return {
        'uid': uid,
        'object_type': object_type,
        'expected_state': recipe.state,
        'user_tags': tags,
        'grants': dict(recipe.grants) if uid == recipe.uid else {},
        'wrapping_key_uid': recipe.kek,
    }


def create_recipe(
    client: KmipClient, recipe: Recipe, public_ids: dict[str, str]
) -> list[JSON]:
    """Execute a recipe once; capture actual public IDs rather than guessing them."""
    tags = sorted(recipe.tags or ('mig' if recipe.uid.startswith('mig_') else 'bulk',))
    uid = recipe.uid
    if recipe.kind == 'aes':
        client.kmip(
            build_create_symmetric_key(
                uid,
                length=recipe.bits,
                tags=tags,
                wrapping_key_uid=recipe.kek,
                name=recipe.name,
                activation_date=(
                    FUTURE_ACTIVATION_DATE
                    if recipe.state == 'PreActive'
                    else DEFAULT_ACTIVATION_DATE
                ),
            )
        )
        items = [object_record(recipe, uid, 'SymmetricKey', tags)]
    elif recipe.kind in ('rsa', 'ec', 'ed25519', 'covercrypt'):
        algorithm = {
            'rsa': 'RSA',
            'ec': 'ECDSA',
            'ed25519': 'Ed25519',
            'covercrypt': 'CoverCrypt',
        }[recipe.kind]
        extra = (
            [
                ttlv('ObjectType', 'PrivateKey', 'Enumeration'),
                vendor_attribute(
                    'cover_crypt_access_structure', COVERCRYPT_POLICY_HEX, 'ByteString'
                ),
            ]
            if recipe.kind == 'covercrypt'
            else []
        )
        response = client.kmip(
            build_create_key_pair(
                uid,
                algorithm=algorithm,
                length=recipe.bits,
                curve=recipe.curve,
                tags=tags,
                extra_attributes=extra,
            )
        )
        public_uid = required_value(response, 'PublicKeyUniqueIdentifier')
        public_ids[uid] = public_uid
        items = [
            object_record(recipe, uid, 'PrivateKey', tags),
            object_record(recipe, public_uid, 'PublicKey', tags),
        ]
        if recipe.kind in ('rsa', 'ec'):
            items[0]['signature'] = {
                'public_uid': public_uid,
                'rsa': recipe.kind == 'rsa',
            }
        if recipe.with_cert:
            cert_uid = 'bulk_cert_2' if uid == 'bulk_rsa_3072' else uid + '_cert'
            certificate = (
                build_import(cert_uid, 'Certificate', recipe.cert_hex, tags)
                if recipe.cert_hex
                else build_certify(public_uid, cert_uid, tags)
            )
            client.kmip(certificate)
            items.append(object_record(recipe, cert_uid, 'Certificate', tags))
    else:
        kind = {
            'certificate': 'Certificate',
            'secret': 'SecretData',
            'opaque': 'OpaqueObject',
        }[recipe.kind]
        payload = (
            build_certify(public_ids[recipe.cert_from], uid, tags)
            if recipe.cert_from
            else build_import(
                uid,
                kind,
                recipe.cert_hex or recipe.material_hex,
                tags,
            )
        )
        client.kmip(payload)
        items = [object_record(recipe, uid, kind, tags)]
    for kind, linked_uid in recipe.links:
        client.kmip(
            request(
                'SetAttribute',
                uid,
                ttlv('NewAttribute', [link_attribute(kind, linked_uid)]),
            )
        )
    for user, operations in recipe.grants:
        client.grant_access(uid, user, list(operations))
    if recipe.state in ('Deactivated', 'Compromised', 'Destroyed'):
        reason = {
            'Deactivated': 'CessationOfOperation',
            'Compromised': 'KeyCompromise',
            'Destroyed': 'Superseded',
        }[recipe.state]
        client.kmip(
            request(
                'Revoke',
                uid,
                ttlv(
                    'RevocationReason',
                    [ttlv('RevocationReasonCode', reason, 'Enumeration')],
                ),
            )
        )
        if recipe.state == 'Destroyed':
            client.kmip(request('Destroy', uid))
    return items


def populate(
    client: KmipClient, recipes: list[Recipe]
) -> tuple[list[JSON], list[JSON]]:
    items, skipped = [], []
    public_ids: dict[str, str] = {}
    for recipe in recipes:
        try:
            items.extend(create_recipe(client, recipe, public_ids))
        except KmipRequestError as error:
            if (
                recipe.kind not in ('ed25519', 'covercrypt')
                or error.operation != 'CreateKeyPair'
                or not is_unsupported_feature_error(error)
            ):
                raise
            print(f'SKIP {recipe.uid}: {error}', file=sys.stderr)
            skipped.append({'uid': recipe.uid, 'reason': str(error)})
    return items, skipped


def extract_normalized_attributes(node: Any) -> dict[str, list[str]]:
    attributes: dict[str, set[str]] = {}
    for item in walk(node, exclude=('RandomNumberGenerator',)):
        key = str(item.get('tag', '')).lower().replace('_', '').replace(' ', '')
        value = item.get('value')
        if key in EXTRACTED_ATTR_KEYS and not isinstance(value, (dict, list)):
            attributes.setdefault(key, set()).add(str(value))
    return {key: sorted(values) for key, values in attributes.items()}


def extract_object_material_digest(response: JSON, uid: str = 'Get') -> str:
    material = [
        item
        for item in walk(response)
        if item.get('tag') in ('KeyMaterial', 'CertificateValue', 'OpaqueDataValue')
        or (item.get('tag') == 'KeyValue' and item.get('type') == 'ByteString')
    ]
    if not material:
        raise UpgradeVerificationFailure(
            uid=uid,
            check='material present',
            expected='key or object material',
            actual='missing',
        )
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()


def access_list(client: KmipClient, uid: str) -> JSON:
    return {
        entry['user_id']: sorted(entry['operations'])
        for entry in client.list_access(uid)
    }


def encrypt_and_check(client: KmipClient, uid: str, plaintext: str) -> JSON:
    response = client.kmip(build_cryptographic_request('Encrypt', uid, plaintext))
    ciphertext = {
        'uid': uid,
        'plaintext_hex': plaintext,
        'ciphertext_hex': required_value(response, 'Data'),
        'iv_hex': required_value(response, 'IVCounterNonce'),
        'auth_tag_hex': required_value(response, 'AuthenticatedEncryptionTag'),
    }
    decrypt_and_check(client, ciphertext)
    return ciphertext


def decrypt_and_check(client: KmipClient, ciphertext: JSON) -> None:
    uid = ciphertext['uid']
    response = client.kmip(
        build_cryptographic_request(
            'Decrypt',
            uid,
            ciphertext['ciphertext_hex'],
            iv=ciphertext['iv_hex'],
            auth_tag=ciphertext['auth_tag_hex'],
        )
    )
    check(
        uid,
        'Decrypt plaintext',
        ciphertext['plaintext_hex'],
        required_value(response, 'Data').upper(),
    )


def verify_signature(client: KmipClient, signature: JSON) -> None:
    uid = signature['public_uid']
    response = client.kmip(
        build_signature_request(
            uid,
            signature['data_hex'],
            signature=signature['signature_hex'],
            rsa=signature['rsa'],
        )
    )
    check(
        uid, 'SignatureVerify', 'Valid', required_value(response, 'ValidityIndicator')
    )


def locate(client: KmipClient, tag: str) -> list[str]:
    return sorted(
        set(
            find_all_tag_values(
                client.kmip(
                    request('Locate', None, ttlv('Attributes', [tag_attribute([tag])]))
                ),
                'UniqueIdentifier',
            )
        )
    )


def _assert_kmip_rejected(error: KmipRequestError, *, uid: str, check: str) -> None:
    message = f'{error.result_reason or ""} {error.server_message}'.lower()
    if error.http_status not in (400, 401, 403, 404, 422) or not any(
        marker in message
        for marker in (
            'not_found',
            'not found',
            'permission',
            'denied',
            'unauthori',
            'forbidden',
        )
    ):
        raise UpgradeVerificationFailure(
            uid=uid,
            check=check,
            expected='4xx permission denial or not-found',
            actual=str(error),
        )


def assert_denied(client: KmipClient, payload: JSON) -> None:
    uid = required_value(payload, 'UniqueIdentifier')
    try:
        client.kmip(payload)
    except KmipRequestError as error:
        _assert_kmip_rejected(error, uid=uid, check=payload['tag'] + ' denial')
        return
    raise UpgradeVerificationFailure(
        uid=uid, check=payload['tag'] + ' denial', expected='denied', actual='succeeded'
    )


def check_grantee_denials(owner: KmipClient, grantee: KmipClient) -> None:
    assert_denied(grantee, request('Export', 'bulk_aes_256'))
    assert_denied(
        grantee, build_cryptographic_request('Encrypt', 'mig_wrapped', '48656C6C6F')
    )
    owner.kmip(build_get_attributes('mig_kek'))


def take_snapshot(
    owner: KmipClient, grantee: KmipClient, items: list[JSON], seed: int
) -> JSON:
    """Validate the seed on the old server before recording any upgrade expectations."""
    objects, ciphertexts, signatures = {}, [], []
    tags: set[str] = set()
    for item in items:
        uid = item['uid']
        attributes = extract_normalized_attributes(
            owner.kmip(build_get_attributes(uid))
        )
        all_tags = extract_all_tags(
            owner.kmip(build_get_attributes(uid, include_tags=True))
        )
        user_tags = [tag for tag in all_tags if not tag.startswith('_')]
        grants = access_list(owner, uid)
        check(uid, 'seed State', [item['expected_state']], attributes.get('state'))
        check(uid, 'seed tags', item['user_tags'], user_tags)
        check(
            uid,
            'seed grants',
            {user: sorted(ops) for user, ops in item['grants'].items()},
            grants,
        )
        tags.update(user_tags)
        material = None
        if item['expected_state'] == 'Active':
            material = extract_object_material_digest(
                owner.kmip(request('Get', uid)), uid
            )
            if item['object_type'] == 'SymmetricKey':
                plaintext = f'kms-upgrade-plain-{seed}-{uid}'.encode().hex().upper()
                for actor, client in (('owner', owner), ('grantee', grantee)):
                    if actor == 'grantee' and not {'encrypt', 'decrypt'} <= set(
                        grants.get(GRANTEE_USER, [])
                    ):
                        continue
                    ciphertexts.append(
                        {**encrypt_and_check(client, uid, plaintext), 'actor': actor}
                    )
            if 'signature' in item:
                signature = {
                    **item['signature'],
                    'data_hex': f'kms-sign-{seed}-{uid}'.encode().hex().upper(),
                }
                response = owner.kmip(
                    build_signature_request(
                        uid, signature['data_hex'], rsa=signature['rsa']
                    )
                )
                signature['signature_hex'] = required_value(response, 'SignatureData')
                verify_signature(owner, signature)
                signatures.append(signature)
        objects[uid] = {
            'attributes': attributes,
            'user_tags': user_tags,
            'material_digest': material,
            'grants': grants,
        }
    check_grantee_denials(owner, grantee)
    return {
        'snapshot_version': 2,
        'seed': seed,
        'objects': objects,
        'ciphertexts': ciphertexts,
        'signatures': signatures,
        'locate_by_tag': {tag: locate(owner, tag) for tag in sorted(tags)},
    }


def _compare_attributes(uid: str, baseline: JSON, current: JSON) -> None:
    for key, expected in baseline.items():
        actual = current.get(key, [])
        if key == 'digestvalue':
            check(uid, 'DigestValue preserved', True, set(expected) <= set(actual))
        else:
            check(uid, 'attribute ' + key, expected, actual)


def mutate_candidate(owner: KmipClient, snapshot: JSON) -> None:
    owner.kmip(
        request(
            'SetAttribute',
            MUTATED_UID,
            ttlv('NewAttribute', [name_attribute(MUTATED_NAME)]),
        )
    )
    names = extract_normalized_attributes(
        owner.kmip(build_get_attributes(MUTATED_UID))
    ).get('namevalue', [])
    check(MUTATED_UID, 'post-upgrade Name set', True, MUTATED_NAME in names)
    owner.kmip(build_create_symmetric_key(CANARY_UID, tags=['canary']))
    snapshot['candidate'] = encrypt_and_check(
        owner, CANARY_UID, '504F53545F555047524144455F43414E415259'
    )
    snapshot['candidate']['name_values'] = names


def check_rewrap(owner: KmipClient, snapshot: JSON) -> None:
    response = owner.kmip(request('ReKey', 'mig_kek'))
    new_uid = required_value(response, 'UniqueIdentifier')
    check('mig_kek', 'ReKey allocates new KEK', True, new_uid != 'mig_kek')
    attributes = extract_normalized_attributes(
        owner.kmip(build_get_attributes('mig_wrapped'))
    )
    check(
        'mig_wrapped',
        'rewrap link',
        True,
        new_uid in attributes.get('linkedobjectidentifier', []),
    )
    for ciphertext in snapshot['ciphertexts']:
        if ciphertext['uid'] == 'mig_wrapped' and ciphertext['actor'] == 'owner':
            decrypt_and_check(owner, ciphertext)


def verify_against_snapshot(
    owner: KmipClient,
    grantee: KmipClient,
    snapshot: JSON,
    *,
    phase: str,
    backend: str,
    mutate: bool = False,
) -> None:
    """Check the same snapshot on the candidate, its restart, and the untouched backup."""
    if phase in ('candidate-restart', 'restore') and 'candidate' not in snapshot:
        raise ValueError('Snapshot has no post-upgrade canary')
    for uid, baseline in snapshot['objects'].items():
        attributes = extract_normalized_attributes(
            owner.kmip(build_get_attributes(uid))
        )
        expected = baseline['attributes']
        if phase == 'candidate-restart' and uid == MUTATED_UID:
            expected = {
                **expected,
                'namevalue': snapshot['candidate']['name_values'],
            }
        _compare_attributes(uid, expected, attributes)
        tags = extract_all_tags(
            owner.kmip(build_get_attributes(uid, include_tags=True))
        )
        check(
            uid,
            'user tags',
            baseline['user_tags'],
            [tag for tag in tags if not tag.startswith('_')],
        )
        if (
            phase != 'restore'
            and backend != 'redis'
            and 'Certificate' in attributes.get('objecttype', [])
        ):
            check(
                uid,
                'certificate serial tag backfill',
                1,
                sum(tag.startswith('_serial=') for tag in tags),
            )
        if baseline['material_digest'] is not None:
            check(
                uid,
                'material digest',
                baseline['material_digest'],
                extract_object_material_digest(owner.kmip(request('Get', uid)), uid),
            )
        check(uid, 'access grants', baseline['grants'], access_list(owner, uid))
    for ciphertext in snapshot['ciphertexts']:
        decrypt_and_check(
            owner if ciphertext['actor'] == 'owner' else grantee, ciphertext
        )
    for signature in snapshot['signatures']:
        verify_signature(owner, signature)
    for tag, expected_uids in snapshot['locate_by_tag'].items():
        check(
            tag,
            'Locate preserves objects',
            True,
            set(expected_uids) <= set(locate(owner, tag)),
        )
    check_grantee_denials(owner, grantee)
    if mutate:
        mutate_candidate(owner, snapshot)
    elif phase == 'candidate-restart':
        decrypt_and_check(owner, snapshot['candidate'])
        check_rewrap(owner, snapshot)
    elif phase == 'restore':
        assert_denied(owner, build_get_attributes(CANARY_UID))


def write_snapshot(path: Path, snapshot: JSON) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(snapshot, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def emit_failure_report(error: Exception, args: argparse.Namespace) -> None:
    fields = {
        'Upgrade path': f'{args.old_version} -> {args.new_version}',
        'Backend / variant': f'{args.backend} / {args.variant}',
        'Phase': args.phase,
        'Seed': args.seed,
        'Object UID': getattr(error, 'uid', 'harness'),
        'Failed check': getattr(error, 'check', getattr(error, 'operation', 'harness')),
        'Expected': getattr(error, 'expected', 'success'),
        'Actual': getattr(error, 'actual', str(error)),
    }
    print(
        'DB UPGRADE GATE FAILURE\n'
        + '\n'.join(f'  {key}: {value}' for key, value in fields.items())
        + f'\n  Replay: {args.replay_cmd}',
        file=sys.stderr,
    )
    if summary_path := os.environ.get('GITHUB_STEP_SUMMARY'):
        rows = '\n'.join(
            f'| {key} | {str(value).replace("|", "/").replace(chr(10), " ")} |'
            for key, value in fields.items()
        )
        with Path(summary_path).open('a', encoding='utf-8') as summary:
            summary.write(
                f'### DB Upgrade Gate Failure\n\n| Field | Value |\n|---|---|\n{rows}\n\n'
                f'```bash\n{args.replay_cmd}\n```\n'
            )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('seed', 'verify'))
    parser.add_argument('--url', required=True)
    parser.add_argument('--snapshot', type=Path, required=True)
    for name in ('ca-cert', 'client-cert', 'client-key', 'grantee-cert', 'grantee-key'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sample-cert', type=Path)
    parser.add_argument('--variant', choices=('fips', 'non-fips'), default='fips')
    parser.add_argument(
        '--backend',
        choices=('sqlite', 'postgresql', 'mysql', 'redis'),
        default='sqlite',
    )
    parser.add_argument('--seed', type=int, default=424242)
    parser.add_argument('--count', type=int, default=10)
    parser.add_argument('--old-version', default='unknown')
    parser.add_argument('--new-version', default='candidate')
    parser.add_argument(
        '--phase',
        choices=('candidate', 'candidate-restart', 'restore'),
        default='candidate',
    )
    parser.add_argument('--mutate', action='store_true')
    parser.add_argument('--replay-cmd', default='')
    args = parser.parse_args(argv)
    if args.count < 0 or (
        args.mutate and (args.command != 'verify' or args.phase != 'candidate')
    ):
        parser.error(
            'Count must be nonnegative; --mutate is only valid for candidate verification'
        )
    if args.command == 'seed':
        args.phase = 'seed'
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        owner = KmipClient(
            args.url,
            ssl_context=make_mtls_context(
                args.ca_cert, args.client_cert, args.client_key
            ),
        )
        grantee = KmipClient(
            args.url,
            ssl_context=make_mtls_context(
                args.ca_cert, args.grantee_cert, args.grantee_key
            ),
        )
        if args.command == 'seed':
            sample_hex = (
                ssl.PEM_cert_to_DER_cert(args.sample_cert.read_text()).hex().upper()
                if args.sample_cert
                else ''
            )
            recipes = fixed_recipes(sample_hex, args.variant) + random_recipes(
                args.seed, args.count, sample_hex, args.variant
            )
            items, skipped = populate(owner, recipes)
            snapshot = {
                **take_snapshot(owner, grantee, items, args.seed),
                'variant': args.variant,
                'skipped': skipped,
            }
            write_snapshot(args.snapshot, snapshot)
        else:
            snapshot = json.loads(args.snapshot.read_text(encoding='utf-8'))
            if snapshot['snapshot_version'] != 2 or not snapshot['objects']:
                raise ValueError('Invalid or empty upgrade snapshot')
            args.seed = snapshot['seed']
            verify_against_snapshot(
                owner,
                grantee,
                snapshot,
                phase=args.phase,
                backend=args.backend,
                mutate=args.mutate,
            )
            if args.mutate:
                write_snapshot(args.snapshot, snapshot)
        print(
            f'PASS {args.phase}: {len(snapshot["objects"])} objects, seed={args.seed}'
        )
        return 0
    except (
        KmipRequestError,
        UpgradeVerificationFailure,
        OSError,
        ValueError,
        KeyError,
    ) as error:
        emit_failure_report(error, args)
        return 1


if __name__ == '__main__':
    sys.exit(main())

# -*- coding: utf-8 -*-
"""Regression checks for the live database upgrade harness."""

from __future__ import annotations

import copy
import io
import json
import unittest
from unittest.mock import Mock, patch

from kmip_json_client import (
    KmipClient,
    KmipRequestError,
    build_create_key_pair,
    extract_all_tags,
    is_unsupported_feature_error,
    required_value,
    ttlv,
)
from verify_db_upgrade import (
    MUTATED_NAME,
    MUTATED_UID,
    Recipe,
    UpgradeVerificationFailure,
    _assert_kmip_rejected,
    _compare_attributes,
    extract_normalized_attributes,
    extract_object_material_digest,
    fixed_recipes,
    populate,
    random_recipes,
    verify_against_snapshot,
)


class ComparisonTests(unittest.TestCase):
    def test_attributes_ignore_synthetic_rng_but_preserve_state(self) -> None:
        response = {
            'tag': 'Attributes',
            'value': [
                {'tag': 'State', 'type': 'Enumeration', 'value': 'Active'},
                {
                    'tag': 'RandomNumberGenerator',
                    'value': [
                        {'tag': 'CryptographicAlgorithm', 'value': 'AES'},
                        {'tag': 'CryptographicLength', 'value': 256},
                    ],
                },
            ],
        }
        self.assertEqual(extract_normalized_attributes(response), {'state': ['Active']})
        _compare_attributes('key', {'digestvalue': ['A']}, {'digestvalue': ['A', 'B']})
        with self.assertRaises(UpgradeVerificationFailure):
            _compare_attributes('key', {'state': ['Active']}, {'state': ['Destroyed']})

    def test_material_change_changes_digest(self) -> None:
        left = {'tag': 'KeyMaterial', 'type': 'ByteString', 'value': 'AAAA'}
        right = {'tag': 'KeyMaterial', 'type': 'ByteString', 'value': 'AAAB'}
        self.assertNotEqual(
            extract_object_material_digest(left), extract_object_material_digest(right)
        )

    def test_structured_key_material_is_compared_not_just_scalar_fields(self) -> None:
        response = ttlv('KeyMaterial', [ttlv('Key', [1, 2, 3], 'ByteString')])
        modified = copy.deepcopy(response)
        modified['value'][0]['value'][0] = 4
        self.assertNotEqual(
            extract_object_material_digest(response),
            extract_object_material_digest(modified),
        )
        with self.assertRaises(UpgradeVerificationFailure):
            extract_object_material_digest({'tag': 'GetResponse', 'value': []})

    def test_wrapped_key_bytestring_is_material_without_nested_key_material(
        self,
    ) -> None:
        left = ttlv('KeyValue', 'AAAA', 'ByteString')
        right = ttlv('KeyValue', 'AAAB', 'ByteString')
        self.assertNotEqual(
            extract_object_material_digest(left), extract_object_material_digest(right)
        )

    def test_malformed_vendor_tags_fail_instead_of_disappearing(self) -> None:
        response = {
            'tag': 'Attribute',
            'value': [
                {'tag': 'VendorIdentification', 'value': 'cosmian'},
                {'tag': 'AttributeName', 'value': 'tag'},
                {'tag': 'AttributeValue', 'value': '{broken'},
            ],
        }
        with self.assertRaises(KmipRequestError):
            extract_all_tags(response)

    def test_restart_expectations_do_not_overwrite_the_backup_snapshot(self) -> None:
        original = {'state': ['Active'], 'namevalue': ['original']}
        snapshot = {
            'objects': {
                MUTATED_UID: {
                    'attributes': original,
                    'user_tags': [],
                    'material_digest': None,
                    'grants': {},
                }
            },
            'ciphertexts': [],
            'signatures': [],
            'locate_by_tag': {},
            'candidate': {'uid': 'canary', 'name_values': [MUTATED_NAME]},
        }
        client = Mock(spec=KmipClient)
        client.kmip.side_effect = [
            ttlv(
                'Attributes',
                [
                    ttlv('State', 'Active'),
                    ttlv('NameValue', MUTATED_NAME),
                ],
            ),
            ttlv('Attributes', []),
        ]
        client.list_access.return_value = []
        with (
            patch('verify_db_upgrade.check_grantee_denials'),
            patch('verify_db_upgrade.decrypt_and_check') as decrypt,
            patch('verify_db_upgrade.check_rewrap') as rewrap,
        ):
            verify_against_snapshot(
                client, client, snapshot, phase='candidate-restart', backend='sqlite'
            )
        self.assertEqual(original, {'state': ['Active'], 'namevalue': ['original']})
        decrypt.assert_called_once_with(client, snapshot['candidate'])
        rewrap.assert_called_once_with(client, snapshot)


class FailureTests(unittest.TestCase):
    def test_server_errors_are_never_optional_feature_skips(self) -> None:
        error = KmipRequestError(
            operation='CreateKeyPair',
            uid='optional',
            http_status=500,
            server_message='algorithm not supported',
        )
        self.assertFalse(is_unsupported_feature_error(error))

    def test_known_unsupported_optional_feature_is_recognized(self) -> None:
        error = KmipRequestError(
            operation='CreateKeyPair',
            uid='optional',
            http_status=422,
            server_message='unknown variant `Ed25519`',
        )
        self.assertTrue(is_unsupported_feature_error(error))

    def test_an_outage_cannot_satisfy_a_permission_denial(self) -> None:
        error = KmipRequestError(
            operation='Export', uid='key', http_status=503, server_message='unavailable'
        )
        with self.assertRaises(UpgradeVerificationFailure):
            _assert_kmip_rejected(error, uid='key', check='denial')

    def test_missing_response_fields_are_errors(self) -> None:
        with self.assertRaises(KmipRequestError):
            required_value(ttlv('EncryptResponse', []), 'IVCounterNonce')


class RecipeTests(unittest.TestCase):
    @staticmethod
    def client() -> Mock:
        client = Mock(spec=KmipClient)

        def respond(payload: dict) -> dict:
            uid = required_value(payload, 'UniqueIdentifier')
            return ttlv(
                payload['tag'] + 'Response',
                [ttlv('PublicKeyUniqueIdentifier', uid + '_pk')],
            )

        client.kmip.side_effect = respond
        return client

    def test_fixed_population_keeps_the_object_type_and_lifecycle_matrix(self) -> None:
        items, skipped = populate(self.client(), fixed_recipes('00', 'fips'))
        self.assertEqual(len(items), 24)
        self.assertEqual(len({item['uid'] for item in items}), len(items))
        self.assertEqual(skipped, [])
        self.assertEqual(
            {item['object_type'] for item in items},
            {
                'SymmetricKey',
                'PrivateKey',
                'PublicKey',
                'Certificate',
                'SecretData',
                'OpaqueObject',
            },
        )
        self.assertEqual(
            {item['expected_state'] for item in items},
            {'Active', 'PreActive', 'Deactivated', 'Compromised', 'Destroyed'},
        )
        by_uid = {item['uid']: item for item in items}
        self.assertEqual(by_uid['mig_wrapped']['wrapping_key_uid'], 'mig_kek')
        self.assertIn('bulk_cert_2', by_uid)
        self.assertIn('mig_imported_cert', by_uid)

    def test_random_inputs_are_replayable_and_keep_non_fips_recipes(self) -> None:
        left = random_recipes(42, 18, '00', 'non-fips')
        self.assertEqual(left, random_recipes(42, 18, '00', 'non-fips'))
        self.assertNotEqual(left, random_recipes(43, 18, '00', 'non-fips'))
        self.assertEqual(
            {recipe.kind for recipe in left},
            {'aes', 'rsa', 'ec', 'secret', 'opaque', 'ed25519', 'covercrypt'},
        )
        self.assertEqual(len(left), 18)

    def test_rsa_and_ec_masks_keep_the_fips_key_pair_constraints(self) -> None:
        for algorithm, expected in (('RSA', (41, 22)), ('ECDSA', (1, 2))):
            payload = build_create_key_pair('key', algorithm=algorithm, tags=['test'])
            private, public = payload['value'][1:3]
            self.assertEqual(
                (
                    int(required_value(private, 'CryptographicUsageMask')),
                    int(required_value(public, 'CryptographicUsageMask')),
                ),
                expected,
            )

    def test_only_the_optional_creation_can_be_skipped(self) -> None:
        client = self.client()
        client.kmip.side_effect = KmipRequestError(
            operation='CreateKeyPair', http_status=422, server_message='unknown variant'
        )
        with patch('sys.stderr', new_callable=io.StringIO):
            items, skipped = populate(client, [Recipe('optional', 'ed25519')])
        self.assertEqual(items, [])
        self.assertEqual(skipped[0]['uid'], 'optional')
        client = self.client()
        client.grant_access.side_effect = KmipRequestError(
            operation='GrantAccess', http_status=422, server_message='unsupported'
        )
        with self.assertRaises(KmipRequestError):
            populate(
                client, [Recipe('optional', 'ed25519', grants=(('user', ('get',)),))]
            )


class TransportTests(unittest.TestCase):
    def test_ttlv_type_precedes_value_for_old_streaming_deserializers(self) -> None:
        node = ttlv('ObjectType', 'SymmetricKey', 'Enumeration')
        self.assertEqual(list(json.loads(json.dumps(node))), ['tag', 'type', 'value'])

    @staticmethod
    def response(payload: object) -> Mock:
        response = Mock()
        response.read.side_effect = io.BytesIO(json.dumps(payload).encode()).read
        response.status = 200
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_kmip_error_on_http_success_is_not_a_success(self) -> None:
        error = ttlv('Error', [ttlv('ResultReason', 'PermissionDenied')])
        with patch('urllib.request.urlopen', return_value=self.response(error)):
            with self.assertRaises(KmipRequestError):
                KmipClient('http://127.0.0.1').kmip(ttlv('Get', []))

    def test_an_invalid_access_list_is_not_an_empty_list(self) -> None:
        with patch('urllib.request.urlopen', return_value=self.response({})):
            with self.assertRaises(KmipRequestError):
                KmipClient('http://127.0.0.1').list_access('key')


if __name__ == '__main__':
    unittest.main()

# -*- coding: utf-8 -*-
import importlib.util
import pathlib
import types
import unittest
from unittest.mock import patch


MODULE_PATH = (
    pathlib.Path(__file__).parents[2] / 'plugins' / 'module_utils' / 'kms_api.py'
)
SPEC = importlib.util.spec_from_file_location('kms_api', MODULE_PATH)
KMS_API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KMS_API)


class KmsApiTests(unittest.TestCase):
    def test_long_integer_round_trip(self):
        for value in (0, 3600, (1 << 63) - 1):
            with self.subTest(value=value):
                self.assertEqual(
                    KMS_API.parse_kmip_long_integer(KMS_API.kmip_long_integer(value)),
                    value,
                )

    def test_long_integer_decodes_twos_complement(self):
        self.assertEqual(KMS_API.parse_kmip_long_integer('0xFFFFFFFFFFFFFFFE'), -2)

    def test_find_values_walks_nested_ttlv(self):
        response = {
            'tag': 'GetAttributesResponse',
            'value': [
                {
                    'tag': 'Attributes',
                    'value': [
                        {
                            'tag': 'RotateInterval',
                            'type': 'LongInteger',
                            'value': '0xE10',
                        }
                    ],
                }
            ],
        }
        self.assertEqual(KMS_API.find_values(response, 'RotateInterval'), ['0xE10'])
        self.assertEqual(
            KMS_API.kmip_attribute_map(response), {'RotateInterval': '0xE10'}
        )

    def test_name_attribute_has_kmip_name_type(self):
        self.assertEqual(
            KMS_API.kmip_object_name('service-key'),
            {
                'tag': 'Name',
                'value': [
                    {'tag': 'NameValue', 'type': 'TextString', 'value': 'service-key'},
                    {
                        'tag': 'NameType',
                        'type': 'Enumeration',
                        'value': 'UninterpretedTextString',
                    },
                ],
            },
        )

    def test_access_plan_only_contains_missing_permissions(self):
        self.assertEqual(
            KMS_API.access_changes(
                'present', ['get', 'encrypt'], ['get', 'encrypt', 'decrypt']
            ),
            ['decrypt'],
        )
        self.assertEqual(
            KMS_API.access_changes('absent', ['get', 'encrypt'], ['get', 'decrypt']),
            ['get'],
        )

    def test_rotation_plan_is_idempotent(self):
        desired, changes = KMS_API.rotation_policy_plan(
            {
                'RotateAutomatic': True,
                'RotateInterval': '0x0000000000000E10',
                'RotateOffset': '0x0000000000000000',
                'RotateName': 'service-key',
            },
            'present',
            3600,
            'service-key',
            0,
        )
        self.assertEqual(changes, [])
        self.assertIn('RotateName', desired)

    def test_disabling_missing_rotation_policy_is_a_noop(self):
        self.assertEqual(
            KMS_API.rotation_policy_plan({}, 'absent', None, None, 0), ({}, [])
        )

    def test_disabling_rotation_updates_only_active_values(self):
        _desired, changes = KMS_API.rotation_policy_plan(
            {
                'RotateAutomatic': True,
                'RotateInterval': '0x0000000000000E10',
                'RotateName': 'service-key',
            },
            'absent',
            None,
            None,
            0,
        )
        self.assertEqual(
            changes,
            [
                ('RotateAutomatic', 'Boolean', False),
                ('RotateInterval', 'LongInteger', 0),
            ],
        )

    def test_request_matches_the_real_fetch_url_signature(self):
        # autospec rejects keyword arguments Ansible's fetch_url does not accept
        class Response:
            def read(self):
                return b'{"tag": "LocateResponse"}'

        module = types.SimpleNamespace(
            params={'kms_url': 'http://kms:9998/', 'timeout': 5, 'api_token': 'secret'}
        )
        with patch('ansible.module_utils.urls.fetch_url', autospec=True) as fetch_url:
            fetch_url.return_value = (Response(), {'status': 200})
            self.assertEqual(
                KMS_API.kms_request(module, 'GET', '/health'), {'tag': 'LocateResponse'}
            )
        self.assertEqual(fetch_url.call_args.args[1], 'http://kms:9998/health')
        self.assertEqual(
            fetch_url.call_args.kwargs['headers']['Authorization'], 'Bearer secret'
        )


if __name__ == '__main__':
    unittest.main()

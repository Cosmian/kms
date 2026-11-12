# -*- coding: utf-8 -*-
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


COLLECTION_ROOT = pathlib.Path(__file__).parents[2]
MODULE_UTILS_NAME = 'ansible_collections.cosmian.kms.plugins.module_utils.kms_api'
HELPER_SPEC = importlib.util.spec_from_file_location(
    MODULE_UTILS_NAME,
    COLLECTION_ROOT / 'plugins' / 'module_utils' / 'kms_api.py',
)
KMS_API = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(KMS_API)

for package_name in (
    'ansible_collections',
    'ansible_collections.cosmian',
    'ansible_collections.cosmian.kms',
    'ansible_collections.cosmian.kms.plugins',
    'ansible_collections.cosmian.kms.plugins.module_utils',
):
    if package_name not in sys.modules:
        package = types.ModuleType(package_name)
        package.__path__ = []
        sys.modules[package_name] = package
sys.modules[MODULE_UTILS_NAME] = KMS_API


def load_module(name):
    path = COLLECTION_ROOT / 'plugins' / 'modules' / (name + '.py')
    spec = importlib.util.spec_from_file_location('kms_collection_test_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KMS_ACCESS = load_module('kms_access')
KMS_CERTIFICATE = load_module('kms_certificate')
KMS_KEY = load_module('kms_key')
KMS_ROTATION_POLICY = load_module('kms_rotation_policy')


class ModuleExit(Exception):
    def __init__(self, result):
        self.result = result


class FakeAnsibleModule:
    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode

    def exit_json(self, **result):
        raise ModuleExit(result)

    def fail_json(self, **result):
        raise AssertionError(result)


class KmsModuleTests(unittest.TestCase):
    def test_key_present_is_idempotent(self):
        module = FakeAnsibleModule({'state': 'present', 'name': 'service-key'})
        with (
            patch.object(KMS_KEY, 'AnsibleModule', return_value=module),
            patch.object(KMS_KEY, 'kmip_locate', return_value=['key-uid']),
            patch.object(KMS_KEY, 'kmip_request') as create,
        ):
            with self.assertRaises(ModuleExit) as result:
                KMS_KEY.run_module()
        self.assertFalse(result.exception.result['changed'])
        self.assertEqual(result.exception.result['key_id'], 'key-uid')
        create.assert_not_called()

    def test_key_check_mode_does_not_create(self):
        module = FakeAnsibleModule(
            {'state': 'present', 'name': 'service-key'}, check_mode=True
        )
        with (
            patch.object(KMS_KEY, 'AnsibleModule', return_value=module),
            patch.object(KMS_KEY, 'kmip_locate', return_value=[]),
            patch.object(KMS_KEY, 'kmip_request') as create,
        ):
            with self.assertRaises(ModuleExit) as result:
                KMS_KEY.run_module()
        self.assertTrue(result.exception.result['changed'])
        create.assert_not_called()

    def test_certificate_check_mode_does_not_certify(self):
        module = FakeAnsibleModule(
            {
                'state': 'present',
                'certificate_id': 'service-tls',
                'csr_content': '-----BEGIN CERTIFICATE REQUEST-----',
                'issuer_private_key_id': 'ca-key',
                'issuer_certificate_id': None,
            },
            check_mode=True,
        )
        with (
            patch.object(KMS_CERTIFICATE, 'AnsibleModule', return_value=module),
            patch.object(KMS_CERTIFICATE, 'kmip_locate', return_value=[]),
            patch.object(KMS_CERTIFICATE, 'kmip_request') as certify,
        ):
            with self.assertRaises(ModuleExit) as result:
                KMS_CERTIFICATE.run_module()
        self.assertTrue(result.exception.result['changed'])
        certify.assert_not_called()

    def test_certificate_present_is_idempotent(self):
        module = FakeAnsibleModule(
            {
                'state': 'present',
                'certificate_id': 'service-tls',
                'csr_content': '-----BEGIN CERTIFICATE REQUEST-----',
                'issuer_private_key_id': 'ca-key',
                'issuer_certificate_id': None,
            }
        )
        with (
            patch.object(KMS_CERTIFICATE, 'AnsibleModule', return_value=module),
            patch.object(KMS_CERTIFICATE, 'kmip_locate', return_value=['service-tls']),
            patch.object(KMS_CERTIFICATE, 'kmip_request') as certify,
        ):
            with self.assertRaises(ModuleExit) as result:
                KMS_CERTIFICATE.run_module()
        self.assertFalse(result.exception.result['changed'])
        certify.assert_not_called()

    def test_access_check_mode_does_not_grant(self):
        module = FakeAnsibleModule(
            {
                'object_id': 'key-uid',
                'user_id': 'application',
                'operation_types': ['get', 'encrypt'],
                'state': 'present',
            },
            check_mode=True,
        )
        with (
            patch.object(KMS_ACCESS, 'AnsibleModule', return_value=module),
            patch.object(
                KMS_ACCESS,
                'kms_request',
                return_value=[{'user_id': 'application', 'operations': ['get']}],
            ) as request,
        ):
            with self.assertRaises(ModuleExit) as result:
                KMS_ACCESS.run_module()
        self.assertTrue(result.exception.result['changed'])
        self.assertEqual(result.exception.result['operation_types'], ['encrypt'])
        self.assertEqual(request.call_count, 1)

    def test_rotation_check_mode_does_not_set_attributes(self):
        module = FakeAnsibleModule(
            {
                'object_id': 'key-uid',
                'state': 'present',
                'interval_seconds': 7200,
                'rotate_name': None,
                'offset_seconds': 0,
            },
            check_mode=True,
        )
        response = {
            'tag': 'GetAttributesResponse',
            'value': [
                {
                    'tag': 'Attributes',
                    'value': [
                        {'tag': 'RotateAutomatic', 'type': 'Boolean', 'value': True},
                        {
                            'tag': 'RotateInterval',
                            'type': 'LongInteger',
                            'value': '0x0000000000000E10',
                        },
                        {
                            'tag': 'RotateOffset',
                            'type': 'LongInteger',
                            'value': '0x0000000000000000',
                        },
                    ],
                }
            ],
        }
        with (
            patch.object(KMS_ROTATION_POLICY, 'AnsibleModule', return_value=module),
            patch.object(
                KMS_ROTATION_POLICY, 'kmip_request', return_value=response
            ) as request,
        ):
            with self.assertRaises(ModuleExit) as result:
                KMS_ROTATION_POLICY.run_module()
        self.assertTrue(result.exception.result['changed'])
        self.assertEqual(request.call_count, 1)


if __name__ == '__main__':
    unittest.main()

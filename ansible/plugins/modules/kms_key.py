#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Cosmian
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: kms_key
short_description: Create or destroy a named symmetric key in Cosmian KMS
version_added: "0.1.0"
description:
  - Uses KMIP Locate, Create, and Destroy operations over the KMS JSON API.
  - The KMIP Name attribute is used as the idempotency key.
options:
  state:
    type: str
    choices: [present, absent]
    default: present
    description: Whether the named key should exist.
  name:
    type: str
    required: true
    description: Stable KMIP Name used to find the key on subsequent runs.
  algorithm:
    type: str
    default: AES
    description: KMIP cryptographic algorithm for the symmetric key.
  length:
    type: int
    default: 256
    description: Cryptographic key length in bits.
  kms_url:
    type: str
    default: http://localhost:9998
    description: Base URL of the KMS server.
  api_token:
    type: str
    description: Optional bearer token for KMS authentication.
  validate_certs:
    type: bool
    default: true
    description: Whether to validate the KMS TLS certificate.
  ca_path:
    type: path
    description: CA bundle used to validate the KMS TLS certificate.
  client_cert:
    type: path
    description: PEM client certificate for mutual TLS.
  client_key:
    type: path
    description: PEM client private key for mutual TLS.
  timeout:
    type: int
    default: 30
    description: HTTP request timeout in seconds.
author:
  - Cosmian (@Cosmian)
"""

EXAMPLES = r"""
- name: Ensure an AES key exists
  cosmian.kms.kms_key:
    kms_url: https://kms.example.com
    api_token: "{{ kms_api_token }}"
    name: application-data
    algorithm: AES
    length: 256
"""

RETURN = r"""
key_id:
  description: KMIP unique identifier of the key, when it exists.
  type: str
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule  # noqa: E402
from ansible_collections.cosmian.kms.plugins.module_utils.kms_api import (  # noqa: E402
    common_argument_spec,
    find_values,
    kmip_destroy,
    kmip_locate,
    kmip_node,
    kmip_object_name,
    kmip_request,
    kmip_structure,
    require_minimum,
)


def run_module():
    argument_spec = common_argument_spec()
    argument_spec.update(
        {
            'state': {
                'type': 'str',
                'choices': ['present', 'absent'],
                'default': 'present',
            },
            'name': {'type': 'str', 'required': True},
            'algorithm': {'type': 'str', 'default': 'AES'},
            'length': {'type': 'int', 'default': 256},
        }
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    params = module.params
    require_minimum(module, 'length', 1)
    attributes = [
        kmip_node('ObjectType', 'Enumeration', 'SymmetricKey'),
        kmip_object_name(params['name']),
    ]
    matches = kmip_locate(module, attributes)
    if len(matches) > 1:
        module.fail_json(msg='More than one key has the requested KMIP Name')
    existing_id = matches[0] if matches else None

    if params['state'] == 'absent':
        if not existing_id:
            module.exit_json(changed=False, key_id=None)
        if not module.check_mode:
            kmip_destroy(module, existing_id)
        module.exit_json(changed=True, key_id=existing_id)

    if existing_id:
        module.exit_json(changed=False, key_id=existing_id)
    if module.check_mode:
        module.exit_json(changed=True, key_id=None)

    create = kmip_structure(
        'Create',
        [
            kmip_node('ObjectType', 'Enumeration', 'SymmetricKey'),
            kmip_structure(
                'Attributes',
                [
                    kmip_node(
                        'CryptographicAlgorithm', 'Enumeration', params['algorithm']
                    ),
                    kmip_node('CryptographicLength', 'Integer', params['length']),
                    kmip_object_name(params['name']),
                ],
            ),
        ],
    )
    response = kmip_request(module, create)
    identifiers = find_values(response, 'UniqueIdentifier')
    if not identifiers:
        module.fail_json(
            msg='KMS created the key without returning a unique identifier'
        )
    module.exit_json(changed=True, key_id=identifiers[0])


def main():
    run_module()


if __name__ == '__main__':
    main()

#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Cosmian
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: kms_rotation_policy
short_description: Configure or disable automatic rotation for a KMS key
version_added: "0.1.0"
description:
  - Reads key attributes before applying only the required KMIP SetAttribute operations.
  - Disabling a policy sets RotateAutomatic to false and RotateInterval to zero.
options:
  object_id:
    type: str
    required: true
    description: KMIP unique identifier of the key.
  state:
    type: str
    choices: [present, absent]
    default: present
    description: Whether automatic rotation should be configured or disabled.
  interval_seconds:
    type: int
    description: Required for state present.
  rotate_name:
    type: str
    description: Optional keyset name used to group rotated keys.
  offset_seconds:
    type: int
    default: 0
    description: Delay in seconds before the first rotation interval starts.
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
- name: Rotate a key daily
  cosmian.kms.kms_rotation_policy:
    kms_url: https://kms.example.com
    api_token: "{{ kms_api_token }}"
    object_id: "{{ kms_key_id }}"
    interval_seconds: 86400
    rotate_name: application-key
    offset_seconds: 60
"""

RETURN = r"""
policy:
  description: Rotation policy values requested for the object.
  type: dict
  returned: always
"""

from ansible.module_utils.basic import AnsibleModule  # noqa: E402
from ansible_collections.cosmian.kms.plugins.module_utils.kms_api import (  # noqa: E402
    common_argument_spec,
    kmip_attribute_map,
    kmip_long_integer,
    kmip_node,
    kmip_request,
    kmip_structure,
    require_minimum,
    rotation_policy_plan,
)


def run_module():
    argument_spec = common_argument_spec()
    argument_spec.update(
        {
            'object_id': {'type': 'str', 'required': True},
            'state': {
                'type': 'str',
                'choices': ['present', 'absent'],
                'default': 'present',
            },
            'interval_seconds': {'type': 'int'},
            'rotate_name': {'type': 'str'},
            'offset_seconds': {'type': 'int', 'default': 0},
        }
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[('state', 'present', ['interval_seconds'])],
        supports_check_mode=True,
    )
    params = module.params
    require_minimum(module, 'interval_seconds', 1)
    require_minimum(module, 'offset_seconds', 0)
    response = kmip_request(
        module,
        kmip_structure(
            'GetAttributes',
            [kmip_node('UniqueIdentifier', 'TextString', params['object_id'])],
        ),
    )
    current = kmip_attribute_map(response)
    desired, changed = rotation_policy_plan(
        current,
        params['state'],
        params.get('interval_seconds'),
        params.get('rotate_name'),
        params['offset_seconds'],
    )
    policy = {name: value for name, (_type_name, value) in desired.items()}
    if not changed:
        module.exit_json(changed=False, policy=policy)
    if not module.check_mode:
        for name, type_name, value in changed:
            if type_name == 'LongInteger':
                value = kmip_long_integer(value)
            kmip_request(
                module,
                kmip_structure(
                    'SetAttribute',
                    [
                        kmip_node(
                            'UniqueIdentifier', 'TextString', params['object_id']
                        ),
                        kmip_structure(
                            'NewAttribute',
                            [kmip_node(name, type_name, value)],
                        ),
                    ],
                ),
            )
    module.exit_json(changed=True, policy=policy)


def main():
    run_module()


if __name__ == '__main__':
    main()

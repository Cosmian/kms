#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Cosmian
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: kms_access
short_description: Ensure KMIP permissions for a user on a KMS object
version_added: "0.1.0"
description:
  - Reads the current access list and grants or revokes only the missing permissions.
  - Supports check mode without changing the KMS.
options:
  object_id:
    type: str
    required: true
    description: KMIP unique identifier of the object.
  user_id:
    type: str
    required: true
    description: KMS user receiving or losing access.
  operation_types:
    type: list
    elements: str
    required: true
    description: KMIP operations to grant or revoke.
  state:
    type: str
    choices: [present, absent]
    default: present
    description: Whether the permissions should be granted or revoked.
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
- name: Allow the application to use a key
  cosmian.kms.kms_access:
    kms_url: https://kms.example.com
    api_token: "{{ kms_api_token }}"
    object_id: "{{ kms_key_id }}"
    user_id: application
    operation_types: [get, encrypt, decrypt]
    state: present
"""

RETURN = r"""
operation_types:
  description: Permissions that were granted or revoked; empty when nothing changed.
  type: list
  elements: str
  returned: always
"""

from urllib.parse import quote  # noqa: E402

from ansible.module_utils.basic import AnsibleModule  # noqa: E402
from ansible_collections.cosmian.kms.plugins.module_utils.kms_api import (  # noqa: E402
    access_changes,
    common_argument_spec,
    kms_request,
)


def run_module():
    argument_spec = common_argument_spec()
    argument_spec.update(
        {
            'object_id': {'type': 'str', 'required': True},
            'user_id': {'type': 'str', 'required': True},
            'operation_types': {'type': 'list', 'elements': 'str', 'required': True},
            'state': {
                'type': 'str',
                'choices': ['present', 'absent'],
                'default': 'present',
            },
        }
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    params = module.params
    if not params['operation_types']:
        module.fail_json(msg='operation_types must contain at least one operation')
    existing = kms_request(
        module,
        'GET',
        '/access/list/{}'.format(quote(params['object_id'], safe='')),
    )
    access = next(
        (item for item in (existing or []) if item.get('user_id') == params['user_id']),
        {},
    )
    change = access_changes(
        params['state'], access.get('operations', []), params['operation_types']
    )
    if not change:
        module.exit_json(changed=False, operation_types=[])
    if not module.check_mode:
        kms_request(
            module,
            'POST',
            '/access/grant' if params['state'] == 'present' else '/access/revoke',
            {
                'unique_identifier': params['object_id'],
                'user_id': params['user_id'],
                'operation_types': change,
            },
        )
    module.exit_json(changed=True, operation_types=change)


def main():
    run_module()


if __name__ == '__main__':
    main()

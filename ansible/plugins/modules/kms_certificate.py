#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Cosmian
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r"""
---
module: kms_certificate
short_description: Issue a certificate from a PEM CSR or destroy a certificate
version_added: "0.1.0"
description:
  - Uses KMIP Certify, Locate, and Destroy operations over the KMS JSON API.
  - The certificate is stored under a stable O(certificate_id), which is the idempotency key.
    An existing certificate with that identifier is never re-issued or overwritten.
  - The subject and public key come from the CSR. The KMS cannot self-sign a CSR, so an
    issuing CA private key is required.
options:
  state:
    type: str
    choices: [present, absent]
    default: present
    description: Whether the certificate should exist.
  certificate_id:
    type: str
    required: true
    description: Unique identifier the certificate is stored under.
  csr_content:
    type: str
    description: PEM-encoded PKCS#10 certificate signing request. Required when O(state=present).
  issuer_private_key_id:
    type: str
    description: Private key UID of the issuing CA. Must be an active key. Required when O(state=present).
  issuer_certificate_id:
    type: str
    description:
      - Certificate UID of the issuing CA.
      - Required with O(issuer_private_key_id) unless that key is already linked to its certificate.
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
- name: Issue a service certificate signed by an existing CA
  cosmian.kms.kms_certificate:
    kms_url: https://kms.example.com
    api_token: "{{ kms_api_token }}"
    certificate_id: service-tls
    csr_content: "{{ lookup('ansible.builtin.file', 'files/service.csr') }}"
    issuer_private_key_id: "{{ kms_ca_private_key_id }}"
    issuer_certificate_id: "{{ kms_ca_certificate_id }}"
"""

RETURN = r"""
certificate_id:
  description: KMIP unique identifier of the certificate, when it exists.
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
    kmip_request,
    kmip_structure,
)


def issuer_link(link_type, object_id):
    return kmip_structure(
        'Link',
        [
            kmip_node('LinkType', 'Enumeration', link_type),
            kmip_node('LinkedObjectIdentifier', 'TextString', object_id),
        ],
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
            'certificate_id': {'type': 'str', 'required': True},
            'csr_content': {'type': 'str'},
            'issuer_private_key_id': {'type': 'str'},
            'issuer_certificate_id': {'type': 'str'},
        }
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[('state', 'present', ['csr_content', 'issuer_private_key_id'])],
        supports_check_mode=True,
    )
    params = module.params
    certificate_id = params['certificate_id']

    exists = bool(
        kmip_locate(
            module,
            [
                kmip_node('ObjectType', 'Enumeration', 'Certificate'),
                kmip_node('UniqueIdentifier', 'TextString', certificate_id),
            ],
        )
    )
    if params['state'] == 'absent':
        if exists and not module.check_mode:
            kmip_destroy(module, certificate_id)
        module.exit_json(
            changed=exists, certificate_id=certificate_id if exists else None
        )

    if exists:
        module.exit_json(changed=False, certificate_id=certificate_id)
    if module.check_mode:
        module.exit_json(changed=True, certificate_id=None)

    attributes = [
        kmip_node('UniqueIdentifier', 'TextString', certificate_id),
        issuer_link('PrivateKeyLink', params['issuer_private_key_id']),
    ]
    if params.get('issuer_certificate_id'):
        attributes.append(
            issuer_link('CertificateLink', params['issuer_certificate_id'])
        )
    response = kmip_request(
        module,
        kmip_structure(
            'Certify',
            [
                kmip_node('CertificateRequestType', 'Enumeration', 'PEM'),
                kmip_node(
                    'CertificateRequestValue',
                    'ByteString',
                    params['csr_content'].encode('utf-8').hex().upper(),
                ),
                kmip_structure('Attributes', attributes),
            ],
        ),
    )
    identifiers = find_values(response, 'UniqueIdentifier')
    if not identifiers:
        module.fail_json(
            msg='KMS certified the CSR without returning a certificate UID'
        )
    module.exit_json(changed=True, certificate_id=identifiers[0])


def main():
    run_module()


if __name__ == '__main__':
    main()

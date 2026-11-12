# cosmian.kms Ansible collection

This collection deploys Cosmian KMS and manages keys, certificates, access
grants, and automatic-rotation policies through the KMS REST/KMIP JSON APIs.

## Install

```sh
ansible-galaxy collection install cosmian.kms
ansible-galaxy collection install -r requirements.yml
```

The server role's container mode uses `community.docker`, declared as a
collection dependency.

## Deploy a server

Set `kms_config_toml` to the complete `kms.toml` content. Keep passwords and
other secrets in Ansible Vault. `kms_config_tls_certificate` and
`kms_config_tls_private_key` are optional PEM contents copied to the configured paths.

```yaml
- hosts: kms_servers
  become: true
  vars:
    kms_server_install_method: deb
    kms_server_package_source: https://downloads.example.com/cosmian-kms.deb
    kms_config_toml: |
      default_username = "admin"
      [db]
      database_type = "sqlite"
      sqlite_path = "/var/lib/cosmian"
      [tls]
      tls_cert_file = "/etc/cosmian/tls/server.crt"
      tls_key_file = "/etc/cosmian/tls/server.key"
    kms_config_tls_certificate: "{{ vault_kms_tls_certificate }}"
    kms_config_tls_private_key: "{{ vault_kms_tls_private_key }}"
  roles:
    - cosmian.kms.kms_server
    - cosmian.kms.kms_health
```

`kms_server_install_method` accepts `deb`, `rpm`, or `container`. For package modes,
`kms_server_package_source` is a package path or URL. For container mode, set
`kms_server_container_image`. TLS files are mounted into containers automatically.
HSM instances and credentials are configured in `kms_config_toml` using the server's
normal TOML format; add device mounts through `kms_server_container_extra_volumes`
when the HSM integration requires them.

## Manage resources

Every module accepts `kms_url`, `api_token`, TLS validation options, and
client-certificate options. TLS verification is enabled by default.

```yaml
- hosts: localhost
  tasks:
    - cosmian.kms.kms_key:
        kms_url: https://kms.example.com
        api_token: "{{ vault_kms_api_token }}"
        name: application-data
        algorithm: AES
        length: 256
      register: application_key

    - cosmian.kms.kms_access:
        kms_url: https://kms.example.com
        api_token: "{{ vault_kms_api_token }}"
        object_id: "{{ application_key.key_id }}"
        user_id: application
        operation_types: [get, encrypt, decrypt]

    - cosmian.kms.kms_rotation_policy:
        kms_url: https://kms.example.com
        api_token: "{{ vault_kms_api_token }}"
        object_id: "{{ application_key.key_id }}"
        interval_seconds: 86400
        rotate_name: application-data
```

`kms_key` currently manages named symmetric keys. `kms_certificate` issues a
certificate from a PEM CSR under a stable `certificate_id`, signed by an active
CA private key (`issuer_private_key_id`, plus `issuer_certificate_id` unless the
key is already linked to its certificate); an existing certificate with that
identifier is left untouched. `kms_rotation_policy` requires the KMS
automatic-rotation scheduler to be enabled; HSM keys are not eligible for
automatic rotation.

The resource modules support check mode. Access control is evaluated by the
KMS as the authenticated caller, so that caller must own the relevant object
or have the required administrative permission.

## Test and build

From this directory:

```sh
python -m pip install -r requirements-test.txt
ansible-galaxy collection install -r requirements.yml
python -m unittest discover -s tests/unit
ansible-lint
cd extensions && molecule test
cd ..
ansible-galaxy collection build
```

The Galaxy version is maintained in `galaxy.yml`. Publishing is automated for
GitHub releases tagged `ansible-v*`; configure the repository secret
`GALAXY_API_KEY` before publishing.

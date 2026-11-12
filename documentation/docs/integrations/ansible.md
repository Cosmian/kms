# Ansible collection

The `cosmian.kms` collection deploys Cosmian KMS and manages KMIP resources
through its REST/KMIP JSON API. Install it from Ansible Galaxy:

```bash
ansible-galaxy collection install cosmian.kms
ansible-galaxy collection install -r requirements.yml
```

The collection's `kms_server` role installs a Debian package, RPM, or container;
`kms_config` renders `kms.toml` and installs optional TLS files; and
`kms_health` waits for the server health endpoint. HSM instances and credentials
are expressed using the regular KMS TOML configuration and should be encrypted
with Ansible Vault.

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
  roles:
    - cosmian.kms.kms_server
    - cosmian.kms.kms_health
```

The `kms_key`, `kms_certificate`, `kms_access`, and `kms_rotation_policy`
modules support check mode and avoid reporting changes when the requested
resource state is already present. The key module currently manages named
symmetric keys; the certificate module issues a certificate from a PEM CSR
under a stable certificate ID and requires an issuing CA private key. Automatic
rotation requires the KMS scheduler to be enabled and is not supported for HSM
keys.

See the collection's [README](https://github.com/Cosmian/kms/tree/develop/ansible)
for role variables, authentication options, module examples, and test commands.

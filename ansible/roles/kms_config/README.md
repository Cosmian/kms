# kms_config

Renders `kms.toml` and, optionally, the TLS certificate and private key, then
restarts the service when the configuration changes. `kms_server` includes this
role; use it alone to manage the configuration of an existing installation.

## Variables

| Variable                            | Default                         | Description                                                    |
|-------------------------------------|---------------------------------|----------------------------------------------------------------|
| `kms_config_toml`                   | `""`                            | Complete `kms.toml` content. Required.                         |
| `kms_config_path`                   | `/etc/cosmian/kms.toml`         | Destination of the configuration file.                         |
| `kms_config_tls_certificate`        | `""`                            | PEM certificate. Set together with the private key, or neither.|
| `kms_config_tls_private_key`        | `""`                            | PEM private key.                                               |
| `kms_config_tls_certificate_path`   | `/etc/cosmian/tls/server.crt`   | Certificate destination.                                       |
| `kms_config_tls_private_key_path`   | `/etc/cosmian/tls/server.key`   | Private key destination.                                       |
| `kms_config_owner`, `kms_config_group` | `root`                       | Owner and group of the files.                                  |
| `kms_config_manage_service`         | `false`                         | Restart the service or container on change.                    |
| `kms_config_service_type`           | `systemd`                       | `systemd`, `deb`, `rpm`, or `container`.                       |
| `kms_config_service_name`           | `cosmian_kms`                   | systemd unit name.                                             |
| `kms_config_container_name`         | `cosmian-kms`                   | Container name.                                                |

Keep the TOML content and the PEM values in Ansible Vault: the rendered
configuration task runs with `no_log`.

## Example

```yaml
- hosts: kms_servers
  become: true
  roles:
    - role: cosmian.kms.kms_config
      vars:
        kms_config_toml: "{{ vault_kms_toml }}"
```

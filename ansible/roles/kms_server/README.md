# kms_server

Installs Cosmian KMS from a `.deb` package, an `.rpm` package, or a container
image, renders its configuration through the `kms_config` role, and starts the
service.

## Variables

| Variable                            | Default                         | Description                                                    |
|-------------------------------------|---------------------------------|----------------------------------------------------------------|
| `kms_server_install_method`         | `deb`                           | `deb`, `rpm`, or `container`.                                  |
| `kms_server_package_source`         | `""`                            | Package path or URL (`deb` and `rpm` modes).                   |
| `kms_server_rpm_gpg_check`          | `true`                          | Verify the RPM GPG signature. Set `false` for unsigned RPMs.   |
| `kms_server_container_image`        | `""`                            | Container image (`container` mode).                            |
| `kms_server_container_name`         | `cosmian-kms`                   | Container name.                                                |
| `kms_server_http_port`              | `9998`                          | Published port in `container` mode.                            |
| `kms_server_tls_certificate_path`   | `/etc/cosmian/tls/server.crt`   | TLS certificate path on the host.                              |
| `kms_server_tls_private_key_path`   | `/etc/cosmian/tls/server.key`   | TLS private key path on the host.                              |
| `kms_server_container_extra_volumes`| `[]`                            | Extra container mounts, for example HSM devices.               |
| `kms_server_service_name`           | `cosmian_kms`                   | systemd unit name.                                             |

`kms_config_toml` (see the `kms_config` role) is required.

## Example

```yaml
- hosts: kms_servers
  become: true
  roles:
    - role: cosmian.kms.kms_server
      vars:
        kms_server_install_method: deb
        kms_server_package_source: https://downloads.example.com/cosmian-kms.deb
        kms_config_toml: "{{ lookup('file', 'kms.toml') }}"
```

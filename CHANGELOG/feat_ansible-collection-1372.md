## Features

### Ansible collection `cosmian.kms` (#1372)

- New collection under `ansible/` (published to Ansible Galaxy on `ansible-v*` releases) with the roles `kms_server`
  (deb, rpm or container install), `kms_config` (`kms.toml` and optional TLS files, restart on change) and
  `kms_health` (wait for `/health`). HSM settings go in the regular `kms.toml` content.
- Idempotent modules with check mode over the KMIP JSON API: `kms_key` (named symmetric keys), `kms_certificate`
  (certificate from a CSR, signed by an active CA key), `kms_access` and `kms_rotation_policy`.
- Unit tests, a Molecule scenario, `ansible-lint` and `ansible-test sanity` run in CI. The collection is licensed
  GPL-3.0-or-later, as required by Ansible for modules published on Galaxy.

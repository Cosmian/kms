## Features

### Vault-compatible API

- HashiCorp Vault auto-unseal with `seal "transit"`: the Transit engine adds `aes256-gcm96` keys (the default key type), `encrypt/{name}` and `decrypt/{name}` with Vault ciphertexts (`vault:vN:`), and `keys/{name}/rotate` for key versions. Keys are non-exportable KMS AES-256 keys, one per version; `POST` and `PUT` are both accepted ([#1365](https://github.com/Cosmian/kms/issues/1365)).

## Testing

- `mise run test:spire:vault-transit-seal` runs Vault OSS 1.21 with `seal "transit"` against the KMS: init, auto-unseal after restart and after key rotation, and sealed after key deletion.

## Documentation

- New guide: [HashiCorp Vault auto-unseal](../documentation/docs/integrations/hashicorp_vault_auto_unseal.md).

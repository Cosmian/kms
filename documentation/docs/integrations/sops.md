# SOPS integration

[SOPS](https://github.com/getsops/sops) encrypts structured configuration files while keeping the
encrypted data suitable for source control. The Eviden KMS can be used with SOPS' native key sources
without an additional key-service sidecar:

- **Vault Transit** (`hc_vault_transit`) uses the KMS Vault-compatible Transit API.
- **OpenPGP** (`pgp`) uses GnuPG and the KMS PKCS#11 provider through
  [`gnupg-pkcs11-scd`](https://github.com/alonbl/gnupg-pkcs11-scd).

## Vault Transit

The Vault Transit source uses the KMS Transit `encrypt` and `decrypt` endpoints delivered for
issue [#1385](https://github.com/Cosmian/kms/issues/1385) and merged in PR
[#1398](https://github.com/Cosmian/kms/pull/1398).

Configure SOPS with the Vault-compatible mount and key name:

```yaml
creation_rules:
  - path_regex: \.yaml$
    hc_vault_transit_uri: http://127.0.0.1:9998/v1/transit/keys/sops
```

Set the endpoint and token used by SOPS:

```bash
export VAULT_ADDR="http://127.0.0.1:9998"
export VAULT_TOKEN="<TOKEN>"
```

The KMS Transit key must already exist and the token must be authorized for the Transit routes.
Follow the [Vault-compatible integration guide](spire_spiffe.md) for the Transit endpoint and token
setup. Do not commit `VAULT_TOKEN` or any other credential to a repository.

## OpenPGP through GnuPG and PKCS#11

The OpenPGP source uses the GnuPG keyring and therefore works with a key exposed by
`gnupg-pkcs11-scd`. Follow the [GnuPG smartcard guide](gnupg/smartcard.md) to install and configure
the KMS PKCS#11 provider, create the RSA key and certificate tags, and register the virtual
smartcard with GnuPG.

After the card is visible to GnuPG, use the OpenPGP fingerprint in `.sops.yaml`:

```yaml
creation_rules:
  - path_regex: \.yaml$
    pgp: "<OPENPGP_FINGERPRINT>"
```

The private key operation remains in the KMS. GnuPG and SOPS receive only the result of the
operation, as described in the smartcard guide.

## Encrypt, decrypt, and rotate

Encrypt a plaintext file according to `.sops.yaml`:

```bash
sops -e --in-place secrets.yaml
```

Decrypt it to standard output without creating a plaintext copy:

```bash
sops -d secrets.yaml
```

After changing the creation rule or adding another recipient, rewrap the data keys:

```bash
sops updatekeys secrets.yaml
```

Confirm the proposed recipient changes before accepting them. Keep decrypted files out of source
control and remove any temporary plaintext files after a manual verification.

## Validation

The repository's `test:interop:sops` task validates encryption, decryption, and `sops updatekeys`
for both native sources. It runs the Vault Transit scenario against the KMS Transit API and runs
the OpenPGP source through `gnupg-pkcs11-scd` and the KMS PKCS#11 provider. The OpenPGP path is
non-FIPS because it uses the existing KMS OpenPGP and GnuPG smartcard integration.

If SOPS, GnuPG, or `gnupg-pkcs11-scd` is not installed, install the versions provided by the
project's development shell rather than downloading an unverified binary.

## Troubleshooting

### SOPS reports that no matching PGP key is available

Check that GnuPG can list the fingerprint configured in `.sops.yaml` and that the virtual card is
visible with `gpg --card-status`. Re-run `gpg-connect-agent 'scd learn --force' /bye` after changing
the PKCS#11 provider configuration.

### Vault Transit returns an authentication or not-found error

Check `VAULT_ADDR`, `VAULT_TOKEN`, the Transit mount name, and the key name. The KMS token must be
authorized for the requested Transit key; a valid network connection alone is not sufficient.

### Plaintext is not restored after rotation

Run `sops updatekeys` and accept the recipient change. Rotation changes the encrypted data-key
metadata; it does not rewrite the plaintext content.

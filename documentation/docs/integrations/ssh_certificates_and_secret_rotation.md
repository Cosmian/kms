# SSH certificates and external secret rotation

This guide covers the KMS SSH certificate API and a rotation pattern for an external PostgreSQL credential stored in the Vault-compatible KV v2 API. The SSH certificate API uses an existing KMS-managed signing key; the password endpoint generates a value but does not change a database or write to KV.

For the separate OpenSSH PKCS#11 integration, see [OpenSSH keys in the KMS](openssh.md). For KV configuration and supported Vault-compatible operations, see [Vault-compatible KV Secret Store](../configuration/secret_backends.md#vault-compatible-kv-secret-store).

## Prerequisites

- A running KMS instance with an active RSA or NIST ECDSA private key that permits `Sign`. Ed25519 CA keys are supported only in non-FIPS builds.
- An authenticated Crypto Officer to configure the SSH CA and roles.
- A caller authorized to sign with the configured CA key and, for password generation, the KMS `Create` permission.
- For the rotation example, an enabled KV v2 mount and a token authorized to write the target path.

The CA key remains in the KMS. HSM-backed signing uses the HSM oracle; the SSH API does not export the CA private key or fall back to software signing.

## Configure the SSH CA and role

Set `API_URL` to the KMS HTTPS base URL and use the KMS authentication method configured for your deployment. The following requests use a bearer token; client-certificate authentication may also be used.

Configure an existing KMS private-key UID as the CA:

```bash
curl --fail-with-body --silent --show-error \
  --request PUT "$API_URL/v1/ssh/config/ca" \
  --header "Authorization: Bearer $API_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"ca_key_uid":"<CA_PRIVATE_KEY_UID>"}'
```

Retrieve the CA public key as OpenSSH text and install it on each SSH host:

```bash
curl --fail-with-body --silent --show-error \
  "$API_URL/v1/ssh/public_key" \
  --output trusted_user_ca_keys
```

Configure the SSH server to trust that file:

```text
TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
```

Create a role with exact allowed principals and a bounded certificate lifetime:

```bash
curl --fail-with-body --silent --show-error \
  --request PUT "$API_URL/v1/ssh/roles/developers" \
  --header "Authorization: Bearer $API_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"allowed_principals":["alice","db-admin"],"default_ttl":"15m","max_ttl":"1h"}'
```

Role names may contain ASCII letters, digits, `_`, `-`, and `.`. Principal names are exact login names; wildcard principals and duplicate entries are rejected. The certificate includes the `permit-pty` extension.

## Issue a short-lived user certificate

Generate a user key pair locally. Use an algorithm permitted by your deployment policy; Ed25519 user keys require a non-FIPS build.

```bash
ssh-keygen -t ecdsa -b 256 -f "$HOME/.ssh/id_ecdsa"
```

Submit only the public key. The optional `ttl` must not exceed the role's `max_ttl`; if omitted, the role's `default_ttl` is used.

```bash
curl --fail-with-body --silent --show-error \
  --request POST "$API_URL/v1/ssh/sign/developers" \
  --header "Authorization: Bearer $API_TOKEN" \
  --header "Content-Type: application/json" \
  --data "$(jq -n \
    --arg public_key "$(cat "$HOME/.ssh/id_ecdsa.pub")" \
    '{public_key:$public_key,valid_principals:["alice"],ttl:"15m"}')" \
  | jq -r '.data.signed_key' > "$HOME/.ssh/id_ecdsa-cert.pub"
```

Use `ssh-keygen -L -f "$HOME/.ssh/id_ecdsa-cert.pub"` to inspect the certificate. Configure the SSH client to use the certificate alongside its private key, then connect as one of the certificate's allowed principals.

## Generate a password for an external rotation

`POST /v1/secrets/password` requires the caller's KMS `Create` permission. It returns a fresh 32-character alphanumeric value in `data.password`; it neither stores nor logs the password.

```bash
curl --fail-with-body --silent --show-error \
  --request POST "$API_URL/v1/secrets/password" \
  --header "Authorization: Bearer $API_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{}' \
  | jq -er '.data.password'
```

The endpoint does not modify PostgreSQL or publish the value to KV. The application orchestrating a rotation is responsible for both operations and for recovering from partial failure.

## Rotate a PostgreSQL role password and publish it to KV

This example keeps a pending copy in a permission-restricted file so the same credential can be published again if the KV write fails after PostgreSQL has changed. Set `API_URL`, `API_TOKEN`, `KV_TOKEN`, `DATABASE_URL`, and `DB_ADMIN_PASSWORD` in the environment. Use a TLS-verified PostgreSQL connection string, for example one with `sslmode=verify-full` and the appropriate CA configuration. Protect the pending file's directory with encrypted storage and access controls.

First generate the password and write it to the pending file without printing it:

```bash
set -euo pipefail
umask 077
pending_file=$(mktemp "${TMPDIR:-/tmp}/kms-rotation.XXXXXX")
password=$(
  curl --fail-with-body --silent --show-error \
    --request POST "$API_URL/v1/secrets/password" \
    --header "Authorization: Bearer $API_TOKEN" \
    --header "Content-Type: application/json" \
    --data '{}' \
    | jq -er '.data.password'
)
printf '%s' "$password" > "$pending_file"
unset password
```

Change the external PostgreSQL role before publishing to KV. This example uses `psql`'s environment-variable and SQL-literal interpolation rather than placing the new password in the SQL command line:

```bash
export NEW_DB_PASSWORD
NEW_DB_PASSWORD=$(<"$pending_file")
PGPASSWORD="$DB_ADMIN_PASSWORD" psql "$DATABASE_URL" \
  --no-psqlrc -v ON_ERROR_STOP=1 <<'SQL'
\getenv new_password NEW_DB_PASSWORD
ALTER ROLE app_user PASSWORD :'new_password';
SQL
unset NEW_DB_PASSWORD
```

Publish the same password to the KV v2 path. The path and token must be authorized by the KMS KV configuration:

```bash
jq -n --rawfile password "$pending_file" '{data:{password:$password}}' \
  | curl --fail-with-body --silent --show-error \
      --request POST "$API_URL/v1/kv/data/database/app" \
      --header "X-Vault-Token: $KV_TOKEN" \
      --header "Content-Type: application/json" \
      --data-binary @-
```

After the KV write succeeds, remove the pending file:

```bash
rm -f "$pending_file"
```

If PostgreSQL accepted the new password but the KV write failed, do not generate another password or rotate PostgreSQL again. Keep the pending file protected and retry only the KV publication step with that same file. Alert the operator and remove the file only after the secret is available to consumers. If the pending copy is lost, use the database's approved recovery procedure to set and publish a new password before resuming consumers.

If the PostgreSQL update itself fails, do not publish the pending value; confirm the database state, then remove the pending file once the value is no longer needed.

This pattern demonstrates recovery from a failed KV publication; it is not an atomic transaction across PostgreSQL and KMS. Adapt the database update and retry/alerting logic to the deployment, and ensure the process can securely retain the pending value across the expected recovery window.

## What the operator configures

- The CA key, in the KMS or on an HSM (`Sign` granted only to trusted callers), and the CA configuration and roles, done by a Crypto Officer.
- On each SSH host: `TrustedUserCAKeys` pointing to the public key from `GET /v1/ssh/public_key`, and the principals allowed for each account.
- For rotation: the database update, the KV token and the secure retention of the pending value; the KMS only generates the password.
- Log hygiene: the KMS does not log generated passwords or private keys; keep it that way in the scripts that call the API.

## Automated checks

- `mise run test:ssh-certificates` starts a real `sshd` trusting the KMS CA (ECDSA P-256 and RSA-3072) and checks that a certificate is accepted before expiry and refused after, and that unauthorized principals, an excessive TTL and weak subject keys are rejected.
- `mise run test:secret-rotation` rotates a PostgreSQL password, checks that the new one works and the old one fails, that a KV consumer reads the new value, and that a failed KV write can be retried.
- `tests::hsm::ssh_ca` (run by `mise run test:hsm-softhsm2`) checks certificates signed by a non-extractable HSM CA key.

## Limits

- SSH CA configuration and role changes require an active Crypto Officer.
- Certificate signing requires `Sign` authorization for the selected CA key; every requested principal must be allowed by the role.
- Roles are not bound to users: any caller authorized to `Sign` with the CA key can request any role. Grant `Sign` on the CA key only to callers trusted with every role's principals.
- Subject public keys must be RSA of at least 2048 bits, NIST ECDSA, or (non-FIPS only) Ed25519.
- `GET /v1/ssh/public_key` requires no authentication so that hosts can fetch the CA public key.
- The CA must be active and use a supported algorithm. RSA keys must be at least 2048 bits; ECDSA CA keys must use NIST P-256, P-384, or P-521. Ed25519 is non-FIPS only.
- Generated passwords are not stored or automatically rotated into an external service.
- The KV API implements a supported Vault KV v2-compatible subset; see its reference for operations that are not implemented.

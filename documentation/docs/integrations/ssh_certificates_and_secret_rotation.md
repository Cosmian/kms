# SSH certificates and external secret rotation

This guide covers the KMS SSH certificate API and a rotation pattern for the credential of any external system (a database, a directory, a service account) stored in the Vault-compatible KV v2 API. The SSH certificate API uses an existing KMS-managed signing key; the password endpoint generates a value but does not change the external system or write to KV. PostgreSQL and MySQL appear below as worked examples of the one step that depends on the system.

For the separate OpenSSH PKCS#11 integration, see [OpenSSH keys in the KMS](openssh.md). For KV configuration and supported Vault-compatible operations, see [Vault-compatible KV Secret Store](../configuration/secret_backends.md#vault-compatible-kv-secret-store).

## Prerequisites

- A running KMS instance with an active RSA or NIST ECDSA private key that permits `Sign`. Ed25519 CA keys are supported only in non-FIPS builds.
- An authenticated Crypto Officer to configure the SSH CA and roles.
- A caller listed in the role's `allowed_users` (or an active Crypto Officer); it needs no right on the CA key. For password generation, the KMS `Create` permission.
- For the rotation example, an enabled KV v2 mount and a token authorized to write the target path, and administrative access to the system whose credential is rotated.

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

Create a role with exact allowed principals, the users who may request certificates with it, and a bounded certificate lifetime:

```bash
curl --fail-with-body --silent --show-error \
  --request PUT "$API_URL/v1/ssh/roles/developers" \
  --header "Authorization: Bearer $API_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"allowed_principals":["alice","db-admin"],"allowed_users":["alice@example.com"],"default_ttl":"15m","max_ttl":"1h"}'
```

Role names may contain ASCII letters, digits, `_`, `-`, and `.`. Principal names are exact login names; wildcard principals and duplicate entries are rejected. `allowed_users` lists the authenticated KMS user names (for example the JWT email, the client certificate subject, or the API-token user) that may sign with the role; wildcards are rejected, and an empty or omitted list restricts the role to active Crypto Officers. The certificate includes the `permit-pty` extension.

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

The endpoint does not modify the external system or publish the value to KV, and it knows nothing about the system the password is for. The application orchestrating a rotation is responsible for both operations and for recovering from partial failure.

## Rotate an external credential and publish it to KV

The procedure has four steps. Only step 2 depends on the system being rotated; the KMS is involved in steps 1 and 3 only.

1. Generate the password and keep a pending copy in a permission-restricted file.
2. Change the credential in the external system.
3. Publish the same password to a KV v2 path.
4. Remove the pending file.

The pending copy lets the same credential be published again if the KV write fails after the external system has changed. Set `API_URL`, `API_TOKEN` and `KV_TOKEN` in the environment, plus the connection details of the system being rotated (the examples use `DATABASE_URL`, `DB_HOST`, `DB_ADMIN_USER` and `DB_ADMIN_PASSWORD`). Use a TLS-verified connection to the external system. Protect the pending file's directory with encrypted storage and access controls.

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

Change the credential in the external system before publishing to KV. This is the only step that depends on what you rotate: whatever the system, give it the new password without placing it on a command line or in logs. Two examples follow.

**PostgreSQL** uses `psql`'s environment-variable and SQL-literal interpolation:

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

**MySQL** reads the statement from standard input; `printf` is a shell builtin, so the new password appears in no process argument list. The administrator credentials go in a temporary option file readable only by the current user, not on the command line and not in the `MYSQL_PWD` environment variable (which MySQL documents as insecure). The generated password is alphanumeric, so single-quoting it in SQL is safe. MariaDB accepts the same statement:

```bash
admin_cnf=$(mktemp "${TMPDIR:-/tmp}/kms-mysql-admin.XXXXXX")   # created with mode 0600
printf '[client]\nuser=%s\npassword=%s\n' "$DB_ADMIN_USER" "$DB_ADMIN_PASSWORD" > "$admin_cnf"
printf "ALTER USER 'app_user'@'%%' IDENTIFIED BY '%s';" "$(<"$pending_file")" \
  | mysql --defaults-extra-file="$admin_cnf" --host "$DB_HOST" --ssl-mode=VERIFY_IDENTITY
rm -f "$admin_cnf"
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

If the external system accepted the new password but the KV write failed, do not generate another password or change the external system again. Keep the pending file protected and retry only the KV publication step with that same file. Alert the operator and remove the file only after the secret is available to consumers. If the pending copy is lost, use the system's approved recovery procedure to set and publish a new password before resuming consumers.

If the change in the external system itself fails, do not publish the pending value; confirm the system's state, then remove the pending file once the value is no longer needed.

This pattern demonstrates recovery from a failed KV publication; it is not an atomic transaction across the external system and the KMS. Adapt the update step and the retry/alerting logic to the deployment, and ensure the process can securely retain the pending value across the expected recovery window.

## What the operator configures

- The CA key, in the KMS or on an HSM, and the CA configuration and roles, done by a Crypto Officer who owns the key. HSM CA keys must be created sensitive (`--sensitive`); extractable HSM keys are refused. Configuring the CA grants `Sign` on the key to the KMS's internal SSH signing identity; role users need no right on the key.
- On each SSH host: `TrustedUserCAKeys` pointing to the public key from `GET /v1/ssh/public_key`, and the principals allowed for each account.
- For rotation: the update of the external system, the KV token and the secure retention of the pending value; the KMS only generates the password.
- Log hygiene: the KMS does not log generated passwords or private keys; keep it that way in the scripts that call the API.

## Automated checks

- `mise run test:interop:ssh-secrets` runs the scenarios below: `test_ssh_certificates.sh`, then `test_secret_rotation.sh` once per database engine (PostgreSQL and MySQL; `--db postgres|mysql` selects one when running the script directly).
- The SSH scenario starts a real `sshd` (inetd mode, through `ProxyCommand`) trusting the KMS CA (ECDSA P-256 and RSA-3072) over mTLS with three identities: a Crypto Officer configures the CA, a role user obtains certificates but cannot call raw KMIP `Sign`, and an unlisted user is refused. It also checks acceptance before expiry and refusal after, unauthorized principals, an excessive TTL and weak subject keys.
- The rotation scenario is identical for each engine: it rotates a database password, checks that the new one works and the old one fails, that a KV consumer with its own identity is refused until the rotator grants it `get` on the path's metadata object, cannot overwrite or delete afterwards, reads the new value, and that a failed KV write can be retried. Only the few database helper functions at the top of the script differ between engines, which shows that the KMS side does not depend on the database.
- `tests::hsm::ssh_ca` (run by `mise run test:hsm:softhsm2`) checks certificates signed by a non-extractable HSM CA key (ECDSA P-256 and RSA-3072), including acceptance before expiry and refusal after expiry by a real `sshd` (`ssh`, `ssh-keygen` and `sshd` must be installed).

## Limits

- SSH CA configuration and role changes require an active Crypto Officer.
- Certificate signing is performed by the KMS under its internal identity, so callers need no right on the CA key. The caller must be listed in the role's `allowed_users` (or be an active Crypto Officer), and every requested principal must be allowed by the role. A missing role and a role the caller may not use return the same `401`.
- Role users cannot call KMIP `Sign` on the CA key unless they were granted that right separately; role checks (`allowed_principals`, `max_ttl`) are their only path to a certificate. Anyone you grant raw `Sign` on the CA key has full CA authority and bypasses every role.
- The certificate Key ID is `<requester>/<role>/<serial>`, and every issuance writes an `SSH_CERTIFICATE_ISSUED` audit event (user, role, serial, principals, TTL, validity window). The SSH server trusts the CA, not individual keys: a caller allowed to sign with a role that permits principal `alice` can get its own key certified as `alice`. On each SSH host, restrict the accepted principals per account with `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand`.
- SSH CA and role records are stored under identifiers keyed with a server secret, so KMIP users cannot pre-create or replace them.
- When the Vault token verifier (`vault_api_enabled` with `vault_auth_verifier_url`) is the only authentication method, the SSH and `/v1/secrets/password` endpoints refuse requests that carry no valid `X-Vault-Token` instead of running them as the default user, unless `force_default_username` is enabled.
- Subject public keys must be RSA of at least 3072 bits, NIST ECDSA, or (non-FIPS only) Ed25519.
- `GET /v1/ssh/public_key` requires no authentication so that hosts can fetch the CA public key. It is served outside the authenticated scope and is not recorded by the audit middleware.
- The SSH endpoints are always registered; there is no switch to disable them. Without a configured CA they return an error.
- A role's `max_ttl` has no server-side upper bound. Choose short values: a certificate cannot be revoked by the KMS before it expires.
- The CA must be active and use a supported algorithm. RSA CA keys must be at least 3072 bits, like subject keys; ECDSA CA keys must use NIST P-256, P-384, or P-521. Ed25519 is non-FIPS only.
- Generated passwords are not stored or automatically rotated into an external service; no connector for a specific system is provided.
- The KV API implements a supported Vault KV v2-compatible subset; see its reference for operations that are not implemented.

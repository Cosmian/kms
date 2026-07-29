## Bug Fixes

- **RSA transit signatures now honor the requested `signature_algorithm`**: the Vault
  Transit `POST /sign/{name}/{hash}` handler reads the `signature_algorithm` field
  (`pss` or `pkcs1v15`) and threads it through to the KMIP `Sign` request for RSA keys.
  Previously the field was ignored and RSA always signed with PSS, so a client that asked
  for `pkcs1v15` received signatures that failed verification. When the field is absent the
  default is `pss` (matching Vault). The field is RSA-only and ignored for other key types.
- **Transit keys are now genuinely non-exportable**: SPIRE transit (and PKI CA-linked)
  private keys are created with `sensitive: true`, so the KMIP `Get`/`Export` guard denies
  retrieval of the raw private key for *all* API surfaces (KMIP, `ckms`), not only the
  Vault-compatible HTTP dialect. This enforces the ADR's `exportable: false` invariant
  server-side unconditionally. Signing and certificate signing are server-side operations
  and remain unaffected.
- **`GET /keys/{name}` now returns the full Vault-compatible key metadata** required
  by SPIRE's `KeyManager` plugin at startup:
    - `latest_version: 1` field added to `TransitKeyInfo`.
    - `keys` map added: `"1" → { public_key: "<SPKI PEM>", creation_time: "<RFC3339>" }`.
    The public key PEM is retrieved by following the KMIP `PublicKeyLink` from the
    private key and exported with `kmip_public_key_to_openssl` + `public_key_to_pem()`.
    - `type` field now correctly reflects the stored KMIP algorithm attributes
    (`ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`, `ed25519`, `ml-dsa-65`)
    instead of the placeholder `"unknown"`.
- **`POST /keys/{name}/config` no-op route added**: SPIRE's delete worker POSTs
  `{ "deletion_allowed": true }` before calling `DELETE /keys/{name}`.
  The server returns `204 No Content` and ignores the body (deletion policy is
  controlled server-side).
- **PKI `ttl` forwarding**: the `ttl` field in `POST /root/sign-intermediate`
  requests (`"8760h"`, `"3600s"`, `"365d"`, or bare seconds) is now parsed and
  forwarded to the KMIP `Certify` operation as `requested_validity_days`.

## Features

- **Vault-compatible API for SPIRE/SPIFFE support** (KMS side):
    - Added `vault_api_enabled`, `vault_auth_verifier_url`, `vault_transit_mount`,
    `vault_pki_mount`, `vault_pki_ca_key_label`, and `vault_token_cache_ttl_secs`
    configuration fields to `ServerParams`.
    - Added `VaultTokenCache` middleware (`crate/server/src/middlewares/vault_token.rs`)
    for validating Vault-compatible tokens via the Cosmian Authentication Server
    (`auth-verifier`); uses a 30-second DashMap cache to reduce round-trips.
    - Added Vault Transit engine routes under `/v1/{transit_mount}/keys`:
        - `POST /keys/{name}` — create a transit key (EC P-256/P-384, RSA-2048/4096,
      and `ed25519`/`ml-dsa-65` under `non-fips`);
        - `GET /keys/{name}` — retrieve key metadata;
        - `GET /keys` — list all transit keys;
        - `DELETE /keys/{name}` — delete (destroy) a transit key;
        - `POST /sign/{name}/{hash_alg}` — sign with a transit key.
    - Added Vault PKI engine route under `/v1/{pki_mount}`:
        - `POST /root/sign-intermediate` — sign an intermediate CA CSR with the
      configured CA key, returning the certificate chain in Vault-compatible JSON.
    - Both scopes are protected by the `vault_token_middleware` and registered only
    when `vault_api_enabled = true`.
- **`ckms vault` CLI subcommands** (`crate/clients/clap/src/actions/vault/`):
    - `ckms vault approle login` — exchange a `role_id` + `secret_id` for a Vault
    token (unauthenticated).
    - `ckms vault approle create-role` — create or update an AppRole role.
    - `ckms vault approle list-roles` — list all AppRole roles.
    - `ckms vault approle get-role-id` — retrieve the stable `role_id` for a role.
    - `ckms vault approle generate-secret-id` — generate a new secret ID.
    - `ckms vault approle destroy-secret-id` — invalidate a secret ID by accessor.
    - `ckms vault approle delete-role` — permanently delete a role.
    - Admin commands authenticate to the auth-verifier's `_` realm via HTTP Basic
    Auth (`--admin-user` / `--admin-password` or env vars
    `CKMS_VAULT_ADMIN_USER` / `CKMS_VAULT_ADMIN_PASSWORD`).

## Testing

- **`tests/spire/` — SPIRE + Cosmian integration test stack** added:
    - `docker-compose.yml` — 8-service stack: PostgreSQL, auth-verifier, KMS, nginx
    Vault proxy, SPIRE server, SPIRE agent, and two simulated Mistral AI agents.
    - `certs/generate-test-certs.sh` — generates self-signed CA + leaf TLS certs for
    all services.
    - `nginx/vault-proxy.conf` — routes `/v1/auth/*` → auth-verifier,
    `/v1/transit/*` + `/v1/pki/*` → KMS, presenting a single `vault_addr` to SPIRE.
    - `config/spire-server.conf` / `spire-agent.conf` — SPIRE configuration with
    Vault `KeyManager` and `UpstreamAuthority` plugins pointing to the nginx proxy.
    - `config/kms.toml` / `auth_verifier.toml` — service configuration files.
    - `setup/provision.sh` — creates two AppRoles (`spire-server` and `mistral-agents`,
    G5 fix), generates secret-IDs, and creates the PKI CA key in KMS.
    - `mistral-client/` — Python 3.12 Dockerfile + `test_spiffe_identity.py` that
    fetches a JWT-SVID from the Workload API and validates the SPIFFE ID and expiry.

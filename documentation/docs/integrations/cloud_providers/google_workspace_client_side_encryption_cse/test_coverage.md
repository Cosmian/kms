# Test coverage

This page lists which parts of the Google Workspace CSE support are exercised by automated tests,
and which are not. It covers the KACLS endpoints served by the KMS (`/google_cse/*`) and the
`ckms google` commands.

All the tests marked **Offline** run in a plain `cargo test`: they need no Google account, no
Google network access and none of the CI secrets. Only one test needs real Google credentials.

## Running the tests

| Scope | Command | Credentials |
| --- | --- | --- |
| Server endpoints, token validation, crypto, startup | `cargo test -p cosmian_kms_server google_cse` | none |
| `ckms google` commands (clap actions) | `cargo test -p cosmian_kms_cli_actions --features non-fips google_cmd` | none |
| `ckms google` through the `ckms` binary | `cargo test -p ckms --features non-fips google_cmd` | none |
| All of the above, plus the real Google token test | `mise run test:google-cse` | The real Google test needs `TEST_GOOGLE_OAUTH_CLIENT_ID`, `TEST_GOOGLE_OAUTH_CLIENT_SECRET` and `TEST_GOOGLE_OAUTH_REFRESH_TOKEN` (CI only); without them it is skipped with a warning, and fails when `CI` is set |

## Server endpoints

The tests use a local identity provider: tokens are signed with a locally generated RSA key and the
JWKS is loaded in memory. Endpoints are tested through the real Actix HTTP stack.

| Endpoint | Offline coverage | Gap |
| --- | --- | --- |
| `GET /google_cse/status` | Response fields, `kacls_url` built from `kms_public_url`, missing `kms_public_url` | none |
| `GET /google_cse/certs` | JWK content, `kid` equals the one in `create_jwt` tokens, signature verified by the production signed-token validation, failure when the public key is destroyed | none |
| `POST /google_cse/wrap` and `/unwrap` | Round trip, `google_email` over `email`, case-insensitive email match, email mismatch, missing email, unknown signing key, garbage token, wrong `resource_name`, bad base64, truncated and tampered wrapped keys | none |
| `POST /google_cse/digest` | Hash equals `compute_resource_key_hash` for an empty perimeter, migration `verifier` authorization token, missing email | none |
| `POST /google_cse/privilegedwrap` and `/privilegedunwrap` | Round trip, Drive audience check, wrong `resource_name`, migration token issued by another KACLS, real loopback HTTP request from the new KACLS to the original KACLS | none |
| `POST /google_cse/privatekeysign` | `SHA256withRSA`, `SHA512withRSA`, `SHA256withRSA/PSS`, `SHA512withRSA/PSS` with PKCS#1 and PKCS#8 keys (FIPS and non-FIPS), SHA-1 variants (non-FIPS only), `rsa_pss_salt_length`, unknown algorithm, bad digest | none |
| `POST /google_cse/privatekeydecrypt` | PKCS#1 v1.5 and OAEP (SHA-1, SHA-256, SHA-512) with PKCS#1 and PKCS#8 keys, OAEP label, unknown algorithm, bad ciphertext, bad base64 | The end-to-end create-pair flow with a PKCS#12 certificate (`pkcs12_certify`) runs only with `--features non-fips` |
| `POST /google_cse/privilegedprivatekeydecrypt` | Same algorithm matrix (PKCS#1 key), SPKI hash mismatch, unknown SPKI hash algorithm | PKCS#8 wrapped keys are not accepted by this endpoint |
| `POST /google_cse/rewrap` | Two-KACLS DEK migration: outbound `privilegedunwrap`, re-wrap, hash, rejection, bad source URL, missing email | Production-handler success: the SSRF guard rejects offline loopback targets |
| `POST /google_cse/wrapprivatekey` | none | Not implemented: the handler returns an empty `200` |
| `POST /google_cse/delegate` | none | Not implemented: the handler returns an empty `200` |

### Token validation

| Check | Offline coverage | Gap |
| --- | --- | --- |
| Authorization token: signature, `kid`, issuer, audience, `crit`, nested JWT, empty and malformed tokens | Covered | none |
| Role, `resource_name` and `kacls_url` checks, audience post-check | Covered by unit tests of the extracted helpers | The helpers are compiled out of the `insecure` feature; the wiring in release builds is not run end to end |
| Authentication token signature | Covered through the production signed-token validation on the `/certs` key | In test builds the authentication token is decoded without signature check, so HTTP tests do not verify it |
| Token expiry (`exp`) | none | Disabled in test builds |
| Real Google-issued tokens and Google JWKS | `routes::google_cse::jwt::tests::test_wrap_auth` | Needs the CI credentials; the only ignored server test |

### Server startup and configuration

| Area | Offline coverage | Gap |
| --- | --- | --- |
| `google_cse_rsa` key pair: generation, reuse, import from `google_cse_migration_key`, invalid PEM | Covered | The `UNIQUE constraint` race branch |
| JWKS URIs and issuers: defaults, whitelist, `KMS_GOOGLE_CSE_<APP>_JWKS_URI`, `KMS_GOOGLE_CSE_<APP>_JWT_ISSUER`, `KMS_GOOGLE_CSE_AUDIENCE` | Covered | none |

## `ckms google` commands

The Gmail API is replaced by a local mock server: the token endpoint comes from `token_uri` and the
API base URL from the optional `gmail_api_base_url` field of `gmail_api_conf`.

| Command | Offline coverage | Gap |
| --- | --- | --- |
| `google key-pairs create` | All certificate options (extensions, existing certificate, PKCS#12), `--dry-run`, push to Gmail with the expected PKCS#7 and KACLS metadata, Gmail error, existing RSA key, invalid key id (non-private key, no linked public key) | These tests run only with `--features non-fips`: a FIPS `cargo test` does not cover `create` |
| `google key-pairs get`, `list`, `enable`, `disable`, `obliterate` | HTTP method, path, bearer token | none |
| `google identities get`, `list`, `insert`, `delete`, `patch` | HTTP method, path, body, bearer token | none |
| Gmail client | OAuth token request, token endpoint error, non-JSON token response, invalid service-account key, Gmail error with and without JSON body, missing `gmail_api_conf` | The real Gmail API contract is not tested |
| `ckms` binary dispatch | `identities list`, `key-pairs list`, `key-pairs get` error | Runs only with `--features non-fips`. The other subcommands are covered at the clap level only |
| HSM-backed CSE (`using_hsm.rs`) | none | Ignored: needs a Utimaco HSM and Google credentials |

## Compliance of the simulated Google payloads

The tests build the requests and tokens Google would send. They follow Google's
[CSE API reference](https://developers.google.com/workspace/cse/reference):

| Payload | What the tests use |
| --- | --- |
| Docs, Drive, Calendar and Meet authorization token | Issuer `gsuitecse-tokenissuer-drive@system.gserviceaccount.com`, audience `cse-authorization`, claims `email`, `role`, `resource_name`, `perimeter_id`, `kacls_url`, `iat`, `exp`; roles `writer` (wrap), `reader` (unwrap) |
| Gmail authorization token | Issuer `gsuitecse-tokenissuer-gmail@system.gserviceaccount.com`, claims `message_id`, `resource_name`, `spki_hash` (base64 SHA-256 of the DER public key), `spki_hash_algorithm`, `kacls_url`; roles `signer` (privatekeysign), `decrypter` (privatekeydecrypt) |
| Migration authorization token | Roles `migrator` (rewrap) and `verifier` (digest) |
| Authentication token | IdP issuer, `aud`, `email` and the optional `google_email` |
| KACLS migration JWT (`privilegedunwrap`) | `iss` is the URL of the requesting KACLS, `kacls_url` is the URL of the KACLS decrypting the data, audience `kacls-migration`, keys published at `<iss>/certs` |
| Request bodies | Exact field names of each endpoint; `reason` and `perimeter_id` are optional and a test omits them; `rsa_oaep_label` is base64-encoded |
| Wrapped private key | AES-GCM `nonce \|\| ciphertext \|\| tag` without additional data, created like `ckms google key-pairs create` does |

Deliberate differences from the reference:

- `exp` and `iat` are numbers, as RFC 7519 requires, although the reference tables list them as strings.
- `/status` also returns `kacls_url`, a Cosmian extension used by the CLI and the web UI.
- Tests that disable token validation send placeholder tokens: they are ignored by the server.
- One fixture captured from a real Gmail token also carries the `kacls_owner_domain` claim.

## Known gaps

- `wrapprivatekey` and `delegate` are not implemented, so they are not tested.
- `digest` and `rewrap` always validate the authorization token, even when
  `google_cse_disable_tokens_validation` is set.
- Production-handler `rewrap` success cannot use loopback offline because its SSRF guard rejects it; injected-client migration logic is covered.
- Real Google tokens are validated by one test, which runs only in the upstream CI.
- In a FIPS build the SHA-1 signatures, the `key-pairs create` tests, the `ckms` binary tests and
  the PKCS#12 create-pair test are not run.

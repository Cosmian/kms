# Log Call-Site Directory

This page lists every production log call-site across all Cosmian KMS components,
grouped by domain and crate.

It is not listed in the navigation menu but is accessible via
It is not listed in the navigation menu but is accessible via
[Logging and telemetry](./logging.md).

## How to read this page

The index is organised by usage-domains. Within each domain, each table covers one crate (the UI section is an exception). All tables, ui included, have 5 columns:

| Column        | Meaning                                                    |
| ------------- | ---------------------------------------------------------- |
| **Level**     | `error` `warn` `info` `debug` `trace`                      |
| **Message**   | Constant log string; interpolated values shown as `{name}` |
| **File**      | Source file relative to the crate root                     |
| **Variables** | Each `{name}` — description; `—` when none                 |
| **Notes**     | Reserved for security flags and operator guidance          |

Rows are ordered by severity (`error` → `warn` → `info` → `debug` → `trace`), then
alphabetically by message. Test files are excluded.

> **Tip:** The level filter defaults to `error`.
> Switching to `all` or `trace` reveals hundreds of rows and the page will become long.

---

## Domain: KMS Server

### `cosmian_kms_server`

Crate path: `crate/server`
`RUST_LOG` target: `cosmian_kms_server`

| Level | Message | File | Variables | Notes |
|---|---|---|---|---|
| `error` | `Authentication method configured, but no authentication provided` | `src/middlewares/ensure_auth.rs` | - | Returns 401. Check middleware stack - auth is configured but no bearer/cert/API-token was sent. |
| `error` | `AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set` | `src/routes/aws_xks/sigv4_middleware.rs` | - | Server misconfiguration - enable XKS routes only when `aws_xks_params` is set. |
| `error` | `Error handling socket client: {}` | `src/socket_server.rs` | - | Unix socket handler crashed. The server continues running. |
| `error` | `Failed to open index.html: {e:?}` | `src/start_kms_server.rs` | `e`: caught error | UI not served - verify `ui_index_html_folder` points to a built UI artifact. |
| `error` | `Socket server failed to acquire write lock for stop request: {}` | `src/socket_server.rs` | - | Internal threading issue on shutdown. Server may need SIGTERM if it hangs. |
| `error` | `Socket server failed to connect to itself: {}` | `src/socket_server.rs` | - | Internal stop-signal socket unreachable. Port may be in use by another process. |
| `error` | `Socket server failed to get local address for stop signal` | `src/socket_server.rs` | - | Network/IPC failure. Check connectivity and port availability. |
| `error` | `Socket server failed to write stop request` | `src/socket_server.rs` | - | Network/IPC failure. Check connectivity and port availability. |
| `error` | `Socket server stop signal contained error: {}` | `src/socket_server.rs` | - | Stop channel returned an error. Inspect the formatted error value. |
| `error` | `Windows service failed: {e}` | `src/windows_service.rs` | `e`: caught error | Fatal Windows service error. Check Windows Event Log for the full stack trace. |
| `error` | `{:?} {} 401 unauthorized: Client and server authentication tokens mismatch` | `src/middlewares/api_token/api_token_auth.rs` | - | API token mismatch - rotate the `kms_api_token_id` / `kms_api_token` config values. |
| `error` | `{status_code} - {message}` | `src/routes/mod.rs` | `status_code`: HTTP status code<br>`message`: human-readable message text | Unhandled HTTP error response emitted to the client. |
| `error` | `{}` | `src/start_kms_server.rs` | - | Catch-all error log. Inspect the formatted value for the actual error. |
| `warn` | `Activate: object {} is already Active, rejecting` | `src/core/operations/activate.rs` | - | - |
| `warn` | `AWS XKS create: key {uid} already exists (ignoring creation).` | `src/routes/aws_xks/key_metadata.rs` | `uid`: KMIP object UID | - |
| `warn` | `Azure EKM client authentication is disabled, this should only be done in tests, and won't work for production environments.` | `src/start_kms_server.rs` | - | - |
| `warn` | `Could not insert: certificate: AKI: {}, SKI: {}` | `src/core/operations/validate.rs` | - | - |
| `warn` | `Failed to persist auto-activation of object {}: {}` | `src/core/retrieve_object_utils.rs` | - | - |
| `warn` | `Fetch JWKS: {e}` | `src/middlewares/jwt/jwks.rs` | `e`: caught error | - |
| `warn` | `SigV4 failure: {signature_error}` | `src/routes/aws_xks/sigv4_middleware.rs` | `signature_error`: SigV4 signature validation error | - |
| `warn` | `Socket server: connection failed: {e}` | `src/socket_server.rs` | `e`: caught error | - |
| `warn` | `UI folder invalid or Linux default detected, falling back to: {fallback:#?}` | `src/config/params/server_params.rs` | `fallback`: fallback UI folder path | - |
| `warn` | `{:?} {} 401 unauthorized, no email in JWT` | `src/middlewares/jwt/jwt_token_auth.rs` | - | - |
| `warn` | `{:?} {} 401 unauthorized: bad JWT` | `src/middlewares/jwt/jwt_token_auth.rs` | - | - |
| `warn` | `{error:?}` | `src/middlewares/jwt/jwt_token_auth.rs` | `error`: error detail | - |
| `warn` | `{status_code} - {message}` | `src/routes/mod.rs` | `status_code`: HTTP status code<br>`message`: human-readable message text | - |
| `warn` | `{status} - {}` | `src/routes/crypto/error.rs` | `status`: HTTP response status | - |
| `info` | `AUTHENTICATION token: {:?}` | `src/routes/google_cse/jwt.rs` | - | - |
| `info` | `AUTHORIZATION token headers: {:?}` | `src/routes/google_cse/jwt.rs` | - | - |
| `info` | `AUTHORIZATION token: {:?}` | `src/routes/google_cse/jwt.rs` | - | - |
| `info` | `azure EKM API enabled at {}` | `src/start_kms_server.rs` | - | - |
| `info` | `Command line / file config: {clap_config:#?}` | `src/main.rs` | `clap_config`: parsed CLI configuration | - |
| `info` | `Created Key Pair with cryptographic algorithm {:?}` | `src/core/operations/create_key_pair.rs` | - | - |
| `info` | `Created Object of type {:?}` | `src/core/operations/create.rs` | - | - |
| `info` | `Creating key pair for certification - private key: {sk_uid}, public key: {pk_uid}` | `src/core/operations/certify/resolve_subject.rs` | `sk_uid`: private key UID<br>`pk_uid`: public key UID | - |
| `info` | `Destroyed object` | `src/core/operations/destroy.rs` | - | - |
| `info` | `Encrypted Data : {encrypted_data:?}` | `src/routes/ms_dke/mod.rs` | `encrypted_data`: encrypted data payload | - |
| `info` | `Exported object of type: {}` | `src/core/operations/export_get.rs` | - | - |
| `info` | `Extracted IDP Configs: {:#?}` | `src/config/command_line/idp_auth_config.rs` | - | - |
| `info` | `Feature Test enabled` | `src/main.rs` | - | - |
| `info` | `Found Google CSE migration key, importing it.` | `src/start_kms_server.rs` | - | - |
| `info` | `GET /access/list/{object_id} {user}` | `src/routes/access.rs` | `object_id`: KMIP object UID<br>`user`: authenticated user identity | - |
| `info` | `GET /access/obtained {user}` | `src/routes/access.rs` | `user`: authenticated user identity | - |
| `info` | `GET /access/owned {user}` | `src/routes/access.rs` | `user`: authenticated user identity | - |
| `info` | `GET /certs` | `src/routes/google_cse/mod.rs` | - | - |
| `info` | `GET /download-cli {}` | `src/routes/mod.rs` | - | - |
| `info` | `GET /google_cse/status {}` | `src/routes/google_cse/mod.rs` | - | - |
| `info` | `GET /health {}` | `src/routes/health.rs` | - | - |
| `info` | `GET /hsm/status {}` | `src/routes/mod.rs` | - | - |
| `info` | `GET /me {user}` | `src/routes/access.rs` | `user`: authenticated user identity | - |
| `info` | `GET /server-info {}` | `src/routes/mod.rs` | - | - |
| `info` | `GET /version {}` | `src/routes/mod.rs` | - | - |
| `info` | `GET /version {}` | `src/routes/ms_dke/mod.rs` | - | - |
| `info` | `Key pair created for certification` | `src/core/operations/certify/resolve_subject.rs` | - | - |
| `info` | `KMIP Request message with {} operation(s): {:?}` | `src/core/operations/message.rs` | - | - |
| `info` | `KMS Server configuration: {server_params:#?}` | `src/start_kms_server.rs` | `server_params`: server configuration (debug display) | - |
| `info` | `Load default provider` | `src/openssl_providers.rs` | - | - |
| `info` | `Load FIPS provider` | `src/openssl_providers.rs` | - | - |
| `info` | `Load legacy provider` | `src/openssl_providers.rs` | - | - |
| `info` | `No migration key found, creating new RSA keypair.` | `src/start_kms_server.rs` | - | - |
| `info` | `OpenSSL version: {ossl_version}, in {ossl_dir}, number: {ossl_number:x}` | `src/main.rs` | `ossl_version`: OpenSSL version string<br>`ossl_dir`: OpenSSL modules directory<br>`ossl_number`: OpenSSL version number (hex) | - |
| `info` | `POST /access/grant` | `src/routes/access.rs` | - | - |
| `info` | `POST /access/revoke` | `src/routes/access.rs` | - | - |
| `info` | `POST /aws/kms/xks/v1/health - request id {} - operation {}` | `src/routes/aws_xks/health_status.rs` | - | - |
| `info` | `POST /ekm/info api-version={} user={}` | `src/routes/azure_ekm/mod.rs` | - | - |
| `info` | `POST /ekm/{}/metadata api-version={} user={}` | `src/routes/azure_ekm/mod.rs` | - | - |
| `info` | `POST /ekm/{}/unwrapkey alg={:?} api-version={} user={}` | `src/routes/azure_ekm/mod.rs` | - | - |
| `info` | `POST /ekm/{}/wrapkey alg={:?} api-version={} user={}` | `src/routes/azure_ekm/mod.rs` | - | - |
| `info` | `POST /google_cse/delegate: not implemented yet` | `src/routes/google_cse/mod.rs` | - | - |
| `info` | `POST /google_cse/wrapprivatekey: not implemented yet` | `src/routes/google_cse/mod.rs` | - | - |
| `info` | `POST /google_cse/{info_msg}` | `src/routes/google_cse/mod.rs` | `info_msg`: route info message | - |
| `info` | `POST /kms/xks/v1/keys/{key_id}/decrypt - operation: {} - id: {} - user: {}` | `src/routes/aws_xks/encrypt_decrypt/decrypt_.rs` | `key_id`: XKS key identifier | - |
| `info` | `POST /kms/xks/v1/keys/{key_id}/encrypt - operation: {} - id: {} - user: {}` | `src/routes/aws_xks/encrypt_decrypt/encrypt_.rs` | `key_id`: XKS key identifier | - |
| `info` | `POST /kms/xks/v1/keys/{key_id}/metadata - operation: {} - id: {} - user: {}` | `src/routes/aws_xks/key_metadata.rs` | `key_id`: XKS key identifier | - |
| `info` | `Refreshing JWKS` | `src/middlewares/jwt/jwks.rs` | - | - |
| `info` | `Response TTLV: {ttlv:?}` | `src/routes/kmip.rs` | `ttlv`: TTLV-encoded response | - |
| `info` | `Revoked object type: {}` | `src/core/operations/revoke.rs` | - | - |
| `info` | `RSA Keypair for Google CSE already exists (detected by UNIQUE constraint). Continuing without error.` | `src/start_kms_server.rs` | - | - |
| `info` | `RSA Keypair for Google CSE already exists (pre-check).` | `src/start_kms_server.rs` | - | - |
| `info` | `RSA Keypair for Google CSE already exists.` | `src/start_kms_server.rs` | - | - |
| `info` | `RSA Keypair for Google CSE created.` | `src/start_kms_server.rs` | - | - |
| `info` | `Server started with --info. Exiting` | `src/main.rs` | - | - |
| `info` | `Serving index.html from {}` | `src/start_kms_server.rs` | - | - |
| `info` | `Serving UI from {}` | `src/start_kms_server.rs` | - | - |
| `info` | `Socket server listening on {}` | `src/socket_server.rs` | - | - |
| `info` | `Socket server shutting down due to stop request` | `src/socket_server.rs` | - | - |
| `info` | `Socket server stop signal sent` | `src/socket_server.rs` | - | - |
| `info` | `Starting Cosmian KMS server version {}` | `src/main.rs` | - | - |
| `info` | `Starting the HTTPS KMS server...` | `src/start_kms_server.rs` | - | - |
| `info` | `Windows service received Stop signal, shutting down...` | `src/windows_service.rs` | - | - |
| `info` | `Windows service reporting Running to SCM` | `src/windows_service.rs` | - | - |
| `info` | `XKS Decrypt internal error: {:?}` | `src/routes/aws_xks/encrypt_decrypt/decrypt_.rs` | - | - |
| `info` | `XKS Encrypt internal error: {:?}` | `src/routes/aws_xks/encrypt_decrypt/encrypt_.rs` | - | - |
| `info` | `{}` | `src/main.rs` | - | - |
| `debug` | `<== encrypted {} ciphertexts` | `src/core/operations/encrypt.rs` | - | - |
| `debug` | `==> encrypting {} clear texts` | `src/core/operations/encrypt.rs` | - | - |
| `debug` | `[metrics-cron] Failed to build runtime: {}` | `src/cron.rs` | - | - |
| `debug` | `[metrics-cron] Shutdown signal received; stopping cron thread` | `src/cron.rs` | - | - |
| `debug` | `[OK] base64 of encrypted_dek has been removed` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `[OK] recovered private_key DER bytes (len: {}). Perform RSA decryption` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `[{idx}] Certificate carries id-ce-noRevAvail (RFC 9608): skipping CRL check` | `src/core/operations/validate.rs` | `idx`: certificate index in validation chain | - |
| `debug` | `[{idx}] Verifying certificate: subject: {:?}` | `src/core/operations/validate.rs` | `idx`: certificate index in validation chain | - |
| `debug` | `Access granted on {}` | `src/routes/access.rs` | - | - |
| `debug` | `Access revoke for {}` | `src/routes/access.rs` | - | - |
| `debug` | `Activate: object {} current state = {:?}` | `src/core/operations/activate.rs` | - | - |
| `debug` | `Add Attribute: {}` | `src/core/operations/attributes/add.rs` | - | - |
| `debug` | `AES-GCM decryption failed (expected for implicit rejection): {e}` | `src/routes/crypto/aes_gcm.rs` | `e`: caught error | - |
| `debug` | `after getting CRL: url: {url}` | `src/core/operations/validate.rs` | `url`: URL | - |
| `debug` | `algorithm: {ca:?}, ciphertext length: {}` | `src/core/operations/encrypt.rs` | `ca`: cryptographic algorithm | - |
| `debug` | `allocation_size: {allocation_size}` | `src/routes/google_cse/operations.rs` | `allocation_size`: allocated buffer size | ×2 in this file |
| `debug` | `API token authentication failed: {e:?}` | `src/middlewares/api_token/api_token_middleware.rs` | `e`: caught error | - |
| `debug` | `Authenticated user: {}` | `src/core/kms/permissions.rs` | - | - |
| `debug` | `Authenticated using forced default user: {}` | `src/core/kms/permissions.rs` | - | - |
| `debug` | `Authentication token check: validation disabled` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Building and signing certificate` | `src/core/operations/certify/build_certificate.rs` | - | - |
| `debug` | `check algorithm` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Client certificate authentication failed: {e:?}` | `src/middlewares/tls_auth.rs` | `e`: caught error | - |
| `debug` | `computing resource_key_hash` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Configuration TOML: {conf_str}` | `src/config/command_line/clap_config.rs` | `conf_str`: configuration TOML string | ×2 in this file |
| `debug` | `Create key pair: {request}` | `src/core/operations/create_key_pair.rs` | `request`: KMIP request (debug display) | - |
| `debug` | `create_user_decryption_key_: Access Policy: {access_policy:?}` | `src/core/cover_crypt/create_user_decryption_key.rs` | `access_policy`: Covercrypt access policy expression | - |
| `debug` | `Created secret data with attributes: {}` | `src/core/kms/other_kms_methods.rs` | - | - |
| `debug` | `Created symmetric key with attributes: {}` | `src/core/kms/other_kms_methods.rs` | - | - |
| `debug` | `Creating SecretData object` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `CRL list already contains key: {path}` | `src/core/operations/validate.rs` | `path`: filesystem path | - |
| `debug` | `CRL list already contains key: {url}` | `src/core/operations/validate.rs` | `url`: URL | - |
| `debug` | `CSE Error: {:?}` | `src/routes/google_cse/mod.rs` | - | - |
| `debug` | `decode encrypted_dek` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `decrypt private key` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `decrypt request: {:?}` | `src/routes/aws_xks/encrypt_decrypt/decrypt_.rs` | - | - |
| `debug` | `decrypt_bulk: ==> decrypted {} plaintexts` | `src/core/operations/decrypt.rs` | - | - |
| `debug` | `decrypt_bulk: ==> decrypting {} ciphertexts` | `src/core/operations/decrypt.rs` | - | - |
| `debug` | `Decryption Oracle for prefix: {prefix}, total ciphertext is {} bytes long` | `src/core/operations/decrypt.rs` | `prefix`: decryption oracle prefix bytes | - |
| `debug` | `DeriveKey operation completed successfully` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `DeriveKey operation starting` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `DeriveKey: activation_date={:?} <= now, setting state to Active` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `DeriveKey: no activation_date or future date, setting state to PreActive` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `DeriveKey: No derivation data (info) provided for HKDF` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `DeriveKey: No iteration count provided for PBKDF2, using default` | `src/core/operations/derive_key.rs` | - | - |
| `debug` | `EKM Error: {:?}` | `src/routes/azure_ekm/error.rs` | - | - |
| `debug` | `Enable Google CSE JWT Authorization: {enable_google_cse_authentication}` | `src/start_kms_server.rs` | `enable_google_cse_authentication`: whether Google CSE JWT auth is on | - |
| `debug` | `encode base64 wrapped_dek` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `encrypt request: {:?}` | `src/routes/aws_xks/encrypt_decrypt/encrypt_.rs` | - | - |
| `debug` | `encrypting with RSA {algorithm:?} {padding:?} hashing_fn:{hashing_fn:?} mgf1:{mgf1_hash_fn:?} label_len:{}` | `src/core/operations/encrypt.rs` | `algorithm`: cryptographic algorithm<br>`padding`: asymmetric padding scheme<br>`hashing_fn`: hash function<br>`mgf1_hash_fn`: MGF1 hash function | - |
| `debug` | `entering` | `src/routes/google_cse/jwt.rs` | - | - |
| `debug` | `entering` | `src/routes/google_cse/operations.rs` | - | ×9 in this file |
| `debug` | `exiting with success` | `src/routes/google_cse/operations.rs` | - | ×4 in this file |
| `debug` | `exiting with success: decrypt_size: {decrypt_size}` | `src/routes/google_cse/operations.rs` | `decrypt_size`: decrypted payload length | ×2 in this file |
| `debug` | `exiting with success: {}` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `exporting private key with format: {:?}` | `src/core/operations/export_get.rs` | - | - |
| `debug` | `fetching {jwks_uri}` | `src/middlewares/jwt/jwks.rs` | `jwks_uri`: JWKS endpoint URL | - |
| `debug` | `from_rsa` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Generated JWT for original KACLS: {jwt:?}` | `src/routes/google_cse/operations.rs` | `jwt`: JWT token (debug display) | - |
| `debug` | `Get Attributes: available vendor attributes: [{}]` | `src/core/operations/attributes/get.rs` | - | - |
| `debug` | `Get Attributes: fallback vendor attribute match {}:{} from object attributes` | `src/core/operations/attributes/get.rs` | - | - |
| `debug` | `Get Attributes: no vendor attributes present on object` | `src/core/operations/attributes/get.rs` | - | - |
| `debug` | `Get Attributes: requested vendor attribute not found {}:{}` | `src/core/operations/attributes/get.rs` | - | - |
| `debug` | `Get Attributes: returning vendor attribute match {}:{}` | `src/core/operations/attributes/get.rs` | - | - |
| `debug` | `Get input certificates as bytes` | `src/core/operations/validate.rs` | - | - |
| `debug` | `get metadata request: {:?}` | `src/routes/aws_xks/key_metadata.rs` | - | - |
| `debug` | `get rsa public key on {current_kacls_url}` | `src/routes/google_cse/operations.rs` | `current_kacls_url`: current KACLS server URL | - |
| `debug` | `get_crl_bytes: exiting in success with {} CRLs` | `src/core/operations/validate.rs` | - | - |
| `debug` | `get_status` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Google CSE request authorized for user {authentication_email}` | `src/routes/google_cse/jwt.rs` | `authentication_email`: email from the authentication token | - |
| `debug` | `Import: activation_date={:?} <= now, setting state to Active` | `src/core/operations/import.rs` | - | - |
| `debug` | `Import: no activation_date or future date, setting state to PreActive` | `src/core/operations/import.rs` | - | - |
| `debug` | `Imported object with uid: {}` | `src/core/operations/import.rs` | - | - |
| `debug` | `Importing leaf certificate with attributes: {}` | `src/core/operations/import.rs` | - | - |
| `debug` | `Importing PKCS12: private_key_id={:?}, leaf_certificate_id={:?}, chain={:?}` | `src/core/operations/import.rs` | - | - |
| `debug` | `JWT Access granted to {email}!` | `src/middlewares/jwt/jwt_token_auth.rs` | `email`: user email address | - |
| `debug` | `JWT authentication failed: {e:?}` | `src/middlewares/jwt/jwt_middleware.rs` | `e`: caught error | - |
| `debug` | `Key successfully unwrapped with wrapping key: {}` | `src/core/wrapping/unwrap.rs` | - | - |
| `debug` | `Key wrap type: {:?}` | `src/core/operations/export_get.rs` | - | - |
| `debug` | `Key wrapped successfully by key {}` | `src/core/wrapping/wrap.rs` | - | - |
| `debug` | `ModifyAttribute: persisting attributes for {}` | `src/core/operations/attributes/modify.rs` | - | - |
| `debug` | `no token validation` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Number of certificates in chain: {certificates_number}` | `src/core/operations/validate.rs` | `certificates_number`: number of certificates in chain | - |
| `debug` | `object is not wrapped, no need to unwrap` | `src/core/wrapping/unwrap.rs` | - | - |
| `debug` | `Object type: {}, with unique identifier: {}, destroyed by user {}` | `src/core/operations/destroy.rs` | - | - |
| `debug` | `Object with unique identifier: {} destroyed` | `src/core/operations/destroy.rs` | - | - |
| `debug` | `Object with unique identifier: {} revoked` | `src/core/operations/revoke.rs` | - | - |
| `debug` | `Object with unique identifier: {} revoked by user {}` | `src/core/operations/revoke.rs` | - | - |
| `debug` | `OpenSSL Extensions: {}` | `src/core/operations/certify/build_certificate.rs` | - | - |
| `debug` | `Parent CRL verification: revocation status: {res:?}` | `src/core/operations/validate.rs` | `res`: result (debug display) | - |
| `debug` | `proxy_config: {config:#?}` | `src/config/params/proxy_params.rs` | `config`: configuration (debug display) | - |
| `debug` | `re-wrapping key with current KMS` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `reading full bytes of CRL: url: {url}` | `src/core/operations/validate.rs` | `url`: URL | - |
| `debug` | `Register: activation_date={:?} <= now, setting state to Active` | `src/core/operations/register.rs` | - | - |
| `debug` | `Register: no activation_date or future date, setting state to PreActive` | `src/core/operations/register.rs` | - | - |
| `debug` | `Registered object with uid: {}` | `src/core/operations/register.rs` | - | - |
| `debug` | `Request already authenticated, skipping Ensure Auth middleware` | `src/middlewares/ensure_auth.rs` | - | - |
| `debug` | `request.encrypted_data_encryption_key: {}` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Retrieved Attributes for {} {}, tags {:?}` | `src/core/operations/attributes/get.rs` | - | - |
| `debug` | `retrieving RSA private key from KMS` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `Revocation status: result: {res:?}` | `src/core/operations/validate.rs` | `res`: result (debug display) | - |
| `debug` | `RSA key pair generation: size in bits: {key_size_in_bits}` | `src/core/operations/create_key_pair.rs` | `key_size_in_bits`: RSA key size in bits | - |
| `debug` | `RSA-OAEP encrypt: wrapped CEK ({} bytes) with {} ({} bit key)` | `src/routes/crypto/encrypt.rs` | - | - |
| `debug` | `RSA-OAEP unwrap failed or CEK size mismatch — using implicit rejection` | `src/routes/crypto/decrypt.rs` | - | - |
| `debug` | `Set Attribute: {}` | `src/core/operations/attributes/set.rs` | - | - |
| `debug` | `Set Object Attribute: {}` | `src/core/operations/attributes/add.rs` | - | - |
| `debug` | `Set Object Attribute: {}` | `src/core/operations/attributes/set.rs` | - | - |
| `debug` | `Setting key_wrap_type to NotWrapped due to default_unwrap_types` | `src/core/operations/export_get.rs` | - | - |
| `debug` | `Signature verification result: {validity_indicator:?}` | `src/core/operations/signature_verify.rs` | `validity_indicator`: signature validity result | - |
| `debug` | `signature_verify: effective CP => alg={:?} pad={:?} hash={:?} dsa={:?} mgf1_hash={:?}` | `src/core/operations/signature_verify.rs` | - | - |
| `debug` | `Sigv4 Middleware - Adding missing HOST header: {}` | `src/routes/aws_xks/sigv4_middleware.rs` | - | - |
| `debug` | `Skipping non-HTTP CRL URI: {url}` | `src/core/operations/validate.rs` | `url`: URL | - |
| `debug` | `Socket server received stop signal: {result:?}` | `src/socket_server.rs` | `result`: operation result | - |
| `debug` | `socket server: client connected from {}` | `src/socket_server.rs` | - | - |
| `debug` | `socket server: client {} disconnected` | `src/socket_server.rs` | - | - |
| `debug` | `socket server: received request: {}` | `src/socket_server.rs` | - | - |
| `debug` | `success` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `The wrapping key {wrapping_key_uid} is itself wrapped, unwrapping it first` | `src/core/wrapping/wrap.rs` | `wrapping_key_uid`: UID of the wrapping key | - |
| `debug` | `TLS Authentication enabled` | `src/middlewares/tls_auth.rs` | - | - |
| `debug` | `tls_config: {config:#?}` | `src/config/params/tls_params.rs` | `config`: configuration (debug display) | - |
| `debug` | `Token authentication successful` | `src/middlewares/api_token/api_token_auth.rs` | - | - |
| `debug` | `unwrap key` | `src/routes/google_cse/operations.rs` | - | ×2 in this file |
| `debug` | `Unwrapped cache hit` | `src/core/kms/other_kms_methods.rs` | - | - |
| `debug` | `Unwrapped cache miss. Calling unwrap` | `src/core/kms/other_kms_methods.rs` | - | - |
| `debug` | `user signed data via crypto oracle using: {uid}` | `src/core/operations/sign.rs` | `uid`: KMIP object UID | - |
| `debug` | `validate_tokens` | `src/routes/google_cse/operations.rs` | - | - |
| `debug` | `wrap dek` | `src/routes/google_cse/operations.rs` | - | ×2 in this file |
| `debug` | `Xks Error: {:?}` | `src/routes/aws_xks/error.rs` | - | - |
| `debug` | `XKS Proxy - Path not found: {}` | `src/routes/aws_xks/error.rs` | - | - |
| `debug` | `{conf:#?}` | `src/config/params/server_params.rs` | `conf`: configuration (debug display) | - |
| `debug` | `{request}` | `src/core/operations/attributes/modify.rs` | `request`: KMIP request (debug display) | - |
| `debug` | `{request}` | `src/core/operations/attributes/set.rs` | `request`: KMIP request (debug display) | - |
| `debug` | `{res:#?}` | `src/config/params/server_params.rs` | `res`: result (debug display) | - |
| `debug` | `{ui_index_html_folder:#?}` | `src/config/params/server_params.rs` | `ui_index_html_folder`: configured UI folder path | ×2 in this file |
| `debug` | `{wrap_request:?}` | `src/routes/google_cse/jwt.rs` | `wrap_request`: CSE wrap request (debug display) | - |
| `debug` | `{} identifiers` | `src/core/operations/validate.rs` | - | - |
| `trace` | `:` | `src/core/operations/attributes/dispatch_macros.rs` | — | — |
| `trace` | `: {:?}` | `src/core/operations/attributes/dispatch_macros.rs` | — | — |
| `trace` | `[api_token_auth] Authorization header received (length: {} chars)` | `src/middlewares/api_token/api_token_auth.rs` | — | — |
| `trace` | `[api_token_auth] comparing client token ({} chars) with server token` | `src/middlewares/api_token/api_token_auth.rs` | — | — |
| `trace` | `[destroy-core] certificate zeroization uid={unique_identifier}` | `src/core/operations/destroy.rs` | `unique_identifier` — … | — |
| `trace` | `[destroy-core] opaque object zeroization uid={unique_identifier} len={}` | `src/core/operations/destroy.rs` | `unique_identifier` — … | — |
| `trace` | `[destroy-core] uid={unique_identifier} type={:?} pre-state={:?} object={object}` | `src/core/operations/destroy.rs` | `unique_identifier` — …<br>`object` — … | — |
| `trace` | `[destroy] DENY revoke-before-destroy (explicitly activated) uid={} type={:?} state={:?} activation_date={:?} initial_date={:?}` | `src/core/operations/destroy.rs` | — | — |
| `trace` | `[destroy] Failed to destroy linked private key {}: {:?}. Continuing with public key destruction.` | `src/core/operations/destroy.rs` | — | — |
| `trace` | `[destroy] policy-eval uid={} type={:?} db_state={:?} attr_state={:?} effective_state={:?} activation_date={:?} policy_state={:?} remove={}` | `src/core/operations/destroy.rs` | — | — |
| `trace` | `[revoke] proceed-destroyed uid={uid} state={:?}` | `src/core/operations/revoke.rs` | `uid` — … | — |
| `trace` | `[revoke] skip uid={uid} reason=state-not-revocable state={:?}` | `src/core/operations/revoke.rs` | `uid` — … | — |
| `trace` | `algorithm: {:?}, padding: {:?}, hashing_fn: {:?}` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `algorithm={:?}, data_len={}` | `src/core/operations/hash.rs` | — | — |
| `trace` | `All certificates have been sorted` | `src/core/operations/validate.rs` | — | ×2 in this file |
| `trace` | `Already an unwrapped key` | `src/core/kms/other_kms_methods.rs` | — | — |
| `trace` | `Attribute: Object type {:?} does not have attributes (nor key block)` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `authentication token validated for {authentication_email}` | `src/routes/google_cse/jwt.rs` | `authentication_email` — … | — |
| `trace` | `authorization token validated successfully` | `src/routes/google_cse/jwt.rs` | — | — |
| `trace` | `Auto-activating object {} (activation_date {} <= now {})` | `src/core/retrieve_object_utils.rs` | — | — |
| `trace` | `build_pkcs12_for_private_key: {} with format: {:?}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `building chain from leaf certificate:  {}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `building the PKCS12` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `Certificate attribute link: {}` | `src/core/operations/certify/certify_op.rs` | — | — |
| `trace` | `Certificate attributes links: None` | `src/core/operations/certify/certify_op.rs` | — | — |
| `trace` | `certificate parent id is:  {}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `Certificate parent id is: {parent_id}` | `src/core/operations/export_get.rs` | `parent_id` — … | — |
| `trace` | `Certify KeypairAndSubjectName:{unique_identifier} : keypair data: {keypair_data}` | `src/core/operations/certify/certify_op.rs` | `unique_identifier` — …<br>`keypair_data` — … | — |
| `trace` | `Certify X509Req or Certificate:{unique_identifier}` | `src/core/operations/certify/certify_op.rs` | `unique_identifier` — … | — |
| `trace` | `Checking key with ID: {}` | `src/core/retrieve_object_utils.rs` | — | — |
| `trace` | `Checking permissions to wrap with key {wrapping_key_uid}` | `src/core/wrapping/wrap.rs` | `wrapping_key_uid` — … | — |
| `trace` | `Checking usage mask for wrapping key {wrapping_key_uid}` | `src/core/wrapping/wrap.rs` | `wrapping_key_uid` — … | — |
| `trace` | `ciphertext (ECB): {ciphertext:?}, aad: {aad:?}, padding_method: {padding_method:?}` | `src/core/operations/decrypt.rs` | `ciphertext` — …<br>`aad` — …<br>`padding_method` — … | — |
| `trace` | `Client certificate common name: {}` | `src/middlewares/tls_auth.rs` | — | — |
| `trace` | `configure_cipher_suites: Enable default cipher suites (mozilla_intermediate_v5)` | `src/tls_config.rs` | — | — |
| `trace` | `configure_cipher_suites: Setting custom cipher string: {suites}` | `src/tls_config.rs` | `suites` — … | — |
| `trace` | `Configuring client certificate verification for {}` | `src/tls_config.rs` | — | — |
| `trace` | `converting the private key {} to openssl pkey` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `create_base_openssl_acceptor: creating OpenSSL SslAcceptorBuilder for {server_type}` | `src/tls_config.rs` | `server_type` — … | — |
| `trace` | `Creating object of type {:?} with UID {} and attributes {}` | `src/core/operations/create.rs` | — | — |
| `trace` | `Creating OpenSSL SslAcceptor for socket server` | `src/socket_server.rs` | — | — |
| `trace` | `Creating OpenSSL SslAcceptorBuilder with TLS parameters` | `src/start_kms_server.rs` | — | — |
| `trace` | `CRL deserialized OK: {crl_path}` | `src/core/operations/validate.rs` | `crl_path` — … | ×2 in this file |
| `trace` | `cryptographic_algorithm: {cryptographic_algorithm}` | `src/core/operations/create_key_pair.rs` | `cryptographic_algorithm` — … | — |
| `trace` | `curve: {curve}` | `src/core/operations/create_key_pair.rs` | `curve` — … | — |
| `trace` | `Decrypt: uid={:?}, data_len={}` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `DELETE /v1/crypto/keys/{kid}` | `src/routes/crypto/keys.rs` | `kid` — … | — |
| `trace` | `Description: {:?}` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `Discover versions: {}` | `src/core/operations/discover_versions.rs` | — | — |
| `trace` | `ECB encrypt result: ciphertext_len={}` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `ECB encrypt: plaintext_len={}, padding_method={padding_method:?}` | `src/core/operations/encrypt.rs` | `padding_method` — … | — |
| `trace` | `effective RSA CP -> padding={:?} hashing={:?} mgf1={:?} label_len={}` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `encrypt result: ciphertext_len={}, tag_len={}` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `entering` | `src/routes/google_cse/jwt.rs` | — | — |
| `trace` | `Entering get_key_and_cipher` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `Entering import KMIP operation: uid={}, object_type={}` | `src/core/operations/import.rs` | — | — |
| `trace` | `Entering message KMIP operation: {request}` | `src/core/operations/message.rs` | `request` — … | — |
| `trace` | `entering. owm: {}` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `export_get_private_key: {} for operation: {}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `Extracting key block for decryption to identify key format type...` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `Fetching public key: {public_key_name} and attempting to extract RSA modulus and public exponent from key material` | `src/routes/utils.rs` | `public_key_name` — … | — |
| `trace` | `Found CRL URI: {crl_uri}` | `src/core/operations/validate.rs` | `crl_uri` — … | — |
| `trace` | `found link to certificate: {}` | `src/core/certificate/find.rs` | — | — |
| `trace` | `found link to public key: {}. Will get certificate link from there` | `src/core/certificate/find.rs` | — | — |
| `trace` | `Found uid: {}, attributes: {}` | `src/core/operations/locate.rs` | — | — |
| `trace` | `function={:?}` | `src/core/operations/pkcs11.rs` | — | — |
| `trace` | `Get Attributes: Attributes: {}` | `src/core/operations/attributes/get.rs` | — | — |
| `trace` | `Get Attributes: computing LinkType set` | `src/core/operations/attributes/get.rs` | — | — |
| `trace` | `Get Attributes: Requested attributes: {req_attributes:?}` | `src/core/operations/attributes/get.rs` | `req_attributes` — … | — |
| `trace` | `Get Attributes: Response: {}` | `src/core/operations/attributes/get.rs` | — | — |
| `trace` | `Get Attributes: Retrieved object for get attributes: {}` | `src/core/operations/attributes/get.rs` | — | — |
| `trace` | `GET KEY /{} {:?}` | `src/routes/ms_dke/mod.rs` | — | — |
| `trace` | `Get: {}` | `src/core/operations/get.rs` | — | — |
| `trace` | `get_crl_bytes: entering: uri_list: {uri_list:?}` | `src/core/operations/validate.rs` | `uri_list` — … | — |
| `trace` | `got key bytes of length: {}, aead: {:?}. Proceeding to get the nonce...` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `HMAC computed: {} bytes` | `src/core/operations/mac.rs` | — | — |
| `trace` | `HSM get_key_type probe for '{uid}' failed: {e}; proceeding with destroy` | `src/core/operations/destroy.rs` | `uid` — …<br>`e` — … | — |
| `trace` | `Ignoring tag {x:?} which does not match to an attribute` | `src/core/operations/attributes/get.rs` | `x` — … | — |
| `trace` | `import opaque_object: uid={}` | `src/core/operations/import.rs` | — | — |
| `trace` | `import secret_data: uid={}` | `src/core/operations/import.rs` | — | — |
| `trace` | `Internal create key pair` | `src/core/operations/create_key_pair.rs` | — | — |
| `trace` | `Internal create private key` | `src/core/kms/other_kms_methods.rs` | — | — |
| `trace` | `Internal create private key (FIPS build)` | `src/core/kms/other_kms_methods.rs` | — | — |
| `trace` | `Internal rekey key pair Covercrypt` | `src/core/cover_crypt/rekey_keys.rs` | — | — |
| `trace` | `Issuer certificate id: {}` | `src/core/operations/certify/resolve_issuer.rs` | — | — |
| `trace` | `Issuer private key id: {}` | `src/core/operations/certify/resolve_issuer.rs` | — | — |
| `trace` | `Issuer Subject name: {:?}` | `src/core/operations/certify/certify_op.rs` | — | — |
| `trace` | `iv_counter_nonce: {}, ciphertext: {}, authenticated_tag: {}` | `src/routes/google_cse/operations.rs` | — | — |
| `trace` | `JWT Authentication...` | `src/middlewares/jwt/jwt_token_auth.rs` | — | — |
| `trace` | `key id {}` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `key_format_type: {key_format_type:?}` | `src/core/operations/export_get.rs` | `key_format_type` — … | — |
| `trace` | `key_material key format: {:?}` | `src/core/operations/digest.rs` | — | — |
| `trace` | `Leaf certificate extracted from PKCS12` | `src/core/operations/import.rs` | — | — |
| `trace` | `Link: {}` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `Locate: filtering out HSM key {uid_str} — user {user} has no grants` | `src/core/operations/locate.rs` | `uid_str` — …<br>`user` — … | — |
| `trace` | `Mac: algorithm: {algorithm:?}` | `src/core/operations/mac.rs` | `algorithm` — … | — |
| `trace` | `Mac: data len: {}` | `src/core/operations/mac.rs` | — | — |
| `trace` | `matching on key format type: {:?}` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `matching on key format type: {:?}` | `src/core/operations/sign.rs` | — | — |
| `trace` | `matching on public key format type: {:?}` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `ModifyAttribute: ActivationDate: {:?}` | `src/core/operations/attributes/modify.rs` | — | — |
| `trace` | `ModifyAttribute: Link: {}` | `src/core/operations/attributes/modify.rs` | — | — |
| `trace` | `ModifyAttribute: Name: {}` | `src/core/operations/attributes/modify.rs` | — | — |
| `trace` | `ModifyAttribute: retrieved target object {}` | `src/core/operations/attributes/modify.rs` | — | — |
| `trace` | `ModifyAttribute: VendorAttribute: {}` | `src/core/operations/attributes/modify.rs` | — | — |
| `trace` | `Name: {name}` | `src/core/operations/attributes/add.rs` | `name` — … | — |
| `trace` | `no effective cryptographic parameters; defaults will apply` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `No issuer certificate id provided` | `src/core/operations/certify/resolve_issuer.rs` | — | — |
| `trace` | `No issuer private key id provided` | `src/core/operations/certify/resolve_issuer.rs` | — | — |
| `trace` | `No UI folder containing index.html found at {}` | `src/start_kms_server.rs` | — | — |
| `trace` | `Non revocable keys detected: won't be revoked {non_revocable_key_id:?}` | `src/core/operations/revoke.rs` | `non_revocable_key_id` — … | — |
| `trace` | `Not using Client Certificate Authentication with OpenSSL` | `src/start_kms_server.rs` | — | — |
| `trace` | `OpenSSL Private Key instantiated before signing` | `src/core/operations/sign.rs` | — | — |
| `trace` | `OpenSSL Public Key instantiated before encryption` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `Operation processed successfully: {op}` | `src/core/operations/message.rs` | `op` — … | — |
| `trace` | `Operation processing failed: {e}` | `src/core/operations/message.rs` | `e` — … | — |
| `trace` | `params: {server_params:?}` | `src/core/kms/mod.rs` | `server_params` — … | — |
| `trace` | `PKCS12 parsed successfully` | `src/core/operations/import.rs` | — | — |
| `trace` | `plaintext length: {} bytes` | `src/core/operations/decrypt.rs` | — | — |
| `trace` | `plaintext_len={}, nonce_len={}, aad_len={}, padding_method={padding_method:?}` | `src/core/operations/encrypt.rs` | `padding_method` — … | — |
| `trace` | `POST /v1/crypto/decrypt` | `src/routes/crypto/decrypt.rs` | — | — |
| `trace` | `POST /v1/crypto/encrypt kid={} alg={}` | `src/routes/crypto/encrypt.rs` | — | — |
| `trace` | `POST /v1/crypto/keys kty={}` | `src/routes/crypto/keys.rs` | — | — |
| `trace` | `POST /v1/crypto/keys/unwrap` | `src/routes/crypto/unwrap.rs` | — | — |
| `trace` | `POST /v1/crypto/mac kid={}` | `src/routes/crypto/mac.rs` | — | — |
| `trace` | `POST /v1/crypto/sign kid={}` | `src/routes/crypto/sign.rs` | — | — |
| `trace` | `POST /v1/crypto/verify` | `src/routes/crypto/verify.rs` | — | — |
| `trace` | `POST /{key_name}/{key_id}/Decrypt {encrypted_data:?}` | `src/routes/ms_dke/mod.rs` | `key_name` — …<br>`key_id` — …<br>`encrypted_data` — … | — |
| `trace` | `post_process_private_key: operation type: {operation_type:?}` | `src/core/operations/export_get.rs` | `operation_type` — … | — |
| `trace` | `Private key attributes after lifecycle update: {}` | `src/core/operations/create_key_pair.rs` | — | — |
| `trace` | `Private key extracted from PKCS12` | `src/core/operations/import.rs` | — | — |
| `trace` | `Private key linked to leaf certificate` | `src/core/operations/import.rs` | — | — |
| `trace` | `Private key operation created` | `src/core/operations/import.rs` | — | — |
| `trace` | `Private key wrapped and cached` | `src/core/operations/import.rs` | — | — |
| `trace` | `process_secret_data: object_with_metadata: {}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key: object_with_metadata: {}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `processing key_value` | `src/core/operations/digest.rs` | — | — |
| `trace` | `Processing KMIP operation: {operation_name} with user: {user:?}` | `src/core/operations/message.rs` | `operation_name` — …<br>`user` — … | — |
| `trace` | `Processing PKCS12 import` | `src/core/operations/import.rs` | — | — |
| `trace` | `Public key attributes after lifecycle update: {}` | `src/core/operations/create_key_pair.rs` | — | — |
| `trace` | `Public key extracted from PKCS12` | `src/core/operations/import.rs` | — | — |
| `trace` | `ReKey: {}` | `src/core/operations/rekey/symmetric/mod.rs` | — | — |
| `trace` | `ReKeyKeyPair: {}` | `src/core/operations/rekey/keypair/mod.rs` | — | — |
| `trace` | `Request: {:?}` | `src/routes/azure_ekm/mod.rs` | — | ×4 in this file |
| `trace` | `request: {username} {}` | `src/start_kms_server.rs` | `username` — … | — |
| `trace` | `Response message: {response_message}` | `src/core/operations/message.rs` | `response_message` — … | — |
| `trace` | `Response sent to {}` | `src/socket_server.rs` | — | — |
| `trace` | `Retrieved certificate: {} for private key: {}` | `src/core/certificate/find.rs` | — | — |
| `trace` | `Retrieved object for: {}` | `src/core/operations/activate.rs` | — | — |
| `trace` | `Retrieved object for: {}` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `Retrieved object for: {}` | `src/core/operations/attributes/delete.rs` | — | — |
| `trace` | `Retrieving certificate for private key: {}` | `src/core/certificate/find.rs` | — | — |
| `trace` | `Retrieving issuer private key and certificate: private_key_id: {:?}, certificate_id: {:?}` | `src/core/certificate/find.rs` | — | — |
| `trace` | `Retrieving private key for certificate: certificate_uid_or_tags: {:?}` | `src/core/certificate/find.rs` | — | — |
| `trace` | `RNGRetrieve: {}` | `src/core/operations/rng_retrieve.rs` | — | — |
| `trace` | `Root and possibly leaf removed from initial certificate list. Left: {}` | `src/core/operations/validate.rs` | — | — |
| `trace` | `Sensitive: {:?}` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `Set Attribute: Link: {}` | `src/core/operations/attributes/set.rs` | — | — |
| `trace` | `Set Attribute: Name: {}` | `src/core/operations/attributes/set.rs` | — | — |
| `trace` | `Set Attribute: Object type {:?} does not have attributes (nor key block)` | `src/core/operations/attributes/set.rs` | — | — |
| `trace` | `Set Attribute: Retrieved target object` | `src/core/operations/attributes/set.rs` | — | — |
| `trace` | `Set Attribute: Vendor Attribute: {}` | `src/core/operations/attributes/set.rs` | — | — |
| `trace` | `sk_uid: {sk_uid}, pk_uid: {pk_uid}` | `src/core/operations/create_key_pair.rs` | `sk_uid` — …<br>`pk_uid` — … | — |
| `trace` | `state_allows: {state_allows}: state: {state}, operation_type: {operation_type}` | `src/core/retrieve_object_utils.rs` | `state_allows` — …<br>`state` — …<br>`operation_type` — … | — |
| `trace` | `Subject name: {:?}` | `src/core/operations/certify/certify_op.rs` | — | — |
| `trace` | `The wrapping key {wrapping_key_uid} is authorized to wrap keys` | `src/core/wrapping/wrap.rs` | `wrapping_key_uid` — … | — |
| `trace` | `TLS Authentication...` | `src/middlewares/tls_auth.rs` | — | — |
| `trace` | `TLS Authentication: no peer certificate found` | `src/middlewares/tls_auth.rs` | — | — |
| `trace` | `Token authentication using this API token ID: {api_token_id}` | `src/middlewares/api_token/api_token_auth.rs` | `api_token_id` — … | — |
| `trace` | `token decoded with {app_name} jwt config` | `src/routes/google_cse/jwt.rs` | `app_name` — … | — |
| `trace` | `Try to validate token from issuer: {issuer_uri:?}` | `src/routes/google_cse/jwt.rs` | `issuer_uri` — … | — |
| `trace` | `UID: {:?}, State: {:?}, Attributes: {}` | `src/core/operations/locate.rs` | — | ×2 in this file |
| `trace` | `uid={:?}` | `src/core/operations/mac.rs` | — | — |
| `trace` | `uid={:?}, data_len={}` | `src/core/operations/encrypt.rs` | — | — |
| `trace` | `uid={}` | `src/core/operations/mac.rs` | — | — |
| `trace` | `uid={} remove={} cascade={}` | `src/core/operations/destroy.rs` | — | — |
| `trace` | `UIDs count (post-truncate): {}` | `src/core/operations/locate.rs` | — | — |
| `trace` | `updated_master_secret_key_bytes len: {}` | `src/core/cover_crypt/create_user_decryption_key.rs` | — | — |
| `trace` | `User {user} does not have permission for operation {operation_type:?} on object {}` | `src/core/retrieve_object_utils.rs` | `user` — …<br>`operation_type` — … | — |
| `trace` | `User {user} has permission for operation {operation_type:?} on object {}` | `src/core/retrieve_object_utils.rs` | `user` — …<br>`operation_type` — … | — |
| `trace` | `Using Client Certificate Authentication with OpenSSL` | `src/start_kms_server.rs` | — | — |
| `trace` | `valid_jwt headers: {:?}` | `src/routes/google_cse/jwt.rs` | — | — |
| `trace` | `valid_jwt user claims: {:?}` | `src/routes/google_cse/jwt.rs` | — | — |
| `trace` | `validate token: KACLS URL {google_cse_kacls_url}` | `src/routes/google_cse/jwt.rs` | `google_cse_kacls_url` — … | — |
| `trace` | `Validate: {}` | `src/core/operations/validate.rs` | — | — |
| `trace` | `validate_cse_authorization_token: KACLS URL {google_cse_kacls_url}` | `src/routes/google_cse/jwt.rs` | `google_cse_kacls_url` — … | — |
| `trace` | `validating authentication token, expected JWT issuer: {}` | `src/middlewares/jwt/jwt_config.rs` | — | — |
| `trace` | `validating CSE authorization token, expected issuer : {}` | `src/routes/google_cse/jwt.rs` | — | — |
| `trace` | `Vendor Attribute: {}` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `verify_chain_signature: entering: number of certificates: {}` | `src/core/operations/validate.rs` | — | — |
| `trace` | `verify_crls: exiting in success` | `src/core/operations/validate.rs` | — | — |
| `trace` | `Waiting for test socket server to start...` | `src/socket_server.rs` | — | — |
| `trace` | `wrapped_key length: {} chars` | `src/routes/google_cse/operations.rs` | — | — |
| `trace` | `Wrapping key retrieved successfully: {wrapping_key}` | `src/core/wrapping/wrap.rs` | `wrapping_key` — … | — |
| `trace` | `Wrapping key with id: {wrapping_key_id}` | `src/core/wrapping/wrap.rs` | `wrapping_key_id` — … | — |
| `trace` | `{debug_msg}. Certificate: subject: {:?}, AKI: {:?}, SKI: {:?}` | `src/core/operations/validate.rs` | `debug_msg` — … | — |
| `trace` | `{info_msg} request received` | `src/routes/google_cse/mod.rs` | `info_msg` — … | — |
| `trace` | `{jwt_authorization_config:#?}` | `src/routes/google_cse/jwt.rs` | `jwt_authorization_config` — … | — |
| `trace` | `{request}` | `src/core/operations/attributes/get.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/check.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/create.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/destroy.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/export.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/query.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/register.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/revoke.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/rng_seed.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/sign.rs` | `request` — … | — |
| `trace` | `{request}` | `src/core/operations/signature_verify.rs` | `request` — … | — |
| `trace` | `{}` | `src/core/operations/activate.rs` | — | — |
| `trace` | `{}` | `src/core/operations/attributes/add.rs` | — | — |
| `trace` | `{}` | `src/core/operations/attributes/delete.rs` | — | — |
| `trace` | `{}` | `src/core/operations/certify/certify_op.rs` | — | — |
| `trace` | `{}` | `src/core/operations/locate.rs` | — | — |
| `error` | `Failed to convert response message to TTLV: {}` | `src/routes/kmip.rs` | — | ×2 in this file |
| `error` | `Failed to find KMIP version` | `src/routes/kmip.rs` | — | — |
| `error` | `Failed to parse RequestMessage: {}` | `src/routes/kmip.rs` | — | — |
| `error` | `Failed to process request: {}` | `src/routes/kmip.rs` | — | ×2 in this file |
| `error` | `OpenSSL does not appear to be available (version number is 0).              Please verify that OpenSSL is correctly installed and accessible.` | `src/main.rs` | — | — |
| `warn` | `An Edwards Keypair on curve 25519 should not be requested to perform                              ECDH. Creating anyway.` | `src/core/operations/create_key_pair.rs` | — | — |
| `warn` | `An Edwards Keypair on curve 448 should not be requested to perform                              ECDH. Creating anyway.` | `src/core/operations/create_key_pair.rs` | — | — |
| `warn` | `CRL signature could not be verified against chain issuers; issuer: {:?}.                          Continuing with status checks.` | `src/core/operations/validate.rs` | — | — |
| `warn` | `Import: CRL check could not be completed ({e}),                              proceeding with {desired_state:?} state` | `src/core/operations/import.rs` | `e`, `desired_state` | — |
| `warn` | `The UI index HTML folder does not contain an index.html file:                  {ui_index_html_folder:#?}` | `src/config/params/server_params.rs` | `ui_index_html_folder` | — |
| `warn` | `Unsupported Block Cipher Mode for AES: {x:?}. The Authenticated                                  Encryption Tag will NOT be extracted.` | `src/routes/kmip.rs` | `x` | — |
| `warn` | `User-supplied keyUsage in extension config overrides the RFC-mandated PQC keyUsage              extension (RFC 9881/9909/9935)` | `src/core/operations/certify/build_certificate.rs` | — | — |
| `info` | `POST /kmip {}.{} Binary. Request: {:?} {}` | `src/routes/kmip.rs` | — | — |
| `info` | `POST /kmip {}.{} JSON. Request: {:?} {}` | `src/routes/kmip.rs` | — | — |
| `info` | `POST /kmip/2_1. Request: {:?} {}` | `src/routes/kmip.rs` | — | — |
| `debug` | `...unwrapping the key block with key uid: {unwrapping_key_uid} using an encryption              oracle, user: {user}` | `src/core/wrapping/unwrap.rs` | `unwrapping_key_uid`, `user` | — |
| `debug` | `...unwrapping the key block with key uid: {unwrapping_key_uid} using the KMS, user:              {user}` | `src/core/wrapping/unwrap.rs` | `unwrapping_key_uid`, `user` | — |
| `debug` | `...wrapping the key block with key uid: {wrapping_key_uid} using an encryption              oracle, user: {user}` | `src/core/wrapping/wrap.rs` | `wrapping_key_uid`, `user` | — |
| `debug` | `...wrapping the key block with key uid: {wrapping_key_uid} using the KMS, user:              {user}` | `src/core/wrapping/wrap.rs` | `wrapping_key_uid`, `user` | — |
| `debug` | `[kms-init] Failed to seed kms.keys.active.count: {e}` | `src/core/kms/mod.rs` | `e` | — |
| `debug` | `[kms-init] Failed to seed kms.objects.total: {e}` | `src/core/kms/mod.rs` | `e` | — |
| `debug` | `[metrics-cron] Failed to sync kms.keys.active.count: {}` | `src/cron.rs` | — | — |
| `debug` | `[metrics-cron] Failed to sync kms.objects.total: {}` | `src/cron.rs` | — | — |
| `debug` | `[metrics-cron] kms.keys.active.count synced to {}` | `src/cron.rs` | — | — |
| `debug` | `[metrics-cron] kms.objects.total synced to {}` | `src/cron.rs` | — | — |
| `debug` | `[metrics-cron] reconcile_all_object_counts failed: {}` | `src/cron.rs` | — | — |
| `debug` | `API Token Middleware: An authenticated user was found; there is no need to                      authenticate twice...` | `src/middlewares/api_token/api_token_middleware.rs` | — | — |
| `debug` | `DeriveKey: No derivation data provided - this may be acceptable if a Secret Data              object identifier is provided` | `src/core/operations/derive_key.rs` | — | — |
| `debug` | `Import: certificate is revoked per CRL check,                              setting state to Compromised` | `src/core/operations/import.rs` | — | — |
| `debug` | `JWT: An authenticated user was found; there is no need to authenticate                      twice...` | `src/middlewares/jwt/jwt_middleware.rs` | — | — |
| `debug` | `JWT: An authenticated user was found; there is no need to authenticate                      twice...` | `src/middlewares/tls_auth.rs` | — | — |
| `debug` | `Request bytes: {}` | `src/routes/kmip.rs` | — | — |
| `debug` | `Request TTLV: {ttlv:#?}` | `src/routes/kmip.rs` | `ttlv` | — |
| `debug` | `Response Message Bytes: {}` | `src/routes/kmip.rs` | — | — |
| `debug` | `Response Message TTLV: {response_ttlv:#?}` | `src/routes/kmip.rs` | `response_ttlv` | — |
| `debug` | `The user: {user}, is authorized to wrap with the key {wrapping_key_uid}. Encoding: {:?},          format: {}` | `src/core/wrapping/wrap.rs` | `user`, `wrapping_key_uid` | — |
| `debug` | `This is a {major}.{minor} Decrypt message. Extracting                                      Authenticated Encryption Tag of length {len} from Data field` | `src/routes/kmip.rs` | `major`, `minor`, `len` | — |
| `trace` | `Certify PublicKeyAndSubjectName:{unique_identifier}: public key:                  {from_public_key}` | `src/core/operations/certify/certify_op.rs` | `unique_identifier`, `from_public_key` | — |
| `trace` | `ciphertext: {ciphertext:?}, nonce: {nonce:?}, aad: {aad:?}, tag: {tag:?},              padding_method: {padding_method:?}` | `src/core/operations/decrypt.rs` | `ciphertext`, `nonce`, `aad`, `tag`, `padding_method` | — |
| `trace` | `enter export_get op={:?} req={}` | `src/core/operations/export_get.rs` | — | ×2 in this file |
| `trace` | `get_attribute_list uid={} refs=[{}]` | `src/core/operations/attributes/get_list.rs` | — | — |
| `trace` | `post-process symmetric key uid={} final_format={:?}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key enter uid={} requested_format={:?} wrap_type={:?}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key exit uid={} final_format={:?}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key key_block initial format={:?} wrapped={} uid={}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key missing key_value structure uid={}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key set Raw uid={}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `process_symmetric_key set TransparentSymmetricKey uid={}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `processing symmetric key uid={} state={:?} requested_format={:?}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `Request Message: {request_message}` | `src/routes/kmip.rs` | `request_message` | — |
| `trace` | `Response Message: {response_message}` | `src/routes/kmip.rs` | `response_message` | — |
| `trace` | `retrieved object uid={} type={:?} state={:?} key_fmt={:?}` | `src/core/operations/export_get.rs` | — | — |
| `trace` | `uid_or_tags: {uid_or_tags:?}, user: {user},          operation_type: {operation_type:?}` | `src/core/retrieve_object_utils.rs` | `uid_or_tags`, `user`, `operation_type` | — |
| `error` | `Failed to convert Response TTLV to bytes: {}: TTLV:\n{:#?}` | `src/routes/kmip.rs` | — | — |
| `warn` | `Failed to process request:\n{response_message}` | `src/routes/kmip.rs` | `response_message` | — |
| `info` | `\n{:?}` | `src/routes/kmip.rs` | — | — |
| `trace` | `JWK has been found:\n{jwk:?}` | `src/middlewares/jwt/jwt_config.rs` | `jwk` | — |
| `trace` | `JWK has been found:\n{jwk:?}` | `src/routes/google_cse/jwt.rs` | `jwk` | — |
| `warn` | `Failed to persist auto-deactivation of object {}: {}` | `src/core/retrieve_object_utils.rs` | - | ×2 in this file |
| `warn` | `failed to re-wrap dependant {dep_uid} with new key: {e}, skipping` | `src/core/operations/rekey/common.rs` | `dep_uid`, `e` | - |
| `warn` | `failed to unwrap dependant {dep_uid}: {e}, skipping` | `src/core/operations/rekey/common.rs` | `dep_uid`, `e` | - |
| `warn` | `skipping re-wrap of dependant {dep_uid}: owned by '{}', not by '{owner}'` | `src/core/operations/rekey/common.rs` | `dep_uid`, `owner` | - |
| `warn` | `wrapped dependant {dep_uid} not found, skipping` | `src/core/operations/rekey/common.rs` | `dep_uid` | - |
| `warn` | `{}: keyset chain depth {} ≥ warn threshold {} for uid {};                              consider re-encrypting with the latest key` | `src/core/operations/key_ops/crypto_op.rs` | - | - |
| `info` | `Rekey finalized: old={} → new={}, user={user}` | `src/core/operations/rekey/common.rs` | `user` | - |
| `debug` | `[auto-rotate-cron] Failed to build runtime: {}` | `src/cron.rs` | - | - |
| `debug` | `[auto-rotate-cron] Running scheduled key auto-rotation check` | `src/cron.rs` | - | - |
| `debug` | `[auto-rotate-cron] Shutdown signal received; stopping cron thread` | `src/cron.rs` | - | - |
| `trace` | `Auto-deactivating object {} (deactivation_date {} <= now {})` | `src/core/retrieve_object_utils.rs` | - | ×2 in this file |
| `trace` | `execute_keyset_try_each: key {} failed for {}: {}` | `src/core/operations/key_ops/crypto_op.rs` | - | - |
| `trace` | `HSM ReKey: old={uid} → new={new_uid} (slot={slot_id}, gen={new_gen}), user={user}` | `src/core/operations/rekey/symmetric/hsm.rs` | `uid`, `new_uid`, `slot_id`, `new_gen`, `user` | - |
| `trace` | `ReCertify: {}` | `src/core/operations/recertify.rs` | - | - |
| `trace` | `ReKey: resolved keyset ref '{}' → '{}'` | `src/core/operations/rekey/symmetric/mod.rs` | - | - |
| `trace` | `SetAttribute: clearing CKA_START_DATE / CKA_END_DATE on HSM key '{}' (rotation disabled)` | `src/core/operations/attributes/set.rs` | - | - |
| `trace` | `SetAttribute: writing CKA_LABEL '{}' on HSM key '{}'` | `src/core/operations/attributes/set.rs` | - | - |
| `trace` | `SetAttribute: writing CKA_START_DATE={} CKA_END_DATE={} on HSM key '{}'` | `src/core/operations/attributes/set.rs` | - | - |
| `trace` | `walk_keyset_chain: keyset '{}' has {} keys in chain` | `src/core/uid_utils.rs` | - | - |
| `warn` | `` ui_session_salt is not configured — using a randomly generated ephemeral              session key. Sessions will be invalidated on server restart and are not              portable across instances. For persistent sessions and load-balanced              deployments, set `ui_session_salt` (or KMS_UI_SESSION_SALT) to a strong              random secret value. `` | `src/start_kms_server.rs` | - | - |
| `trace` | `` Found valid JWK in JWKS at `{jwks_uri}`: {jwk:#?} `` | `src/middlewares/jwt/jwks.rs` | `jwks_uri`, `jwk` | - |
| `trace` | `` Ignoring invalid JWK in JWKS at `{jwks_uri}`: {e}: {v:#?} `` | `src/middlewares/jwt/jwks.rs` | `jwks_uri`, `e`, `v` | - |
| `trace` | `` PKCS#11 `C_CloseSession` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_Decrypt` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_DecryptFinal` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_DecryptInit` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_DecryptUpdate` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_DestroyObject` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_Encrypt` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_EncryptFinal` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_EncryptInit` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_EncryptUpdate` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_Finalize` failed: {e} `` | `src/core/operations/pkcs11.rs` | `e` | - |
| `trace` | `` PKCS#11 `C_FindObjects` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_FindObjectsFinal` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_FindObjectsInit` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_GenerateKey` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_GenerateKeyPair` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_GenerateRandom` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_GetAttributeValue` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_GetInfo` failed: {e} `` | `src/core/operations/pkcs11.rs` | `e` | - |
| `trace` | `` PKCS#11 `C_GetMechanismInfo` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_GetMechanismList` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_Initialize` called on already initialized library - treating as success `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_Initialize` failed: {e} `` | `src/core/operations/pkcs11.rs` | `e` | - |
| `trace` | `` PKCS#11 `C_Login` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_Logout` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_OpenSession` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_SeedRandom` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_UnwrapKey` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `` PKCS#11 `C_WrapKey` not yet implemented `` | `src/core/operations/pkcs11.rs` | - | - |
| `trace` | `ReKeyKeyPair: resolved keyset ref '{}' → '{}'` | `src/core/operations/rekey/keypair/mod.rs` | - | - |
| `info` | `KMS HTTP server configured with {n} worker thread(s)` | `src/start_kms_server.rs` | `n` | - |
| `warn` | `find_wrapped_by({old_uid}) failed — skipping re-wrap of dependants: {e}` | `src/core/operations/rekey/common.rs` | `old_uid`, `e` | - |
| `warn` | `[auto-rotate] Failed to query keys due for rotation: {e}` | `src/core/operations/auto_rotate.rs` | `e` | - |
| `warn` | `[auto-rotate] Failed to re-arm rotation policy on replacement {new_uid}: {e}` | `src/core/operations/auto_rotate.rs` | `new_uid`, `e` | - |
| `warn` | `[auto-rotate] Failed to retrieve key {uid}: {e}; skipping` | `src/core/operations/auto_rotate.rs` | `uid`, `e` | - |
| `warn` | `[auto-rotate] Failed to rotate key {uid} (owner={owner}): {e}` | `src/core/operations/auto_rotate.rs` | `uid`, `owner`, `e` | - |
| `warn` | `[auto-rotate] Key {uid} not found; skipping` | `src/core/operations/auto_rotate.rs` | `uid` | - |
| `info` | `[auto-rotate] Found {} key(s) due for rotation` | `src/core/operations/auto_rotate.rs` | - | - |
| `info` | `[auto-rotate] Key {uid} (owner={owner}) rotation due in {days} day(s)              (warning threshold: {threshold} days)` | `src/core/operations/auto_rotate.rs` | `uid`, `owner`, `days`, `threshold` | - |
| `info` | `[auto-rotate] Key {uid} (owner={owner}, algo={algorithm}) rotated successfully` | `src/core/operations/auto_rotate.rs` | `uid`, `owner`, `algorithm` | - |
| `debug` | `[auto-rotate] Failed to query keys for renewal warnings: {e}` | `src/core/operations/auto_rotate.rs` | `e` | - |
| `debug` | `[auto-rotate] No keys due for rotation at {now}` | `src/core/operations/auto_rotate.rs` | `now` | - |
| `debug` | `[auto-rotate] rotate_one_key returned: {e}` | `src/core/operations/auto_rotate.rs` | `e` | - |
| `debug` | `[auto-rotate] Skipping HSM key {uid}` | `src/core/operations/auto_rotate.rs` | `uid` | - |
| `debug` | `[auto-rotate] Skipping {uid}: object type {other:?} has no auto-rotation support` | `src/core/operations/auto_rotate.rs` | `uid`, `other` | - |
| `debug` | `[auto-rotate] Skipping {uid}: PublicKey is rotated as part of its paired                  PrivateKey rotation` | `src/core/operations/auto_rotate.rs` | `uid` | - |
| `debug` | `SetAttribute: implicitly enabling rotate_automatic for key '{}' (RotateInterval > 0 with no explicit RotateAutomatic)` | `src/core/operations/attributes/set.rs` | - | - |
| `warn` | `Azure EKM JSON deserialization error: {err}` | `src/routes/azure_ekm/mod.rs` | `err` | - |

### `cosmian_kms_server_database`

Crate path: `crate/server_database`
`RUST_LOG` target: `cosmian_kms_server_database`

| Level | Message | File | Variables | Notes |
|---|---|---|---|---|
| `warn` | `Failed to send cache access timestamp: {}` | `src/core/unwrapped_cache.rs` | - | - |
| `debug` | `Cache garbage collection thread shutting down` | `src/core/unwrapped_cache.rs` | - | - |
| `debug` | `Cache garbage collection thread terminated` | `src/core/unwrapped_cache.rs` | - | - |
| `debug` | `Empty Redis database detected. Initializing a new database instance.` | `src/stores/redis/redis_with_findex.rs` | - | - |
| `debug` | `Existing Redis database detected (version {version}). Using current database.` | `src/stores/redis/redis_with_findex.rs` | `version`: version | - |
| `debug` | `Garbage collected {} stale cache entries` | `src/core/unwrapped_cache.rs` | - | - |
| `debug` | `Listed {} rows` | `src/stores/sql/mysql.rs` | - | ×2 in this file |
| `debug` | `Owner = {}` | `src/stores/sql/mysql.rs` | - | - |
| `debug` | `PG find query: {}` | `src/stores/sql/pgsql.rs` | - | - |
| `debug` | `Running cache garbage collection` | `src/core/unwrapped_cache.rs` | - | - |
| `debug` | `Sent shutdown signal to cache garbage collection thread` | `src/core/unwrapped_cache.rs` | - | - |
| `debug` | `Uid = {}` | `src/stores/sql/mysql.rs` | - | - |
| `trace` | `Created in DB: {uid} / {owner}` | `src/stores/sql/mysql.rs` | `uid` — …<br>`owner` — … | — |
| `trace` | `Deleted in DB: {uid}` | `src/stores/sql/mysql.rs` | `uid` — … | — |
| `trace` | `find: tags: {tags:?}` | `src/stores/redis/redis_with_findex.rs` | `tags` — … | — |
| `trace` | `find: uids before permissions: {:?}` | `src/stores/redis/redis_with_findex.rs` | — | — |
| `trace` | `find: user must be owner` | `src/stores/redis/redis_with_findex.rs` | — | — |
| `trace` | `find_: {:?}` | `src/stores/sql/mysql.rs` | — | — |
| `trace` | `Insert read access right in DB: {uid} / {userid}` | `src/stores/sql/mysql.rs` | `uid` — …<br>`userid` — … | — |
| `trace` | `Invalidating the cache for {}` | `src/core/unwrapped_cache.rs` | — | — |
| `trace` | `Redis DB size: {count}` | `src/stores/redis/redis_with_findex.rs` | `count` — … | — |
| `trace` | `Updated in DB: {uid}` | `src/stores/sql/mysql.rs` | `uid` — … | ×2 in this file |
| `trace` | `Upserted in DB: {uid}` | `src/stores/sql/mysql.rs` | `uid` — … | — |
| `warn` | `[database] count_all_non_destroyed failed: {e}` | `src/core/database_objects.rs` | `e` | — |
| `warn` | `[database] count_non_destroyed_keys failed: {e}` | `src/core/database_objects.rs` | `e` | — |
| `warn` | `[database] reconcile_counts failed for a store: {e}` | `src/core/database_objects.rs` | `e` | — |
| `debug` | `[redis-bootstrap] skipping key {key}: {e}` | `src/stores/redis/objects_db.rs` | `key`, `e` | ×2 in this file |
| `debug` | `[redis-metrics] reconcile: live_objects={live_count}, non_destroyed_keys={key_count}` | `src/stores/redis/redis_with_findex.rs` | `live_count`, `key_count` | — |
| `debug` | `` [redis-metrics] bootstrapped {} live object(s) into `{}` `` | `src/stores/redis/redis_with_findex.rs` | - | - |
| `debug` | `` [redis-metrics] bootstrapped {} non-destroyed key(s) into `{}` `` | `src/stores/redis/redis_with_findex.rs` | - | - |
| `debug` | `[redis-scan-rotation] skipping key {key}: {e}` | `src/stores/redis/objects_db.rs` | `key`, `e` | - |

### `cosmian_kms_crypto`

Crate path: `crate/crypto`
`RUST_LOG` target: `cosmian_kms_crypto`

| Level   | Message                                                                                                                                                                                                                                | File                                                | Variables                                                                         | Notes           |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------- | --------------- |
| `error` | `Error verifying ({:?}) signature: {:?}, data: {:?}, error: {err:?}`                                                                                                                                                                   | `src/crypto/rsa/verify.rs`                          | `err`: error detail                                                               | -               |
| `error` | `Error verifying digest ({:?}) signature: {:?}, data: {:?}, error: {err:?}`                                                                                                                                                            | `src/crypto/rsa/verify.rs`                          | `err`: error detail                                                               | ×2 in this file |
| `error` | `Error verifying raw ({:?}) signature: {:?}, data: {:?}, error: {err:?}`                                                                                                                                                               | `src/crypto/rsa/verify.rs`                          | `err`: error detail                                                               | -               |
| `warn`  | `test_openssl_cli_compat: openssl CLI call failed, skipping test: {output:#?}`                                                                                                                                                         | `src/crypto/rsa/ckm_rsa_aes_key_wrap.rs`            | `output`: output                                                                  | -               |
| `warn`  | `test_openssl_cli_compat: openssl CLI not found, skipping test`                                                                                                                                                                        | `src/crypto/rsa/ckm_rsa_aes_key_wrap.rs`            | -                                                                                 | -               |
| `warn`  | `test_openssl_cli_compat: openssl CLI output is not valid UTF-8`                                                                                                                                                                       | `src/crypto/rsa/ckm_rsa_aes_key_wrap.rs`            | -                                                                                 | -               |
| `info`  | `===> Wrapping asymmetric key with asymmetric key`                                                                                                                                                                                     | `src/crypto/wrap/tests.rs`                          | -                                                                                 | -               |
| `info`  | `===> Wrapping asymmetric key with symmetric key`                                                                                                                                                                                      | `src/crypto/wrap/tests.rs`                          | -                                                                                 | -               |
| `info`  | `===> Wrapping symmetric key with asymmetric key`                                                                                                                                                                                      | `src/crypto/wrap/tests.rs`                          | -                                                                                 | -               |
| `info`  | `===> Wrapping symmetric key with symmetric key`                                                                                                                                                                                       | `src/crypto/wrap/tests.rs`                          | -                                                                                 | -               |
| `info`  | `value is: {:?}`                                                                                                                                                                                                                       | `src/openssl/x509_extensions.rs`                    | -                                                                                 | ×2 in this file |
| `debug` | `attribute: {attribute:?}, encryption_hint: {encryption_hint:?}`                                                                                                                                                                       | `src/crypto/cover_crypt/access_structure.rs`        | `attribute`: KMIP attribute (debug display)<br>`encryption_hint`: encryption hint | -               |
| `debug` | `create_dk_object: key len: {}, attributes: {attributes}`                                                                                                                                                                              | `src/crypto/kem.rs`                                 | `attributes`: KMIP attribute (debug display)s                                     | -               |
| `debug` | `create_msk_object: key len: {}, attributes: {attributes}`                                                                                                                                                                             | `src/crypto/cover_crypt/master_keys.rs`             | `attributes`: KMIP attribute (debug display)s                                     | -               |
| `debug` | `Decrypted data with user key {} of len (Plain/Enc): {}/{}`                                                                                                                                                                            | `src/crypto/cover_crypt/decryption.rs`              | -                                                                                 | -               |
| `debug` | `Encrypted data with auth data {:?} of len (Plain/Enc): {}/{}`                                                                                                                                                                         | `src/crypto/cover_crypt/encryption.rs`              | -                                                                                 | -               |
| `debug` | `RSA key pair generated: private key id: {private_key_uid}`                                                                                                                                                                            | `src/crypto/rsa/operation.rs`                       | `private_key_uid`: private key uid                                                | -               |
| `debug` | `RSA key pair generation: size in bits: {key_size_in_bits}`                                                                                                                                                                            | `src/crypto/rsa/operation.rs`                       | `key_size_in_bits`: RSA key size in bits                                          | -               |
| `debug` | `server: access_structure: {access_structure:?}`                                                                                                                                                                                       | `src/crypto/cover_crypt/master_keys.rs`             | `access_structure`: Covercrypt access structure                                   | -               |
| `debug` | `using GCM`                                                                                                                                                                                                                            | `src/crypto/wrap/wrap_key.rs`                       | -                                                                                 | -               |
| `debug` | `wrapping with CKM_RSA (v1.5)`                                                                                                                                                                                                         | `src/crypto/wrap/wrap_key.rs`                       | -                                                                                 | -               |
| `debug` | `wrapping with CKM_RSA_AES_KEY_WRAP and hashing function: {hashing_fn}`                                                                                                                                                                | `src/crypto/wrap/wrap_key.rs`                       | `hashing_fn`: hash function                                                       | -               |
| `debug` | `wrapping with CKM_RSA_OAEP and hashing function: {hashing_fn}`                                                                                                                                                                        | `src/crypto/wrap/wrap_key.rs`                       | `hashing_fn`: hash function                                                       | -               |
| `trace` | `Access Policy: {access_policy:?}`                                                                                                                                                                                                     | `src/crypto/cover_crypt/user_key.rs`                | `access_policy` — …                                                               | —               |
| `trace` | `authenticated_encryption_additional_data: {ad:?}`                                                                                                                                                                                     | `src/crypto/cover_crypt/encryption.rs`              | `ad` — …                                                                          | —               |
| `trace` | `bytes len: {:?}, bits: {}`                                                                                                                                                                                                            | `src/crypto/elliptic_curves/operation.rs`           | —                                                                                 | ×2 in this file |
| `trace` | `bytes len: {}, bits: {}`                                                                                                                                                                                                              | `src/crypto/rsa/operation.rs`                       | —                                                                                 | ×2 in this file |
| `trace` | `ChaCha20 (pure) encryption: key_len={}, nonce_len={}, pt_len={}`                                                                                                                                                                      | `src/crypto/symmetric/symmetric_ciphers.rs`         | —                                                                                 | —               |
| `trace` | `Created user decryption key with access policy: {access_policy:?}`                                                                                                                                                                    | `src/crypto/cover_crypt/user_key.rs`                | `access_policy` — …                                                               | —               |
| `trace` | `decrypt: ad: {ad:?}`                                                                                                                                                                                                                  | `src/crypto/cover_crypt/decryption.rs`              | `ad` — …                                                                          | —               |
| `trace` | `Ed25519`                                                                                                                                                                                                                              | `src/crypto/elliptic_curves/ecies/salsa_sealbox.rs` | —                                                                                 | —               |
| `trace` | `encrypted_bytes len: {}`                                                                                                                                                                                                              | `src/crypto/cover_crypt/decryption.rs`              | —                                                                                 | —               |
| `trace` | `encrypted_header parsed`                                                                                                                                                                                                              | `src/crypto/cover_crypt/decryption.rs`              | —                                                                                 | —               |
| `trace` | `encryption_policy: {ap:?}`                                                                                                                                                                                                            | `src/crypto/cover_crypt/encryption.rs`              | `ap` — …                                                                          | ×2 in this file |
| `trace` | `instantiate entering`                                                                                                                                                                                                                 | `src/crypto/cover_crypt/decryption.rs`              | —                                                                                 | —               |
| `trace` | `Instantiated hybrid Covercrypt encipher for public key id: {public_key_uid}`                                                                                                                                                          | `src/crypto/cover_crypt/encryption.rs`              | `public_key_uid` — …                                                              | —               |
| `trace` | `Key format type: convert Rsa<Public> openssl object`                                                                                                                                                                                  | `src/openssl/public_key.rs`                         | —                                                                                 | —               |
| `trace` | `Key format type: TransparentDSAPublicKey`                                                                                                                                                                                             | `src/openssl/public_key.rs`                         | —                                                                                 | —               |
| `trace` | `Key format type: TransparentRSAPublicKey`                                                                                                                                                                                             | `src/openssl/public_key.rs`                         | —                                                                                 | —               |
| `trace` | `key_wrapping_specification: {}`                                                                                                                                                                                                       | `src/crypto/wrap/wrap_key.rs`                       | —                                                                                 | —               |
| `trace` | `nonce_len={}, tag_len={}`                                                                                                                                                                                                             | `src/crypto/wrap/wrap_key.rs`                       | —                                                                                 | —               |
| `trace` | `output object: {output}`                                                                                                                                                                                                              | `src/crypto/rsa/operation.rs`                       | `output` — …                                                                      | —               |
| `trace` | `private key converted OK`                                                                                                                                                                                                             | `src/crypto/elliptic_curves/operation.rs`           | —                                                                                 | —               |
| `trace` | `public key converted OK`                                                                                                                                                                                                              | `src/crypto/elliptic_curves/operation.rs`           | —                                                                                 | —               |
| `trace` | `Refreshed user decryption key {usk:?}`                                                                                                                                                                                                | `src/crypto/cover_crypt/user_key.rs`                | `usk` — …                                                                         | —               |
| `trace` | `using RFC-3394 (AES Key Wrap, no padding)`                                                                                                                                                                                            | `src/crypto/wrap/wrap_key.rs`                       | —                                                                                 | —               |
| `trace` | `using RFC-5649 (AES Key Wrap with Padding)`                                                                                                                                                                                           | `src/crypto/wrap/wrap_key.rs`                       | —                                                                                 | —               |
| `trace` | `with object type: {:?}`                                                                                                                                                                                                               | `src/crypto/wrap/wrap_key.rs`                       | —                                                                                 | —               |
| `trace` | `wrapping key: format={}`                                                                                                                                                                                                              | `src/crypto/wrap/wrap_key.rs`                       | —                                                                                 | —               |
| `trace` | `X25519`                                                                                                                                                                                                                               | `src/crypto/elliptic_curves/ecies/salsa_sealbox.rs` | —                                                                                 | —               |
| `trace` | `{}`                                                                                                                                                                                                                                   | `src/openssl/public_key.rs`                         | —                                                                                 | —               |
| `warn`  | `test_openssl_cli_compat: openssl version is not OpenSSL 3: {res}, skipping                      test`                                                                                                                                 | `src/crypto/rsa/ckm_rsa_aes_key_wrap.rs`            | `res`                                                                             | —               |
| `info`  | `\n\next: {:?}`                                                                                                                                                                                                                        | `src/openssl/x509_extensions.rs`                    | —                                                                                 | ×2 in this file |
| `debug` | `Instantiated hybrid CoverCrypt decipher for user decryption key id:              {user_decryption_key_uid}`                                                                                                                           | `src/crypto/cover_crypt/decryption.rs`              | `user_decryption_key_uid`                                                         | —               |
| `debug` | `symmetric wrapping using {cryptographic_algorithm} and                          block_cipher_mode: {:?}, padding_method: {:?}`                                                                                                        | `src/crypto/wrap/wrap_key.rs`                       | `cryptographic_algorithm`                                                         | —               |
| `trace` | `algorithm: {algorithm:?}, block_cipher_mode: {block_cipher_mode:?}, key_size:              {key_size}`                                                                                                                                | `src/crypto/symmetric/symmetric_ciphers.rs`         | `algorithm`, `block_cipher_mode`, `key_size`                                      | —               |
| `trace` | `encrypt: sym_cipher: {sym_cipher:?}, key length: {}, nonce length: {}, aad length: {},          plaintext length: {}, padding_method: {padding_method:?}`                                                                             | `src/crypto/symmetric/symmetric_ciphers.rs`         | `sym_cipher`, `padding_method`                                                    | —               |
| `warn`  | ``ignored `basicConstraints` extension's value: {value}``                                                                                                                                                                              | `src/openssl/x509_extensions.rs`                    | `value`                                                                           | -               |
| `info`  | ``RFC 3394 is deprecated in favor of RFC 5649 and is supported only for legacy compatibility. Please consider using `BlockCipherMode::AESKeyWrapPadding` (RFC 5649) for new applications instead of `BlockCipherMode::NISTKeyWrap `.`` | `src/crypto/symmetric/symmetric_ciphers.rs`         | -                                                                                 | ×2 in this file |

### `cosmian_kmip`

Crate path: `crate/kmip`
`RUST_LOG` target: `cosmian_kmip`

| Level   | Message                                                                                                                   | File                                                               | Variables                                          | Notes           |
| ------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------- | --------------- |
| `warn`  | `Custom attribute name does not start with 'x-' or 'y-': {}`                                                              | `src/kmip_1_4/kmip_attributes.rs`                                  | -                                                  | -               |
| `warn`  | `Failed to deserialize KMIP 2.1 attribute: {}`                                                                            | `src/kmip_1_4/kmip_attributes.rs`                                  | -                                                  | -               |
| `warn`  | `KMIP 1.4 Lease Time ({v}) exceeds i32::MAX; clamping to {}`                                                              | `src/kmip_1_4/kmip_attributes.rs`                                  | `v`: parsed value                                  | ×2 in this file |
| `warn`  | `KMIP 2.1 does not support the KMIP 1 attribute {attribute:?}`                                                            | `src/kmip_1_4/kmip_attributes.rs`                                  | `attribute`: KMIP attribute (debug display)        | ×9 in this file |
| `warn`  | `Unexpected value type for y-unsupported-2_1-attribute: {:?}`                                                             | `src/kmip_1_4/kmip_attributes.rs`                                  | -                                                  | -               |
| `debug` | `[serialize] writing tag: {}`                                                                                             | `src/ttlv/wire/ttlv_bytes_serializer.rs`                           | -                                                  | -               |
| `debug` | `Converting KMIP 2.1 QueryResponse to KMIP 1.4: {value}`                                                                  | `src/kmip_1_4/kmip_operations.rs`                                  | `value`: value                                     | -               |
| `trace` | `... => This is an Object => identifier: key: Object`                                                                     | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... added a struct field: {key}, the parent struct is now: {:?}`                                                         | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `key` — …                                          | —               |
| `trace` | `... assuming deserialization of BigInteger: {:?}`                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... assuming deserialization of ByteString: {:?}`                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... coerced ShortUniqueIdentifier ByteString -> hex string: {}`                                                          | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... coerced {} Enumeration(code={}) -> string`                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... coerced {} Enumeration(name={}) -> string`                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... coerced {} Integer({}) -> string`                                                                                    | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... deserializing an adjacently tagged structure`                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... deserializing enum at root`                                                                                          | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... deserializing enum that is the only child of the current element`                                                    | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... deserializing transparent seq with tag: {tag}`                                                                       | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `tag` — …                                          | —               |
| `trace` | `... detected VendorAttribute triple children; deserializing element itself as enum variant`                              | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... enum: index: {:#x}`                                                                                                  | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... enum: name: {}`                                                                                                      | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... identifier: key: {}`                                                                                                 | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... Seq element added, the current parent value is: {:?}`                                                                | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `... str: key: {}`                                                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... structure recognized as byte-like; concatenated len={} for tag {}`                                                   | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... structure: 1.4 Object`                                                                                               | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... structure: 2.1 Object`                                                                                               | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... structure: tag: {}`                                                                                                  | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... tag: {}`                                                                                                             | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `... text string: value: {}`                                                                                              | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `===> KeyMaterial: Deserializing Bytes String for key format type: {:?}`                                                  | `src/kmip_2_1/kmip_data_structures.rs`                             | —                                                  | ×2 in this file |
| `trace` | `===> KeyMaterial: Deserializing key format type: {f:?} as struct`                                                        | `src/kmip_1_4/kmip_data_structures.rs`                             | `f` — …                                            | —               |
| `trace` | `===> KeyMaterial: Deserializing Structure for key format type: {f:?}`                                                    | `src/kmip_2_1/kmip_data_structures.rs`                             | `f` — …                                            | —               |
| `trace` | `===> KeyMaterial: Deserializing {:?} key format type as seq`                                                             | `src/kmip_1_4/kmip_data_structures.rs`                             | —                                                  | —               |
| `trace` | `==> Deserializing KeyBlock`                                                                                              | `src/kmip_1_4/kmip_data_structures.rs`                             | —                                                  | —               |
| `trace` | `==> Deserializing KeyBlock`                                                                                              | `src/kmip_2_1/kmip_data_structures.rs`                             | —                                                  | —               |
| `trace` | `array_access: next_element_seed in seq: {}, current index: {}, elem at index:  {:?}`                                     | `src/ttlv/kmip_ttlv_deserializer/array_deserializer.rs`            | —                                                  | —               |
| `trace` | `Checking usage mask authorization {:?} for flag: {:?}`                                                                   | `src/kmip_2_1/kmip_attributes.rs`                                  | —                                                  | —               |
| `trace` | `Converting KMIP 2.1 CreateKeyPairResponse to KMIP 1.4: {value}`                                                          | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 CreateResponse to KMIP 1.4: {value}`                                                                 | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 DecryptResponse to KMIP 1.4: {value}`                                                                | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 DestroyResponse to KMIP 1.4: {value}`                                                                | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 EncryptResponse to KMIP 1.4: {value}`                                                                | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 GetAttributesResponse to KMIP 1.4: {value}`                                                          | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 GetResponse to KMIP 1.4: {value}`                                                                    | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 ImportResponse to KMIP 1.4: {value}`                                                                 | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 LocateResponse to KMIP 1.4: {value}`                                                                 | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 RegisterResponse to KMIP 1.4: {value}`                                                               | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `Converting KMIP 2.1 SignResponse to KMIP 1.4: {value}`                                                                   | `src/kmip_1_4/kmip_operations.rs`                                  | `value` — …                                        | —               |
| `trace` | `current struct: {}, num children: {}, next child {:?}`                                                                   | `src/ttlv/kmip_ttlv_deserializer/structure_walker.rs`              | —                                                  | —               |
| `trace` | `deserialize_any of enum variant: name: {}`                                                                               | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_any of enum variant: value: {}`                                                                              | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_any value of BigInt: {:?}`                                                                                   | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_any value of Structure: {:?}`                                                                                | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_any: map access state: key, tag: {}`                                                                         | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_any: map access state: {:?}, index: {}, child: {:?}`                                                         | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_any: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/kmip_big_int_deserializer.rs`     | —                                                  | —               |
| `trace` | `deserialize_bool: state:  {:?}`                                                                                          | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_bytes: state:  {:?}`                                                                                         | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_bytes_buff: state:  {:?}`                                                                                    | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_char: state:  {:?}`                                                                                          | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_enum: name {name}, element: {:?}`                                                                            | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `name` — …                                         | —               |
| `trace` | `deserialize_f32: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_f64: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_i128: element: {:?}`                                                                                         | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_i16 state:  {:?}`                                                                                            | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_i32: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_i64: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_identifier: map state: {:?}, element: {:?}`                                                                  | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_ignored_any: state:  {:?}`                                                                                   | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_map: calling Untagged Enum deserializer for: {:?}`                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_new_type_struct with name: {name}, state:  {:?}`                                                             | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `name` — …                                         | —               |
| `trace` | `deserialize_option: state:  {:?}`                                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_seq: child index: {}: {:?}`                                                                                  | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_seq: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/kmip_big_int_deserializer.rs`     | —                                                  | —               |
| `trace` | `deserialize_str: map state: {:?}, element tag: {}`                                                                       | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_string: state:  {:?}`                                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_struct: name {name}, fields: {fields:?}, element: {:?}`                                                      | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `name` — …<br>`fields` — …                         | —               |
| `trace` | `deserialize_tuple: child index: {}, current :  {:?}`                                                                     | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_tuple: state:  {:?}`                                                                                         | `src/ttlv/kmip_ttlv_deserializer/kmip_big_int_deserializer.rs`     | —                                                  | —               |
| `trace` | `deserialize_tuple_struct: name: {name}, len: {len},  state:  {:?}`                                                       | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `name` — …<br>`len` — …                            | —               |
| `trace` | `deserialize_u16: state:  {:?}`                                                                                           | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_u32: state: {}: {:?}`                                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_u64: state:  {}: {:?}`                                                                                       | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_u8: state:  {:?}`                                                                                            | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_unit: state:  {:?}`                                                                                          | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | —                                                  | —               |
| `trace` | `deserialize_unit_struct with name: {name}, state:  {:?}`                                                                 | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `name` — …                                         | —               |
| `trace` | `deserializing bytes string at tag: {}, of len: {}`                                                                       | `src/ttlv/kmip_ttlv_deserializer/byte_string_deserializer.rs`      | —                                                  | —               |
| `trace` | `deserializing OffsetDateTime at tag: {}, value: {}, index: {}`                                                           | `src/ttlv/kmip_ttlv_deserializer/offset_date_time_deserializer.rs` | —                                                  | —               |
| `trace` | `element:  {:?}`                                                                                                          | `src/ttlv/kmip_ttlv_deserializer/enum_walker.rs`                   | —                                                  | —               |
| `trace` | `element: {:?}`                                                                                                           | `src/ttlv/kmip_ttlv_deserializer/structure_walker.rs`              | —                                                  | —               |
| `trace` | `Finished serializing byte sequence as ByteString, parent: {:?}`                                                          | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `Finished serializing the sequence, the parent is: {:?}`                                                                  | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `from_ttlv: {s:?}`                                                                                                        | `src/ttlv/kmip_ttlv_deserializer/deserializer.rs`                  | `s` — …                                            | —               |
| `trace` | `Key: State ? {:?}`                                                                                                       | `src/ttlv/kmip_ttlv_deserializer/adjacently_tagged_structure.rs`   | —                                                  | —               |
| `trace` | `key_wrap_type: {key_wrap_type:?}, attributes: {attributes}`                                                              | `src/kmip_2_1/requests/import.rs`                                  | `key_wrap_type` — …<br>`attributes` — …            | —               |
| `trace` | `MessageBatchItem operation: {operation:?}`                                                                               | `src/kmip_1_4/kmip_messages.rs`                                    | `operation` — …                                    | —               |
| `trace` | `MessageBatchItem operation: {operation:?}`                                                                               | `src/kmip_2_1/kmip_messages.rs`                                    | `operation` — …                                    | —               |
| `trace` | `MessageBatchItem request payload: {request_payload}`                                                                     | `src/kmip_1_4/kmip_messages.rs`                                    | `request_payload` — …                              | —               |
| `trace` | `MessageBatchItem request payload: {request_payload}`                                                                     | `src/kmip_2_1/kmip_messages.rs`                                    | `request_payload` — …                              | —               |
| `trace` | `MessageResponseBatchItem operation: {operation:?}`                                                                       | `src/kmip_1_4/kmip_messages.rs`                                    | `operation` — …                                    | —               |
| `trace` | `MessageResponseBatchItem operation: {operation:?}`                                                                       | `src/kmip_2_1/kmip_messages.rs`                                    | `operation` — …                                    | —               |
| `trace` | `MessageResponseBatchItem response payload: {response_payload}`                                                           | `src/kmip_1_4/kmip_messages.rs`                                    | `response_payload` — …                             | —               |
| `trace` | `MessageResponseBatchItem response payload: {response_payload}`                                                           | `src/kmip_2_1/kmip_messages.rs`                                    | `response_payload` — …                             | —               |
| `trace` | `newtype_variant_seed: child index: {}, at root: {}, current tag: {:?}`                                                   | `src/ttlv/kmip_ttlv_deserializer/enum_walker.rs`                   | —                                                  | —               |
| `trace` | `Not a BulkData`                                                                                                          | `src/kmip_2_1/extra/bulk_data.rs`                                  | —                                                  | —               |
| `trace` | `Object Visitor: visit_map: key: {key:?},`                                                                                | `src/kmip_1_4/kmip_objects.rs`                                     | `key` — …                                          | —               |
| `trace` | `Object Visitor: visit_map: key: {key:?},`                                                                                | `src/kmip_2_1/kmip_objects.rs`                                     | `key` — …                                          | —               |
| `trace` | `Seq Element: serializing a seq element with tag {}, stack is: {:?}`                                                      | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `seq_access: next_element_seed: state:  {:?}`                                                                             | `src/ttlv/kmip_ttlv_deserializer/kmip_big_int_deserializer.rs`     | —                                                  | —               |
| `trace` | `serialize_map of len: {len:?}. Current: {:?}`                                                                            | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `len` — …                                          | —               |
| `trace` | `serialize_newtype_variant, name: {name}::{variant} (variant index: {variant_index})`                                     | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name` — …<br>`variant` — …<br>`variant_index` — … | —               |
| `trace` | `serialize_seq of len: {len:?} in receiver: {:?}`                                                                         | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `len` — …                                          | —               |
| `trace` | `serialize_seq of len: {len:?} in receiver: {:?} (byte accumulation mode)`                                                | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `len` — …                                          | —               |
| `trace` | `serialize_struct named: {name} in parent: {:?}`                                                                          | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name` — …                                         | —               |
| `trace` | `serialize_struct, no parent found, creating a new one with tag: {}`                                                      | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `serialize_tuple of len {len}. Current: {:?}`                                                                             | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `len` — …                                          | —               |
| `trace` | `serialize_tuple_struct {name} of len {len}. Current: {:?}`                                                               | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name` — …<br>`len` — …                            | —               |
| `trace` | `serialize_unit_variant, name: {name}::{variant}; variant_index: {variant_index}`                                         | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name` — …<br>`variant` — …<br>`variant_index` — … | —               |
| `trace` | `serializing a struct field with name: {key}, stack: {:?}`                                                                | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `key` — …                                          | —               |
| `trace` | `struct_variant with fields: {fields:?}: state:  {:?}`                                                                    | `src/ttlv/kmip_ttlv_deserializer/enum_walker.rs`                   | `fields` — …                                       | —               |
| `trace` | `Structure finalized, stack: {:?}`                                                                                        | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `tag: {:?}, content: {:?}`                                                                                                | `src/ttlv/kmip_ttlv_deserializer/adjacently_tagged_structure.rs`   | —                                                  | —               |
| `trace` | `tuple_variant of len: {len}, child index: {}, current: {:?}`                                                             | `src/ttlv/kmip_ttlv_deserializer/enum_walker.rs`                   | `len` — …                                          | —               |
| `trace` | `unique_identifier: {unique_identifier}`                                                                                  | `src/kmip_2_1/requests/import.rs`                                  | `unique_identifier` — …                            | —               |
| `trace` | `unit_variant: child index: {}, current: {:?}`                                                                            | `src/ttlv/kmip_ttlv_deserializer/enum_walker.rs`                   | —                                                  | —               |
| `trace` | `Untagged Enum map: next_value_seed: current tag:  {:?}, at root: {}`                                                     | `src/ttlv/kmip_ttlv_deserializer/untagged_enum_walker.rs`          | —                                                  | —               |
| `trace` | `Value: State ? {:?}`                                                                                                     | `src/ttlv/kmip_ttlv_deserializer/adjacently_tagged_structure.rs`   | —                                                  | —               |
| `trace` | `visit_f64: {}`                                                                                                           | `src/ttlv/deserialize.rs`                                          | —                                                  | —               |
| `trace` | `visit_i64: {}`                                                                                                           | `src/ttlv/deserialize.rs`                                          | —                                                  | —               |
| `trace` | `visit_map: Enumeration`                                                                                                  | `src/ttlv/deserialize.rs`                                          | —                                                  | —               |
| `trace` | `visit_str: {}`                                                                                                           | `src/ttlv/deserialize.rs`                                          | —                                                  | —               |
| `trace` | `visit_u64: {}`                                                                                                           | `src/ttlv/deserialize.rs`                                          | —                                                  | —               |
| `trace` | `... replacing  "Object" with: {name}`                                                                                    | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name`                                             |                 |
| `trace` | `serialize_seq, no parent found. This is a direct vec![] serialization. Creating                  a new one with tag: {}` | `src/ttlv/kmip_ttlv_serializer.rs`                                 | —                                                  | —               |
| `trace` | `serialize_struct_variant {name}::{variant} (variant index: {variant_index}) of len              {len}. Current: {:?}`    | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name`, `variant`, `variant_index`, `len`          | —               |
| `trace` | `serialize_tuple_variant {name}::{variant} (variant index: {variant_index}) of len              {len}. Current: {:?}`     | `src/ttlv/kmip_ttlv_serializer.rs`                                 | `name`, `variant`, `variant_index`, `len`          | —               |
| `trace` | `Untagged Enum map: next_key_seed: completed?: {}, at root: {}, index: {}, current              tag: {:?}`                | `src/ttlv/kmip_ttlv_deserializer/untagged_enum_walker.rs`          | —                                                  | —               |

### `cosmian_kms_interfaces`

Crate path: `crate/interfaces`
`RUST_LOG` target: `cosmian_kms_interfaces`

| Level   | Message                                                                                                                                                                 | File                          | Variables                                                      | Notes                                                                                    |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `error` | `Failed to decode object_id {}`                                                                                                                                         | `src/hsm/hsm_store.rs`        | -                                                              | Malformed object ID in PKCS#11 session. Key may have been created by a different client. |
| `debug` | `Created HSM AES Key of length {key_length} with id {uid}`                                                                                                              | `src/hsm/hsm_store.rs`        | `key_length`: key length<br>`uid`: KMIP object UID             | -                                                                                        |
| `debug` | `Creating RSA keypair with uid: {uid}`                                                                                                                                  | `src/hsm/hsm_store.rs`        | `uid`: KMIP object UID                                         | -                                                                                        |
| `debug` | `HSM find: incompatible filter, skipping HSM search: {e}`                                                                                                               | `src/hsm/hsm_store.rs`        | `e`: caught error                                              | -                                                                                        |
| `debug` | `Is {owner} an HSM admin? {}`                                                                                                                                           | `src/hsm/hsm_store.rs`        | `owner`: object owner identity                                 | -                                                                                        |
| `debug` | `No researched_attributes provided. Defaulting to empty filter attributes`                                                                                              | `src/hsm/hsm_store.rs`        | -                                                              | -                                                                                        |
| `debug` | `sign: using algorithm {algorithm:?} for key {uid}`                                                                                                                     | `src/hsm/hsm_store.rs`        | `algorithm`: cryptographic algorithm<br>`uid`: KMIP object UID | -                                                                                        |
| `debug` | `User '{}' is not an HSM admin; skipping HSM keys for ownership query`                                                                                                  | `src/hsm/hsm_store.rs`        | -                                                              | -                                                                                        |
| `debug` | `Using default algorithm to decrypt`                                                                                                                                    | `src/hsm/hsm_store.rs`        | -                                                              | -                                                                                        |
| `debug` | `Using default algorithm to encrypt`                                                                                                                                    | `src/hsm/hsm_store.rs`        | -                                                              | -                                                                                        |
| `debug` | `{e}`                                                                                                                                                                   | `src/hsm/hsm_store.rs`        | `e`: caught error                                              | -                                                                                        |
| `trace` | `Found: {uid}`                                                                                                                                                          | `src/hsm/hsm_store.rs`        | `uid` — …                                                      | —                                                                                        |
| `trace` | `Getting metadata for: {:02X?}`                                                                                                                                         | `src/hsm/hsm_store.rs`        | —                                                              | —                                                                                        |
| `warn`  | `count_all_non_destroyed not implemented for this ObjectsStore backend —              kms.objects.total will read 0 until a real implementation is provided`            | `src/stores/objects_store.rs` | —                                                              | —                                                                                        |
| `warn`  | `count_non_destroyed_keys not implemented for this ObjectsStore backend —              kms.keys.active.count will read 0 until a real implementation is provided`       | `src/stores/objects_store.rs` | —                                                              | —                                                                                        |
| `warn`  | `HSM count_non_destroyed_keys: failed to list slots: {e}`                                                                                                               | `src/hsm/hsm_store.rs`        | `e`                                                            | —                                                                                        |
| `warn`  | `ModifyAttribute/SetAttribute on HSM key {uid}: attribute update accepted but not              persisted to PKCS#11 slot (HSM does not support KMIP attribute storage)` | `src/hsm/hsm_store.rs`        | `uid`                                                          | —                                                                                        |
| `debug` | `encrypt: an RSA private key {uid} was specified. Trying to use                              public key {pk_uid} for encryption`                                        | `src/hsm/hsm_store.rs`        | `uid`, `pk_uid`                                                | —                                                                                        |
| `debug` | `HSM count_non_destroyed_keys: slot {slot_id} query failed: {e}`                                                                                                        | `src/hsm/hsm_store.rs`        | `slot_id`, `e`                                                 | —                                                                                        |
| `debug` | `HSM key {uid} export failed ({e}); falling back to metadata-only stub for                      attribute operations`                                                   | `src/hsm/hsm_store.rs`        | `uid`, `e`                                                     | —                                                                                        |

### `cosmian_kms_access`

Crate path: `crate/access`
`RUST_LOG` target: `cosmian_kms_access`

_No production log call-sites in this crate._

### `cosmian_kms_base_hsm`

Crate path: `crate/hsm/base_hsm`
`RUST_LOG` target: `cosmian_kms_base_hsm`

| Level | Message | File | Variables | Notes |
|---|---|---|---|---|
| `warn` | `HSM library already initialized (CKR_CRYPTOKI_ALREADY_INITIALIZED); continuing` | `src/hsm_lib.rs` | - | - |
| `warn` | `user already logged in, ignoring logging` | `src/slots.rs` | - | - |
| `debug` | `Creating new session: {session_handle}. Logging in? {logging_in}` | `src/session/session_impl.rs` | `session_handle`: session handle<br>`logging_in`: logging in | - |
| `debug` | `Found {} possible handles` | `src/session/session_impl.rs` | - | - |
| `debug` | `Invalid object, skipping` | `src/kms_hsm.rs` | - | - |
| `debug` | `Logging in session {session_handle} with password` | `src/slots.rs` | `session_handle`: session handle | - |
| `debug` | `Opening a session on slot: {slot_id}. Read write? {read_write}. Logging in? {}` | `src/slots.rs` | `slot_id`: PKCS#11 slot identifier<br>`read_write`: read write | - |
| `debug` | `Performing multi round AES CBC decryption` | `src/session/session_impl.rs` | - | - |
| `debug` | `Performing multi round AES CBC encryption` | `src/session/session_impl.rs` | - | - |
| `debug` | `Retrieved HSM key type for key handle {key_handle}: {key_type:?}` | `src/session/session_impl.rs` | `key_handle`: key handle<br>`key_type`: key type | - |
| `debug` | `Retrieving HSM key attributes for key handle: {key_handle}` | `src/session/session_impl.rs` | `key_handle`: key handle | - |
| `debug` | `Reusing slot {slot_id}` | `src/base_hsm.rs` | `slot_id`: PKCS#11 slot identifier | - |
| `debug` | `Using PKCS#11 library with {:?}` | `src/base_hsm.rs` | - | - |
| `trace` | `Doing round with {round_length} bytes. {processed_length} of {total_length} done` | `src/session/session_impl.rs` | `round_length` — …<br>`processed_length` — …<br>`total_length` — … | ×2 in this file |
| `trace` | `Found {object_count} objects` | `src/session/session_impl.rs` | `object_count` — … | — |
| `debug` | `OAEP hash {hash} not supported: {e}` | `src/session/session_impl.rs` | `hash`, `e` | - |

---

## Domain: CLI (`ckms`)

### `cosmian_kms_cli_actions`

Crate path: `crate/clients/clap`
`RUST_LOG` target: `cosmian_kms_cli_actions`

| Level   | Message                                                                        | File                                              | Variables                                                                                           | Notes           |
| ------- | ------------------------------------------------------------------------------ | ------------------------------------------------- | --------------------------------------------------------------------------------------------------- | --------------- |
| `info`  | `[{email}] - certificate ID used: {certificate_unique_identifier}`             | `src/actions/google/key_pairs/create.rs`          | `email`: Google Workspace user email<br>`certificate_unique_identifier`: KMS UID of the certificate | -               |
| `info`  | `[{email}] - Import PKCS12 file before using it in Google key pair generation` | `src/actions/google/key_pairs/create.rs`          | `email`: Google Workspace user email                                                                | -               |
| `info`  | `ModifyAttributes response for {effective_uid}: {attribute}`                   | `src/actions/attributes/modify.rs`                | `effective_uid`: resolved KMIP object UID<br>`attribute`: updated attribute name and value          | -               |
| `info`  | `SetAttributes response for {unique_identifier}: {attribute}`                  | `src/actions/attributes/set.rs`                   | `unique_identifier`: KMIP object UID<br>`attribute`: attribute name and value that was set          | -               |
| `debug` | `{decrypt_request}`                                                            | `src/actions/cover_crypt/decrypt.rs`              | `decrypt_request`: full Covercrypt decrypt request (debug display)                                  | -               |
| `debug` | `{encrypt_request}`                                                            | `src/actions/cover_crypt/encrypt.rs`              | `encrypt_request`: full Covercrypt encrypt request (debug display)                                  | -               |
| `debug` | `access_structure: {access_structure}`                                         | `src/actions/cover_crypt/keys/create_key_pair.rs` | `access_structure`: Covercrypt access structure (debug display)                                     | -               |
| `debug` | `Creating new leaf certificate with attributes: {attributes}`                  | `src/actions/google/key_pairs/create.rs`          | `attributes`: X.509 certificate attributes being submitted                                          | -               |
| `debug` | `GetAttributes response for {unique_identifier}: {attributes}`                 | `src/actions/attributes/get.rs`                   | `unique_identifier`: KMIP object UID<br>`attributes`: structured attributes response                | -               |
| `debug` | `import certificate as {format_label} file`                                    | `src/actions/certificates/import_certificate.rs`  | `format_label`: certificate format name (e.g. `PEM`, `DER`)                                         | -               |
| `debug` | `import certificate as PKCS12 file`                                            | `src/actions/certificates/import_certificate.rs`  | -                                                                                                   | -               |
| `debug` | `import certificate chain as PEM file`                                         | `src/actions/certificates/import_certificate.rs`  | -                                                                                                   | -               |
| `trace` | `{self}`                                                                       | `src/actions/attributes/delete.rs`                | `self` — full delete action configuration (debug display)                                           | —               |
| `trace` | `{self}`                                                                       | `src/actions/attributes/get.rs`                   | `self` — full get-attributes action configuration (debug display)                                   | —               |
| `trace` | `{self}`                                                                       | `src/actions/attributes/modify.rs`                | `self` — full modify action configuration (debug display)                                           | —               |
| `trace` | `{self}`                                                                       | `src/actions/attributes/set.rs`                   | `self` — full set-attributes action configuration (debug display)                                   | —               |
| `trace` | `{self}`                                                                       | `src/actions/certificates/export_certificate.rs`  | `self` — full export action configuration (debug display)                                           | —               |
| `trace` | `{self}`                                                                       | `src/actions/certificates/import_certificate.rs`  | `self` — full import action configuration (debug display)                                           | —               |
| `trace` | `{id}`                                                                         | `src/actions/shared/get_key_uid.rs`               | `id` — resolved KMIP object UID                                                                     | —               |
| `trace` | `data_encryption_algorithm: {data_encryption_algorithm}`                       | `src/actions/symmetric/encrypt.rs`                | `data_encryption_algorithm` — selected symmetric encryption algorithm                               | —               |
| `trace` | `Determine the certificate to use - either existing or newly created`          | `src/actions/google/key_pairs/create.rs`          | —                                                                                                   | —               |
| `trace` | `import certificate as TTLV JSON file`                                         | `src/actions/certificates/import_certificate.rs`  | —                                                                                                   | —               |
| `trace` | `response for {unique_identifier}: <none>`                                     | `src/actions/attributes/delete.rs`                | `unique_identifier` — KMIP object UID (no attribute was present)                                    | —               |
| `trace` | `unwrap using server-side HSM crypto oracle for key: {key_id}`                 | `src/actions/shared/unwrap_key.rs`                | `key_id` — UID of the key being unwrapped via the HSM crypto oracle                                 | —               |
| `info`  | `[{email}] - Generating new leaf certificate with extensions file: {:?}`       | `src/actions/google/key_pairs/create.rs`          | `email`                                                                                             | —               |
| `debug` | `GetAttributes response for {unique_identifier}: {}`                           | `src/actions/attributes/get.rs`                   | `unique_identifier`                                                                                 | —               |
| `debug` | `MoveFileExW(DELAY_UNTIL_REBOOT) failed for '{}'; leftover file is harmless.`  | `src/actions/cng.rs`                              | —                                                                                                   | —               |
| `trace` | `dek (len={}): {dek:?}`                                                        | `src/actions/symmetric/encrypt.rs`                | `dek`                                                                                               | —               |
| `trace` | `dek length {}`                                                                | `src/actions/symmetric/decrypt.rs`                | —                                                                                                   | ×2 in this file |
| `trace` | `encapsulation length {}`                                                      | `src/actions/symmetric/decrypt.rs`                | —                                                                                                   | —               |
| `trace` | `encryption algorithm {:?}, key id {:?}, ciphertext (len={}): {:?}`            | `src/actions/symmetric/decrypt.rs`                | —                                                                                                   | —               |
| `trace` | `Leaf certificate attributes: {}`                                              | `src/actions/certificates/import_certificate.rs`  | —                                                                                                   | —               |
| `trace` | `pkcs7_object: {:?}`                                                           | `src/actions/google/key_pairs/create.rs`          | —                                                                                                   | —               |
| `trace` | `response for {unique_identifier}: {}`                                         | `src/actions/attributes/delete.rs`                | `unique_identifier`                                                                                 | —               |
| `trace` | `wrapped_key_bytes: {:?}`                                                      | `src/actions/google/key_pairs/create.rs`          | —                                                                                                   | —               |

---

### `ckms`

Crate path: `crate/clients/ckms`
`RUST_LOG` target: `ckms`

| Level   | Message                                       | File              | Variables                                                               | Notes |
| ------- | --------------------------------------------- | ----------------- | ----------------------------------------------------------------------- | ----- |
| `info`  | `Starting KMS CLI`                            | `src/commands.rs` | -                                                                       | -     |
| `info`  | `Starting KMS CLI configuration wizard`       | `src/commands.rs` | -                                                                       | -     |
| `debug` | `Loading configuration from: {conf_path_buf}` | `src/config.rs`   | `conf_path_buf`: filesystem path of the configuration file being loaded | -     |
| `trace` | `Configuration: {config}`                     | `src/commands.rs` | `config` — full resolved CLI configuration (pretty debug display)       | —     |
| `info`  | `Configuration saved at {}`                   | `src/commands.rs` | —                                                                       | —     |

---

### `cosmian_kms_client`

Crate path: `crate/clients/client`
`RUST_LOG` target: `cosmian_kms_client`

| Level | Message | File | Variables | Notes |
|---|---|---|---|---|
| `info` | `GET {server_url}` | `src/kms_rest_client.rs` | `server_url`: full URL of the GET request being sent | - |
| `info` | `The decrypted file is available at {output_file}` | `src/file_utils.rs` | `output_file`: path to the decrypted output file | ×2 in this file |
| `info` | `The encrypted file is available at {output_file}` | `src/file_utils.rs` | `output_file`: path to the encrypted output file | ×2 in this file |
| `info` | `Using server URL: {}` | `src/http_client/client.rs` | — | — |
| `trace` | `<==\n{}` | `src/kms_rest_client.rs` | — | ×2 in this file |
| `trace` | `==>\n{}` | `src/kms_rest_client.rs` | — | ×2 in this file |
| `warn` | `Failed to set TLS 1.2 cipher list '{}' (using defaults): {}` | `src/http_client/tls.rs` | — | — |
| `warn` | `Failed to set TLS 1.3 ciphersuites '{}' (using defaults): {}` | `src/http_client/tls.rs` | — | — |
| `warn` | `Unknown TLS 1.2 IANA cipher suite '{}' (skipping)` | `src/http_client/tls.rs` | — | — |
| `info` | `Using proxy: {:?}` | `src/http_client/client.rs` | — | — |
| `debug` | `CONNECT tunnel established: {target_host}:{target_port}` | `src/http_client/proxy.rs` | `target_host`, `target_port` | — |
| `debug` | `CONNECT tunnel: {proxy_addr} → {target_host}:{target_port}` | `src/http_client/proxy.rs` | `proxy_addr`, `target_host`, `target_port` | — |
| `trace` | `Error response on {endpoint}: status={status}, body={text}` | `src/kms_rest_client.rs` | `endpoint`, `status`, `text` | — |
| `warn` | `` ckms config: `{}` is deprecated — rename it to `{}` in your                          ckms.toml to silence this warning. `` | `src/http_client/client.rs` | - | - |

---

### `cosmian_kms_client_utils`

Crate path: `crate/clients/client_utils`
`RUST_LOG` target: `cosmian_kms_client_utils`

| Level  | Message                                                                                                                                                                    | File                  | Variables | Notes |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | --------- | ----- |
| `info` | `WARNING: the PEM file contains multiple objects. Only the private key will                      be imported. A corresponding public key will be generated automatically.` | `src/import_utils.rs` | —         | —     |

---

## Domain: PKCS#11

### `cosmian_pkcs11`

Crate path: `crate/clients/pkcs11/provider`
`RUST_LOG` target: `cosmian_pkcs11`

| Level   | Message                                                                                                                                                                                                                                                                    | File                        | Variables                                                                                             | Notes                                                                                           |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `error` | `C_GetFunctionList: failed to instantiate base KMS client: {}`                                                                                                                                                                                                             | `src/lib.rs`                | -                                                                                                     | PKCS#11 module failed to create the KMS client on load. Check server URL and auth in ckms.toml. |
| `error` | `Failed to parse EC P256 public key: {:?}`                                                                                                                                                                                                                                 | `src/pkcs11_public_key.rs`  | -                                                                                                     | HSM returned a malformed EC P256 key. Verify key generation parameters.                         |
| `error` | `Failed to parse RSA private key: {:?}`                                                                                                                                                                                                                                    | `src/pkcs11_private_key.rs` | -                                                                                                     | -                                                                                               |
| `error` | `Failed to parse RSA public key: {:?}`                                                                                                                                                                                                                                     | `src/pkcs11_public_key.rs`  | -                                                                                                     | -                                                                                               |
| `error` | `Public key is not an EC P256 key`                                                                                                                                                                                                                                         | `src/pkcs11_private_key.rs` | -                                                                                                     | -                                                                                               |
| `error` | `Public key is not an EC P256 key`                                                                                                                                                                                                                                         | `src/pkcs11_public_key.rs`  | -                                                                                                     | -                                                                                               |
| `error` | `Public key is not an RSA key`                                                                                                                                                                                                                                             | `src/pkcs11_public_key.rs`  | -                                                                                                     | -                                                                                               |
| `error` | `remote_sign failed for Pkcs11PrivateKey with remote_id {}: {e}`                                                                                                                                                                                                           | `src/pkcs11_private_key.rs` | `e`: caught error                                                                                     | Remote signing via PKCS#11 failed. Check KMS connectivity and key permissions.                  |
| `error` | `Unsupported cryptographic algorithm: {:?}`                                                                                                                                                                                                                                | `src/kms_object.rs`         | -                                                                                                     | -                                                                                               |
| `error` | `Unsupported key algorithm: {:?}`                                                                                                                                                                                                                                          | `src/kms_object.rs`         | -                                                                                                     | -                                                                                               |
| `error` | `verify not implemented for Pkcs11PublicKey`                                                                                                                                                                                                                               | `src/pkcs11_public_key.rs`  | -                                                                                                     | -                                                                                               |
| `warn`  | `create_private_key_from_id: {id} has type {:?} (expected PrivateKey), skipping`                                                                                                                                                                                           | `src/backend.rs`            | `id`: object ID                                                                                       | -                                                                                               |
| `warn`  | `create_symmetric_key_from_id: {id} has type {:?} (expected SymmetricKey), skipping`                                                                                                                                                                                       | `src/backend.rs`            | `id`: object ID                                                                                       | -                                                                                               |
| `debug` | `decrypt: decrypt_ctx: {ctx:?}`                                                                                                                                                                                                                                            | `src/backend.rs`            | `ctx`: ctx                                                                                            | -                                                                                               |
| `debug` | `encrypt: ctx: {ctx:?}`                                                                                                                                                                                                                                                    | `src/backend.rs`            | `ctx`: ctx                                                                                            | -                                                                                               |
| `debug` | `kms_encrypt_async: ciphertext: {}`                                                                                                                                                                                                                                        | `src/kms_object.rs`         | -                                                                                                     | -                                                                                               |
| `debug` | `kms_import_object_async: label: {label}, data (length): {}`                                                                                                                                                                                                               | `src/kms_object.rs`         | `label`: label                                                                                        | -                                                                                               |
| `debug` | `Locate response: ids: {:?}`                                                                                                                                                                                                                                               | `src/kms_object.rs`         | -                                                                                                     | -                                                                                               |
| `debug` | `Located objects: tags: {tags:?}, type: {object_type:?} => {uniques_identifiers:?}`                                                                                                                                                                                        | `src/kms_object.rs`         | `tags`: KMIP tag set<br>`object_type`: KMIP object type<br>`uniques_identifiers`: uniques identifiers | -                                                                                               |
| `debug` | `remote_sign: remote_id: {remote_id}, algorithm: {algorithm:?}`                                                                                                                                                                                                            | `src/backend.rs`            | `remote_id`: remote id<br>`algorithm`: cryptographic algorithm                                        | -                                                                                               |
| `debug` | `vol1: {}`                                                                                                                                                                                                                                                                 | `src/tests.rs`              | -                                                                                                     | -                                                                                               |
| `trace` | `create_object: {label:?}`                                                                                                                                                                                                                                                 | `src/backend.rs`            | `label` — …                                                                                           | —                                                                                               |
| `trace` | `find_all_certificates`                                                                                                                                                                                                                                                    | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_data_objects: entering`                                                                                                                                                                                                                                          | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_data_objects: found {} objects`                                                                                                                                                                                                                                  | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_objects: entering`                                                                                                                                                                                                                                               | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_objects: found {} keys`                                                                                                                                                                                                                                          | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_private_keys`                                                                                                                                                                                                                                                    | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_public_keys`                                                                                                                                                                                                                                                     | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_all_symmetric_keys`                                                                                                                                                                                                                                                  | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_certificate`                                                                                                                                                                                                                                                         | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_data_object: {:?}`                                                                                                                                                                                                                                                   | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_private_key: {:?}`                                                                                                                                                                                                                                                   | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_public_key: {:?}`                                                                                                                                                                                                                                                    | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `find_symmetric_key: {:?}`                                                                                                                                                                                                                                                 | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `Found {} objects`                                                                                                                                                                                                                                                         | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `trace` | `generate_key: {algorithm:?}-{key_length}, {label:?}`                                                                                                                                                                                                                      | `src/backend.rs`            | `algorithm` — …<br>`key_length` — …<br>`label` — …                                                    | —                                                                                               |
| `trace` | `get_kms_certificate_objects_async: found {} Certificate objects`                                                                                                                                                                                                          | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `trace` | `get_kms_certificate_objects_async: no Certificate objects found for tags: {:?}`                                                                                                                                                                                           | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `trace` | `get_kms_objects_async: no objects found for tags: {:?}`                                                                                                                                                                                                                   | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `trace` | `get_kms_secret_data_objects_async: found {} SecretData objects`                                                                                                                                                                                                           | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `trace` | `get_kms_secret_data_objects_async: no SecretData objects found for tags: {:?}`                                                                                                                                                                                            | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `error` | `C_GetFunctionList: failed to instantiate KMS client: {}.                      Check that ckms.toml exists alongside the DLL                      (C:\opt\oracle\extapi\64\pkcs11\ckms.toml),                      at ~/.cosmian/ckms.toml, or set CKMS_CONF to its path.` | `src/lib.rs`                | —                                                                                                     |                                                                                                 |
| `error` | `C_GetFunctionList: failed to load ckms.toml: {}.                  Check that ckms.toml exists alongside the DLL                  (C:\opt\oracle\extapi\64\pkcs11\ckms.toml),                  at ~/.cosmian/ckms.toml, or set CKMS_CONF to its path.`                     | `src/lib.rs`                | —                                                                                                     |                                                                                                 |
| `warn`  | `create_object_from_attributes: unsupported object type: {other}, skipping                      {id}`                                                                                                                                                                      | `src/backend.rs`            | `other`, `id`                                                                                         | —                                                                                               |
| `warn`  | `create_private_key_from_id: unsupported key/algorithm for PrivateKey {id}:                      {e}, skipping`                                                                                                                                                            | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `create_private_key_object: unsupported key/algorithm for PrivateKey {id}:                      {e}, skipping`                                                                                                                                                             | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `create_public_key_object: unsupported key/algorithm for PublicKey {id}: {e},                      skipping`                                                                                                                                                               | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `create_symmetric_key_from_id: unsupported key/algorithm for SymmetricKey                      {id}: {e}, skipping`                                                                                                                                                        | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `create_symmetric_key_object: unsupported key/algorithm for SymmetricKey                      {id}: {e}, skipping`                                                                                                                                                         | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `find_all_public_keys: failed to build Pkcs11PublicKey for {id}: {e},                      skipping`                                                                                                                                                                       | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `find_all_public_keys: failed to export public key {id}: {e},                              skipping`                                                                                                                                                                       | `src/backend.rs`            | `id`, `e`                                                                                             | —                                                                                               |
| `warn`  | `find_all_data_objects: failed to build DataObject for disk-encryption                          key: {e}, skipping`                                                                                                                                                        | `src/backend.rs`            | `e`                                                                                                   | —                                                                                               |
| `warn`  | `find_all_data_objects: failed to fetch disk-encryption data objects: {e},                  returning empty list`                                                                                                                                                          | `src/backend.rs`            | `e`                                                                                                   | —                                                                                               |
| `warn`  | `find_all_objects: failed to build DataObject for disk-encryption key:                          {e}, skipping`                                                                                                                                                             | `src/backend.rs`            | `e`                                                                                                   | —                                                                                               |
| `warn`  | `find_all_objects: failed to fetch disk-encryption data objects: {e},                  returning empty list`                                                                                                                                                               | `src/backend.rs`            | `e`                                                                                                   | —                                                                                               |
| `trace` | `find_all_objects: total {} objects (including disk-encryption DataObjects)`                                                                                                                                                                                               | `src/backend.rs`            | —                                                                                                     | —                                                                                               |
| `trace` | `get_kms_disk_encryption_data_objects_async: found {} SymmetricKey objects`                                                                                                                                                                                                | `src/kms_object.rs`         | —                                                                                                     | —                                                                                               |
| `trace` | `get_kms_disk_encryption_data_objects_async: no SymmetricKey objects found for tag:              {disk_encryption_tag}`                                                                                                                                                    | `src/kms_object.rs`         | `disk_encryption_tag`                                                                                 | —                                                                                               |

### `cosmian_pkcs11_module`

Crate path: `crate/clients/pkcs11/module`
`RUST_LOG` target: `cosmian_pkcs11_module`

| Level | Message | File | Variables | Notes |
|---|---|---|---|---|
| `error` | `C_GetAttributeValue: error: {e}, session: {:?}, object: {:?}, type: {:?}` | `src/pkcs11.rs` | `e`: caught error | - |
| `error` | `certificate: type_ unimplemented: {type_:?}` | `src/core/object.rs` | `type_`: type  | - |
| `error` | `Data object: type_ unimplemented: {type_:?}` | `src/core/object.rs` | `type_`: type  | - |
| `error` | `Failed to extract RSA key parameters: {e:?}` | `src/core/object.rs` | `e`: caught error | - Could not read RSA key components from HSM object. Key may be non-exportable. |
| `error` | `Failed to parse RSA private key from PKCS#8 DER: {e:?}` | `src/core/object.rs` | `e`: caught error | - HSM returned a malformed RSA PKCS#8 blob. Check HSM firmware and key type. |
| `error` | `pParameter incorrect: {} != {}` | `src/core/mechanism.rs` | - | PKCS#11 mechanism parameter size mismatch. Client sent the wrong parameter struct. |
| `error` | `private_key: type_ unimplemented: {type_:?}` | `src/core/object.rs` | `type_`: type  | - |
| `error` | `profile: type_ unimplemented: {type_:?}` | `src/core/object.rs` | `type_`: type  | - |
| `error` | `public_key: type_ unimplemented: {type_:?}` | `src/core/object.rs` | `type_`: type  | - |
| `error` | `symmetric_key: type_ unimplemented: {type_:?}` | `src/core/object.rs` | `type_`: type  | - |
| `error` | `Unsupported hashAlg: {}` | `src/core/mechanism.rs` | - | PKCS#11 hash algorithm not supported. Use SHA-256 or SHA-384. |
| `error` | `Unsupported mgf: {}` | `src/core/mechanism.rs` | - | PKCS#11 MGF algorithm not supported. Use MGF1 with a supported hash. |
| `error` | `{}: {}` | `src/pkcs11.rs` | - | Generic two-part error - inspect both values for the error type and detail. |
| `warn` | `load_find_context: id {label} not found in store` | `src/sessions.rs` | `label`: label | - |
| `info` | `C_CloseAllSessions: slot: {:?}` | `src/pkcs11.rs` | - | - |
| `info` | `C_CloseSession: session: {:?}` | `src/pkcs11.rs` | - | - |
| `info` | `C_FindObjects: session: {:?}, no more objects to return` | `src/pkcs11.rs` | - | - |
| `info` | `C_FindObjects: session: {:?}, returning {} object with handles {:?}` | `src/pkcs11.rs` | - | - |
| `info` | `C_GetAttributeValue: session: {:?}, object: {:?} [handle: {}], type: {:?}` | `src/pkcs11.rs` | - | - |
| `info` | `C_OpenSession: slot={slotID:?} flags={flags:?} session handle written` | `src/pkcs11.rs` | `slotID`: slotID<br>`flags`: flags | - |
| `debug` | `C_DestroyObject: session: {hSession:?}, hObject: {hObject}` | `src/pkcs11.rs` | `hSession`: hSession<br>`hObject`: hObject | - |
| `debug` | `CKO_DATA match: remote_id={}, handle={}` | `src/sessions.rs` | - | - |
| `debug` | `CKO_DATA search: label_filter={:?}, store has {} DataObjects` | `src/sessions.rs` | - | - |
| `debug` | `create_object: attributes: {attributes:?}` | `src/sessions.rs` | `attributes`: KMIP attribute (debug display)s | - |
| `debug` | `create_object: created object with handle: {handle}` | `src/sessions.rs` | `handle`: PKCS#11 object handle | - |
| `debug` | `destroy_object: handle: {handle}` | `src/sessions.rs` | `handle`: PKCS#11 object handle | ×2 in this file |
| `debug` | `generate_key: generated key with handle: {handle}` | `src/sessions.rs` | `handle`: PKCS#11 object handle | - |
| `debug` | `generate_key: generating key with mechanism: {:?} and attributes: {:?}` | `src/sessions.rs` | - | - |
| `debug` | `load_find_context: display current store: {find_ctx}` | `src/sessions.rs` | `find_ctx`: find ctx | - |
| `debug` | `load_find_context: loading for label: {label:?} and attributes: {attributes:?}` | `src/sessions.rs` | `label`: label<br>`attributes`: KMIP attribute (debug display)s | - |
| `debug` | `load_find_context: search by id: {label} -> handle: {} -> object: {}: {}` | `src/sessions.rs` | `label`: label | - |
| `debug` | `load_find_context_by_class: added {} objects with handles: {:?}` | `src/sessions.rs` | - | - |
| `debug` | `map_oracle_tde_security_to_mk: processing label: {label}` | `src/sessions.rs` | `label`: label | - |
| `debug` | `Object: {}, attribute: {:?} => {:?}` | `src/core/object.rs` | - | - |
| `debug` | `parse_mechanism: iv: {iv:?}` | `src/core/mechanism.rs` | `iv`: iv | - |
| `debug` | `parse_mechanism: {mechanism:?}` | `src/core/mechanism.rs` | `mechanism`: PKCS#11 mechanism | - |
| `debug` | `session: {h} found` | `src/sessions.rs` | `h`: h | - |
| `debug` | `STORE: inserting new object with remote id: {id} and handle: {handle}` | `src/objects_store.rs` | `id`: object ID<br>`handle`: PKCS#11 object handle | - |
| `debug` | `STORE: updating object with remote id: {id} and handle: {handle}` | `src/objects_store.rs` | `id`: object ID<br>`handle`: PKCS#11 object handle | - |
| `trace` | `Attribute::try_from: attribute parsed: {:?} => {:?}` | `src/core/attribute.rs` | — | — |
| `trace` | `Attribute::try_from: parsing attribute: {:?}` | `src/core/attribute.rs` | — | — |
| `trace` | `Attribute::try_from: type: {attr_type:?}` | `src/core/attribute.rs` | `attr_type` — … | — |
| `trace` | `Attribute::try_from: value: {val:?}` | `src/core/attribute.rs` | `val` — … | — |
| `trace` | `Attributes::try_from: parsing single attribute: {attr:?}` | `src/core/attribute.rs` | `attr` — … | — |
| `trace` | `C_FindObjects: session: {:?}, objects available: {:?}` | `src/pkcs11.rs` | — | — |
| `trace` | `C_GetAttributeValue: session: {:?}, object: {:?}` | `src/pkcs11.rs` | — | — |
| `trace` | `C_GetSessionInfo: session: {:?}, slot: {:?}, state: {:?}, flags: {:?}` | `src/pkcs11.rs` | — | — |
| `trace` | `create_object: class: {class:?}` | `src/sessions.rs` | `class` — … | — |
| `trace` | `create_object: Object not supported: {o}` | `src/sessions.rs` | `o` — … | — |
| `trace` | `Generated random: {}` | `src/pkcs11.rs` | — | — |
| `trace` | `load_find_context succeeded` | `src/sessions.rs` | — | — |
| `info` | `C_FindObjectsInit: session: {hSession:?}, load Objects Store context for                  attributes: {attributes:?}` | `src/pkcs11.rs` | `hSession`, `attributes` | — |
| `debug` | `C_CreateObject: session: {hSession:?}, pTemplate: {pTemplate:?}, ulCount:              {ulCount:?}, phObject: {phObject:?}` | `src/pkcs11.rs` | `hSession`, `pTemplate`, `ulCount`, `phObject` | — |
| `debug` | `C_Decrypt: pEncryptedData: {pEncryptedData:?}, ulEncryptedDataLen:              {ulEncryptedDataLen:?}, pData: {pData:?}, pulDataLen: {pulDataLen:?}` | `src/pkcs11.rs` | `pEncryptedData`, `ulEncryptedDataLen`, `pData`, `pulDataLen` | — |
| `debug` | `C_Decrypt: session: {:?}, encrypted_data_len: {:?}, cleartext_len: {:?},                      ciphertext: {:?}` | `src/pkcs11.rs` | — | — |
| `debug` | `C_DecryptInit: session: {hSession:?}, hKey: {hKey:?}, mechanism: {mechanism:?},                  object: {object:?}` | `src/pkcs11.rs` | `hSession`, `hKey`, `mechanism`, `object` | — |
| `debug` | `C_Encrypt: pData: {pData:?}, ulDataLen: {ulDataLen:?}, pEncryptedData:              {pEncryptedData:?}, pulEncryptedDataLen: {pulEncryptedDataLen:?}` | `src/pkcs11.rs` | `pData`, `ulDataLen`, `pEncryptedData`, `pulEncryptedDataLen` | — |
| `debug` | `C_Encrypt: session: {:?}, plain_data_len: {:?}, ciphertext_len: {:?},                      cleartext: {:?}` | `src/pkcs11.rs` | — | — |
| `debug` | `C_EncryptInit: session: {hSession:?}, hKey: {hKey:?}, mechanism: {mechanism:?},                  object: {object:?}` | `src/pkcs11.rs` | `hSession`, `hKey`, `mechanism`, `object` | — |
| `debug` | `C_GenerateKey: session: {hSession:?}, pMechanism: {pMechanism:?}, pTemplate:              {pTemplate:?}, ulCount: {ulCount:?}, phKey: {phKey:?}` | `src/pkcs11.rs` | `hSession`, `pMechanism`, `pTemplate`, `ulCount`, `phKey` | — |
| `debug` | `load_find_context_by_class: loading for class: {search_class:?} and options:              {search_options:?}, attributes: {attributes:?}` | `src/sessions.rs` | `search_class`, `search_options`, `attributes` | — |
| `debug` | `load_find_context_by_class: search by id: {} -> handle:                                          {} -> certificate: {}:{}` | `src/sessions.rs` | — | — |
| `debug` | `load_find_context_by_class: search by id: {} -> handle: {} -> object:                          {}:{}` | `src/sessions.rs` | — | — |

---

## Domain: CNG (Windows)

### `cosmian_cng`

Crate path: `crate/clients/cng`
`RUST_LOG` target: `cosmian_cng`

| Level   | Message                                                                          | File              | Variables                                                      | Notes                                                                        |
| ------- | -------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `error` | `CNG KSP decrypt: {e}`                                                           | `src/provider.rs` | `e`: caught error                                              | Decryption via CNG failed. Check key state and CNG provider logs.            |
| `error` | `CNG KSP delete_key: {e}`                                                        | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP encrypt: {e}`                                                           | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP enum_keys: {e}`                                                         | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP export_key private: {e}`                                                | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP export_key: {e}`                                                        | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP finalize_key: {e}`                                                      | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP import_key attrs: {e}`                                                  | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP import_key backend: {e}`                                                | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP import_key parse blob: {e}`                                             | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `error` | `CNG KSP open_key attrs({name}): {e}`                                            | `src/provider.rs` | `name`: key or object name<br>`e`: caught error                | -                                                                            |
| `error` | `CNG KSP open_key pub({name}): {e}`                                              | `src/provider.rs` | `name`: key or object name<br>`e`: caught error                | -                                                                            |
| `error` | `CNG KSP open_key({name}): {e}`                                                  | `src/provider.rs` | `name`: key or object name<br>`e`: caught error                | -                                                                            |
| `error` | `CNG KSP open_provider: {e}`                                                     | `src/provider.rs` | `e`: caught error                                              | CNG provider DLL failed to load or initialise. Verify the DLL is registered. |
| `error` | `CNG KSP sign_hash: {e}`                                                         | `src/provider.rs` | `e`: caught error                                              | Signing via CNG failed. Key may be non-exportable or in an invalid state.    |
| `error` | `CNG KSP verify_signature: {e}`                                                  | `src/provider.rs` | `e`: caught error                                              | -                                                                            |
| `info`  | `CNG KSP provider already registered; skipping BCryptRegisterProvider`           | `src/registry.rs` | -                                                              | -                                                                            |
| `info`  | `DLL was locked; old copy renamed to '{}' and scheduled for deletion on reboot.` | `src/registry.rs` | -                                                              | -                                                                            |
| `debug` | `BCryptAddContextFunction returned {status:#010x} (may already exist)`           | `src/registry.rs` | `status`: HTTP response status                                 | -                                                                            |
| `debug` | `BCryptRemoveContextFunctionProvider returned {status:#010x}`                    | `src/registry.rs` | `status`: HTTP response status                                 | -                                                                            |
| `debug` | `CNG KSP GetKeyStorageInterface called`                                          | `src/lib.rs`      | -                                                              | -                                                                            |
| `debug` | `CNG KSP register: source dll={}`                                                | `src/registry.rs` | -                                                              | -                                                                            |
| `debug` | `CNG KSP unregister`                                                             | `src/registry.rs` | -                                                              | -                                                                            |
| `debug` | `CNG KSP: create_ec_key_pair name={key_name} curve={curve:?}`                    | `src/backend.rs`  | `key_name`: CNG key name<br>`curve`: elliptic curve identifier | -                                                                            |
| `debug` | `CNG KSP: create_rsa_key_pair name={key_name} bits={bit_length}`                 | `src/backend.rs`  | `key_name`: CNG key name<br>`bit_length`: key size in bits     | -                                                                            |
| `debug` | `CNG KSP: decoded PEM to {} bytes DER`                                           | `src/key.rs`      | -                                                              | -                                                                            |
| `debug` | `CNG KSP: decrypt_data uid={uid} len={}`                                         | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: destroy_key uid={uid}`                                                 | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: encrypt_data uid={uid} len={}`                                         | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: export_private_key_pkcs8 uid={uid}`                                    | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: export_public_key_spki uid={uid}`                                      | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: finalize import blob len={}, first_bytes={:?}`                         | `src/key.rs`      | -                                                              | -                                                                            |
| `debug` | `CNG KSP: finalized key '{}' → priv={}, pub={}`                                  | `src/key.rs`      | -                                                              | -                                                                            |
| `debug` | `CNG KSP: import_rsa_private_key name={key_name}`                                | `src/backend.rs`  | `key_name`: CNG key name                                       | -                                                                            |
| `debug` | `CNG KSP: revoke_key uid={uid}`                                                  | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: sign_hash uid={uid} hash_len={}`                                       | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `CNG KSP: verify_signature uid={uid} hash_len={} sig_len={}`                     | `src/backend.rs`  | `uid`: KMIP object UID                                         | -                                                                            |
| `debug` | `Copying {} -> {}`                                                               | `src/registry.rs` | -                                                              | -                                                                            |
| `debug` | `MoveFileExW(DELAY_UNTIL_REBOOT) failed for '{}'; leftover file is harmless.`    | `src/registry.rs` | -                                                              | -                                                                            |
| `trace` | `CNG KSP: list_cng_keys`                                                         | `src/backend.rs`  | —                                                              | —                                                                            |
| `trace` | `CNG KSP: locate_key_by_name tag={tag}`                                          | `src/backend.rs`  | `tag` — …                                                      | —                                                                            |
| `trace` | `CNG KSP: locate_public_key_by_name tag={tag}`                                   | `src/backend.rs`  | `tag` — …                                                      | —                                                                            |

## Domain: Web UI

The Web UI emits browser console messages via `console.*`. These are visible in the
browser developer tools (F12 → Console tab) and are not captured by `RUST_LOG` or
the OTLP pipeline.

Crate path: `ui/src/`

| Level   | Message                                                  | File                                              | Variables                                                     | Notes           |
| ------- | -------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- | --------------- |
| `warn`  | `revoke_ttlv_request not available in WASM package`      | `components/common/Locate.tsx`                    | -                                                             | -               |
| `info`  | `[KMS] vendor_id set to "{vendorId}"`                    | `App.tsx`                                         | `vendorId`: vendor identifier string received from the server | -               |
| `error` | `Aggregate date error:`                                  | `actions/Tokenize/TokenizeAggregateDate.tsx`      | —                                                             | —               |
| `error` | `Aggregate number error:`                                | `actions/Tokenize/TokenizeAggregateNumber.tsx`    | —                                                             | —               |
| `error` | `Certificate validation failed:`                         | `pages/LoginPage.tsx`                             | —                                                             | —               |
| `error` | `Error creating FPE key:`                                | `actions/FPE/FpeKeysCreate.tsx`                   | —                                                             | —               |
| `error` | `Error fetching create permission:`                      | `actions/Access/AccessObtained.tsx`               | —                                                             | —               |
| `error` | `Error fetching CSE information:`                        | `actions/Keys/CseInfo.tsx`                        | —                                                             | —               |
| `error` | `Error fetching Get for ${uid}:`                         | `components/common/Locate.tsx`                    | `uid`                                                         | ×4 in this file |
| `error` | `Error fetching HSM status:`                             | `actions/Objects/HsmStatus.tsx`                   | —                                                             | —               |
| `error` | `Error fetching privileged access:`                      | `actions/Access/AccessGrant.tsx`                  | —                                                             | —               |
| `error` | `Error fetching privileged access:`                      | `actions/Access/AccessRevoke.tsx`                 | —                                                             | —               |
| `error` | `Error getting attributes:`                              | `actions/Attributes/AttributeGet.tsx`             | —                                                             | —               |
| `error` | `Error listing objects:`                                 | `actions/Access/AccessObtained.tsx`               | —                                                             | —               |
| `error` | `Error listing objects:`                                 | `actions/Objects/ObjectsOwned.tsx`                | —                                                             | —               |
| `error` | `Error loading certificate algorithms from WASM:`        | `actions/Certificates/CertificateCertify.tsx`     | —                                                             | —               |
| `error` | `Error loading EC algorithms from WASM:`                 | `actions/EC/ECKeysCreate.tsx`                     | —                                                             | —               |
| `error` | `Error loading hash algorithms from WASM:`               | `actions/Symmetric/SymmetricHash.tsx`             | —                                                             | —               |
| `error` | `Error loading PQC algorithms from WASM:`                | `actions/PQC/PqcKeysCreate.tsx`                   | —                                                             | —               |
| `error` | `Error loading symmetric algorithms from WASM:`          | `actions/Keys/SymKeysCreate.tsx`                  | —                                                             | —               |
| `error` | `Error parsing tags JSON:`                               | `actions/CloudProviders/AwsExportKeyMaterial.tsx` | —                                                             | —               |
| `error` | `Error parsing tags JSON:`                               | `utils/azureByok.ts`                              | —                                                             | —               |
| `error` | `Fallback Locate without KFT failed:`                    | `components/common/Locate.tsx`                    | —                                                             | —               |
| `error` | `FPE decrypt error:`                                     | `actions/FPE/FpeDecrypt.tsx`                      | —                                                             | —               |
| `error` | `FPE encrypt error:`                                     | `actions/FPE/FpeEncrypt.tsx`                      | —                                                             | —               |
| `error` | `Hash tokenize error:`                                   | `actions/Tokenize/TokenizeHash.tsx`               | —                                                             | —               |
| `error` | `Login error:`                                           | `contexts/AuthContext.tsx`                        | —                                                             | —               |
| `error` | `Login error:`                                           | `pages/LoginPage.tsx`                             | —                                                             | —               |
| `error` | `Noise tokenize error:`                                  | `actions/Tokenize/TokenizeNoise.tsx`              | —                                                             | —               |
| `error` | `Scale number error:`                                    | `actions/Tokenize/TokenizeScaleNumber.tsx`        | —                                                             | —               |
| `error` | `WASM init failed:`                                      | `App.tsx`                                         | —                                                             | —               |
| `error` | `Word mask error:`                                       | `actions/Tokenize/TokenizeWordMask.tsx`           | —                                                             | —               |
| `error` | `Word pattern mask error:`                               | `actions/Tokenize/TokenizeWordPatternMask.tsx`    | —                                                             | —               |
| `error` | `Word tokenize error:`                                   | `actions/Tokenize/TokenizeWordTokenize.tsx`       | —                                                             | —               |
| `warn`  | `[KMS] Could not query server vendor_id, using default:` | `App.tsx`                                         | —                                                             | —               |
| `warn`  | `State+KFT fallback Locate without KFT failed:`          | `components/common/Locate.tsx`                    | —                                                             | —               |
| `warn`  | `Symmetric google_cse key check failed:`                 | `actions/Keys/CseInfo.tsx`                        | —                                                             | —               |
| `debug` | `ECSign: signature length`                               | `actions/EC/ECSign.tsx`                           | —                                                             | —               |
| `debug` | `ECVerify: dataBuf len`                                  | `actions/EC/ECVerify.tsx`                         | —                                                             | —               |
| `debug` | `RsaSign: signature length`                              | `actions/RSA/RsaSign.tsx`                         | —                                                             | —               |
| `debug` | `RsaVerify: dataBuf len`                                 | `actions/RSA/RsaVerify.tsx`                       | —                                                             | —               |
| `error` | `JWT fallback failed:`                                   | `App.tsx`                                         | -                                                             | -               |

---

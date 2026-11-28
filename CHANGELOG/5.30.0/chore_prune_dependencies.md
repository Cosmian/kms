## Build

### Dependencies
- Remove the `csv`, `log`, `native-tls` and `strum_macros` workspace dependencies, and the unused `der`, `csv`, `pem` and `assert_cmd` member declarations (with their dead error variants `CkmsError::{CsvError, DerError}`, `KmsClientError::PemError`, `KmsCliError::CargoError`), in favor of crates already present in each member; no dependency is added or upgraded
- `cosmian_kms_server_database` extracts certificate serials with `openssl` instead of `x509-parser`; the hex output (`BN_bn2hex` form) is unchanged
- `cosmian_kms_client` no longer depends on `actix-web` or `reqwest`: the `OAuth2` callback listener is a small `hyper` server (same `/authorization` contract and responses) and `auth_verifier_login` uses the OpenSSL-backed `HttpClient` (no redirect following, no `HTTP(S)_PROXY` env handling, host CA bundle instead of bundled webpki roots)
- The k8s operator timestamps (`lastSyncTime`, restart annotation) are now formatted with `time` and use the `Z` suffix instead of `+00:00`

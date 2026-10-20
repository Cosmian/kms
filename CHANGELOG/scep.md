### EST and SCEP device enrollment ([#871](https://github.com/Cosmian/kms/issues/871))

- Added **EST** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)): `GET /.well-known/est/cacerts`,
  `GET /.well-known/est/csrattrs`, `POST /.well-known/est/simpleenroll` (TLS client certificate or
  HTTP Basic bootstrap) and `POST /.well-known/est/simplereenroll` (mutual TLS with the certificate
  being renewed; Subject and SubjectAltName must be identical, no challenge needed). Enable with
  `[est] est_enabled = true` and `est_ca_uid`.
- Added **SCEP** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)) at `/scep`: `GetCACaps`
  (`POSTPKIOperation`, `SHA-256`, `AES`, `Renewal` — `DES3`/`SHA-1` are never advertised),
  `GetCACert`, and `PKIOperation` over GET/POST with `PKCSReq` (challenge password) and
  `RenewalReq` signed by a still-valid, active certificate of the SCEP CA (no challenge password;
  disable with `scep_allow_renewal_without_challenge = false`). Enable with `[scep] scep_enabled = true`,
  `scep_ca_uid` and `scep_challenge_password`. The SCEP CA must be an RSA CA.
- Added per-endpoint **certificate templates** (`[templates.<name>]`, selected with `est_template` /
  `scep_template`): minimum RSA size, allowed EC curves, allowed/injected EKUs, maximum and default
  validity, and anchored regular expressions for the subject CN and the DNS / e-mail / UPN SANs.
  `est_template` / `scep_template` is required when EST / SCEP is enabled and the template must set
  `subject_cn_regex` (or `allow_any_identity = true`); the baseline limits (RSA ≥ 2048 or NIST
  P-256/384/521, `clientAuth` only, no `CA:TRUE`, validity ≤ 365 days) apply to every template.
  Without `allow_any_identity` the `serialNumber`, `UID` and `emailAddress` subject attributes are
  refused. Only the `keyUsage` (without `keyCertSign` /
  `cRLSign`), `subjectAltName`, `extendedKeyUsage` and `basicConstraints` CSR extensions are
  accepted; any other requested extension and any duplicated extension is refused.
  The CSR proof of possession is always verified.
- Extended-key-usage entries in X.509 extension files now accept dotted OIDs.
- Added `cosmian_kms_crypto::openssl::{scep_cms, csr_attrs}` (CMS signed attributes through
  the OpenSSL partial-CMS API, challenge-password access).
- Added the `mise run test:scep-interop` (micromdm `scepclient`) and `mise run test:est-interop`
  (globalsign `estclient`, TLS and mTLS) black-box tests, and the interactive macOS
  `mise run test:scep-apple` (native Apple SCEP client through a recording proxy) whose capture
  (`test_data/scep/apple/`) is replayed in CI by `apple_scep_fixtures_parse`.
  Note: the stock `scepclient` always encrypts with single DES-CBC, which the server refuses;
  the test builds it with AES-128-CBC selected.
- `GetCert`, `GetCRL`, `CertPoll` and `GetNextCACert` are not implemented; issuance is synchronous.
  Consequently `GetCACaps` does not advertise `SCEPStandard`.
- No EST/SCEP client is provided in `ckms` or the Web UI: devices and MDM use their own clients
  (e.g. `estclient`, `scepclient`, Apple/Windows MDM payloads).

### Security

- SCEP `CertRep` `senderNonce` now comes from the `KmsRng` public DRBG instead of `openssl::rand::rand_bytes`.
- Configuration-wizard certificate serials now come from `KmsRng` and are 159-bit RFC 5280 serials (previously 128 bits from `BigNum::rand`).
- Anonymization word tokens and noise generators are drawn from, or seeded by, `KmsRng`; the unused PKCS#11 `random_label` helper is removed.
- The root `clippy.toml` now bans every ambient entropy source (OpenSSL `rand` / `BigNum` rand, `rand::rng`, `thread_rng`, `OsRng`, `getrandom`, `from_entropy`, `cookie::Key::generate`, non-cryptographic PRGs) with no suppression allowed, test fixtures included. Seeded PRGs are allowed only through `KmsRng::seeded_csrng` or `from_seed` with `KmsRng` bytes.
- New CI job "KmsRng Policy" (`mise run audit:rng-policy`) rejects lint suppressions, lint-level overrides in Cargo manifests and any additional `clippy.toml`.
- Nonces, IVs and certificate serials (symmetric `random_nonce`, JOSE, AWS XKS, Redis objects, ceremony records, HSM sessions, X.509 serials) and PKCS#11 `C_GenerateRandom` output come from the public DRBG (`fill_public_bytes`), so private-DRBG output never leaves the server.
- `KmsRng::seeded_csrng` returns `SeededCsRng`, whose ChaCha12 state (equal to the seed) is overwritten on drop; OpenPGP key generation, encryption and signing now use it instead of an unzeroized `StdRng`. Drops the `rand` 0.8 (`rand_08`) dependency.
- EST/SCEP issue certificates as the reserved identity `[enrollment-service]` instead of `default_username`.
  It is rejected on every externally authenticated path (JWT, mTLS CN, SPIRE, UI session; the guard is now
  `reject_reserved_service_identity`, shared with `[aws-xks-service]`). It may only use a CA whose owner
  granted it `certify` on the CA certificate and private key (fail closed otherwise). Issued certificates are
  stored atomically under the CA owner, who keeps revoke/destroy control. Startup refuses
  `default_username` or `crypto_officer_users` equal to `[enrollment-service]` when EST or SCEP is enabled.
  **Setup action:** `ckms access-rights grant "[enrollment-service]" -i <ca cert uid> certify` and the same
  for the CA private key.
- The KMIP socket server (TLS port 5696) now maps the client certificate to a user with the same checks as HTTPS
  mTLS (`user_from_client_certificate`): the CN must be non-empty, not `*`, and not a reserved service identity.
  Previously a client certificate from the trusted client CA with `CN=[enrollment-service]` or
  `CN=[aws-xks-service]` acted as that identity over KMIP, bypassing the enrollment templates and AWS SigV4.
- Startup now refuses EST HTTP Basic bootstrap without TLS and `est_require_client_cert = true` without TLS
  and `clients_ca_cert_file`. Empty `allowed_ekus` / `allowed_ec_curves` are rejected.
- Every certificate issued through EST or SCEP carries a marker `certificatePolicies` entry
  (`1.3.6.1.4.1.16376.9.2.1`); `user_from_client_certificate` (HTTPS mTLS and the KMIP socket) refuses such a
  certificate, so a device that chooses `CN=admin` in its CSR can never authenticate to the KMS as that user.
  It remains usable for EST re-enrollment. The marker cannot be requested through a CSR.
- CSR validation is fail-closed: a CSR using the Microsoft `msExtReq` attribute (which OpenSSL honours when
  building the certificate but the validator did not inspect), an undecodable extension request, or more than one
  `extensionRequest` is refused, so a CSR cannot smuggle `CA:TRUE` past the template checks.
- The EST/SCEP renewal identity check compares the raw DER of each `SubjectAltName` entry and treats a malformed
  SAN as an error.
- `est_bootstrap_password` and `scep_challenge_password` are masked in the `Debug` output of the configuration.
- **Enrollment hardening** (threat-model findings of 2026-10-20):
  - Wrong EST Basic credentials or SCEP challenges lock the client address out (`429` + `Retry-After`,
    10 failures, 30 s doubling up to 1 h); at most 16 enrollments run concurrently (`503`); EST/SCEP bodies
    are limited to 64 KiB (`413`) instead of the server-wide 64 MiB; a warning is logged when
    `rate_limit_per_second` is not set. Secrets must have at least 8 characters.
  - SCEP: an authenticated message (signer, transactionID, senderNonce) cannot be replayed (1 h);
    every failure after parsing reports `badRequest` (no decryption oracle); a renewal signer is checked
    before the envelope is decrypted; `transactionID` must be printable ASCII of at most 128 characters; the
    `operation` query value is no longer echoed; a startup warning is logged when SCEP runs without TLS.
  - EST `simpleenroll` refuses a client certificate that carries the enrollment marker but was not issued
    by the EST CA (SCEP-enrolled, earlier CA key); `403` bodies are fixed messages (no certificate UID or
    state) and the CA UID is no longer echoed by `cacerts` / `GetCACert`.
  - The enrolled-certificate marker is checked on the whole verified chain (HTTPS mTLS and KMIP socket);
    when OpenSSL keeps no chain the certificate is not mapped to a user. The HTTPS and KMIP socket
    acceptors that verify client certificates therefore no longer resume TLS sessions (session cache and
    tickets off): every connection does a full handshake.
  - Every issued certificate is checked to be a plain end-entity certificate (no CA, no `keyCertSign`,
    marker present) before it is returned; a non-conforming certificate is deactivated.
  - Enrolled certificates are indexed by issuer and serial (system tag), so renewal no longer scans every
    certificate of the CA.
  - Every EST/SCEP attempt is logged (`info` / `warn`, client address, authentication method) and recorded in
    the audit trail with the issued certificate UID when auditing is enabled.
  - The Certify trace log no longer contains the CSR (which carries the SCEP challenge);
    `KMS_EST_BOOTSTRAP_PASSWORD` / `KMS_SCEP_CHALLENGE_PASSWORD` environment variables are supported; the
    configuration wizard writes its file with mode 0600, validates the Basic user name and secret length and
    requires a subject CN pattern.
  - `RNGSeed` is restricted to Crypto Officers once roles are configured, and its seed bytes are no longer
    traced.
  - OpenAPI: EST `simpleenroll` / `simplereenroll` declare their mTLS / Basic security schemes and the new
    `403` / `413` / `429` / `503` replies.
  - CI: the Windows EST job installs Ninja from a pinned, SHA-256-verified release instead of Chocolatey; the
    SCEP interop script verifies the pinned `smallstep/pkcs7` `go.sum` hashes; the documentation build no
    longer reaches the `curl | sh` rustup bootstrap.

# EST and SCEP device enrollment ([#871](https://github.com/Cosmian/kms/issues/871))

## Breaking Changes

### Server

- Behind a trusted proxy the client address (audit `client_ip` and the enrollment lockout key) is now the
  rightmost `X-Forwarded-For` entry that is not a trusted proxy, read across all header lines, instead of the
  leftmost entry, which the client controls. `X-Forwarded-For` is honoured only when the direct TCP peer is
  one of the configured trusted proxies. Audit logs behind proxies may show different addresses than before:
  update log/SIEM correlation rules.
- `RNGSeed` is restricted to Crypto Officers once roles are configured, and its seed bytes are no longer
  traced. Add the callers that seed the server DRBG to `crypto_officer_users`.
- Server-wide: error responses (EST, SCEP and every other route) are now `text/plain; charset=utf-8` with
  `X-Content-Type-Options: nosniff` instead of `text/html`. Clients that check the error `Content-Type` see the change.
- EST/SCEP certificate templates refuse SANs by default: a CSR SAN of a type without a matching
  `san_dns_regex` / `san_email_regex` / `san_upn_regex` is rejected (422 / `badRequest`); iPAddress and URI SANs
  are accepted only with `allow_any_identity = true` and no `san_*_regex` (`allow_any_identity` now also opens
  SANs). Devices that send SANs under an existing CN-only template get 422 / `badRequest` until a `san_*_regex`
  is added. The configuration wizard now asks for an optional DNS SAN pattern.
- SCEP accepts only AES-128/192/256-CBC envelopes with RSA key transport and SHA-256/384/512 signer digests,
  in every build. Refused envelopes count toward the enrollment lockout.
- SCEP message types the CA does not process, and `RenewalReq` while renewal is disabled, are refused with HTTP 400
  before any CA operation and count toward the lockout: a device that keeps sending them locks out its address.

## Features

### Enrollment

- Added **EST** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)): `GET /.well-known/est/cacerts`,
  `GET /.well-known/est/csrattrs`, `POST /.well-known/est/simpleenroll` (TLS client certificate or
  HTTP Basic bootstrap) and `POST /.well-known/est/simplereenroll` (mutual TLS with the certificate
  being renewed; Subject and SubjectAltName must be identical, no challenge needed). Enable with
  `[est] est_enabled = true` and `est_ca_uid`.
- Added **SCEP** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)) at `/scep`: `GetCACaps`
  (`POSTPKIOperation`, `SHA-256`, `AES`, and `Renewal` only when `scep_allow_renewal_without_challenge = true`
  — `DES3`/`SHA-1` are never advertised), `GetCACert`, and `PKIOperation` over GET/POST with `PKCSReq`
  (challenge password) and `RenewalReq` signed by a still-valid, active certificate of the SCEP CA (no
  challenge password; disable with `scep_allow_renewal_without_challenge = false`). Enable with
  `[scep] scep_enabled = true`, `scep_ca_uid` and `scep_challenge_password`. The SCEP CA must be an RSA CA,
  and the SCEP message signer key must be RSA or EC (the response is encrypted to it).
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

## Security

- Reserved service identities (`[enrollment-service]`, `[aws-xks-service]`) are refused regardless of ASCII case or
  trailing spaces, in authentication and in config checks, so case-insensitive MySQL/MariaDB user ID columns cannot
  map an external user onto them. Visually similar non-ASCII characters still need a binary collation on the user ID column.
- CSRs with a Microsoft `msExtReq` attribute (or an undecodable `extensionRequest`) are refused when signing a SPIRE
  intermediate CA, as EST/SCEP already did.
- Anonymization word tokens now come from the public DRBG, since they are returned to clients.
- SCEP: when the CA cannot be used, unauthenticated callers get a fixed HTTP 500 message; CA and key identifiers go
  only to the server log. A successful renewal no longer clears the challenge-password failure counter. The envelope
  replay key (not a signer-key equality check) stops a re-signed captured request, because Apple's SCEP client signs
  with a key distinct from the CSR key.
- EST: the HTTP Basic lockout no longer blocks `simpleenroll` requests that present a TLS client certificate.
- Renewal of certificates without a serial index checks every candidate linked to the CA, so a planted copy with the
  same serial cannot block a genuine renewal.
- `X-Forwarded-For` is only read when the peer is a trusted proxy.
- SCEP rejects DES, 3DES and RC2 envelopes (`badRequest`) and SHA-1/MD5 signed messages (HTTP 400); previously the
  FIPS build accepted 3DES and SHA-1, and the non-FIPS build also DES, RC2 and MD5.
- Templates without a SAN pattern no longer issue certificates for arbitrary SAN identities (see Breaking Changes).
- Error bodies that quote CSR Subject/SAN text can no longer be rendered as HTML on the KMS/Web UI origin.
- A non-ASCII byte in an `X-Forwarded-For` line no longer drops the whole line, so clients behind a trusted proxy
  do not share the proxy's EST/SCEP lockout bucket or audit address.
- SCEP `CertRep` `senderNonce` now comes from the `KmsRng` public DRBG instead of `openssl::rand::rand_bytes`.
- Configuration-wizard certificate serials now come from `KmsRng` and are 159-bit RFC 5280 serials (previously 128 bits from `BigNum::rand`).
- Anonymization word tokens and noise generators are drawn from, or seeded by, `KmsRng`; the unused PKCS#11 `random_label` helper is removed.
- The root `clippy.toml` now bans every ambient entropy source (OpenSSL `rand` / `BigNum` rand, `rand::rng`, `thread_rng`, `OsRng`, `getrandom`, `from_entropy`, `cookie::Key::generate`, non-cryptographic PRGs) with no suppression allowed, test fixtures included. Seeded PRGs are allowed only through `KmsRng::seeded_csrng` or `from_seed` with `KmsRng` bytes.
- Nonces, IVs and certificate serials (symmetric `random_nonce`, JOSE, AWS XKS, Redis objects, ceremony records, HSM sessions, X.509 serials) and PKCS#11 `C_GenerateRandom` output come from the public DRBG (`fill_public_bytes`), so private-DRBG output never leaves the server.
- `KmsRng::seeded_csrng` returns `SeededCsRng`, whose ChaCha12 state (equal to the seed) is overwritten on drop; OpenPGP key generation, encryption and signing now use it instead of an unzeroized `StdRng`. Drops the `rand` 0.8 (`rand_08`) dependency.
- EST/SCEP issue certificates as the reserved identity `[enrollment-service]` instead of `default_username`.
  It is rejected on every externally authenticated path (JWT, mTLS CN, SPIRE, UI session; the guard is now
  `reject_reserved_service_identity`, shared with `[aws-xks-service]`). It may only use a CA whose owner
  granted it `certify` on the CA certificate and private key (fail closed otherwise). Issued certificates are
  stored atomically under the CA owner, who keeps revoke/destroy control. Startup refuses
  `default_username` or `crypto_officer_users` equal to `[enrollment-service]` when EST or SCEP is enabled.
  **Setup action:** `ckms access-rights grant "[enrollment-service]" -i <ca cert uid> certify` and the same
  for the CA private key; when `crypto_officer_users` is configured, also grant it `create`.
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
  - SCEP: an authenticated message cannot be replayed (1 h); the message (signer, `transactionID`,
    `senderNonce`) and, separately, the encrypted CMS envelope are remembered, so a captured request
    re-signed with another key is also refused; every failure after parsing reports `badRequest` (no decryption oracle); a
    renewal signer is checked before the envelope is decrypted; `transactionID` must be a non-empty
    `PrintableString` (letters, digits and `'()+,-./:=?` or space) of at most 128 characters; a signer
    whose key is neither RSA nor EC is refused before a certificate is issued; the `operation` query value
    is no longer echoed; a startup warning is logged when SCEP runs without TLS.
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
  - OpenAPI: EST `simpleenroll` / `simplereenroll` declare their mTLS / Basic security schemes and the new
    `403` / `413` / `429` / `503` replies.

## Documentation

- The audit and server configuration reference now describe the trusted-proxy semantics: `X-Forwarded-For`
  is used only when the direct peer is a trusted proxy, and the client address is its rightmost untrusted
  entry.

## CI

- Windows jobs use the Visual Studio Ninja and fall back to a pinned, SHA-256-verified release
  (`install_ninja.ps1`) instead of
  Chocolatey; the SCEP interop script verifies the pinned `smallstep/pkcs7` `go.sum` hashes; the
  documentation build no longer reaches the `curl | sh` rustup bootstrap.

---

Closes #871

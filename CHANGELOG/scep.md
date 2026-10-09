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
  A baseline template (RSA ≥ 2048, no `CA:TRUE`, validity ≤ 365 days) applies when none is configured.
  The CSR proof of possession is always verified.
- Extended-key-usage entries in X.509 extension files now accept dotted OIDs.
- Added `cosmian_kms_crypto::openssl::{scep_cms, csr_attrs}` (CMS signed attributes through
  the OpenSSL partial-CMS API, challenge-password access).
- Added the `mise run test:scep-interop` (micromdm `scepclient` + Apple `com.apple.security.scep`
  profile) and `mise run test:est-interop` (globalsign `estclient`, TLS and mTLS) black-box tests.
  Note: the stock `scepclient` always encrypts with single DES-CBC, which the server refuses;
  the test builds it with AES-128-CBC selected.
- The CLI (`ckms`) and the Web UI for these endpoints follow in separate pull requests.

### Delegated sub-CA with an HSM-protected key

- Added `POST /certificates/csr`, `ckms certificates generate-csr` and a **Certificates > Generate CSR**
  page: generate a PKCS#10 CSR for a private key held by the KMS. For an HSM key the CSR is signed
  by the HSM through the crypto oracle, so the key can stay non-extractable (`--sensitive`); the
  caller needs the `Sign` permission only. Lets an offline root CA sign the sub-CA CSR.
- `Certify`/`ReCertify` and CRL generation now accept a certificate issuer whose private key is
  in an HSM (non-extractable): the HSM signs the TBS bytes and the result is verified with the
  issuer public key before being stored.
  Behaviour change: this applies to every HSM issuer key, including non-sensitive ones that used to be
  exported; HSM CA keys other than RSA/EC/Ed25519/Ed448 are now rejected, and EC HSM CAs sign with SHA-256.
- The OCSP responder signs with an HSM-protected CA key through the crypto oracle. EST enrollment
  issues through `Certify`, so it works with any HSM CA key. SCEP returns a clear `NotSupported`
  error for a non-extractable (sensitive) HSM CA key instead of failing while trying to load it;
  non-sensitive HSM CA keys keep working as before. Ed25519/Ed448 HSM keys (non-FIPS) are supported
  for CSRs, certificates, CRLs and OCSP. CSR generation refuses a private key that is not Active
  or whose usage mask lacks `Sign`, never follows the user-settable `PublicKeyLink` (it leaked
  attributes of other users' objects), and answers 4xx for keys that cannot sign (X25519, ML-KEM).
- Fixed: the OCSP responder answered `unauthorized` to every request for a sub-CA (issuer hashes
  were computed from the CA's issuer name instead of its subject name).

### Certificate serial number tag

- Certificates created (`Certify`, `ReCertify`) or imported (including PKCS#12) get a system tag
  `_serial=<UPPERCASE HEX>`, so `Locate` by tag finds a certificate by serial number.
- On the first start after upgrade, existing certificates (SQLite, PostgreSQL, MySQL/MariaDB, Redis-Findex)
  are given their `_serial=` tag in a one-time database write, recorded by a completion marker.

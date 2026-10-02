## Security

### SPIRE PKI: `sign-intermediate` now requires a `certify` grant on the CA key

Any Vault token accepted by the auth-verifier could previously obtain an
intermediate CA certificate (`CA:TRUE`) signed by the server's PKI root, because
`POST /v1/{pki_mount}/root/sign-intermediate` never checked what the caller was
allowed to do. The caller's KMS identity (`spire:<AppRole name>`) must now hold
the `certify` access right on the CA private key, otherwise `403` is returned.
The CA key is looked up only among keys **owned** by `default_username` (a key
shared with it by another user is ignored), and CSRs that request their own
`basicConstraints` are rejected so the server-set `pathlen:0` cannot be
overridden.

**Upgrade action:** after provisioning AppRoles, run
`ckms access-rights grant spire:<AppRole name> certify --object-uid <ca-private-key-uid>`.

### SPIRE transit: key names resolve only to keys owned by the caller

Transit `sign`, `GET /keys/{name}`, list and delete looked keys up by tag among all
keys shared with the caller, so another user could share a key under the same name
and have it used for signing. Lookups are now owner-only, and creating a key whose
name already exists is a no-op instead of creating a duplicate.

### JWKS endpoint publishes only keys owned by `default_username`

Keys merely shared with `default_username` or with `*` were published on the
unauthenticated `/.well-known/jwks.json`, letting any user advertise a key they
control. Only owned keys are published now.

### JOSE tag endpoints enforce attribute permissions

`POST`/`DELETE /v1/crypto/keys/{kid}/tags` only required read access, so any grant
(e.g. `encrypt`) allowed rewriting a key's tags, including the `jwks` publishing tag.
They now require `add_attribute` / `delete_attribute`, like the KMIP operations.

### PKCS#11 module: fix buffer overflows in `C_GetAttributeValue` and `C_Encrypt`

Both functions overwrote the caller's buffer length before checking it, so a buffer
smaller than the value was overflowed instead of returning `CKR_BUFFER_TOO_SMALL`.
`C_GenerateKey` now also rejects a null `phKey` with `CKR_ARGUMENTS_BAD`.

### CRL / OCSP: revocation status could be lost, stale or wrong

- `Destroy` keeps a certificate's issuer link and revocation details; CRLs and OCSP
  now keep reporting a revoked-then-destroyed certificate as revoked (RFC 5280 §3.3).
- Certificate serials are random 159-bit values instead of SHA-1(SPKI): `ReCertify`
  no longer reuses the serial of the certificate it replaces (which made the renewed
  certificate appear revoked).
- OCSP response cache: correct expiry (never past `nextUpdate`), keyed by the full
  `CertID`, used only for single-`CertID` requests (cached serials in multi-`CertID`
  requests were answered `unknown`), bounded, and `unknown` responses are not cached.
- OCSP requests must name the configured CA in every `CertID` (`unauthorized` otherwise).
- OCSP `revocationTime` and reason are the recorded ones, matching the CRL.
- Automatic CRL regeneration (after `Revoke` and by the refresh cron) signs on behalf
  of the CA owner; it previously failed silently for revokers without CA-key access.
- Each node re-reads the stored CRL from the database at most every 60 s instead of
  serving its in-memory copy forever.
- OCSP and CRL signing unwrap CA keys wrapped at rest (`key_encryption_key` / user KEK).
- CRLs fetched during `Validate`/`Import` are refreshed after 5 minutes or once expired
  (an expired cached CRL previously failed validation until restart), and the cache
  lock is no longer held across network fetches.

### CRL fetching: SSRF check bypass via `kms_public_url` prefix match

The "own URL" exemption from the CRL SSRF check compared raw strings, so
`http://kms.corp@169.254.169.254/…` or `http://kms.corp.attacker.tld/` bypassed it. The
check now compares parsed scheme, host, port and path and rejects URLs with credentials.

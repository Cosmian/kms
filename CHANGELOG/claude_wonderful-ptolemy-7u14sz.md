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

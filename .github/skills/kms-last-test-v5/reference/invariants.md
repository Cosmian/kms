# KMS Domain Invariants

These are the semantic invariants the agent must treat as always-true unless the PR explicitly changes them. Any scenario that contradicts one of these is a **critical finding**.

## Contents

- [Key lifecycle](#key-lifecycle)
- [Security](#security)
- [Access control](#access-control)
- [Protocol](#protocol)
- [Concurrency](#concurrency)
- [JOSE REST API and JWKS](#jose-rest-api-and-jwks)

---

## Key lifecycle

- A key in `PreActive` state **cannot** encrypt, decrypt, sign, or verify
- A key in `Deactivated` or `Compromised` state **cannot** be used for new encrypt/wrap operations
- A `Destroyed` key **cannot** be retrieved, activated, or used in any operation
- Wrapping a key with itself must be rejected
- State transitions follow KMIP 2.1: `PreActive → Active → Deactivated → Compromised → Destroyed` (plus `Destroyed_Compromised`)

---

## Security

- Key material must **never** appear in logs, error messages, or HTTP response bodies (except in legitimate Export/Get responses)
- All administrative operations must be reflected in the audit log with caller identity and timestamp
- Operations gated behind `non-fips` must not be reachable when the server is built without that feature
- Algorithm allowlists in KMIP policy must be enforced — a policy forbidding RSA-2048 must reject RSA-2048 key creation

---

## Access control

- A user without explicit access cannot perform operations on another user's objects
- `default_username` is used only when no authentication is configured
- `non_revocable_key_id` keys cannot have their access revoked
- Granting access is an owner-only operation

---

## Protocol

- `POST /kmip/2_1` with empty body returns 422, not 404 or 500
- Unknown KMIP operations return `RouteNotFound` / `Unsupported_Operation`
- KMIP responses always include `ProtocolVersion`, `TimeStamp`, `BatchCount`
- Enterprise endpoints conform to vendor specs (AWS SigV4, Azure mTLS, Google JWT)

---

## Concurrency

- Concurrent operations on the same key must not produce inconsistent state
- No partial rotation, no duplicate IDs
- Database transactions must be isolated properly across backends

---

## JOSE REST API and JWKS

- `POST /v1/crypto/keys` with key material fields (`k`, `d`) imports; without them, generates. The two code paths must not be confused.
- `DELETE /v1/crypto/keys/{kid}` must revoke-then-destroy. Using a deleted key in any subsequent `/v1/crypto/*` call must fail with `404 Not Found`.
- JWE decryption failures must return the same `{"error":"DecryptionFailed","description":"Decryption failed"}` regardless of root cause, per RFC 7516 §11.5.
- `POST /v1/crypto/sign` must return a detached JWS protected header and signature; the payload must **not** appear in the response.
- `POST /v1/crypto/verify` must use the `kid` in the protected header, not an independently supplied one. A `kid` pointing to a different key type than the `alg` must fail.
- `/.well-known/jwks.json` returns `404` when `jwks_endpoint_enabled = false`.
- `/.well-known/jwks.json` must never return private key material — only public coordinates (`x`, `y`, `n`, `e`).
- Auto-tagging (`KMS_JWKS_ENDPOINT_AUTO_TAG=true`, the default): every key pair created via `POST /v1/crypto/keys` must receive the `"jwks"` tag. When disabled, newly created keys must **not** be auto-tagged.
- System tags (prefix `_`) must be rejected with `400` by `POST`/`DELETE /v1/crypto/keys/{kid}/tags`.
- `EdDSA` (Ed25519 / `OKP` key type) must only be reachable in `non-fips` builds; a FIPS build must reject `kty=OKP` at key creation with a clear error.

# Server allocation reduction across request and lifecycle paths

## Breaking Changes

### KMIP

- `cosmian_kmip`: `TTLV.tag` and `KmipEnumerationVariant.name` are now `Cow<'static, str>` instead of `String`. Serializers and the binary decoder borrow static tag names; the JSON deserializer stores known KMIP 2.1 tags as borrowed values but still allocates each tag `String` while parsing, so the JSON request path saves nothing from this change. Replace `x.tag.as_str()` with `&*x.tag` or `x.tag.as_ref()`, and use `.into()` when building a `TTLV`.
- `POST /kmip/2_1` now takes the body directly as `Bytes` instead of decoding as `String`. Invalid UTF-8 returns HTTP 422 (`InvalidRequest`) instead of HTTP 400, matching `/kmip`.
- `POST /kmip/2_1` requires `Content-Type: application/json` (parameters such as `charset` allowed); other content types return HTTP 422 (COSMIAN-2026-039).
- Crypto operations (`Encrypt`, `Decrypt`, `Sign`, `MAC`, ...) on a key the caller has no grant on now fail with `Item_Not_Found`, like a missing key, instead of `Permission_Denied`; callers holding a grant on the key still get the permission error (COSMIAN-2026-037).
- KMIP requests above 10,000 batch items fail with `Invalid_Message`; `DeriveKey` PBKDF2 with fewer than 1 or more than 10,000,000 iterations (0 now fails with `Invalid_Request` instead of an OpenSSL error) and RSA key generation above 16,384 bits are rejected (COSMIAN-2026-036).

### KMIP socket server

- The socket server (port 5696) closes connections idle for more than 120 s and aborts TLS handshakes longer than 10 s; clients that keep a connection open between requests must reconnect. At most 1,024 connections are accepted concurrently (COSMIAN-2026-032).

### REST

- `/v1/crypto/*` and `/tokenize/*` no longer answer CORS requests from arbitrary origins: like the KMIP scope, they accept same-origin requests and the origins listed in `cors_allowed_origins` (COSMIAN-2026-039).

### JOSE

- Protected header parsing in `/v1/crypto/decrypt`, `/v1/crypto/verify`, and `/v1/crypto/keys/unwrap` now strictly requires a JSON object (RFC 7515 §5.2); JSON arrays are rejected with HTTP 400. Duplicate header parameters now fail with HTTP 400 (`duplicate field`) rather than taking the last value.

## Security

- `Get`/`Export` of a key with `Fresh = true` could write the auto-unwrapped key back to the database when `default_unwrap_types` was set. The write-back now uses the stored object. See `SECURITY.md` (COSMIAN-2026-031).
- KMIP socket server: connection limit, handshake and idle timeouts, and messages above 64 MiB rejected before allocation (COSMIAN-2026-032).
- KMIP socket server: client certificate CNs get the same checks as HTTP mTLS (no empty, `*` or reserved AWS XKS CN; whitespace trimmed) (COSMIAN-2026-033).
- JWT: each identity provider, whitelisted Google CSE KACLS and the Google CSE token issuers now have their own JWKS; a token is only verified against the keys of its issuer (COSMIAN-2026-034).
- Google CSE `rewrap`: the call to the original KACLS no longer follows redirects, IPv6 and IPv4-mapped literals are checked, and the host is resolved, checked and pinned (COSMIAN-2026-035).
- Limits on batch size, PBKDF2 iterations and RSA modulus size (COSMIAN-2026-036).
- Crypto operations no longer reveal the existence or state of keys the caller may not use (COSMIAN-2026-037).
- The AWS XKS SigV4 secret access key is masked in the startup (`info`) and debug configuration logs (COSMIAN-2026-038).
- `/kmip/2_1` content-type check and allowed-origins CORS on `/v1/crypto` and `/tokenize` (COSMIAN-2026-039).
- Startup warnings when no authentication method, no `key_encryption_key` or no `rate_limit_per_second` is configured.
- AWS XKS: the SigV4 access key ID is compared in constant time.
- CI: `azure/setup-helm` and `medyagh/setup-minikube` are pinned by commit SHA.

## Refactor

- `ObjectWithMetadata::into_parts`; `Database::retrieve_objects` returns `Arc<ObjectWithMetadata>`; `retrieve_object_for_operation` returns `Arc<ObjectWithMetadata>` and clones only when it mutates.
- Borrow keys (`key_bytes_ref`) in symmetric decrypt, FPE, MAC, split/join key and derive key; move instead of clone in Activate, Revoke, Get/Export, key-pair creation and the attribute operations.
- SQLite: queries converted once, objects serialized before the writer closure. PostgreSQL: `Json<T>` reads/writes. MySQL: no intermediate `Value`.
- Audit: `AuditResult::as_canonical_str` returns `Cow`, the row hash is streamed (canonical bytes unchanged).
- Middlewares, JOSE headers, AWS XKS SigV4 body, Google CSE and the rotate-name cache avoid per-request copies.

### Performance

Measured once per tree on debug builds (single sample, counting allocator), base commit `20274da5b` vs this branch:

| Case | Allocations | Bytes |
|---|---|---|
| 4 KiB `Encrypt` decode+encode, binary TTLV | 76 → 32 | 28,391 → 27,838 |
| 4 KiB `Encrypt` decode+encode, JSON TTLV | 101 → 69 | 61,228 → 60,837 |
| `retrieve_object_for_operation`, cached key | 36 → 3 | 42,823 → 13,264 |
| SQLite `atomic(UpdateObject)` | 57 → 39 | 12,713 → 7,391 |

Other changes in this branch were not measured.

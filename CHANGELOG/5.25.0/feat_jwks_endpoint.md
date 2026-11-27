## Features

### API

- Add `GET /.well-known/jwks.json` public-key discovery endpoint (RFC 7517 JWKS)
  - Unauthenticated; only registered when `jwks_endpoint_enabled = true`
  - Returns all public keys tagged `"jwks"` that are in `Active` or `Deactivated` state (rotation-overlap support)
  - Supported key types: RSA (RS256 / RS384 / RS512), EC P-256/P-384/P-521 (ES256 / ES384 / ES512), Ed25519 (non-FIPS only)
  - Response content-type: `application/jwk-set+json`; `Cache-Control: no-store`
  - ETag + HTTP 304 conditional-GET caching
  - `X-JWKS-Truncated: true` response header when the eligible key count exceeds `jwks_endpoint_max_keys`
- Auto-tag key pairs created via `POST /v1/crypto/keys` with the `"jwks"` tag so they appear immediately in the JWKS document (opt-out per key by removing the tag; opt-out globally with `jwks_endpoint_auto_tag = false`)

### Configuration

Three new server config fields / CLI flags / environment variables:

| Flag                       | Env var                      | Default | Description                                        |
| -------------------------- | ---------------------------- | ------- | -------------------------------------------------- |
| `--jwks-endpoint-enabled`  | `KMS_JWKS_ENDPOINT_ENABLED`  | `false` | Enable the JWKS endpoint                           |
| `--jwks-endpoint-max-keys` | `KMS_JWKS_ENDPOINT_MAX_KEYS` | `50`    | Maximum keys per JWKS response                     |
| `--jwks-endpoint-auto-tag` | `KMS_JWKS_ENDPOINT_AUTO_TAG` | `true`  | Auto-tag REST-created key pairs for JWKS inclusion |

### Documentation

- Add `integrations/jose/jwks_endpoint.md` — JWKS endpoint reference with quickstart, sequence diagram, key selection, and rotation guide
- Remove `integrations/jose/jwks_key_selection.md` (content merged into the new page)
- Update `mkdocs.yml` navigation to reflect the new page structure

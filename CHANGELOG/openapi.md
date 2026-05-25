## Features

### Web UI

- Add `/openapi.yaml` endpoint serving the OpenAPI 3.1 spec for the KMS server, embedded at compile time via `include_str!`
- Add `/swagger-ui` endpoint serving a locally-vendored Swagger UI (swagger-ui-dist 5.18.2) with no external CDN dependency and a strict Content-Security-Policy header

### Google CSE

- Register `POST /google_cse/wrapprivatekey` endpoint (stub) in the Google CSE scope — was defined but not reachable

### OpenAPI spec

- Trim `info.description` to minimalist (Authentication section only)
- Use relative server URL (`url: /`) so Swagger UI always uses the current origin, fixing CORS errors when `http_hostname` is a bind address like `0.0.0.0`
- When `kms_public_url` is configured, inject the absolute URL into the served spec

## Testing

- Add Playwright E2E test suite `ui/tests/e2e/swagger.spec.ts` covering:
    - HTTP contract for `/openapi.yaml` (status, content-type, security headers, size bounds)
    - OpenAPI spec structure (version declaration, all expected tags, all documented paths, component schemas)
    - HTTP contract for `/swagger-ui` (status, content-type, CDN SRI hashes, CSP header)
    - Browser rendering via Playwright (Swagger UI mounts, title renders, tag sections visible, expand on click)
    - Cross-validation of live server responses against the documented spec for all public endpoints

## Bug Fixes

- Fix `operation_types` enum values in `openapi.yaml`: were PascalCase (`Get`, `Encrypt`) but server expects lowercase (`get`, `encrypt`) due to `#[serde(rename_all = "lowercase")]` on `KmipOperation`
- Add reusable `KmipOperation` enum schema with all 24 valid values; use `$ref` in `Access`, `AccessRightsObtainedResponse`, and `UserAccessResponse` schemas
- Fix `/access/create` response schema in `openapi.yaml`: was `type: object` (no properties), now documents `{has_create_permission: boolean}`
- Fix `/access/privileged` response schema in `openapi.yaml`: was `type: object` (no properties), now documents `{has_privileged_access: boolean}`
- Fix `POST /v1/crypto/keys` error response in `openapi.yaml`: document `400` (Bad Request) instead of missing, matching actual server behaviour for JSON deserialization errors
- Fix swagger E2E test assertions: KMIP TTLV-as-JSON uses `ResultStatus:"Success"` (not `"OperationSuccess"`); server accepts all KMIP versions (1.0–2.1) for backward compatibility; `POST /v1/crypto/keys {}` returns `400` (not `422`)

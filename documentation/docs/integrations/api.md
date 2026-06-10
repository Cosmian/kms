# API

The Eviden KMS server implements the JSON TTLV profile of the KMIP 1.x and 2.x specifications.
In addition, the server exposes a few additional endpoints for authorization operations.

## Calling the KMIP API

This API is documented in the [KMIP section](../kmip_support/json_ttlv_api.md) of this manual.

### Calling the authorization API

This API is documented in the [authorization section](../configuration/authorization.md) of this manual.

## Authentication

The Eviden server supports various authorization mechanisms: see
the [authentication section](../configuration/authentication.md)
of this manual for details. When authenticating using JWT, an HTTP `Authorization` header must be
passed with the JWT token as a bearer token.

For example: `Authorization: Bearer <JWT_TOKEN>`

## REST Native Crypto API

In addition to the KMIP protocol, the server exposes a lightweight JOSE-compatible REST API
under `/v1/crypto` for encrypt, decrypt, sign, verify, and MAC operations.
See the [REST Native Crypto API](jose/jose_api.md) page for full documentation.

## OpenAPI specification and interactive documentation

The KMS server exposes its full API as an [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0)
specification and serves an interactive Swagger UI browser directly from the server binary.

| Endpoint | Description |
|---|---|
| `GET /openapi.yaml` | Full OpenAPI 3.1 schema in YAML format |
| `GET /swagger` | Interactive Swagger UI (locally served, authentication required) |

### Using the Swagger UI

Navigate to `<server_url>/swagger` in a browser. The page serves Swagger UI assets
directly from the KMS server binary (no external CDN dependency) and applies a strict
`Content-Security-Policy` header with `frame-ancestors 'none'` for clickjacking protection.

```text
https://<your-kms-host>:9998/swagger
```

The UI displays all documented operations grouped by tag:

- **KMIP** — TTLV-over-HTTP (`POST /kmip/2_1`, `POST /kmip/1_4`)
- **REST Crypto API** — key lifecycle, encrypt/decrypt/sign/verify/MAC under `/v1/crypto`
- **Server** — health, version, server-info
- **Access control** — grant, revoke, list, and check permissions
- **HSM** — HSM status
- **Download** — CLI download endpoint

### Downloading the spec

```bash
curl -O https://<your-kms-host>:9998/openapi.yaml
```

The downloaded YAML can be imported into any OpenAPI-compatible tooling (Postman,
Insomnia, code generators, etc.).

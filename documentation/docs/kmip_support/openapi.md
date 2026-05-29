# OpenAPI Specification and Swagger UI

The Eviden KMS server publishes its complete API as an [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0)
specification and serves an interactive Swagger UI browser directly from the server binary.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/openapi.yaml` | `GET` | Full OpenAPI 3.1 schema in YAML format |
| `/swagger` | `GET` | Interactive Swagger UI (HTML page, locally served) |

No authentication is required to access either endpoint; the UI itself uses the configured authentication mechanism to authorize API calls made through the browser.

## Using the Swagger UI

Navigate to `<server_url>/swagger` in a browser.

```text
https://<your-kms-host>:9998/swagger
```

The page displays all documented operations grouped by tag:

| Tag | Operations |
|---|---|
| **KMIP** | TTLV-over-HTTP via `POST /kmip/2_1` and `POST /kmip/1_4` |
| **REST Crypto API** | Encrypt, decrypt, sign, verify, and MAC under `/v1/crypto` |
| **Server** | Health, version, and server-info endpoints |
| **Access control** | Grant, revoke, list, and check object permissions |
| **HSM** | HSM status and diagnostics |
| **Download** | CLI binary download endpoint |

### Authentication in the UI

When the KMS is configured with JWT bearer authentication, click the **Authorize** button
in the Swagger UI and enter your token. The UI will send it as an `Authorization: Bearer <token>`
header on every subsequent request.

## Downloading the spec

```bash
curl -O https://<your-kms-host>:9998/openapi.yaml
```

The downloaded YAML can be imported into any OpenAPI-compatible tooling:

- **[Postman](https://www.postman.com/)** — `Import > OpenAPI` to generate a full collection with example requests.
- **[Insomnia](https://insomnia.rest/)** — `Import > OpenAPI 3.0`.
- **[openapi-generator](https://openapi-generator.tech/)** — generate a typed client in any language:

  ```bash
  openapi-generator-cli generate \
    -i openapi.yaml \
    -g python \
    -o ./kms-client-python
  ```

- **[swagger-codegen](https://swagger.io/tools/swagger-codegen/)** — similar code-generation approach.

## Security

All assets (JavaScript bundle and stylesheet) are served directly from the KMS binary — there is **no external CDN dependency**. The server is therefore fully usable in air-gapped environments.

The Swagger UI page is protected by the following HTTP response headers:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'` |

The `frame-ancestors 'none'` directive prevents the page from being embedded in an `<iframe>`, protecting against clickjacking.

## Relationship to the JSON TTLV API

The OpenAPI spec documents the HTTP transport layer of the KMS API. The KMIP operations
themselves are sent as JSON TTLV payloads in the body of `POST /kmip/2_1` or `POST /kmip/1_4`.
See [The JSON TTLV KMIP API](./json_ttlv_api.md) for the full description of the KMIP message format.

## Spec version and server URL

The `version` field in the OpenAPI YAML is injected dynamically to match the running KMS
binary version. When the `kms_public_url` configuration option is set, the `servers[].url`
field is replaced with the configured public URL, making the downloaded spec self-contained
for use in external tooling.

See [Configuration file](../configuration/server_configuration_file.md) for the
`kms_public_url` option.

# API

The Cosmian KMS server implements the JSON TTLV profile of the KMIP 1.x and 2.x specifications.
In addition, the server exposes a few additional endpoints for authorization operations.

## Calling the KMIP API

This API is documented in the [KMIP section](./kmip/json_ttlv_api.md) of this manual.

### Calling the authorization API

This API is documented in the [authorization section](./authorization.md) of this manual.

## Authentication

The Cosmian server supports various authorization mechanisms: see
the [authentication section](./authentication.md)
of this manual for details. When authenticating using JWT, an HTTP `Authorization` header must be
passed with the JWT token as a bearer token.

For example: `Authorization: Bearer <JWT_TOKEN>`

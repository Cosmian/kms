# API

The Cosmian KMS server implements the JSON TTLV profile of the KMIP 1.x and 2.x specifications.
In addition, the server exposes a few additional endpoints for authorization operations.

## Calling the KMIP API

This API is documented in the [KMIP section](../kmip_support/json_ttlv_api.md) of this manual.

### Calling the authorization API

This API is documented in the [authorization section](../configuration/authorization.md) of this manual.

## Authentication

The Cosmian server supports various authorization mechanisms: see
the [authentication section](../configuration/authentication.md)
of this manual for details. When authenticating using JWT, an HTTP `Authorization` header must be
passed with the JWT token as a bearer token.

For example: `Authorization: Bearer <JWT_TOKEN>`

## REST Native Crypto API

In addition to the KMIP protocol, the server exposes a lightweight JOSE-compatible REST API
under `/v1/crypto` for encrypt, decrypt, sign, verify, and MAC operations.
See the [REST Native Crypto API](rest_crypto_api.md) page for full documentation.

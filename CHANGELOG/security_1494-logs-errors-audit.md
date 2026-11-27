## Bug Fixes

### Hardening

- Startup configuration dumps no longer print proxy credentials (URL password, basic-auth password, custom auth header), the Redis URL password or the Google CSE migration key ([#1494](https://github.com/Cosmian/kms/issues/1494))
- The KMIP socket server and the `/google_cse`, `/ms_dke`, `/aws` and `/azureekm` scopes are now audited when audit logging is enabled, requests refused by the AWS XKS `SigV4` middleware are recorded, unnamed requests are recorded as `METHOD /route/pattern` with the key taken from the route, and the server logs a `SECURITY:` warning at startup when audit logging is disabled ([#1494](https://github.com/Cosmian/kms/issues/1494))
- 5xx responses keep carrying the full error detail, exactly as before: the generic body and `X-Request-Id` header proposed for finding F-029 of [#1494](https://github.com/Cosmian/kms/issues/1494) are not part of this change

## Build

- The `cosmian_kms_server`, workspace non-FIPS and manual FIPS pre-commit test hooks now build the server with the `insecure` feature, required by the server unit tests

---

Refs #1494

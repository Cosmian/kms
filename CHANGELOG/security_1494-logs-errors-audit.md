## Bug Fixes

### Hardening

- Startup configuration dumps no longer print proxy credentials (URL password, basic-auth password, custom auth header), the Redis URL password or the Google CSE migration key ([#1494](https://github.com/Cosmian/kms/issues/1494))
- Every 5xx response now has the body `Internal Server Error (request id: <uuid>)` and an `X-Request-Id` header; the full error is only written to the server log under the same id. This covers KMIP, Google CSE, AWS XKS, Azure EKM, SPIRE, KV, JOSE, SCEP, UI authentication and audit-reject responses, and keeps their JSON schemas. Clients should quote the request id when reporting an error ([#1494](https://github.com/Cosmian/kms/issues/1494))
- The KMIP socket server and the `/google_cse`, `/ms_dke`, `/aws` and `/azureekm` scopes are now audited when audit logging is enabled, requests refused by the AWS XKS `SigV4` middleware are recorded, unnamed requests are recorded as `METHOD /route/pattern` with the key taken from the route, and the server logs a `SECURITY:` warning at startup when audit logging is disabled ([#1494](https://github.com/Cosmian/kms/issues/1494))

---

Closes #1494

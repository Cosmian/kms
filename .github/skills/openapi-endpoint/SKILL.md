---
name: openapi-endpoint
description: Implement a new REST endpoint following sync rule 4.2: handler, routes/mod.rs, start_kms_server.rs with LIFO middleware, openapi.yaml, validation tests. Use when adding a new REST endpoint.
---

# REST Endpoint Implementation (Rule 4.2)

Implement a new REST endpoint following the full synchronization rule 4.2 for this codebase.

## When to Use

- Adding a new REST endpoint (non-KMIP, e.g. health check, cloud provider route, management API)
- Modifying an existing REST endpoint's path, method, or auth requirements
- Adding a new enterprise route (AWS XKS, Azure EKM, Google CSE, MS DKE)

## Step 1 — Identify the Endpoint

Gather from the user (or infer from context):

- HTTP method: GET / POST / PUT / PATCH / DELETE
- Path: `/api/v1/...`
- Authentication required: yes/no, which auth method (JWT, mTLS, API token, none)
- Request body schema (if POST/PUT/PATCH)
- Response schema
- Which existing routes module to add it to, or whether a new module is needed

## Step 2 — Implement the Handler

Create or extend `crate/server/src/routes/<module>/`:

```rust
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::core::kms::KMS;
use crate::result::KResult;

#[derive(Debug, Deserialize)]
pub struct MyRequest {
    // request fields
}

#[derive(Debug, Serialize)]
pub struct MyResponse {
    // response fields
}

pub async fn my_handler(
    kms: web::Data<KMS>,
    request: web::Json<MyRequest>,
) -> KResult<HttpResponse> {
    trace!("my_handler: {:?}", request);

    // implementation

    debug!("my_handler: success");
    Ok(HttpResponse::Ok().json(MyResponse { /* ... */ }))
}
```

Handler rules:

- Use `KResult<HttpResponse>` as return type (maps to actix error responses)
- Log with `trace!` at entry, `debug!` on success, `warn!`/`error!` on failures
- Keep the function ≤ 50 lines; extract helpers for complex logic
- Never `.unwrap()` — always use `?` propagation

## Step 3 — Declare in routes/mod.rs

In `crate/server/src/routes/mod.rs`, add:

```rust
pub mod my_module;
```

## Step 4 — Register in start_kms_server.rs

In `crate/server/src/start_kms_server.rs`, find the correct `App` configuration block and add the scope.

**Critical: Actix-web middleware is applied in LIFO order** (last `.wrap()` runs first on request). The standard stack is:

```rust
web::scope("/api/v1/my-endpoint")
    .service(web::resource("").route(web::post().to(my_module::my_handler)))
    .wrap(EnsureAuth::new(auth_is_configured))
    // auth extractors added last (run first):
    .wrap(Condition::new(use_api_token_auth, ApiTokenAuth::default()))
    .wrap(Condition::new(use_cert_auth, SslAuth::default()))
    .wrap(Condition::new(use_jwt_auth, JwtAuth::new(...)))
    .wrap(Cors::default())  // outermost — handles preflight
```

For **public endpoints** (no auth required), omit the auth middleware chain and `EnsureAuth`.

For **enterprise routes** (cloud providers) that use mTLS only, see `azure_ekm` scope for the pattern.

If the endpoint is non-FIPS-only, wrap the entire registration:

```rust
#[cfg(feature = "non-fips")]
{
    app = app.service(
        web::scope("/api/v1/my-endpoint")
            // ...
    );
}
```

## Step 5 — Update openapi.yaml

In `crate/server/documentation/openapi.yaml`, add the path:

```yaml
paths:
  /api/v1/my-endpoint:
    post:
      summary: Short description
      operationId: myEndpoint
      tags:
        - MyCategory
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/MyRequest'
      responses:
        '200':
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/MyResponse'
        '401':
          description: Unauthorized
        '403':
          description: Forbidden
      security:
        - BearerAuth: []   # or ApiKeyAuth, or []

components:
  schemas:
    MyRequest:
      type: object
      required: [field1]
      properties:
        field1:
          type: string
    MyResponse:
      type: object
      properties:
        result:
          type: string
```

## Step 6 — Validate via OpenAPI Tests

Run the OpenAPI validation tests to confirm the spec is consistent with the implementation:

```bash
cargo test -p test_kms_server openapi_validation
```

Fix any schema mismatch before proceeding.

## Step 7 — Write Handler Tests

Add a unit test or integration test for the new handler. At minimum:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn test_my_handler_success() {
        // test success path
    }

    #[actix_web::test]
    async fn test_my_handler_unauthorized() {
        // test auth rejection path
    }
}
```

## Checklist

- [ ] Handler implemented in `crate/server/src/routes/<module>/`
- [ ] `crate/server/src/routes/mod.rs` — `pub mod <module>;` declared
- [ ] `crate/server/src/start_kms_server.rs` — scope registered with correct LIFO middleware stack
- [ ] Non-FIPS route wrapped in `#[cfg(feature = "non-fips")] { ... }` if applicable
- [ ] `crate/server/documentation/openapi.yaml` — path, schemas, security tags added
- [ ] `cargo test -p test_kms_server openapi_validation` passes
- [ ] Handler tests written (success + auth failure paths)
- [ ] `cargo clippy-all` passes

## Bug Fixes

### JWT authentication

- Fix server worker panic on the first JWT-authenticated request: `jsonwebtoken` 10.x requires
  an explicit crypto-backend feature (`rust_crypto` or `aws_lc_rs`); added `rust_crypto` to both
  the workspace and CLI `jsonwebtoken` dependencies
- Fix `401 No authentication provided` when the JWT token carries an `aud` claim but the server
  has no expected audience configured: `jsonwebtoken` 10.x now rejects such tokens with
  `InvalidAudience` unless `validate_aud` is explicitly disabled; the server's JWT validation now
  sets `validate_aud = false` when no audience restriction is configured

## Testing

- Add `start_default_test_kms_server_with_jwt_auth` to `test_kms_server` crate for reuse across
  integration tests that require a JWT-authenticated server
- Export `AUTH0_TOKEN` from `test_kms_server` crate
- Add `test_jwt_authentication_no_panic` regression test in the `ckms` crate that exercises the
  full JWT authentication path end-to-end

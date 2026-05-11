## Bug Fixes

### Google CSE

- Fix Google CSE authorization token validation failure with jsonwebtoken 10.x: the `aud` claim in Google CSE tokens (e.g. `"cse-authorization"`) was rejected because `decode_jwt_authorization_token` did not configure the expected audience on the `Validation` struct, causing jsonwebtoken to reject all tokens carrying an `aud` claim with `InvalidAudience` ([#947](https://github.com/Cosmian/kms/issues/947))
- Fix KACLS migration `rewrap`/`privilegedunwrap` flow: `list_jwt_configurations` now sets the expected audience to `"kacls-migration"` for whitelist KACLS configs, so `validate_authentication_token` calls `set_audience()` instead of relying on `validate_aud = false`, which makes jsonwebtoken 10.x accept migration tokens on the receiving KACLS ([#947](https://github.com/Cosmian/kms/issues/947))
- Add JWKS refresh-retry to `validate_cse_authentication_token`: when all JWT configs fail, refresh the JWKS and retry once, matching the same pattern used by the auth middleware. This prevents permanent validation failures when a KACLS JWKS entry is evicted during a periodic refresh failure ([#947](https://github.com/Cosmian/kms/issues/947))
- Add non-regression tests for CSE authorization token audience validation and KACLS migration authentication flow

Closes #947

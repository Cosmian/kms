pub(super) mod access_control;
pub(super) mod cors_config;
pub(super) mod lifecycle;
pub(super) mod privilege_bypass;
pub(super) mod uid_injection;
// SSRF redirect tests for JWKS fetching live in
// crate/server/src/middlewares/jwt/jwks.rs (sr01_*, sr02_*)
// because `parse_jwks` is module-private to that crate.

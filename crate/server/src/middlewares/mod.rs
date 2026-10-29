mod audit;
pub(crate) use audit::{
    AuditMiddleware, BatchItemAuditContext, KmipAlgorithm, KmipBatchOperations, KmipObjectUid,
    KmipOperationName, forwarded_for, resolve_client_ip,
};

mod tls_auth;
pub(crate) use cosmian_kms_interfaces::UserId;
pub(crate) use tls_auth::{
    PeerCertificate, extract_peer_certificate, is_enrollment_issued, tls_auth_fn,
    user_from_client_certificate, verified_issuers,
};

mod api_token;
pub(crate) use api_token::api_token_middleware;

mod auth_verifier;
#[cfg(test)]
pub(crate) use auth_verifier::test_helpers as auth_verifier_test_helpers;
pub(crate) use auth_verifier::{
    AUTH_VERIFIER_SESSION_COOKIE, AuthVerifier, authenticate_auth_verifier_session_cookie,
    verify_auth_verifier_jwt_subject,
};

mod ensure_auth;
pub(crate) use ensure_auth::ensure_auth_middleware;

mod jwt;
pub(crate) use jwt::{
    JwksManager, JwtConfig, JwtTokenHeaders, UserClaim, jwt_auth_middleware, validate_jwt_svid,
};

mod rate_limiter;
pub(crate) use rate_limiter::{RateLimiterConfig, RateLimiterMiddleware};

mod otel_http_middleware;
pub(crate) use otel_http_middleware::otel_http_metrics_middleware;

mod spire_token;
pub(crate) use spire_token::{
    SpireTokenCache, spire_token_middleware, vault_token_optional_middleware,
};

mod session_auth;
use actix_web::{dev::ServiceRequest, http::header};
pub(crate) use session_auth::SessionAuth;

use crate::{
    error::KmsError,
    result::KResult,
    routes::{aws_xks::AWS_XKS_SERVICE_USER, enrollment::ENROLLMENT_SERVICE_USER},
};

/// Extract a Bearer token from the `Authorization` header of a request.
///
/// Returns the raw token string (trimmed) on success, or an `Unauthorized`
/// error when the header is missing, malformed, or empty.
///
/// Shared by the API-token, Auth Verifier server, and any future Bearer-based
/// middleware so the parsing logic stays in one place.
pub(crate) fn extract_bearer_token(req: &ServiceRequest) -> KResult<&str> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let mut parts = auth_header.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token = parts.next().unwrap_or("").trim();

    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(KmsError::Unauthorized(
            "missing or malformed Authorization header (expected Bearer token)".to_owned(),
        ));
    }
    Ok(token)
}

/// Identifies which authentication method was used for a request.
///
/// Stored alongside [`AuthenticatedUser`] so that audit logs and operators
/// can distinguish SPIRE, OIDC, API-token, mTLS, session, and default-user
/// authentication after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMethod {
    /// SPIRE / Vault-compatible `X-Vault-Token` validation
    SpireToken,
    /// Standard OIDC / `IdP` JWT (with `kid`)
    OidcJwt,
    /// SPIFFE JWT-SVID (no `email` claim; identity taken from `sub = spiffe://...`)
    JwtSvid,
    /// Cosmian Auth Verifier JWT (no `kid`)
    AuthVerifierJwt,
    /// Cosmian Auth Verifier `_ea_` session cookie (browser SAML single sign-on)
    AuthVerifierSession,
    /// Static API token (Bearer)
    ApiToken,
    /// mTLS client certificate
    Mtls,
    /// Server-side session cookie (UI browser)
    Session,
    /// No authentication configured; `default_username` injected
    DefaultUser,
}

/// Represents an authenticated user
///
/// This struct is stored in the request extensions after successful
/// authentication and can be used by request handlers.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedUser {
    /// The authenticated username
    pub username: UserId,
    /// Which authentication method was used
    pub auth_method: AuthMethod,
}

/// Internal service identities that must stay unreachable through any externally-derived
/// authentication path (OIDC/SVID/Auth Verifier JWT, mTLS CN, SPIRE token, UI session).
const RESERVED_SERVICE_IDENTITIES: [&str; 2] = [AWS_XKS_SERVICE_USER, ENROLLMENT_SERVICE_USER];

/// Whether `name` would resolve to the `reserved` identity in the database: `MySQL` / `MariaDB`
/// compare the `userid` / `owner` columns with their default `_ci` collation (case-insensitive),
/// and the default `MariaDB` `PAD SPACE` collation also ignores trailing spaces.
pub(crate) fn names_reserved_identity(name: &str, reserved: &str) -> bool {
    name.trim_end_matches(' ').eq_ignore_ascii_case(reserved)
}

/// Reject a reserved service identity on externally-derived auth paths.
pub(crate) fn reject_reserved_service_identity(username: &UserId) -> KResult<()> {
    if RESERVED_SERVICE_IDENTITIES
        .iter()
        .any(|reserved| names_reserved_identity(username.as_str(), reserved))
    {
        return Err(KmsError::Unauthorized(format!(
            "reserved service identity `{username}` cannot be used as an externally \
             authenticated username"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_reserved_service_identity_rejects_every_reserved_username() {
        for reserved in RESERVED_SERVICE_IDENTITIES {
            assert!(matches!(
                reject_reserved_service_identity(&UserId::from(reserved)),
                Err(KmsError::Unauthorized(_))
            ));
        }
    }

    #[test]
    fn reject_reserved_service_identity_rejects_case_and_padding_variants() {
        for reserved in RESERVED_SERVICE_IDENTITIES {
            for variant in [
                reserved.to_ascii_uppercase(),
                reserved
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_ascii_uppercase()
                        } else {
                            c
                        }
                    })
                    .collect(),
                format!("{reserved}  "),
            ] {
                assert!(
                    matches!(
                        reject_reserved_service_identity(&UserId::from(variant.as_str())),
                        Err(KmsError::Unauthorized(_))
                    ),
                    "{variant}"
                );
            }
        }
    }

    #[test]
    fn reject_reserved_service_identity_accepts_regular_username() {
        assert!(matches!(
            reject_reserved_service_identity(&UserId::from("alice@example.com")),
            Ok(())
        ));
    }
}

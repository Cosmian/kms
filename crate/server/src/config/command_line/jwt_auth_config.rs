use std::collections::HashMap;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{config::IdpConfig, error::KmsError};

// Support for JWT token inspired by the doc at : https://cloud.google.com/api-gateway/docs/authenticating-users-jwt
// and following pages

#[derive(Debug, Default, Args, Deserialize, Serialize)]
#[serde(default)]
pub struct JwtAuthConfig {
    /// DEPRECATED: use the Idp config section instead.
    /// JWT authentication issuer URI
    ///
    /// For Auth0, this would be like: `https://<your-tenant>.<region>.auth0.com/`
    /// For Google, this would be: `https://accounts.google.com`
    ///
    /// This argument can be repeated to configure multiple identity providers.
    #[clap(long, env = "KMS_JWT_ISSUER_URI", action = clap::ArgAction::Append)]
    pub jwt_issuer_uri: Option<Vec<String>>,

    /// DEPRECATED: use the Idp config section instead.
    /// JWT authentication JWKS URI
    ///
    /// Url that exposes the `OpenID` Connect provider JSON Web Key Set.
    /// If not specified, it will default to `<jwt-issuer-uri>/.well-known/jwks.json`
    ///
    /// This argument can be repeated to configure multiple identity providers.
    #[clap(long, env = "KMS_JWKS_URI", action = clap::ArgAction::Append)]
    pub jwks_uri: Option<Vec<String>>,

    /// DEPRECATED: use the Idp config section instead.
    /// JWT authentication audience
    ///
    /// Optional JWT audience for additional validation
    ///
    /// This argument can be repeated to configure multiple identity providers.
    #[clap(long, env = "KMS_JWT_AUDIENCE", action = clap::ArgAction::Append)]
    pub jwt_audience: Option<Vec<String>>,
}

impl JwtAuthConfig {
    /// Build a JWKS URI using `jwt_issuer_uri` and an optional `jwks_uri`.
    pub(crate) fn uri(jwt_issuer_uri: &str, jwks_uri: Option<&str>) -> String {
        jwks_uri.as_ref().map_or_else(
            || {
                format!(
                    "{}/.well-known/jwks.json",
                    jwt_issuer_uri.trim_end_matches('/')
                )
            },
            std::string::ToString::to_string,
        )
    }

    /// Parse this configuration into one identity provider configuration per JWT authentication provider.
    ///
    /// This method maintains backward compatibility by handling the legacy three separate field format.
    /// For new configurations, use `IdpConfig` with th`jwt_auth_provider`er field instead.
    pub(crate) fn extract_idp_configs(self) -> Result<Option<Vec<IdpConfig>>, KmsError> {
        let jwt_issuer_uris = self.jwt_issuer_uri.unwrap_or_default();
        let jwks_uris = self.jwks_uri.unwrap_or_default();
        let jwt_audiences = self.jwt_audience.unwrap_or_default();

        if jwt_issuer_uris.is_empty() {
            return Ok(None);
        }

        let mut configs: HashMap<String, IdpConfig> = HashMap::new();

        for (index, jwt_issuer_uri) in jwt_issuer_uris.iter().enumerate() {
            if jwt_issuer_uri.trim().is_empty() {
                return Err(KmsError::InvalidRequest(
                    "JWT issuer URI cannot be empty".to_owned(),
                ));
            }

            let jwks_uri = jwks_uris.get(index).cloned();
            let jwt_audience = jwt_audiences.get(index).cloned();

            // Use issuer URI as key for backward compatibility (last one wins for same issuer)
            configs.insert(
                jwt_issuer_uri.clone(),
                IdpConfig {
                    jwt_issuer_uri: jwt_issuer_uri.clone(),
                    jwks_uri,
                    jwt_audience,
                },
            );
        }

        Ok(Some(configs.into_values().collect()))
    }
}

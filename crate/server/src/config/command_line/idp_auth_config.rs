use std::collections::HashMap;

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{config::IdpConfig as IdpConfigStruct, error::KmsError};

// Support for JWT token inspired by the doc at : https://cloud.google.com/api-gateway/docs/authenticating-users-jwt
// and following pages

#[derive(Debug, Default, Args, Deserialize, Serialize)]
#[serde(default)]
pub struct IdpAuthConfig {
    /// JWT authentication provider configuration
    ///
    /// Each provider configuration should be in the format: "`JWT_ISSUER_URI,JWKS_URI,JWT_AUDIENCE_1,JWT_AUDIENCE_2,...`"
    /// where:
    /// - `JWT_ISSUER_URI`: The issuer URI of the JWT token (required)
    /// - `JWKS_URI`: The JWKS (JSON Web Key Set) URI (optional, defaults to <JWT_ISSUER_URI>/.well-known/jwks.json)
    /// - `JWT_AUDIENCE_1..N`: One or more audience values for the JWT token (optional)
    ///
    /// Examples:
    /// - "<https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience>"
    /// - "<https://auth0.example.com,,my-app>"  (JWKS URI will default)
    /// - "<https://keycloak.example.com/auth/realms/myrealm>,," (no audience, JWKS URI will default)
    ///
    /// For Auth0, the issuer would be like: `https://<your-tenant>.<region>.auth0.com/`
    /// For Google, this would be: `https://accounts.google.com`
    ///
    /// This argument can be repeated to configure multiple identity providers.
    #[clap(long, env = "KMS_JWT_AUTH_PROVIDER", action = clap::ArgAction::Append)]
    pub jwt_auth_provider: Option<Vec<String>>,
}

impl IdpAuthConfig {
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
    /// Each provider configuration string is parsed in the format: "`JWT_ISSUER_URI,JWKS_URI,JWT_AUDIENCE_1,JWT_AUDIENCE_2,...`"
    /// where `JWKS_URI` and `JWT_AUDIENCE_*` are optional and can be empty.
    ///
    /// Duplicate configurations (same JWT issuer URI, JWKS URI, and audience list) are automatically
    /// deduplicated, with the last one taking precedence. The entire audience list is compared
    /// for equality when determining duplicates.
    pub(crate) fn extract_idp_configs(self) -> Result<Option<Vec<IdpConfigStruct>>, KmsError> {
        self.jwt_auth_provider
            .map(|provider_configs| {
                // Key the map by the full triple to handle exact duplicates (last one wins)
                type IdpKey = (String, Option<String>, Option<Vec<String>>);
                let mut configs: HashMap<IdpKey, IdpConfigStruct> = HashMap::new();

                for provider_config in provider_configs {
                    let parts: Vec<&str> = provider_config.split(',').collect();

                    // Extract the issuer URI (first part, required)
                    let jwt_issuer_uri = match parts.first() {
                        Some(issuer) if !issuer.trim().is_empty() => issuer.trim().to_owned(),
                        _ => {
                            return Err(KmsError::InvalidRequest(
                                "JWT provider configuration must contain at least a non-empty \
                                 issuer URI"
                                    .to_owned(),
                            ));
                        }
                    };

                    // Extract JWKS URI (second part, optional)
                    let jwks_uri = parts
                        .get(1)
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.trim().to_owned());

                    // Extract JWT audiences (third and subsequent parts, optional)
                    let jwt_audience = parts.get(2..).and_then(|slice| {
                        let audiences: Vec<String> = slice
                            .iter()
                            .map(|s| s.trim().to_owned())
                            .filter(|s| !s.is_empty())
                            .collect();
                        (!audiences.is_empty()).then_some(audiences)
                    });

                    let idp_config = IdpConfigStruct {
                        jwt_issuer_uri: jwt_issuer_uri.clone(),
                        jwks_uri: jwks_uri.clone(),
                        jwt_audience: jwt_audience.clone(),
                    };

                    // Insert using the full triple as key to handle exact duplicates (last one wins)
                    let key = (jwt_issuer_uri, jwks_uri, jwt_audience);
                    configs.insert(key, idp_config);
                }

                // Convert HashMap values back to Vec
                Ok(configs.into_values().collect())
            })
            .transpose()
    }
}

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

/// Configuration for the `GET /.well-known/jwks.json` public-key-discovery endpoint.
///
/// This endpoint *publishes* the server's own public keys as a RFC 7517 JSON Web Key Set
/// so that external JWT verifiers can discover the keys.
///
/// It is **distinct** from the `JwksManager` used internally to *fetch* public keys
/// from identity providers in order to validate incoming bearer tokens.
#[derive(Debug, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct JwksEndpointConfig {
    /// Enable the `GET /.well-known/jwks.json` endpoint.
    ///
    /// When set, the server publicly exposes all active public keys whose
    /// `CryptographicUsageMask` includes `Verify` as a RFC 7517 JSON Web Key Set.
    /// The endpoint is **unauthenticated** — no credentials are required to fetch it,
    /// and no authentication middleware is applied. Defaults to `false`.
    #[clap(
        long = "jwks-endpoint-enabled",
        id = "jwks_endpoint_enabled",
        value_name = "JWKS_ENDPOINT_ENABLED",
        env = "KMS_JWKS_ENDPOINT_ENABLED",
        default_value_t = false,
        verbatim_doc_comment
    )]
    #[serde(rename = "jwks_endpoint_enabled")]
    pub enabled: bool,

    /// Maximum number of public keys returned in a single JWKS response.
    ///
    /// When the server holds more eligible keys than this limit, the response is
    /// truncated and an `X-JWKS-Truncated: true` header is added to signal consumers.
    /// Increase this value if your deployment performs frequent key rotation and all
    /// overlapping verification keys must be simultaneously discoverable.
    #[clap(
        long = "jwks-endpoint-max-keys",
        id = "jwks_endpoint_max_keys",
        value_name = "JWKS_ENDPOINT_MAX_KEYS",
        env = "KMS_JWKS_ENDPOINT_MAX_KEYS",
        default_value_t = 50,
        verbatim_doc_comment
    )]
    #[serde(rename = "jwks_endpoint_max_keys")]
    pub max_keys: usize,

    /// Automatically tag key pairs created via the REST crypto API for JWKS inclusion.
    ///
    /// When `true` (the default), every key pair created via `POST /v1/crypto/keys`
    /// receives the `"jwks"` tag and immediately appears in
    /// `GET /.well-known/jwks.json`.
    ///
    /// Set to `false` to disable this behaviour globally.  Operators must then
    /// manually tag each public key via `POST /v1/crypto/keys/{kid}/tags` before
    /// it is published in the JWKS document.
    ///
    /// This setting has no effect on keys created directly through the KMIP protocol.
    #[clap(
        long = "jwks-endpoint-auto-tag",
        id = "jwks_endpoint_auto_tag",
        value_name = "JWKS_ENDPOINT_AUTO_TAG",
        env = "KMS_JWKS_ENDPOINT_AUTO_TAG",
        default_value_t = true,
        verbatim_doc_comment
    )]
    #[serde(rename = "jwks_endpoint_auto_tag")]
    pub auto_tag: bool,
}

impl Default for JwksEndpointConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_keys: 50,
            auto_tag: true,
        }
    }
}

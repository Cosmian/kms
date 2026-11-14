mod command_line;
mod params;
pub mod wizard;

pub use command_line::*;
pub use params::{
    AuditBackendParams, EstParams, HsmInstanceParams, KmipPolicyParams, OcspParams,
    OpenTelemetryConfig, ProxyParams, ScepParams, ServerParams, TlsParams, UiParams, VaultParams,
};

#[derive(Debug, Clone)]
pub struct IdpConfig {
    pub jwt_issuer_uri: String,
    pub jwks_uri: Option<String>,
    pub jwt_audience: Option<Vec<String>>, // Optional list of allowed audiences
}

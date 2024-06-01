mod command_line;
mod params;

pub use command_line::*;
pub use params::{HttpParams, ServerParams};

#[derive(Debug, Clone)]
pub struct IdpConfig {
    pub jwt_issuer_uri: String,
    pub jwks_uri: Option<String>,
    pub jwt_audience: Option<String>,
}

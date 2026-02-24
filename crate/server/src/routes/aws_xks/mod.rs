mod aws_xks_config;
mod encrypt_decrypt;
mod error;
mod health_status;
mod key_metadata;
mod sigv4_middleware;

pub use aws_xks_config::AwsXksConfig;
pub(crate) use encrypt_decrypt::{decrypt, encrypt};
pub(crate) use error::{xks_json_error_handler, xks_path_not_found_handler};
pub(crate) use health_status::get_health_status;
pub(crate) use key_metadata::get_key_metadata;
pub use sigv4_middleware::Sigv4MWare;

use crate::{error::KmsError, result::KResultHelper};

#[derive(Debug, Clone)]
pub struct AwsXksParams {
    pub region: String,
    pub service: String,
    pub sigv4_access_key_id: String,
    pub sigv4_secret_access_key: String,
}

impl TryFrom<AwsXksConfig> for AwsXksParams {
    type Error = KmsError;

    fn try_from(config: AwsXksConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            region: config
                .aws_xks_region
                .context("AWS XKS region is required")?,
            service: config
                .aws_xks_service
                .context("AWS XKS service is required")?,
            sigv4_access_key_id: config
                .aws_xks_sigv4_access_key_id
                .context("AWS XKS SigV4 access key ID is required")?,
            sigv4_secret_access_key: config
                .aws_xks_sigv4_secret_access_key
                .context("AWS XKS SigV4 secret access key is required")?,
        })
    }
}

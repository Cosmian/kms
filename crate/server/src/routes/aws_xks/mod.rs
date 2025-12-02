// use const_format::concatcp;

// mod encrypt_decrypt;
// mod error;
// mod health_status;
// mod key_metadata;
mod aws_xks_config;
mod sigv4_middleware;

pub use aws_xks_config::AwsXksConfig;
pub use sigv4_middleware::Sigv4MWare;

use crate::{error::KmsError, result::KResultHelper};

// const METADATA: &str = "metadata";
// const ENCRYPT: &str = "encrypt";
// const DECRYPT: &str = "decrypt";
// const HEALTH: &str = "health";
// const KMS_XKS_V1_PATH: &str = "/kms/xks/v1/";
// const URI_PATH_META_DATA: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", METADATA);
// const URI_PATH_ENCRYPT: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", ENCRYPT);
// const URI_PATH_DECRYPT: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", DECRYPT);
// const URI_PATH_HEALTH: &str = concatcp!(KMS_XKS_V1_PATH, HEALTH);
// // Used for ALB ping
// const URI_PATH_PING: &str = "/ping";
// const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Debug, Clone)]
pub struct AwsXksParams {
    pub region: String,
    pub service: String,
    // This could be per uri
    pub uri_path_prefix: String,
    pub sigv4_access_key_id: String,
    pub sigv4_secret_access_key: String,
    //
    pub partition: String,
    pub account_id: String,
    pub user_path: String,
    pub user_name: String,
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
            uri_path_prefix: config
                .aws_xks_uri_path_prefix
                .context("AWS XKS URI path prefix is required")?,
            sigv4_access_key_id: config
                .aws_xks_sigv4_access_key_id
                .context("AWS XKS SigV4 access key ID is required")?,
            sigv4_secret_access_key: config
                .aws_xks_sigv4_secret_access_key
                .context("AWS XKS SigV4 secret access key is required")?,
            partition: config
                .aws_xks_partition
                .context("AWS XKS partition is required")?,
            account_id: config
                .aws_xks_account_id
                .context("AWS XKS account ID is required")?,
            user_path: config
                .aws_xks_user_path
                .context("AWS XKS user path is required")?,
            user_name: config
                .aws_xks_user_name
                .context("AWS XKS user name is required")?,
        })
    }
}

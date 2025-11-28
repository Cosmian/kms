use const_format::concatcp;

// mod encrypt_decrypt;
// mod error;
// mod health_status;
// mod key_metadata;
mod aws_xks_config;
mod sigv4_middleware;

pub use aws_xks_config::AwsXksConfig;

const METADATA: &str = "metadata";
const ENCRYPT: &str = "encrypt";
const DECRYPT: &str = "decrypt";
const HEALTH: &str = "health";
const KMS_XKS_V1_PATH: &str = "/kms/xks/v1/";
const URI_PATH_META_DATA: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", METADATA);
const URI_PATH_ENCRYPT: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", ENCRYPT);
const URI_PATH_DECRYPT: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", DECRYPT);
const URI_PATH_HEALTH: &str = concatcp!(KMS_XKS_V1_PATH, HEALTH);
// Used for ALB ping
const URI_PATH_PING: &str = "/ping";
const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

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

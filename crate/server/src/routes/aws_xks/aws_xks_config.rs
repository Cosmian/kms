use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct AwsXksConfig {
    /// This setting turns on endpoints handling Google CSE feature
    #[clap(long, env = "KMS_AWX_XKS_ENABLE", default_value = "false")]
    pub aws_xks_enable: bool,

    /// The AWS XKS region to use for signing requests (sigv4)
    #[clap(
        long,
        env = "KMS_AWX_XKS_REGION",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_region: Option<String>,

    /// The AWS XKS service name to use for signing requests (sigv4)
    #[clap(
        long,
        env = "KMS_AWX_XKS_SERVICE",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_service: Option<String>,

    // This could be per uri
    #[clap(
        long,
        env = "KMS_AWX_XKS_URI_PATH_PREFIX",
        default_value = "/kms/v1",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_uri_path_prefix: Option<String>,

    #[clap(
        long,
        env = "KMS_AWX_XKS_SIGV4_ACCESS_KEY_ID",
        required_if_eq("aws_xks_enable", "true")
    )]
    /// The AWS XKS `SigV4` access key ID used to sign requests
    pub aws_xks_sigv4_access_key_id: Option<String>,

    #[clap(
        long,
        env = "KMS_AWX_XKS_SIGV4_ACCESS_KEY_USER",
        required_if_eq("aws_xks_enable", "true")
    )]
    /// The AWS XKS `SigV4` access key user that can retrieve the key
    pub aws_xks_sigv4_access_key_user: Option<String>,

    #[clap(
        long,
        env = "KMS_AWX_XKS_SIGV4_SECRET_ACCESS_KEY",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_sigv4_secret_access_key: Option<String>,
    //
    #[clap(
        long,
        env = "KMS_AWX_XKS_PARTITION",
        default_value = "aws",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_partition: Option<String>,

    #[clap(
        long,
        env = "KMS_AWX_XKS_ACCOUNT_ID",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_account_id: Option<String>,

    #[clap(
        long,
        env = "KMS_AWX_XKS_USER_PATH",
        default_value = "/kms",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_user_path: Option<String>,

    #[clap(
        long,
        env = "KMS_AWX_XKS_USER_NAME",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_user_name: Option<String>,
}

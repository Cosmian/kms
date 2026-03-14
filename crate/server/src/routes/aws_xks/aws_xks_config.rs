use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
#[allow(clippy::struct_field_names)]
pub struct AwsXksConfig {
    /// This setting turns on endpoints handling the AWS XKS feature
    #[clap(long, env = "KMS_AWS_XKS_ENABLE", default_value = "false")]
    pub aws_xks_enable: bool,

    /// The AWS XKS region to use for signing requests (sigv4)
    #[clap(
        long,
        env = "KMS_AWS_XKS_REGION",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_region: Option<String>,

    /// The AWS XKS service name to use for signing requests (sigv4)
    #[clap(
        long,
        env = "KMS_AWS_XKS_SERVICE",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_service: Option<String>,

    #[clap(
        long,
        env = "KMS_AWS_XKS_SIGV4_ACCESS_KEY_ID",
        required_if_eq("aws_xks_enable", "true")
    )]
    /// The AWS XKS `SigV4` access key ID used to sign requests
    pub aws_xks_sigv4_access_key_id: Option<String>,

    #[clap(
        long,
        env = "KMS_AWS_XKS_SIGV4_SECRET_ACCESS_KEY",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_sigv4_secret_access_key: Option<String>,
}

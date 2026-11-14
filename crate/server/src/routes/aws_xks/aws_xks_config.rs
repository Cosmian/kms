use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct AwsXksConfig {
    /// This setting turns on endpoints handling the AWS XKS feature
    #[clap(
        long = "aws-xks-enable",
        id = "aws_xks_enable",
        value_name = "AWS_XKS_ENABLE",
        env = "KMS_AWS_XKS_ENABLE",
        default_value = "false"
    )]
    #[serde(rename = "aws_xks_enable")]
    pub enable: bool,

    /// The AWS XKS region to use for signing requests (sigv4)
    #[clap(
        long = "aws-xks-region",
        id = "aws_xks_region",
        value_name = "AWS_XKS_REGION",
        env = "KMS_AWS_XKS_REGION",
        required_if_eq("aws_xks_enable", "true")
    )]
    #[serde(rename = "aws_xks_region")]
    pub region: Option<String>,

    /// The AWS XKS service name to use for signing requests (sigv4)
    #[clap(
        long = "aws-xks-service",
        id = "aws_xks_service",
        value_name = "AWS_XKS_SERVICE",
        env = "KMS_AWS_XKS_SERVICE",
        required_if_eq("aws_xks_enable", "true")
    )]
    #[serde(rename = "aws_xks_service")]
    pub service: Option<String>,

    #[clap(
        long = "aws-xks-sigv4-access-key-id",
        id = "aws_xks_sigv4_access_key_id",
        value_name = "AWS_XKS_SIGV4_ACCESS_KEY_ID",
        env = "KMS_AWS_XKS_SIGV4_ACCESS_KEY_ID",
        required_if_eq("aws_xks_enable", "true")
    )]
    /// The AWS XKS `SigV4` access key ID used to sign requests
    #[serde(rename = "aws_xks_sigv4_access_key_id")]
    pub sigv4_access_key_id: Option<String>,

    #[clap(
        long = "aws-xks-sigv4-secret-access-key",
        id = "aws_xks_sigv4_secret_access_key",
        value_name = "AWS_XKS_SIGV4_SECRET_ACCESS_KEY",
        env = "KMS_AWS_XKS_SIGV4_SECRET_ACCESS_KEY",
        required_if_eq("aws_xks_enable", "true")
    )]
    #[serde(rename = "aws_xks_sigv4_secret_access_key")]
    pub sigv4_secret_access_key: Option<String>,
}

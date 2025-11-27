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
    pub region: String,

    /// The AWS XKS service name to use for signing requests (sigv4)
    #[clap(
        long,
        env = "KMS_AWX_XKS_SERVICE",
        required_if_eq("aws_xks_enable", "true")
    )]
    pub aws_xks_service: String,
}

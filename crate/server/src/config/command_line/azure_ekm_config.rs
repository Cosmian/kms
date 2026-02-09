use clap::Args;
use serde::{Deserialize, Serialize};

#[allow(clippy::trivially_copy_pass_by_ref)] // this is required by serde
fn is_false(b: &bool) -> bool {
    !b
}
#[derive(Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct AzureEkmConfig {
    /// This setting turns on/off the endpoints handling Azure EKM features
    #[clap(long, env = "KMS_AZURE_EKM_ENABLE", default_value = "false")]
    pub azure_ekm_enable: bool,

    /// Optional path prefix set within Managed HSM during EKM configuration.
    ///
    /// Enables multi-customer use or isolation of different MHSM pools using the same proxy.
    /// Must be max 64 characters: letters (a-z, A-Z), numbers (0-9), slashes (/), dashes (-).
    #[clap(long, env = "KMS_AZURE_EKM_PATH_PREFIX", verbatim_doc_comment)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_ekm_path_prefix: Option<String>,

    /// WARNING: This bypasses mTLS authentication entirely. Only use for testing!
    #[clap(
        long,
        env = "KMS_AZURE_EKM_DISABLE_CLIENT_AUTH",
        default_value = "false"
    )]
    // serde does not support skipping booleans out of the box so a custom function is used
    #[serde(skip_serializing_if = "is_false")]
    pub azure_ekm_disable_client_auth: bool,

    /// Proxy vendor name to report in /info endpoint.
    #[clap(long, env = "KMS_AZURE_EKM_PROXY_VENDOR", default_value = "Cosmian")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub azure_ekm_proxy_vendor: String,

    /// Proxy name to report in /info endpoint.
    #[clap(
        long,
        env = "KMS_AZURE_EKM_PROXY_VENDOR",
        default_value = "EKM Proxy Service v{version}"
    )]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub azure_ekm_proxy_name: String,

    /// EKMS vendor name report in the /info endpoint.
    #[clap(long, env = "KMS_AZURE_EKM_VENDOR", default_value = "Cosmian")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub azure_ekm_ekm_vendor: String, // double "ekm" is intentional

    /// Product Name and Version of the EKMS to report in the /info endpoint.
    #[clap(
        long,
        env = "KMS_AZURE_EKM_PRODUCT",
        default_value_t = format!("Cosmian KMS v{}", env!("CARGO_PKG_VERSION"))
    )]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub azure_ekm_ekm_product: String, // again, double "ekm" is intentional
}

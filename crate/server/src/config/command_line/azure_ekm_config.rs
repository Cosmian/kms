use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct AzureEkmConfig {
    /// This setting turns on/off the endpoints handling Azure EKM features
    #[clap(
        long = "azure-ekm-enable",
        id = "azure_ekm_enable",
        value_name = "AZURE_EKM_ENABLE",
        env = "KMS_AZURE_EKM_ENABLE",
        default_value = "false"
    )]
    #[serde(rename = "azure_ekm_enable")]
    pub enable: bool,

    /// Optional path prefix set within Managed HSM during EKM configuration.
    ///
    /// Enables multi-customer use or isolation of different MHSM pools using the same proxy.
    /// Must be max 64 characters: letters (a-z, A-Z), numbers (0-9), slashes (/), dashes (-).
    #[clap(
        long = "azure-ekm-path-prefix",
        id = "azure_ekm_path_prefix",
        value_name = "AZURE_EKM_PATH_PREFIX",
        env = "KMS_AZURE_EKM_PATH_PREFIX",
        verbatim_doc_comment
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "azure_ekm_path_prefix")]
    pub path_prefix: Option<String>,

    /// WARNING: This bypasses mTLS authentication entirely. Only use for testing!
    #[clap(
        long = "azure-ekm-disable-client-auth",
        id = "azure_ekm_disable_client_auth",
        value_name = "AZURE_EKM_DISABLE_CLIENT_AUTH",
        env = "KMS_AZURE_EKM_DISABLE_CLIENT_AUTH",
        default_value = "false"
    )]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(rename = "azure_ekm_disable_client_auth")]
    pub disable_client_auth: bool,

    /// Proxy vendor name to report in /info endpoint.
    #[clap(
        long = "azure-ekm-proxy-vendor",
        id = "azure_ekm_proxy_vendor",
        value_name = "AZURE_EKM_PROXY_VENDOR",
        env = "KMS_AZURE_EKM_PROXY_VENDOR",
        default_value = "Cosmian"
    )]
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(rename = "azure_ekm_proxy_vendor")]
    pub proxy_vendor: String,

    /// Proxy name to report in /info endpoint.
    #[clap(
        long = "azure-ekm-proxy-name",
        id = "azure_ekm_proxy_name",
        value_name = "AZURE_EKM_PROXY_NAME",
        env = "KMS_AZURE_EKM_PROXY_NAME",
        default_value = "EKM Proxy Service"
    )]
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(rename = "azure_ekm_proxy_name")]
    pub proxy_name: String,

    /// EKMS vendor name report in the /info endpoint.
    #[clap(
        long = "azure-ekm-ekm-vendor",
        id = "azure_ekm_ekm_vendor",
        value_name = "AZURE_EKM_EKM_VENDOR",
        env = "KMS_AZURE_EKM_VENDOR",
        default_value = "Cosmian"
    )]
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(rename = "azure_ekm_ekm_vendor")]
    pub ekm_vendor: String, // double "ekm" is intentional

    /// Product Name and Version of the EKMS to report in the /info endpoint.
    #[clap(
        long = "azure-ekm-ekm-product", id = "azure_ekm_ekm_product", value_name = "AZURE_EKM_EKM_PRODUCT",
        env = "KMS_AZURE_EKM_PRODUCT",
        default_value_t = format!("Cosmian KMS v{}", env!("CARGO_PKG_VERSION"))
    )]
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(rename = "azure_ekm_ekm_product")]
    pub ekm_product: String, // again, double "ekm" is intentional
}

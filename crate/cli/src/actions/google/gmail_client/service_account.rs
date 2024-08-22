use std::path::PathBuf;

use cosmian_kms_client::ClientConf;
use serde::{Deserialize, Serialize};

use crate::error::{result::CliResult, CliError};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ServiceAccount {
    #[serde(rename = "type")]
    pub account_type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
}

impl ServiceAccount {
    pub(crate) fn load_from_config(conf_path: &PathBuf) -> CliResult<Self> {
        let conf = ClientConf::load(conf_path)?;
        let gmail_api_conf = conf.gmail_api_conf.ok_or_else(|| {
            CliError::Default(format!("No gmail_api_conf object in {conf_path:?}"))
        })?;
        let service_account = Self {
            account_type: gmail_api_conf.account_type,
            project_id: gmail_api_conf.project_id,
            private_key_id: gmail_api_conf.private_key_id,
            private_key: gmail_api_conf.private_key,
            client_email: gmail_api_conf.client_email,
            client_id: gmail_api_conf.client_id,
            auth_uri: gmail_api_conf.auth_uri,
            token_uri: gmail_api_conf.token_uri,
            auth_provider_x509_cert_url: gmail_api_conf.auth_provider_x509_cert_url,
            client_x509_cert_url: gmail_api_conf.client_x509_cert_url,
        };
        Ok(service_account)
    }
}

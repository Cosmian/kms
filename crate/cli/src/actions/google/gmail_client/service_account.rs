use std::path::PathBuf;

use cosmian_kms_client::ClientConf;
use serde::{Deserialize, Serialize};

use crate::error::CliError;


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceAccount {
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
    pub fn load_from_config(conf_path: &PathBuf) -> Result<Self, CliError> {
        let conf = ClientConf::load(conf_path)?;
        let gmail_api_conf = conf
            .gmail_api_conf
            .as_ref()
            .ok_or_else(|| CliError::Default(format!("No gmail_api_conf object in {conf_path:?}")))?;
        let service_account = ServiceAccount {
            account_type: gmail_api_conf.account_type.clone(),
            project_id: gmail_api_conf.project_id.clone(),
            private_key_id: gmail_api_conf.private_key_id.clone(),
            private_key: gmail_api_conf.private_key.clone(),
            client_email: gmail_api_conf.client_email.clone(),
            client_id: gmail_api_conf.client_id.clone(),
            auth_uri: gmail_api_conf.auth_uri.clone(),
            token_uri: gmail_api_conf.token_uri.clone(),
            auth_provider_x509_cert_url: gmail_api_conf.auth_provider_x509_cert_url.clone(),
            client_x509_cert_url: gmail_api_conf.client_x509_cert_url.clone(),
        };
        Ok(service_account)
    }
}

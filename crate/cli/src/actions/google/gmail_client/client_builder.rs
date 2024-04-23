
use std::{path::PathBuf};

use reqwest::{Client, Response};
use serde::Deserialize;

use crate::error::CliError;

use super::{service_account::{ServiceAccount}, token::retrieve_token, {GoogleApiError}};

#[derive(Deserialize)]
pub struct RequestError {
    pub error: ErrorContent
}

#[derive(Deserialize)]
pub struct ErrorContent {
    pub message: String,
}

#[derive(Debug, Clone)]
struct GmailClientBuilder {
    service_account: ServiceAccount,
    user_id: String,
}

impl<'a> GmailClientBuilder {
    pub fn new(
        conf_path: &PathBuf,
        user_id: &str,
    ) -> Result<Self, CliError> {
        let service_account = ServiceAccount::load_from_config(conf_path)?;
        Ok(Self {
            service_account,
            user_id: user_id.to_owned(),
        })
    }

    pub async fn build(self) -> Result<GmailClient, CliError> {
        let token = retrieve_token(&self.service_account, &self.user_id).await?;

        Ok(GmailClient {
            user_id: self.user_id,
            token,
        })
    }
}


#[derive(Debug, Clone)]
pub struct GmailClient {
    user_id: String,
    token: String,
}

impl GmailClient {
    pub async fn new(conf_path: &PathBuf, user_id: &str) -> Result<GmailClient, CliError> {
        let client_builder = GmailClientBuilder::new(conf_path, user_id)?;
        client_builder.build().await
    }

    pub async fn get(&self, endpoint: &str) -> Result<Response, GoogleApiError> {
        let client = Client::new();
        let gmail_url = "https://gmail.googleapis.com/gmail/v1/users/".to_owned() + &self.user_id;
        client.get(gmail_url + endpoint).bearer_auth(&self.token).send().await
            .map_err(GoogleApiError::ReqwestError)
    }

    pub async fn post(&self, endpoint: &str, content: String) -> Result<Response, GoogleApiError> {
        let client = Client::new();
        let gmail_url = "https://gmail.googleapis.com/gmail/v1/users/".to_owned() + &self.user_id;
        client.post(gmail_url + endpoint).header(reqwest::header::CONTENT_TYPE, "application/json").header(reqwest::header::CONTENT_LENGTH, content.len()).body(content).bearer_auth(&self.token).send().await
            .map_err(GoogleApiError::ReqwestError)
    }
}

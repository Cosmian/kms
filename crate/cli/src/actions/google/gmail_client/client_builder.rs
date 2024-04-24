use std::path::PathBuf;

use reqwest::{Client, Response};
use serde::Deserialize;

use super::{service_account::ServiceAccount, token::retrieve_token, GoogleApiError};
use crate::error::CliError;

#[derive(Deserialize)]
pub struct RequestError {
    pub error: ErrorContent,
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
    pub fn new(conf_path: &PathBuf, user_id: &str) -> Result<Self, CliError> {
        let service_account = ServiceAccount::load_from_config(conf_path)?;
        Ok(Self {
            service_account,
            user_id: user_id.to_owned(),
        })
    }

    pub async fn build(self) -> Result<GmailClient, CliError> {
        let token = retrieve_token(&self.service_account, &self.user_id).await?;

        Ok(GmailClient {
            client: Client::new(),
            token,
            base_url: "https://gmail.googleapis.com/gmail/v1/users/".to_string() + &self.user_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GmailClient {
    client: Client,
    token: String,
    base_url: String,
}

impl GmailClient {
    pub async fn new(conf_path: &PathBuf, user_id: &str) -> Result<GmailClient, CliError> {
        let client_builder = GmailClientBuilder::new(conf_path, user_id)?;
        client_builder.build().await
    }

    async fn handle_response(response: Response) -> Result<(), CliError> {
        let status_code = response.status();
        if status_code.is_success() {
            println!(
                "{}",
                response
                    .text()
                    .await
                    .map_err(GoogleApiError::ReqwestError)?
            );
            Ok(())
        } else {
            let json_body = response
                .json::<RequestError>()
                .await
                .map_err(GoogleApiError::ReqwestError)?;
            Err(CliError::GmailApiError(json_body.error.message.to_string()))
        }
    }

    pub async fn get(&self, endpoint: &str) -> Result<(), CliError> {
        let response = self
            .client
            .get(self.base_url.to_string() + endpoint)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::ReqwestError)?;
        Self::handle_response(response).await
    }

    pub async fn post(&self, endpoint: &str, content: String) -> Result<(), CliError> {
        let response = self
            .client
            .post(self.base_url.to_string() + endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_LENGTH, content.len())
            .body(content)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::ReqwestError)?;
        Self::handle_response(response).await
    }

    pub async fn patch(&self, endpoint: &str, content: String) -> Result<(), CliError> {
        let response = self
            .client
            .patch(self.base_url.to_string() + endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_LENGTH, content.len())
            .body(content)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::ReqwestError)?;
        Self::handle_response(response).await
    }

    pub async fn delete(&self, endpoint: &str) -> Result<(), CliError> {
        let response = self
            .client
            .delete(self.base_url.to_string() + endpoint)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::ReqwestError)?;
        Self::handle_response(response).await
    }
}

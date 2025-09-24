use cosmian_kms_client::{GmailApiConf, KmsClientConfig};
use reqwest::{Client, Response};
use serde::Deserialize;

use super::{GoogleApiError, token::retrieve_token};
use crate::{
    actions::kms::console,
    error::{KmsCliError, result::KmsCliResult},
};

#[derive(Deserialize)]
pub(super) struct RequestError {
    pub error: ErrorContent,
}

#[derive(Deserialize)]
pub(super) struct ErrorContent {
    pub message: String,
}

#[derive(Debug, Clone)]
struct GmailClientBuilder {
    service_account: GmailApiConf,
    user_id: String,
}

impl GmailClientBuilder {
    pub(crate) const fn new(service_account: GmailApiConf, user_id: String) -> Self {
        Self {
            service_account,
            user_id,
        }
    }

    pub(crate) async fn build(self) -> KmsCliResult<GmailClient> {
        let token = retrieve_token(&self.service_account, &self.user_id).await?;

        Ok(GmailClient {
            client: Client::new(),
            token,
            base_url: [
                "https://gmail.googleapis.com/gmail/v1/users/".to_owned(),
                self.user_id,
            ]
            .concat(),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GmailClient {
    client: Client,
    token: String,
    base_url: String,
}

impl GmailClient {
    pub(crate) async fn new(config: KmsClientConfig, user_id: &str) -> KmsCliResult<Self> {
        let gmail_api_conf = config.gmail_api_conf.clone().ok_or_else(|| {
            KmsCliError::Default(format!("No gmail_api_conf object in {config:?}",))
        })?;

        GmailClientBuilder::new(gmail_api_conf, user_id.to_owned())
            .build()
            .await
    }

    pub(crate) async fn handle_response(response: Response) -> KmsCliResult<()> {
        if response.status().is_success() {
            let stdout = response.text().await.map_err(GoogleApiError::Reqwest)?;
            console::Stdout::new(&stdout).write()?;
            Ok(())
        } else {
            let json_body = response
                .json::<RequestError>()
                .await
                .map_err(GoogleApiError::Reqwest)?;
            Err(KmsCliError::GmailApiError(json_body.error.message))
        }
    }

    pub(crate) async fn get(&self, endpoint: &str) -> Result<Response, GoogleApiError> {
        self.client
            .get([&self.base_url, endpoint].concat())
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::from)
    }

    pub(crate) async fn post(
        &self,
        endpoint: &str,
        content: String,
    ) -> Result<Response, GoogleApiError> {
        self.client
            .post([&self.base_url, endpoint].concat())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_LENGTH, content.len())
            .body(content)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::from)
    }

    pub(crate) async fn patch(
        &self,
        endpoint: &str,
        content: String,
    ) -> Result<Response, GoogleApiError> {
        self.client
            .patch([&self.base_url, endpoint].concat())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_LENGTH, content.len())
            .body(content)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::from)
    }

    pub(crate) async fn delete(&self, endpoint: &str) -> Result<Response, GoogleApiError> {
        self.client
            .delete([&self.base_url, endpoint].concat())
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(GoogleApiError::from)
    }
}

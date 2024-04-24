use std::path::PathBuf;

use clap::Parser;

use crate::{
    actions::google::{
        gmail_client::{GmailClient, RequestError},
        GoogleApiError,
    },
    error::CliError,
};

/// Lists client-side encryption key pairs for a user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ListKeypairsAction {
    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl ListKeypairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint = "/settings/cse/keypairs/".to_owned();
        let response = gmail_client.await?.get(&endpoint).await?;
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
}

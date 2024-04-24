use std::path::PathBuf;

use clap::Parser;

use crate::{
    actions::google::{
        gmail_client::{GmailClient, RequestError},
        GoogleApiError,
    },
    error::CliError,
};

/// Turns on a client-side encryption key pair that was turned off. The key pair becomes active again for any associated client-side encryption identities.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct EnableKeypairsAction {
    /// The identifier of the key pair to enable
    #[clap(required = true)]
    keypairs_id: String,

    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl EnableKeypairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint = "/settings/cse/keypairs/".to_owned() + &self.keypairs_id + ":enable";
        let response = gmail_client.await?.post(&endpoint, "".to_string()).await?;
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

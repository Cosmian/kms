use std::path::PathBuf;

use clap::Parser;

use crate::{
    actions::google::{
        gmail_client::{GmailClient, RequestError},
        GoogleApiError,
    },
    error::CliError,
};

/// Deletes a client-side encryption identity. The authenticated user can no longer use the identity to send encrypted messages. You cannot restore the identity after you delete it. Instead, use the identities.create method to create another identity with the same configuration.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct DeleteIdentitiesAction {
    /// The primary email address associated with the client-side encryption identity configuration that's retrieved.
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl DeleteIdentitiesAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint = "/settings/cse/identities/".to_owned() + &self.user_id;
        let response = gmail_client.await?.delete(&endpoint).await?;
        let status_code = response.status();
        if status_code.is_success() {
            println!("Identity deleted.",);
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

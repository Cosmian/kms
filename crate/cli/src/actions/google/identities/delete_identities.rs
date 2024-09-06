use std::path::PathBuf;

use clap::Parser;

use super::IDENTITIES_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::CliResult};

/// Deletes a client-side encryption identity. The authenticated user can no longer use the identity
/// to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
/// the identities.create method to create another identity with the same configuration.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct DeleteIdentitiesAction {
    /// The primary email address associated with the client-side encryption identity configuration
    /// that's retrieved.
    #[clap(required = true)]
    user_id: String,
}

impl DeleteIdentitiesAction {
    pub async fn run(&self, conf_path: &PathBuf) -> CliResult<()> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint = [IDENTITIES_ENDPOINT, &self.user_id].concat();
        let response = gmail_client.await?.delete(&endpoint).await?;
        GmailClient::handle_response(response).await
    }
}

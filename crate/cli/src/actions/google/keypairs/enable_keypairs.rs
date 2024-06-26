use std::path::PathBuf;

use clap::Parser;

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

/// Turns on a client-side encryption key pair that was turned off. The key pair becomes active
/// again for any associated client-side encryption identities.
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
        let endpoint = [KEYPAIRS_ENDPOINT, &self.keypairs_id, ":enable"].concat();
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let response = gmail_client.await?.post(&endpoint, String::new()).await?;
        GmailClient::handle_response(response).await
    }
}

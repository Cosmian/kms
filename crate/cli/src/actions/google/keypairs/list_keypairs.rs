use std::path::PathBuf;

use clap::Parser;

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

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
        let endpoint = KEYPAIRS_ENDPOINT.to_string();
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        gmail_client.await?.get(&endpoint).await
    }
}

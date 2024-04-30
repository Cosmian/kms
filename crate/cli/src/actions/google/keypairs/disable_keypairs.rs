use std::path::PathBuf;

use clap::Parser;

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

/// Turns off a client-side encryption key pair. The authenticated user can no longer use the key
/// pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
/// keypairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
/// by using the keypairs.obliterate method.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct DisableKeypairsAction {
    /// The identifier of the key pair to disable
    #[clap(required = true)]
    keypairs_id: String,

    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl DisableKeypairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let endpoint = [KEYPAIRS_ENDPOINT, &self.keypairs_id, ":disable"].concat();
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let response = gmail_client.await?.post(&endpoint, "".to_string()).await?;
        GmailClient::handle_response(response).await
    }
}

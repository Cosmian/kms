use std::path::PathBuf;

use clap::Parser;

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

/// Deletes a client-side encryption key pair permanently and immediately. You can only permanently
/// delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
/// the keypairs.disable method. Gmail can't restore or decrypt any messages that were encrypted by
/// an obliterated key. Authenticated users and Google Workspace administrators lose access to
/// reading the encrypted messages.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ObliterateKeypairsAction {
    /// The identifier of the key pair to obliterate
    #[clap(required = true)]
    keypairs_id: String,

    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl ObliterateKeypairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let endpoint: String = [KEYPAIRS_ENDPOINT, &self.keypairs_id, ":obliterate"].concat();
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let response = gmail_client.await?.post(&endpoint, "".to_string()).await?;
        GmailClient::handle_response(response).await
    }
}

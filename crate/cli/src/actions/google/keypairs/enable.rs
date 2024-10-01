use std::path::PathBuf;

use clap::Parser;

use super::KEY_PAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::CliResult};

/// Turns on a client-side encryption key pair that was turned off. The key pair becomes active
/// again for any associated client-side encryption identities.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct EnableKeyPairsAction {
    /// The identifier of the key pair to enable
    #[clap(required = true)]
    key_pairs_id: String,

    /// The requester's primary email address
    #[clap(long, short = 'u', required = true)]
    user_id: String,
}

impl EnableKeyPairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> CliResult<()> {
        let endpoint = [KEY_PAIRS_ENDPOINT, &self.key_pairs_id, ":enable"].concat();
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let response = gmail_client.await?.post(&endpoint, String::new()).await?;
        GmailClient::handle_response(response).await
    }
}

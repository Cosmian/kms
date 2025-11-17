use clap::Parser;
use cosmian_kms_client::KmsClientConfig;

use super::KEY_PAIRS_ENDPOINT;
use crate::{actions::kms::google::gmail_client::GmailClient, error::result::KmsCliResult};

/// Lists client-side encryption key pairs for a user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ListKeyPairsAction {
    /// The requester's primary email address
    #[clap(required = true)]
    user_id: String,
}

impl ListKeyPairsAction {
    pub async fn run(&self, config: KmsClientConfig) -> KmsCliResult<()> {
        let gmail_client = GmailClient::new(config, &self.user_id);
        let response = gmail_client.await?.get(KEY_PAIRS_ENDPOINT).await?;
        GmailClient::handle_response(response).await
    }
}

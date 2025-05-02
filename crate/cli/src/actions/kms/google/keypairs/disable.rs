use clap::Parser;
use cosmian_kms_client::KmsClientConfig;

use super::KEY_PAIRS_ENDPOINT;
use crate::{actions::kms::google::gmail_client::GmailClient, error::result::KmsCliResult};

/// Turns off a client-side encryption key pair. The authenticated user can no longer use the key
/// pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
/// key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
/// by using the key pairs.obliterate method.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct DisableKeyPairsAction {
    /// The identifier of the key pair to disable
    #[clap(required = true)]
    key_pairs_id: String,

    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl DisableKeyPairsAction {
    pub async fn run(&self, config: KmsClientConfig) -> KmsCliResult<()> {
        let endpoint = [KEY_PAIRS_ENDPOINT, &self.key_pairs_id, ":disable"].concat();
        let gmail_client = GmailClient::new(config, &self.user_id);
        let response = gmail_client.await?.post(&endpoint, String::new()).await?;
        GmailClient::handle_response(response).await
    }
}

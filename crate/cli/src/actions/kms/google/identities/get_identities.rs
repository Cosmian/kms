use clap::Parser;
use cosmian_kms_client::KmsClientConfig;

use super::IDENTITIES_ENDPOINT;
use crate::{actions::kms::google::gmail_client::GmailClient, error::result::KmsCliResult};

/// Retrieves a client-side encryption identity configuration.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct GetIdentitiesAction {
    /// The primary email address associated with the client-side encryption identity configuration
    /// that's retrieved.
    #[clap(required = true)]
    user_id: String,
}

impl GetIdentitiesAction {
    pub async fn run(&self, config: KmsClientConfig) -> KmsCliResult<()> {
        let gmail_client = GmailClient::new(config, &self.user_id);
        let endpoint = [IDENTITIES_ENDPOINT, &self.user_id].concat();
        let response = gmail_client.await?.get(&endpoint).await?;
        GmailClient::handle_response(response).await
    }
}

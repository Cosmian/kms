use std::path::PathBuf;

use clap::Parser;

use super::IDENTITIES_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::CliResult};

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
    pub async fn run(&self, conf_path: &PathBuf) -> CliResult<()> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint = [IDENTITIES_ENDPOINT, &self.user_id].concat();
        let response = gmail_client.await?.get(&endpoint).await?;
        GmailClient::handle_response(response).await
    }
}

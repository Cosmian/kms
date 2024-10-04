use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

use super::IDENTITIES_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::CliResult};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct IdentityInfo {
    primaryKeyPairId: String,
    emailAddress: String,
}

/// Associates a different key pair with an existing client-side encryption identity. The updated
/// key pair must validate against Google's S/MIME certificate profiles.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct PatchIdentitiesAction {
    /// The key pair id, associated with a given cert/key. You can get the by listing the key pairs
    /// associated with the user-id
    #[clap(required = true)]
    key_pairs_id: String,

    /// The primary email address associated with the client-side encryption identity configuration
    /// that's retrieved.
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl PatchIdentitiesAction {
    pub async fn run(&self, conf_path: &PathBuf) -> CliResult<()> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint = [IDENTITIES_ENDPOINT, &self.user_id].concat();

        // Construct identity_info
        let identity_info = IdentityInfo {
            primaryKeyPairId: self.key_pairs_id.clone(),
            emailAddress: self.user_id.clone(),
        };
        let response = gmail_client
            .await?
            .patch(&endpoint, serde_json::to_string(&identity_info)?)
            .await?;
        GmailClient::handle_response(response).await
    }
}

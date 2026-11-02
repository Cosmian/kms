use clap::Parser;
use cosmian_kms_client::KmsClientConfig;
use serde::{Deserialize, Serialize};

use super::IDENTITIES_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::result::KmsCliResult};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityInfo {
    primary_key_pair_id: String,
    email_address: String,
}

/// Creates and configures a client-side encryption identity that's authorized to send mail from the
/// user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
/// people within a Google Workspace organization can encrypt and send mail to the identity.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct InsertIdentitiesAction {
    /// The keypair id, associated with a given cert/key. You can get the by listing the keypairs
    /// associated with the user-id
    #[clap(required = true)]
    key_pairs_id: String,

    /// The primary email address associated with the client-side encryption identity configuration
    /// that's retrieved.
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,
}

impl InsertIdentitiesAction {
    pub async fn run(&self, config: KmsClientConfig) -> KmsCliResult<()> {
        let gmail_client = GmailClient::new(config, &self.user_id);

        // Construct identity_info
        let identity_info = IdentityInfo {
            primary_key_pair_id: self.key_pairs_id.clone(),
            email_address: self.user_id.clone(),
        };
        let response = gmail_client
            .await?
            .post(IDENTITIES_ENDPOINT, serde_json::to_string(&identity_info)?)
            .await?;
        GmailClient::handle_response(response).await
    }
}

#[cfg(test)]
mod characterization_tests {
    use super::IdentityInfo;

    fn build_identity_info() -> IdentityInfo {
        IdentityInfo {
            primary_key_pair_id: "kp-1".to_owned(),
            email_address: "alice@example.com".to_owned(),
        }
    }

    #[test]
    fn characterization_identity_info_serializes_camel_case() {
        let json = serde_json::to_string(&build_identity_info()).unwrap();
        assert_eq!(
            json,
            r#"{"primaryKeyPairId":"kp-1","emailAddress":"alice@example.com"}"#
        );
    }

    #[test]
    fn characterization_identity_info_deserializes_camel_case() {
        let info: IdentityInfo =
            serde_json::from_str(r#"{"emailAddress":"b@x.y","primaryKeyPairId":"k2"}"#).unwrap();
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(json, r#"{"primaryKeyPairId":"k2","emailAddress":"b@x.y"}"#);
    }
}

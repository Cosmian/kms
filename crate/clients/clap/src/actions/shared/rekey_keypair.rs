use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_operations::ReKeyKeyPair, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::{console, labels::KEY_ID},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Rotate an existing asymmetric key pair, generating a new private/public key pair
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ReKeyKeyPairAction {
    /// The unique identifier of the private key to re-key.
    #[clap(long = KEY_ID, short = 'k')]
    pub(crate) key_id: String,
}

impl ReKeyKeyPairAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let rekey_keypair_request = ReKeyKeyPair {
            private_key_unique_identifier: Some(UniqueIdentifier::TextString(self.key_id.clone())),
            ..ReKeyKeyPair::default()
        };
        let response = kms_rest_client
            .rekey_keypair(rekey_keypair_request)
            .await
            .with_context(|| "failed rekeying the key pair")?;

        let mut stdout = console::Stdout::new("The key pair was successfully rotated.");
        stdout.set_unique_identifier(&response.private_key_unique_identifier);
        stdout.write()?;

        Ok(response.private_key_unique_identifier)
    }
}

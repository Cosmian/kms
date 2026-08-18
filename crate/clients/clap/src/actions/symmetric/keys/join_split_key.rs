use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_objects::ObjectType, kmip_operations::JoinSplitKey, kmip_types::UniqueIdentifier,
    },
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Reconstruct a key from split-key shares using XOR-based split knowledge.
///
/// Provide at least `threshold` share UIDs (the minimum number of shares required to
/// reconstruct the key). The reconstructed key is stored as a new managed object and
/// its unique identifier is returned.
///
/// If the shares carry the `x-cosmian-crypto-officer-ceremony`
/// vendor attribute, the server will also activate the corresponding role ceremony.
///
/// Example:
///   `ckms sym keys join-split-key <SHARE_1_UID> <SHARE_2_UID>`
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct JoinSplitKeyAction {
    /// The unique identifiers of the split key shares to join.
    /// At least `threshold` shares must be specified.
    #[clap(required = true, num_args = 2..)]
    pub share_ids: Vec<String>,

    /// The type of object to reconstruct.
    #[clap(long, short = 'o', default_value = "symmetric-key")]
    pub object_type: ObjectTypeArg,
}

/// CLI-friendly enum for the reconstructed object type.
#[derive(Clone, Debug)]
pub enum ObjectTypeArg {
    SymmetricKey,
    SecretData,
}

impl std::str::FromStr for ObjectTypeArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "symmetric-key" | "symmetrickey" | "sym" => Ok(Self::SymmetricKey),
            "secret-data" | "secretdata" | "secret" => Ok(Self::SecretData),
            other => Err(format!(
                "unknown object type `{other}`. Accepted: symmetric-key, secret-data"
            )),
        }
    }
}

impl From<&ObjectTypeArg> for ObjectType {
    fn from(arg: &ObjectTypeArg) -> Self {
        match arg {
            ObjectTypeArg::SymmetricKey => Self::SymmetricKey,
            ObjectTypeArg::SecretData => Self::SecretData,
        }
    }
}

impl JoinSplitKeyAction {
    /// Run the join-split-key command.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = JoinSplitKey {
            object_type: ObjectType::from(&self.object_type),
            unique_identifier: self
                .share_ids
                .iter()
                .map(|id| UniqueIdentifier::TextString(id.clone()))
                .collect(),
            secret_data_type: None,
            attributes: None,
            protection_storage_masks: None,
        };

        let response = kms_rest_client
            .join_split_key(request)
            .await
            .with_context(|| "failed to join split key shares")?;

        let stdout_msg = format!(
            "Key successfully reconstructed from {} shares.\n  Reconstructed key UID: {}",
            self.share_ids.len(),
            response.unique_identifier
        );
        console::Stdout::new(&stdout_msg).write()?;

        Ok(())
    }
}

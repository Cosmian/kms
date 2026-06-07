use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_operations::CreateSplitKey,
        kmip_types::{SplitKeyMethod, UniqueIdentifier},
    },
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Split an existing symmetric key into multiple shares using XOR-based split knowledge.
///
/// The key is split into `--total-parts` shares using XOR (n-of-n). All shares are
/// required to reconstruct the original key — there is no configurable threshold.
///
/// When the key (or the server configuration) is marked for a `CryptoOfficer`
/// ceremony, the server automatically propagates the ceremony vendor attributes to each
/// share — no manual tagging is needed.
///
/// Example:
///   `ckms sym keys create-split-key --key-id <KEY_UID> --total-parts 3`
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateSplitKeyAction {
    /// The unique identifier of the key to split.
    #[clap(long = "key-id", short = 'k', required = true)]
    pub key_id: String,

    /// Total number of share objects to create (n >= 2). All shares are required to
    /// reconstruct the key (XOR n-of-n, no configurable threshold).
    #[clap(long, short = 'p', default_value = "2")]
    pub total_parts: i32,

    /// The splitting method. Accepted value: `xor` (XOR n-of-n, all shares required).
    #[clap(long, short = 'm', default_value = "xor")]
    pub method: SplitKeyMethodArg,
}

/// CLI-friendly enum for split key methods.
#[derive(Clone, Debug)]
pub enum SplitKeyMethodArg {
    Xor,
}

impl std::str::FromStr for SplitKeyMethodArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "xor" => Ok(Self::Xor),
            other => Err(format!("unknown split key method `{other}`. Accepted: xor")),
        }
    }
}

impl From<&SplitKeyMethodArg> for SplitKeyMethod {
    fn from(arg: &SplitKeyMethodArg) -> Self {
        match arg {
            SplitKeyMethodArg::Xor => Self::XOR,
        }
    }
}

impl CreateSplitKeyAction {
    /// Run the create-split-key command.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = CreateSplitKey {
            unique_identifier: UniqueIdentifier::TextString(self.key_id.clone()),
            split_key_parts: self.total_parts,
            split_key_threshold: self.total_parts, /* XOR n-of-n: threshold always equals total parts */
            split_key_method: SplitKeyMethod::from(&self.method),
        };

        let response = kms_rest_client
            .create_split_key(request)
            .await
            .with_context(|| "failed to create split key shares")?;

        let mut stdout = console::Stdout::new(&format!(
            "Key {} successfully split into {} shares (XOR n-of-n).",
            self.key_id, self.total_parts
        ));
        stdout.set_unique_identifiers(&response.split_key_unique_identifiers);
        stdout.write()?;

        Ok(())
    }
}

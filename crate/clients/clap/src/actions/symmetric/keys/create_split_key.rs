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
/// By default this is a **generic split**: all shares are owned by the calling user.
///
/// When `--ceremony` is set, the key is stamped with the `x-cosmian-crypto-officer-ceremony`
/// vendor attribute before splitting. The server then distributes each share to a
/// different Crypto Officer candidate (round-robin), enforcing dual control:
/// the future active CO must obtain GET grants from every other CO before activating.
///
/// Example:
///   `ckms sym keys create-split-key --key-id <KEY_UID> --total-parts 3`
///   `ckms sym keys create-split-key --key-id <KEY_UID> --ceremony`
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateSplitKeyAction {
    /// The unique identifier of the key to split.
    #[clap(long = "key-id", short = 'k', required = true)]
    pub key_id: String,

    /// Total number of share objects to create (n >= 2). All shares are required to
    /// reconstruct the key (XOR n-of-n, no configurable threshold).
    /// Ignored when `--ceremony` is set (share count is auto-determined by the server).
    #[clap(long, short = 'p', default_value = "2")]
    pub total_parts: i32,

    /// The splitting method. Accepted value: `xor` (XOR n-of-n, all shares required).
    #[clap(long, short = 'm', default_value = "xor")]
    pub method: SplitKeyMethodArg,

    /// Stamp the `x-cosmian-crypto-officer-ceremony` vendor attribute on the key
    /// before splitting. The server will distribute shares to different Crypto Officer
    /// candidates instead of assigning them all to the caller.
    #[clap(long, default_value = "false")]
    pub ceremony: bool,
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
    /// When `--ceremony` is set, the key is first stamped with the
    /// `x-cosmian-crypto-officer-ceremony` vendor attribute so the server
    /// distributes shares to different CO candidates instead of assigning
    /// them all to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // If --ceremony, stamp the vendor attribute on the source key first.
        if self.ceremony {
            use cosmian_kms_client::kmip_2_1::{
                kmip_attributes::Attribute,
                kmip_operations::SetAttribute,
                kmip_types::{VendorAttribute, VendorAttributeValue},
            };
            const VENDOR_ID_COSMIAN: &str = "cosmian";
            let attr = Attribute::VendorAttribute(VendorAttribute {
                vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
                attribute_name: "x-cosmian-crypto-officer-ceremony".to_owned(),
                attribute_value: VendorAttributeValue::TextString("true".to_owned()),
            });
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(UniqueIdentifier::TextString(self.key_id.clone())),
                    new_attribute: attr,
                })
                .await
                .with_context(|| "failed to set ceremony attribute on key before splitting")?;
        }

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

        let share_count = response.split_key_unique_identifiers.len();
        let mut stdout = console::Stdout::new(&format!(
            "Key {} successfully split into {} share(s) (XOR n-of-n){}.",
            self.key_id,
            share_count,
            if self.ceremony {
                " — ceremony mode: shares distributed to CO candidates"
            } else {
                ""
            },
        ));
        stdout.set_unique_identifiers(&response.split_key_unique_identifiers);
        stdout.write()?;

        Ok(())
    }
}

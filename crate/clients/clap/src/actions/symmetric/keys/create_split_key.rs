use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_objects,
        kmip_operations::{CreateSplitKey, DeleteAttribute, SetAttribute},
        kmip_types::{
            AttributeReference, SplitKeyMethod, UniqueIdentifier, VendorAttribute,
            VendorAttributeReference, VendorAttributeValue,
        },
    },
};

use crate::{
    actions::{console, shared::VENDOR_ATTR_CO_CEREMONY},
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
/// # Two ceremony split commands
///
/// This command (`ckms sym keys create-split-key --ceremony`) is the **bring-your-own-key**
/// path: the key already exists and the caller wants to turn it into a ceremony key.
/// The guided alternative (`ckms access-rights crypto-officer create-split-key`) creates
/// the AES-256 source key for you, stamps it, splits it, and cleans up the source key on
/// failure — suitable for operators who want a single-step ceremony provisioning command.
/// Both commands stamp the same attribute and call the same server-side `CreateSplitKey`
/// operation; they differ only in who creates and owns the source key.
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
    /// reconstruct the key (XOR n-of-n, no configurable threshold). Ignored when
    /// ceremony mode is enabled for an eligible Crypto Officer candidate (or by the
    /// server's global `require_ceremony` setting); otherwise the requested count is used.
    #[clap(long, short = 'p', default_value = "2")]
    pub total_parts: i32,

    /// The splitting method. Accepted value: `xor` (XOR n-of-n, all shares required).
    #[clap(long, short = 'm', default_value = "xor")]
    pub method: SplitKeyMethodArg,

    /// Stamp the `x-cosmian-crypto-officer-ceremony` vendor attribute on the key
    /// before splitting. When ceremony mode is enabled for an eligible Crypto Officer
    /// candidate (or by the server's global `require_ceremony` setting), the server
    /// distributes shares to different Crypto Officer candidates; otherwise it creates
    /// an ordinary caller-owned split.
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
    /// them all to the caller.  If `CreateSplitKey` fails after the attribute
    /// was stamped, a best-effort `DeleteAttribute` is issued to leave the
    /// caller's key in its original state.  Unlike the guided
    /// `access-rights crypto-officer create-split-key` command, the source key
    /// is **not** destroyed on failure — it existed before this command ran.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let vendor_id = kms_rest_client.config.vendor_id.as_str();

        // If --ceremony, stamp the vendor attribute on the source key first.
        let ceremony_attr_stamped = if self.ceremony {
            let attr = Attribute::VendorAttribute(VendorAttribute {
                vendor_identification: vendor_id.to_owned(),
                attribute_name: VENDOR_ATTR_CO_CEREMONY.to_owned(),
                attribute_value: VendorAttributeValue::TextString("true".to_owned()),
            });
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(UniqueIdentifier::TextString(self.key_id.clone())),
                    new_attribute: attr,
                })
                .await
                .with_context(|| "failed to set ceremony attribute on key before splitting")?;
            true
        } else {
            false
        };

        let request = CreateSplitKey {
            object_type: kmip_objects::ObjectType::SymmetricKey,
            unique_identifier: Some(UniqueIdentifier::TextString(self.key_id.clone())),
            split_key_parts: self.total_parts,
            split_key_threshold: self.total_parts, /* XOR n-of-n: threshold always equals total parts */
            split_key_method: SplitKeyMethod::from(&self.method),
            attributes: None,
            protection_storage_masks: None,
        };

        let split_result = kms_rest_client
            .create_split_key(request)
            .await
            .with_context(|| "failed to create split key shares");

        let response = match split_result {
            Ok(r) => r,
            Err(e) => {
                // Compensating delete: if we stamped the ceremony attribute and then the split
                // failed, remove the attribute so the key is left in its original state.
                // The source key itself is NOT destroyed — it existed before this command.
                if ceremony_attr_stamped {
                    let attr_ref = AttributeReference::Vendor(VendorAttributeReference {
                        vendor_identification: vendor_id.to_owned(),
                        attribute_name: VENDOR_ATTR_CO_CEREMONY.to_owned(),
                    });
                    if let Err(del_err) = kms_rest_client
                        .delete_attribute(DeleteAttribute {
                            unique_identifier: Some(UniqueIdentifier::TextString(
                                self.key_id.clone(),
                            )),
                            current_attribute: None,
                            attribute_references: Some(vec![attr_ref]),
                        })
                        .await
                    {
                        eprintln!(
                            "WARNING: CreateSplitKey failed and the compensating removal of the \
                             ceremony attribute on key '{}' also failed ({del_err}). \
                             The key retains the `{VENDOR_ATTR_CO_CEREMONY}` attribute; \
                             remove it manually with: \
                             ckms attributes delete --id {} --vendor-id {vendor_id} \
                             --attr-name {VENDOR_ATTR_CO_CEREMONY}",
                            self.key_id, self.key_id,
                        );
                    }
                }
                return Err(e);
            }
        };
        let share_count = response.unique_identifier.len();
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
        stdout.set_unique_identifiers(&response.unique_identifier);
        stdout.write()?;

        Ok(())
    }
}

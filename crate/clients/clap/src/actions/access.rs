use clap::{Parser, Subcommand};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_objects::ObjectType,
        kmip_operations::{CreateSplitKey, SetAttribute},
        kmip_types::{
            CryptographicAlgorithm, SplitKeyMethod, UniqueIdentifier, VendorAttribute,
            VendorAttributeValue,
        },
        requests::symmetric_key_create_request,
    },
    kmip_2_1::KmipOperation,
    reexport::cosmian_kms_access::access::{
        Access, AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
    },
};
use serde_json;

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Manage the users' access rights to the cryptographic objects
#[derive(Parser, Debug)]
pub enum AccessAction {
    Grant(GrantAccess),
    Revoke(RevokeAccess),
    List(ListAccessesGranted),
    Owned(ListOwnedObjects),
    Obtained(ListAccessRightsObtained),
    /// Query or manage the Crypto Officer role
    #[clap(subcommand)]
    CryptoOfficer(CryptoOfficerAction),
}

impl AccessAction {
    /// Processes the access action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - The KMS client used for the action.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem running the action.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Grant(action) => action.run(kms_rest_client).await?,
            Self::Revoke(action) => action.run(kms_rest_client).await?,
            Self::List(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Owned(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Obtained(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::CryptoOfficer(action) => action.run(kms_rest_client).await?,
        }

        Ok(())
    }
}

/// Grant another user one or multiple access rights to an object.
///
/// This command can only be called by the owner of the object.
///
/// The right is granted for one or multiple supported KMIP operations:
/// `create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`.
///
/// Multiple operations must be supplied whitespace separated, such as: 'create get rekey'
#[derive(Parser, Debug)]
pub struct GrantAccess {
    /// The user identifier to allow
    #[clap(required = true)]
    pub user: String,

    /// The object unique identifier stored in the KMS
    #[clap(long, short = 'i')]
    pub object_uid: Option<String>,

    /// The operations to grant (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`, `get_attributes`)
    #[clap(required = true)]
    pub operations: Vec<KmipOperation>,
}

impl GrantAccess {
    /// Runs the `GrantAccess` action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let requires_object_uid = self
            .operations
            .iter()
            .any(|op| *op != KmipOperation::Create);

        let uid = if requires_object_uid {
            let object_uid = self
                .object_uid
                .clone()
                .context("Object UID is required for operations other than `create`")?;
            Some(UniqueIdentifier::TextString(object_uid))
        } else {
            None
        };

        let access = Access {
            unique_identifier: uid.clone(),
            user_id: self.user.clone(),
            operation_types: self.operations.clone(),
        };

        kms_rest_client
            .grant_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let stdout = format!(
            "The following kmip operations: {:?}, were successfully granted to user `{}` on \
             object `{}`",
            self.operations,
            self.user,
            uid.as_ref()
                .map_or_else(|| "N/A".to_owned(), std::string::ToString::to_string)
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Revoke another user one or multiple access rights to an object.
///
/// This command can only be called by the owner of the object.
///
/// The right is revoked for one or multiple supported KMIP operations:
/// `create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`
///
/// Multiple operations must be supplied whitespace separated, such as: 'create get rekey'
#[derive(Parser, Debug)]
pub struct RevokeAccess {
    /// The user to revoke access to
    #[clap(required = true)]
    pub(crate) user: String,

    /// The object unique identifier stored in the KMS
    #[clap(long, short = 'i')]
    pub(crate) object_uid: Option<String>,

    /// The operations to revoke (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)
    #[clap(required = true)]
    pub(crate) operations: Vec<KmipOperation>,
}

impl RevokeAccess {
    /// Runs the `RevokeAccess` action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let requires_object_uid = self
            .operations
            .iter()
            .any(|op| *op != KmipOperation::Create);

        let uid = if requires_object_uid {
            let object_uid = self
                .object_uid
                .clone()
                .context("Object UID is required for operations other than `create`")?;
            Some(UniqueIdentifier::TextString(object_uid))
        } else {
            None
        };

        let access = Access {
            unique_identifier: uid.clone(),
            user_id: self.user.clone(),
            operation_types: self.operations.clone(),
        };

        kms_rest_client
            .revoke_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let stdout = format!(
            "The following kmip operations: {:?}, have been removed for user `{}` on object `{}`",
            self.operations,
            self.user,
            uid.as_ref()
                .map_or_else(|| "N/A".to_owned(), std::string::ToString::to_string)
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// List the access rights granted on an object to other users.
///
/// This command can only be called by the owner of the object.
/// Returns a list of users and the operations they have been granted access to.
#[derive(Parser, Debug)]
pub struct ListAccessesGranted {
    /// The object unique identifier
    #[clap(required = true)]
    pub(crate) object_uid: String,
}

impl ListAccessesGranted {
    /// Runs the `ListAccessesGranted` action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<Vec<UserAccessResponse>> {
        let accesses = kms_rest_client
            .list_access(&self.object_uid)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let stdout = format!(
            "The access rights granted on object {} are:",
            self.object_uid
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_accesses(&accesses);
        stdout.write()?;

        Ok(accesses)
    }
}

/// List the objects owned by the calling user.
///
/// Owners of objects can perform any operation on these objects
/// and can grant access rights on any of these operations to any other user.
#[derive(Parser, Default, Debug)]
pub struct ListOwnedObjects;

impl ListOwnedObjects {
    /// Runs the `ListOwnedObjects` action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<Vec<ObjectOwnedResponse>> {
        let objects = kms_rest_client
            .list_owned_objects()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if objects.is_empty() {
            console::Stdout::new("No object owned by this user.").write()?;
        } else {
            let mut stdout = console::Stdout::new("The objects owned by this user are:");
            stdout.set_object_owned(&objects);
            stdout.write()?;
        }

        Ok(objects)
    }
}

/// List the access rights obtained by the calling user
///
/// Returns a list of objects, their state, their owner
/// and the accesses rights granted on the object
#[derive(Parser, Debug)]
pub struct ListAccessRightsObtained;

impl ListAccessRightsObtained {
    /// Runs the `ListAccessRightsObtained` action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<Vec<AccessRightsObtainedResponse>> {
        let objects = kms_rest_client
            .list_access_rights_obtained()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if objects.is_empty() {
            console::Stdout::new("No access right obtained.").write()?;
        } else {
            let mut stdout = console::Stdout::new("The access rights obtained are: ");
            stdout.set_access_rights_obtained(&objects);
            stdout.write()?;
        }

        Ok(objects)
    }
}

// ── CryptoOfficer role sub-commands ──────────────────────────────────────────

/// Query or manage the Crypto Officer role on the KMS server.
#[derive(Subcommand, Debug)]
pub enum CryptoOfficerAction {
    /// Print the current Crypto Officer role configuration and ceremony activation status.
    Status(CryptoOfficerStatus),
    /// Create a ceremony split key (one share per configured CO) and distribute shares.
    ///
    /// The number of shares is automatically determined by the server from the
    /// `crypto_officer_users` list in `kms.toml`. Each share is owned by a different
    /// CO candidate (round-robin), enforcing the dual-control constraint required for
    /// ceremony activation.
    #[clap(name = "create-split-key")]
    CreateSplitKey(CryptoOfficerCreateSplitKey),
    /// Activate the Crypto Officer role via a split-key ceremony.
    ///
    /// Provides all n share UIDs to the server. The server reconstructs the ceremony
    /// secret in RAM (XOR n-of-n), verifies dual-control constraints, activates the CO
    /// role, then zeroizes the secret — the secret is **never** stored as a KMS object.
    Activate(CryptoOfficerActivate),
    /// Disable an active Crypto Officer ceremony (requires active Crypto Officer privileges).
    Disable(CryptoOfficerDisable),
}

impl CryptoOfficerAction {
    /// Processes the crypto-officer sub-command.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Status(action) => action.run(kms_rest_client).await,
            Self::CreateSplitKey(action) => action.run(kms_rest_client).await,
            Self::Activate(action) => action.run(kms_rest_client).await,
            Self::Disable(action) => action.run(kms_rest_client).await,
        }
    }
}

/// Create a ceremony split key distributed across all configured Crypto Officer candidates.
///
/// The number of shares is automatically determined by the server from the
/// `crypto_officer_users` list in `kms.toml`. Each share is owned by a different
/// CO candidate (round-robin), enforcing the dual-control constraint required for
/// ceremony activation.
///
/// Steps performed:
///   1. Fetches CO status to verify the server has ≥ 2 CO candidates configured.
///   2. Creates a fresh AES-256 symmetric key (optionally with a custom UID).
///   3. Stamps the `x-cosmian-crypto-officer-ceremony` vendor attribute on the key.
///   4. Calls `CreateSplitKey` — the server auto-assigns n = `custodians_count` shares,
///      each owned by a different CO candidate.
///   5. Prints the share UIDs (one per CO candidate), suitable for use with `activate`.
///
/// Example:
///   `ckms access-rights crypto-officer create-split-key`
///   `ckms access-rights crypto-officer create-split-key --key-id my-ceremony-key`
///
/// **Requires**: the caller must be listed in `crypto_officer_users` in `kms.toml`.
#[derive(Parser, Debug, Default)]
pub struct CryptoOfficerCreateSplitKey {
    /// Optional custom base UID for the ceremony key.
    /// Shares will be named `<uid>#1`, `<uid>#2`, … for human-friendly lookup.
    /// If omitted, the server assigns a UUID automatically.
    #[clap(long = "key-id", short = 'k')]
    pub key_id: Option<String>,
}

/// Constant: the vendor attribute name for the CO ceremony flag.
const VENDOR_ATTR_CO_CEREMONY: &str = "x-cosmian-crypto-officer-ceremony";

impl CryptoOfficerCreateSplitKey {
    /// Runs the `CryptoOfficerCreateSplitKey` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not CO-configured, key creation fails, or
    /// the split request is rejected by the server.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // 1. Fetch CO status — verify ≥ 2 custodians are configured.
        let status = kms_rest_client
            .crypto_officer_status()
            .await
            .with_context(|| "Failed to fetch Crypto Officer status from KMS server")?;
        let custodians_count = status
            .get("custodians_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if custodians_count < 2 {
            return Err(crate::error::KmsCliError::Default(format!(
                "Crypto Officer ceremony requires at least 2 configured CO candidates; \
                     server reports {custodians_count}. Check `crypto_officer_users` in kms.toml."
            )));
        }
        let n = i32::try_from(custodians_count)
            .with_context(|| "custodians_count overflows i32 — server configuration is invalid")?;

        // 2. Create a fresh AES-256 symmetric key (optionally with the caller's UID).
        let vendor_id = kms_rest_client.config.vendor_id.as_str();
        let key_id = self
            .key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let create_req = symmetric_key_create_request(
            vendor_id,
            key_id,
            256,
            CryptographicAlgorithm::AES,
            std::iter::empty::<&str>(),
            false,
            None,
        )
        .with_context(|| "Failed to build symmetric key creation request")?;
        let created_uid = kms_rest_client
            .create(create_req)
            .await
            .with_context(|| "Failed to create ceremony key on KMS server")?
            .unique_identifier;

        // 3. Stamp the x-cosmian-crypto-officer-ceremony vendor attribute.
        let ceremony_attr = Attribute::VendorAttribute(VendorAttribute {
            vendor_identification: vendor_id.to_owned(),
            attribute_name: VENDOR_ATTR_CO_CEREMONY.to_owned(),
            attribute_value: VendorAttributeValue::TextString("true".to_owned()),
        });
        kms_rest_client
            .set_attribute(SetAttribute {
                unique_identifier: Some(created_uid.clone()),
                new_attribute: ceremony_attr,
            })
            .await
            .with_context(|| "Failed to stamp ceremony attribute on key before splitting")?;

        // 4. Call CreateSplitKey — server auto-assigns n = custodians_count shares,
        //    each owned by a different CO candidate.
        let split_req = CreateSplitKey {
            object_type: ObjectType::SymmetricKey,
            unique_identifier: Some(created_uid.clone()),
            split_key_parts: n,
            split_key_threshold: n,
            split_key_method: SplitKeyMethod::XOR,
            attributes: None,
            protection_storage_masks: None,
        };
        let split_resp = kms_rest_client
            .create_split_key(split_req)
            .await
            .with_context(|| "Failed to split ceremony key on KMS server")?;

        // 5. Print results.
        let share_count = split_resp.unique_identifier.len();
        let mut stdout = console::Stdout::new(&format!(
            "Ceremony key {created_uid} split into {share_count} share(s) \
             (one per CO candidate). Provide all share UIDs to `activate`."
        ));
        stdout.set_unique_identifiers(&split_resp.unique_identifier);
        stdout.write()?;
        Ok(())
    }
}

/// Print the Crypto Officer role configuration and ceremony status.
///
/// Any authenticated user can call this command — it returns no key material.
#[derive(Parser, Debug, Default)]
pub struct CryptoOfficerStatus;

impl CryptoOfficerStatus {
    /// Runs the `CryptoOfficerStatus` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let status = kms_rest_client
            .crypto_officer_status()
            .await
            .with_context(|| "Failed to fetch crypto officer status from KMS server")?;
        let pretty =
            serde_json::to_string_pretty(&status).unwrap_or_else(|_| format!("{status:?}"));
        console::Stdout::new(&pretty).write()?;
        Ok(())
    }
}

/// Activate the Crypto Officer role via a split-key ceremony.
///
/// Sends all n split-key share UIDs to the server. The server:
///
///   1. Retrieves each share (caller must have `Get` permission on all shares).
///   2. Verifies all shares carry `x-cosmian-crypto-officer-ceremony`.
///   3. Verifies all shares originate from the same source key.
///   4. Verifies dual control — at least one share is owned by a different CO
///      (NIST SP 800-57 Part 2 Rev 1 §4.6). The activating candidate may own one or
///      more shares; what is forbidden is that *all* shares belong to the activating
///      candidate (solo self-activation).
///   5. Reconstructs the ceremony secret via XOR in RAM.
///   6. Persists the activation record.
///   7. Zeroizes the secret — **never stored as a KMS object** (ADP-20).
///
/// **Requires**: the caller must be listed in `crypto_officer_users`.
#[derive(Parser, Debug)]
pub struct CryptoOfficerActivate {
    /// UIDs of all n split-key shares (all shares from the ceremony key must be provided).
    #[clap(required = true)]
    pub share_ids: Vec<String>,
}

impl CryptoOfficerActivate {
    /// Runs the `CryptoOfficerActivate` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server rejects the ceremony (wrong user, missing shares,
    /// non-ceremony shares, dual-control violation, etc.).
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .crypto_officer_activate(&self.share_ids)
            .await
            .with_context(|| "Failed to activate Crypto Officer ceremony on KMS server")?;
        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// Disable an active Crypto Officer ceremony.
///
/// Sets `revoked_at` on the current ceremony activation record.
/// Subsequent Crypto Officer ownership-bypass operations will be denied until a new ceremony
/// is completed. In config-only mode, this command returns an error — remove the user
/// from `crypto_officer_users` in `kms.toml` and restart the server instead.
///
/// **Self-revoke** (default): the caller must be an active Crypto Officer.
///
/// **Peer revocation** (`--target-user <EMAIL>`): the caller must be a configured CO candidate;
/// the target must be an active Crypto Officer.
#[derive(Parser, Debug, Default)]
pub struct CryptoOfficerDisable {
    /// The email of the active CO to revoke. If omitted, the caller self-revokes.
    #[clap(long, value_name = "EMAIL")]
    pub target_user: Option<String>,
}

impl CryptoOfficerDisable {
    /// Runs the `CryptoOfficerDisable` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails or the caller is not an active Crypto Officer.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .crypto_officer_disable(self.target_user.as_deref())
            .await
            .with_context(|| "Failed to disable Crypto Officer ceremony on KMS server")?;
        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

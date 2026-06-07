use clap::{Parser, Subcommand};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_objects::ObjectType,
        kmip_operations::{CreateSplitKey, Destroy, SetAttribute},
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
    actions::{console, shared::VENDOR_ATTR_CO_CEREMONY},
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
            Self::Activate(action) => action.run(kms_rest_client).await,
            Self::Disable(action) => action.run(kms_rest_client).await,
        }
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
///   4. Verifies dual control — each share is owned by a different CO, and the
///      activating user does not own any share (NIST SP 800-57 Part 2 Rev 1 §4.6).
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
/// **Requires**: the caller must be an active Crypto Officer.
#[derive(Parser, Debug, Default)]
pub struct CryptoOfficerDisable;

impl CryptoOfficerDisable {
    /// Runs the `CryptoOfficerDisable` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails or the caller is not an active Crypto Officer.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .crypto_officer_disable()
            .await
            .with_context(|| "Failed to disable Crypto Officer ceremony on KMS server")?;
        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

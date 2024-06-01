use clap::Parser;
use cosmian_kms_client::{
    access::Access, cosmian_kmip::kmip::kmip_types::UniqueIdentifier, kmip::KmipOperation,
    KmsClient,
};

use crate::{
    actions::console,
    error::result::{CliResult, CliResultHelper},
};

/// Manage the users' access rights to the cryptographic objects
#[derive(Parser, Debug)]
pub enum AccessAction {
    Grant(GrantAccess),
    Revoke(RevokeAccess),
    List(ListAccessesGranted),
    Owned(ListOwnedObjects),
    Obtained(ListAccessRightsObtained),
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
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Grant(action) => action.run(kms_rest_client).await?,
            Self::Revoke(action) => action.run(kms_rest_client).await?,
            Self::List(action) => action.run(kms_rest_client).await?,
            Self::Owned(action) => action.run(kms_rest_client).await?,
            Self::Obtained(action) => action.run(kms_rest_client).await?,
        };

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
    user: String,

    /// The object unique identifier stored in the KMS
    #[clap(required = true)]
    object_uid: String,

    /// The operations to grant (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)
    #[clap(required = true)]
    operations: Vec<KmipOperation>,
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
    ///
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let access = Access {
            unique_identifier: Some(UniqueIdentifier::TextString(self.object_uid.clone())),
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
            self.operations, self.user, self.object_uid
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
    user: String,

    /// The object unique identifier stored in the KMS
    #[clap(required = true)]
    object_uid: String,

    /// The operations to revoke (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)
    #[clap(required = true)]
    operations: Vec<KmipOperation>,
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
    ///
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let access = Access {
            unique_identifier: Some(UniqueIdentifier::TextString(self.object_uid.clone())),
            user_id: self.user.clone(),
            operation_types: self.operations.clone(),
        };

        kms_rest_client
            .revoke_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let stdout = format!(
            "The following kmip operations: {:?}, have been removed for user `{}` on object `{}`",
            self.operations, self.user, self.object_uid
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
    object_uid: String,
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
    ///
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let accesses = kms_rest_client
            .list_access(&self.object_uid)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let stdout = format!(
            "The access rights granted on object {} are:",
            &self.object_uid
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_accesses(accesses);
        stdout.write()?;

        Ok(())
    }
}

/// List the objects owned by the calling user.
///
/// Owners of objects can perform any operation on these objects
/// and can grant access rights on any of these operations to any other user.
#[derive(Parser, Debug)]
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
    ///
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let objects = kms_rest_client
            .list_owned_objects()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if objects.is_empty() {
            console::Stdout::new("No object owned by this user.").write()?;
        } else {
            let mut stdout = console::Stdout::new("The objects owned by this user are:");
            stdout.set_object_owned(objects);
            stdout.write()?;
        }

        Ok(())
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
    ///
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let objects = kms_rest_client
            .list_access_rights_obtained()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        if objects.is_empty() {
            console::Stdout::new("No access right obtained.").write()?;
        } else {
            let mut stdout = console::Stdout::new("The access rights obtained are: ");
            stdout.set_access_rights_obtained(objects);
            stdout.write()?;
        }

        Ok(())
    }
}

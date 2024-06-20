use clap::Parser;
use cosmian_kms_client::{
    access::{Access, ObjectOperationType},
    cosmian_kmip::kmip::kmip_types::UniqueIdentifier,
    KmsClient,
};

use crate::{
    actions::console,
    error::{result::CliResultHelper, CliError},
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
    pub async fn process(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
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
    operations: Vec<ObjectOperationType>,
}

impl GrantAccess {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
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
            "The following access right were successfully granted to `{}`: {:?}",
            self.user, self.operations,
        );
        console::Stdout::new(&stdout, None).write()?;

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
    operations: Vec<ObjectOperationType>,
}

impl RevokeAccess {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
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
            "The following permissions have been properly removed for `{}`: {:?}",
            self.user, self.operations
        );
        console::Stdout::new(&stdout, None).write()?;

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
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let accesses = kms_rest_client
            .list_access(&self.object_uid)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let stdout = format!(
            "The access rights granted on object {} are:",
            &self.object_uid
        );
        let mut stdout = console::Stdout::new(&stdout, None);
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
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let objects = kms_rest_client
            .list_owned_objects()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let mut stdout = console::Stdout::new("The objects owned by this user are:", None);
        stdout.set_object_owned(objects);
        stdout.write()?;

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
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let objects = kms_rest_client
            .list_access_rights_obtained()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let mut stdout = console::Stdout::new("The access right obtained are:", None);
        stdout.set_access_rights_obtained(objects);
        stdout.write()?;

        Ok(())
    }
}

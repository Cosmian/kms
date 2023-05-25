use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::types::{Access, ObjectOperationTypes};

use crate::error::{result::CliResultHelper, CliError};

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
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Grant(action) => action.run(client_connector).await?,
            Self::Revoke(action) => action.run(client_connector).await?,
            Self::List(action) => action.run(client_connector).await?,
            Self::Owned(action) => action.run(client_connector).await?,
            Self::Obtained(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

/// Grant another user an access right to an object.
///
/// This command can only be called by the owner of the object.
///
/// The right is granted for one of the supported KMIP operations:
/// create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy
///
#[derive(Parser, Debug)]
pub struct GrantAccess {
    /// The user identifier to allow
    #[clap(required = true)]
    user: String,

    /// The object unique identifier stored in the KMS
    #[clap(required = true)]
    object_uid: String,

    /// The KMIP operation to allow
    #[clap(required = true)]
    operation: ObjectOperationTypes,
}

impl GrantAccess {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let access = Access {
            unique_identifier: Some(self.object_uid.clone()),
            user_id: self.user.clone(),
            operation_type: self.operation,
        };

        client_connector
            .grant_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!(
            "The {} access right was successfully granted to {}",
            self.operation, self.user
        );

        Ok(())
    }
}

/// Revoke another user access right to an object.
///
/// This command can only be called by the owner of the object.
#[derive(Parser, Debug)]
pub struct RevokeAccess {
    /// The user to revoke access to
    #[clap(required = true)]
    user: String,

    /// The object unique identifier stored in the KMS
    #[clap(required = true)]
    object_uid: String,

    /// The operation to revoke (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)
    #[clap(required = true)]
    operation: ObjectOperationTypes,
}

impl RevokeAccess {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let access = Access {
            unique_identifier: Some(self.object_uid.clone()),
            user_id: self.user.clone(),
            operation_type: self.operation,
        };

        client_connector
            .revoke_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The permission has been properly removed");

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
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let accesses = client_connector
            .list_access(&self.object_uid)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!(
            "The access rights granted on object {} are:",
            &self.object_uid
        );
        for access in accesses {
            println!(" - {}: {:?}", access.user_id, access.operations);
        }
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
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let objects = client_connector
            .list_owned_objects()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The objects owned by this user are:\n");
        for object in objects {
            println!("{object}");
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
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let objects = client_connector
            .list_access_rights_obtained()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The access right obtained are:\n");
        for object in objects {
            println!("{object}");
        }
        Ok(())
    }
}

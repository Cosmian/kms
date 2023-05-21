use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::types::{Access, ObjectOperationTypes};

use crate::error::{result::CliResultHelper, CliError};

/// Manage the users' access rights to the cryptographic objects
#[derive(Parser, Debug)]
pub enum AccessAction {
    Grant(GrantAccess),
    Revoke(RevokeAccess),
    /// List access rights to an object
    List(ListAccesses),
    /// List objects owned by the current user
    Owned(ListOwnedObjects),
    /// List objects shared to the current user
    Shared(ListSharedObjects),
}

impl AccessAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Grant(action) => action.run(client_connector).await?,
            Self::Revoke(action) => action.run(client_connector).await?,
            Self::List(action) => action.run(client_connector).await?,
            Self::Owned(action) => action.run(client_connector).await?,
            Self::Shared(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

/// Grant another user an access right to an object
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
            self.operation.to_string().to_lowercase(),
            self.user
        );

        Ok(())
    }
}

/// Remove another user access right to an object
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

/// List the permissions of an object.
#[derive(Parser, Debug)]
pub struct ListAccesses {
    /// The object unique identifier stored in the KMS
    #[clap(required = true)]
    object_uid: String,
}

impl ListAccesses {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let accesses = client_connector
            .list_access(&self.object_uid)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The permissions are:\n");
        for access in accesses {
            println!("> {}", access.user_id);
            for op in access.operations {
                println!("\t{:?}", &op)
            }
            println!();
        }
        Ok(())
    }
}

/// List the object owned by a user.
#[derive(Parser, Debug)]
pub struct ListOwnedObjects;

impl ListOwnedObjects {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let objects = client_connector
            .list_owned_objects()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The objects are:\n");
        for object in objects {
            println!("{object}");
        }
        Ok(())
    }
}

/// List the shared objects of a user.
#[derive(Parser, Debug)]
pub struct ListSharedObjects;

impl ListSharedObjects {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let objects = client_connector
            .list_shared_objects()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The objects are:\n");
        for object in objects {
            println!("{object}");
        }
        Ok(())
    }
}

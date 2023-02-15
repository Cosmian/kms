use clap::StructOpt;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::types::{Access, ObjectOperationTypes};
use eyre::Context;

/// Manage the permission of objects.
#[derive(StructOpt, Debug)]
pub enum PermissionAction {
    /// Remove an access authorization for an object to a user
    Remove(RemovePermission),
    /// Add an access authorization for an object to a user
    Add(AddPermission),
    /// List granted access authorizations for an object
    List(ListPermissions),
    /// List objects owned by the current user
    Owned(ListOwnedObjects),
    /// List objects shared for the current user
    Shared(ListSharedObjects),
}

impl PermissionAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        match self {
            Self::Add(action) => action.run(client_connector).await?,
            Self::Remove(action) => action.run(client_connector).await?,
            Self::List(action) => action.run(client_connector).await?,
            Self::Owned(action) => action.run(client_connector).await?,
            Self::Shared(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

/// Add a new permission to an object for the current user.
#[derive(StructOpt, Debug)]
pub struct AddPermission {
    /// The object unique identifier stored in the KMS
    #[structopt(required = true)]
    object_uid: String,

    /// The user to allow
    #[structopt(required = true, long, short = 'u')]
    user: String,

    /// The operation to allow (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)
    #[structopt(required = true, long, short = 'o')]
    operation: ObjectOperationTypes,
}

impl AddPermission {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        let access = Access {
            unique_identifier: Some(self.object_uid.clone()),
            user_id: self.user.clone(),
            operation_type: self.operation,
        };

        client_connector
            .add_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The permission has been properly set");

        Ok(())
    }
}

/// Remove a permission to an object for the current user.
#[derive(StructOpt, Debug)]
pub struct RemovePermission {
    /// The object unique identifier stored in the KMS
    #[structopt(required = true)]
    object_uid: String,

    /// The user to ungrant
    #[structopt(required = true, long, short = 'u')]
    user: String,

    /// The operation to remove (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)
    #[structopt(required = true, long, short = 'o')]
    operation: ObjectOperationTypes,
}

impl RemovePermission {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        let access = Access {
            unique_identifier: Some(self.object_uid.clone()),
            user_id: self.user.clone(),
            operation_type: self.operation,
        };

        client_connector
            .remove_access(access)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!("The permission has been properly removed");

        Ok(())
    }
}

/// List the permissions of an object.
#[derive(StructOpt, Debug)]
pub struct ListPermissions {
    /// The object unique identifier stored in the KMS
    #[structopt(required = true)]
    object_uid: String,
}

impl ListPermissions {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
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
#[derive(StructOpt, Debug)]
pub struct ListOwnedObjects;

impl ListOwnedObjects {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
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
#[derive(StructOpt, Debug)]
pub struct ListSharedObjects;

impl ListSharedObjects {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
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

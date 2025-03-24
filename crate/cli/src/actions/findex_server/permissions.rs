use clap::Parser;
use cosmian_findex_client::RestClient;
use cosmian_findex_structs::Permission;
use uuid::Uuid;

use crate::error::result::{CosmianResult, CosmianResultHelper};

/// Manage the users permissions to the indexes
#[derive(Parser, Debug)]
pub enum PermissionsAction {
    Create(CreateIndex),
    List(ListPermissions),
    Set(SetPermission),
    Revoke(RevokePermission),
}

impl PermissionsAction {
    /// Processes the permissions action.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem running the action.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        match self {
            Self::Create(action) => action
                .run(rest_client)
                .await
                .map(|id| format!("Created Index ID: {id}")),
            Self::List(action) => action
                .run(rest_client)
                .await
                .map(|permissions| format!("Permissions: {permissions}")),
            Self::Set(action) => action.run(rest_client).await,
            Self::Revoke(action) => action.run(rest_client).await,
        }
    }
}

/// Create a new index. It results on an `admin` permission on a new index.
///
/// Users can have 1 permission on multiple indexes
#[derive(Parser, Debug, Default)]
pub struct CreateIndex;

impl CreateIndex {
    /// Create a new Index with a default `admin` permission.
    ///
    /// Generates an unique index ID which is returned to the owner.
    /// This ID will be shared between several users that will be able to:
    ///   * index new keywords with their own datasets
    ///   * or search keywords in the index
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the Findex server fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<Uuid> {
        let response = rest_client
            .create_index_id()
            .await
            .with_context(|| "Can't execute the create index id query on the findex server")?;
        // should replace the user configuration file

        Ok(response.index_id)
    }
}

/// List user's permission. Returns a list of indexes with their permissions.
#[derive(Parser, Debug)]
pub struct ListPermissions {
    /// The user identifier to allow
    #[clap(long, short = 'u', required = true)]
    pub user: String,
}

impl ListPermissions {
    /// Runs the `ListPermissions` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the Findex server fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        let response = rest_client
            .list_permission(&self.user)
            .await
            .with_context(|| "Can't execute the list permission query on the findex server")?;

        Ok(response.to_string())
    }
}

/// Set permission on a index.
///
/// This command can only be called by the owner of the index. It allows to
/// set:
/// * `read` permission: the user can only read the index
/// * `write` permission: the user can read and write the index
/// * `admin` permission: the user can read, write and set permission to the
///   index
#[derive(Parser, Debug)]
pub struct SetPermission {
    /// The user identifier to allow
    #[clap(long, required = true)]
    pub user: String,

    /// The index ID
    #[clap(long, required = true)]
    pub index_id: Uuid,

    #[clap(long, required = true)]
    pub permission: Permission,
}

impl SetPermission {
    /// Runs the `SetPermission` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the Findex server fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        let response = rest_client
            .set_permission(&self.user, &self.permission, &self.index_id)
            .await
            .with_context(|| "Can't execute the set permission query on the findex server")?;

        Ok(response.success)
    }
}

/// Revoke user permission.
///
/// This command can only be called by the owner of the index.
#[derive(Parser, Debug)]
pub struct RevokePermission {
    /// The user identifier to revoke
    #[clap(long, required = true)]
    pub user: String,

    /// The index id
    #[clap(long, required = true)]
    pub index_id: Uuid,
}

impl RevokePermission {
    /// Runs the `RevokePermission` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the Findex server fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        let response = rest_client
            .revoke_permission(&self.user, &self.index_id)
            .await
            .with_context(|| "Can't execute the revoke permission query on the findex server")?;

        Ok(response.success)
    }
}

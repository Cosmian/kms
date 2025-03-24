use cosmian_findex_client::RestClient;
use cosmian_findex_structs::Permission;
use uuid::Uuid;

use crate::{
    actions::findex_server::permissions::{
        CreateIndex, ListPermissions, RevokePermission, SetPermission,
    },
    error::result::CosmianResult,
};

pub(crate) async fn create_index_id(rest_client: RestClient) -> CosmianResult<Uuid> {
    CreateIndex.run(rest_client).await
}

pub(crate) async fn list_permissions(
    rest_client: RestClient,
    user: String,
) -> CosmianResult<String> {
    ListPermissions { user }.run(rest_client).await
}

pub(crate) async fn set_permission(
    rest_client: RestClient,
    user: String,
    index_id: Uuid,
    permission: Permission,
) -> CosmianResult<String> {
    SetPermission {
        user,
        index_id,
        permission,
    }
    .run(rest_client)
    .await
}

pub(crate) async fn revoke_permission(
    rest_client: RestClient,
    user: String,
    index_id: Uuid,
) -> CosmianResult<String> {
    RevokePermission { user, index_id }.run(rest_client).await
}

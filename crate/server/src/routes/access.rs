use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest,
};
use cosmian_kmip::kmip::kmip_types::UniqueIdentifier;
use cosmian_kms_utils::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, SuccessResponse, UserAccessResponse,
};
use tracing::{debug, info};

use crate::{database::KMSServer, result::KResult};

/// List objects owned by the current user
/// i.e. objects for which the user has full access
#[get("/access/owned")]
pub async fn list_owned_objects(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<ObjectOwnedResponse>>> {
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("GET /access/owned {user}");

    let list = kms
        .list_owned_objects(&user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List objects not owned by the user but for which an access
/// has been obtained by the user
#[get("/access/obtained")]
pub async fn list_access_rights_obtained(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<AccessRightsObtainedResponse>>> {
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("GET /access/granted {user}");

    let list = kms
        .list_access_rights_obtained(&user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List access rights for an object
#[get("/access/list/{object_id}")]
pub async fn list_accesses(
    req: HttpRequest,
    object_id: Path<(UniqueIdentifier,)>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<UserAccessResponse>>> {
    let object_id = object_id.to_owned().0;
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("GET /accesses/{object_id} {user}");

    let list = kms
        .list_accesses(&object_id, &user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// Grant an access right for an object, given a `userid`
#[post("/access/grant")]
pub async fn grant_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<SuccessResponse>> {
    let access = access.into_inner();
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("POST /access/grant {access:?} {user}");

    kms.grant_access(&access, &user, database_params.as_ref())
        .await?;
    debug!(
        "Access granted on {:?} for {:?} to {}",
        &access.unique_identifier, &access.operation_type, &access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully added", access.user_id),
    }))
}

/// Revoke an access authorization for an object, given a `userid`
#[post("/access/revoke")]
pub async fn revoke_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<SuccessResponse>> {
    let access = access.into_inner();
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("POST /access/revoke {access:?} {user}");

    kms.revoke_access(&access, &user, database_params.as_ref())
        .await?;
    debug!(
        "Access revoke on {:?} for {:?} to {}",
        &access.unique_identifier, &access.operation_type, &access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully deleted", access.user_id),
    }))
}

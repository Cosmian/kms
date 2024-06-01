use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest,
};
use cosmian_kmip::kmip::kmip_types::UniqueIdentifier;
use cosmian_kms_client::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, SuccessResponse, UserAccessResponse,
};
use tracing::{debug, info};

use crate::{core::KMS, result::KResult};

/// List objects owned by the current user
/// i.e. objects for which the user has full access
#[get("/access/owned")]
pub(crate) async fn list_owned_objects(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<ObjectOwnedResponse>>> {
    let span = tracing::span!(tracing::Level::INFO, "list_owned_objects");
    let _enter = span.enter();

    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(&req);
    info!(user = user, "GET /access/owned {user}");

    let list = kms
        .list_owned_objects(&user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List objects not owned by the user but for which an access
/// has been obtained by the user
#[get("/access/obtained")]
pub(crate) async fn list_access_rights_obtained(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<AccessRightsObtainedResponse>>> {
    let span = tracing::span!(tracing::Level::INFO, "list_access_rights_obtained");
    let _enter = span.enter();

    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(&req);
    info!(user = user, "GET /access/granted {user}");

    let list = kms
        .list_access_rights_obtained(&user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List access rights for an object
#[get("/access/list/{object_id}")]
pub(crate) async fn list_accesses(
    req: HttpRequest,
    object_id: Path<(String,)>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<UserAccessResponse>>> {
    let span = tracing::span!(tracing::Level::INFO, "list_accesses");
    let _enter = span.enter();

    let object_id = UniqueIdentifier::TextString(object_id.to_owned().0);
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(&req);
    info!(user = user, "GET /accesses/{object_id} {user}");

    let list = kms
        .list_accesses(&object_id, &user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// Grant an access right for an object, given a `userid`
#[post("/access/grant")]
pub(crate) async fn grant_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::INFO, "grant_access");
    let _enter = span.enter();

    let access = access.into_inner();
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(&req);
    info!(
        user = user,
        access = access.to_string(),
        "POST /access/grant {access:?} {user}"
    );

    kms.grant_access(&access, &user, database_params.as_ref())
        .await?;
    debug!(
        "Access granted on {:?} for {:?} to {}",
        access.unique_identifier, access.operation_types, access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully added", access.user_id),
    }))
}

/// Revoke an access authorization for an object, given a `userid`
#[post("/access/revoke")]
pub(crate) async fn revoke_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::INFO, "revoke_access");
    let _enter = span.enter();

    let access = access.into_inner();
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(&req);
    info!(
        user = user,
        access = access.to_string(),
        "POST /access/revoke {access:?} {user}"
    );

    kms.revoke_access(&access, &user, database_params.as_ref())
        .await?;
    debug!(
        "Access revoke on {:?} for {:?} to {}",
        access.unique_identifier, access.operation_types, access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully deleted", access.user_id),
    }))
}

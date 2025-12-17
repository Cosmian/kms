use std::sync::Arc;

use actix_web::{
    HttpRequest, get, post,
    web::{self, Data, Json, Path},
};
use cosmian_kms_access::access::{
    Access, AccessRightsObtainedResponse, CreatePermissionResponse, ObjectOwnedResponse,
    PrivilegedAccessResponse, SuccessResponse, UserAccessResponse,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    self, kmip_2_1::kmip_types::UniqueIdentifier,
};
use cosmian_logger::{debug, info};

use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission},
    result::KResult,
};

/// List objects owned by the current user
/// i.e., objects for which the user has full access
#[get("/access/owned")]
pub(crate) async fn list_owned_objects(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<ObjectOwnedResponse>>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_owned_objects");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    info!(user = user, "GET /access/owned {user}");

    let list = kms.list_owned_objects(&user).await?;

    Ok(Json(list))
}

/// List objects not owned by the user, but for which access
/// has been obtained by the user
#[get("/access/obtained")]
pub(crate) async fn list_access_rights_obtained(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<AccessRightsObtainedResponse>>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_access_rights_obtained");
    let _enter = span.enter();

    let user = kms.get_user(&req);
    info!(user = user, "GET /access/obtained {user}");

    let list = kms.list_access_rights_obtained(&user).await?;

    Ok(Json(list))
}

/// List access rights for an object
#[get("/access/list/{object_id}")]
pub(crate) async fn list_accesses(
    req: HttpRequest,
    object_id: Path<(String,)>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<Vec<UserAccessResponse>>> {
    let span = tracing::span!(tracing::Level::ERROR, "list_accesses");
    let _enter = span.enter();

    let object_id = UniqueIdentifier::TextString(object_id.to_owned().0);
    let user = kms.get_user(&req);
    info!(user = user, "GET /access/list/{object_id} {user}");

    let list = kms.list_accesses(&object_id, &user).await?;

    Ok(Json(list))
}

/// Grant an access right for an object, given a `userid`
#[post("/access/grant")]
pub(crate) async fn grant_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMS>>,
    privileged_users: web::Data<Option<Vec<String>>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "grant_access");
    let _enter = span.enter();

    let access = access.into_inner();
    let user = kms.get_user(&req);
    info!(
        user = user,
        access = access.to_string(),
        "POST /access/grant"
    );

    kms.grant_access(&access, &user, privileged_users.as_ref().clone())
        .await?;
    debug!("Access granted on {}", access.user_id);

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
    privileged_users: Data<Option<Vec<String>>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "revoke_access");
    let _enter = span.enter();

    let access = access.into_inner();
    let user = kms.get_user(&req);
    info!(
        user = user,
        access = access.to_string(),
        "POST /access/revoke"
    );

    kms.revoke_access(&access, &user, privileged_users.as_ref().clone())
        .await?;
    debug!("Access revoke for {}", access.user_id);

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully deleted", access.user_id),
    }))
}

/// Get if user has create access right
#[get("/access/create")]
pub(crate) async fn get_create_access(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    privileged_users: web::Data<Option<Vec<String>>>,
) -> KResult<Json<CreatePermissionResponse>> {
    let span = tracing::span!(tracing::Level::INFO, "get_create_access");
    let _enter = span.enter();

    let user = kms.get_user(&req);

    let has_create_permission = match privileged_users.as_ref() {
        Some(users) if users.contains(&user) => true,
        Some(_) => {
            user_has_permission(
                &user,
                None,
                &cosmian_kmip::kmip_2_1::KmipOperation::Create,
                &kms,
            )
            .await?
        }
        None => true, // Default permission when no privileged users are defined
    };
    Ok(Json(CreatePermissionResponse {
        has_create_permission,
    }))
}

/// Get if a user is a privileged user
#[get("/access/privileged")]
pub(crate) async fn get_privileged_access(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    privileged_users: web::Data<Option<Vec<String>>>,
) -> KResult<Json<PrivilegedAccessResponse>> {
    let span = tracing::span!(tracing::Level::INFO, "get_create_access");
    let _enter = span.enter();

    let user = kms.get_user(&req);

    let has_privileged_access = privileged_users
        .as_ref()
        .as_ref()
        .is_some_and(|users| users.contains(&user));
    Ok(Json(PrivilegedAccessResponse {
        has_privileged_access,
    }))
}

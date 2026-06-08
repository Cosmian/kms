use std::sync::Arc;

use actix_web::{
    HttpMessage, HttpRequest, get, post,
    web::{self, Data, Json, Path},
};
use cosmian_kms_access::access::{
    Access, AccessRightsObtainedResponse, CreatePermissionResponse, ObjectOwnedResponse,
    PrivilegedAccessResponse, SuccessResponse, UserAccessResponse,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    self, kmip_0::kmip_types::ErrorReason, kmip_2_1::kmip_types::UniqueIdentifier,
};
use cosmian_logger::{debug, info};
use serde::Serialize;

use crate::{
    core::{
        KMS,
        rbac::{
            audit::emit_rbac_audit,
            input_builder::{OperationContext, PolicyInput, RequestContext, Subject},
        },
        retrieve_object_utils::user_has_permission,
    },
    error::KmsError,
    middlewares::UserClaim,
    result::KResult,
};

/// Return the username that the server resolves for the current request.
/// Placed in the authenticated scope so that TLS/JWT/API-token middleware
/// has already populated `AuthenticatedUser` before this handler runs.
#[get("/me")]
pub(crate) async fn get_current_user(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<CurrentUserResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "GET /me {user}");
    Ok(Json(CurrentUserResponse { user }))
}

#[derive(Serialize)]
pub(crate) struct CurrentUserResponse {
    pub user: String,
}

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

    // RBAC Tier 3: enforce policy for access-management endpoints
    enforce_rbac_access_endpoint(&req, &kms, &user, "Grant", Some(&access))?;

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

    // RBAC Tier 3: enforce policy for access-management endpoints
    enforce_rbac_access_endpoint(&req, &kms, &user, "RevokeAccess", Some(&access))?;

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
                &[],
                None,
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

/// RBAC Tier 3 enforcement for access-management endpoints.
///
/// Evaluates the Regorus policy with an access-management operation context.
/// Only enforced when RBAC is fully enabled; otherwise a no-op.
fn enforce_rbac_access_endpoint(
    req: &HttpRequest,
    kms: &KMS,
    user: &str,
    operation: &str,
    access: Option<&Access>,
) -> KResult<()> {
    // Skip if RBAC not enabled
    if !kms.params.rbac.enabled {
        return Ok(());
    }

    let Some(evaluator) = kms.rbac_evaluator() else {
        return Ok(());
    };

    // Extract roles/tenant from JWT claims
    let extensions = req.extensions();
    let (roles, tenant_id) = extensions.get::<UserClaim>().map_or_else(
        || (Vec::new(), None),
        |claim| {
            (
                claim.extract_roles(&kms.params.rbac.role_claim),
                claim.extract_tenant_id(&kms.params.rbac.tenant_claim),
            )
        },
    );
    drop(extensions);

    let is_privileged = kms
        .params
        .privileged_users
        .as_ref()
        .is_some_and(|pu| pu.iter().any(|p| p == user));
    let is_super_admin = kms.params.rbac.super_admins.iter().any(|sa| sa == user);

    let mut effective_roles = roles;
    if is_super_admin && !effective_roles.contains(&"super-admin".to_owned()) {
        effective_roles.push("super-admin".to_owned());
    }

    // Build operation context with grant details
    let (target_user, grant_ops) = access.map_or((None, None), |a| {
        let ops: Vec<String> = a
            .operation_types
            .iter()
            .map(|op| format!("{op:?}"))
            .collect();
        (Some(a.user_id.clone()), Some(ops))
    });

    let input = PolicyInput::for_access_management(
        Subject {
            user_id: user.to_owned(),
            roles: effective_roles,
            tenant_id,
            is_privileged,
        },
        RequestContext {
            ip: None,
            tls_subject: None,
            user_agent: None,
        },
        OperationContext {
            kmip_op: operation.to_owned(),
            algorithm: None,
            mode: None,
            padding: None,
            target_user,
            grant_ops,
        },
    );

    let regorus_input = input
        .to_regorus_value()
        .map_err(|e| KmsError::ServerError(format!("Failed to build RBAC input: {e}")))?;

    let decision = evaluator.evaluate(&regorus_input);
    let bundle_hash = evaluator.bundle_hash();

    emit_rbac_audit(&input, &decision, &bundle_hash);

    if decision.allowed {
        Ok(())
    } else {
        Err(KmsError::Kmip21Error(
            ErrorReason::Permission_Denied,
            "authorization denied".to_owned(),
        ))
    }
}

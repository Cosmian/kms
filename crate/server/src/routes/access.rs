use std::sync::Arc;

use actix_web::{
    HttpRequest, get, post,
    web::{Data, Json, Path},
};
use cosmian_kms_access::access::{
    Access, AccessRightsObtainedResponse, CreatePermissionResponse, ObjectOwnedResponse,
    PrivilegedAccessResponse, SuccessResponse, UserAccessResponse,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    self, kmip_2_1::kmip_types::UniqueIdentifier,
};
use cosmian_logger::{debug, info};
use serde::{Deserialize, Serialize};
use tracing::info as trace_info;

use crate::{
    core::{
        KMS, operations::perform_crypto_officer_ceremony_activation,
        retrieve_object_utils::user_has_permission,
    },
    middlewares::UserId,
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
    info!(user = user.as_str(), "GET /me {user}");
    Ok(Json(CurrentUserResponse {
        user: user.into_string(),
    }))
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
    info!(user = user.as_str(), "GET /access/owned {user}");

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
    info!(user = user.as_str(), "GET /access/obtained {user}");

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
    info!(user = user.as_str(), "GET /access/list/{object_id} {user}");

    let list = kms.list_accesses(&object_id, &user).await?;

    Ok(Json(list))
}

/// Grant an access right for an object, given a `userid`
#[post("/access/grant")]
pub(crate) async fn grant_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "grant_access");
    let _enter = span.enter();

    let access = access.into_inner();
    let user = kms.get_user(&req);
    info!(
        user = user.as_str(),
        access = access.to_string(),
        "POST /access/grant"
    );

    kms.grant_access(&access, &user).await?;
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
) -> KResult<Json<SuccessResponse>> {
    let span = tracing::span!(tracing::Level::ERROR, "revoke_access");
    let _enter = span.enter();

    let access = access.into_inner();
    let user = kms.get_user(&req);
    info!(
        user = user.as_str(),
        access = access.to_string(),
        "POST /access/revoke"
    );

    kms.revoke_access(&access, &user).await?;
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
) -> KResult<Json<CreatePermissionResponse>> {
    let span = tracing::span!(tracing::Level::INFO, "get_create_access");
    let _enter = span.enter();

    let user = kms.get_user(&req);

    let has_create_permission = {
        let co_users = &kms.params.crypto_officer.users;
        if co_users.is_empty() || co_users.iter().any(|u| u == user.as_str()) {
            true
        } else {
            user_has_permission(
                &user,
                None,
                &cosmian_kmip::kmip_2_1::KmipOperation::Create,
                &kms,
            )
            .await?
        }
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
) -> KResult<Json<PrivilegedAccessResponse>> {
    let span = tracing::span!(tracing::Level::INFO, "get_privileged_access");
    let _enter = span.enter();

    let user = kms.get_user(&req);

    let has_privileged_access = {
        let co_users = &kms.params.crypto_officer.users;
        !co_users.is_empty() && co_users.iter().any(|u| u == user.as_str())
    };
    Ok(Json(PrivilegedAccessResponse {
        has_privileged_access,
    }))
}

// ── Crypto Officer status & disable ───────────────────────────────────────────

/// Response body for `GET /access/crypto_officer/status`
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
pub(crate) struct CryptoOfficerStatusResponse {
    /// Whether a Crypto Officer role configuration exists on the server.
    pub enabled: bool,
    /// List of usernames with Crypto Officer privileges (from server config).
    /// Only populated for active Crypto Officers; other users see an empty list.
    pub users: Vec<String>,
    /// Total number of Crypto Officer custodians configured on the server.
    /// Always set (unlike `users` which is hidden for non-CO users) so that
    /// ceremony candidates know how many share inputs to show in the UI.
    pub custodians_count: usize,
    /// Whether a split-key ceremony is required to activate the role.
    pub require_ceremony: bool,
    /// Whether the ceremony has been completed and the role is currently active.
    pub ceremony_activated: bool,
    /// Whether the current user is an active Crypto Officer.
    pub is_crypto_officer: bool,
}

/// Return the current Crypto Officer configuration and activation status.
///
/// **Authorization**: any authenticated user may call this endpoint (the
/// response is purely informational — it does not reveal key material).
#[get("/access/crypto_officer/status")]
pub(crate) async fn get_crypto_officer_status(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<CryptoOfficerStatusResponse>> {
    let user = kms.get_user(&req);
    info!(user = %user, "GET /access/crypto_officer/status {user}");

    let cfg = &kms.params.crypto_officer;
    if cfg.users.is_empty() {
        return Ok(Json(CryptoOfficerStatusResponse {
            enabled: false,
            users: vec![],
            custodians_count: 0,
            require_ceremony: false,
            ceremony_activated: false,
            is_crypto_officer: false,
        }));
    }

    let ceremony_activated = if cfg.require_ceremony {
        kms.database.is_crypto_officer_activated().await?
    } else {
        false
    };

    let is_crypto_officer = kms.is_crypto_officer(&user).await?;

    // Only reveal the CryptoOfficer user list to active CryptoOfficers.
    // This prevents privileged-user enumeration by regular Operators.
    let users = if is_crypto_officer {
        cfg.users.clone()
    } else {
        Vec::new()
    };

    Ok(Json(CryptoOfficerStatusResponse {
        enabled: true,
        users,
        custodians_count: cfg.users.len(),
        require_ceremony: cfg.require_ceremony,
        ceremony_activated,
        is_crypto_officer,
    }))
}

/// Request body for `POST /access/crypto_officer/disable`.
///
/// When `target_user` is `None`, the caller self-revokes their own active CO ceremony.
/// When `target_user` is `Some(user_id)`, any configured CO candidate can peer-revoke
/// the specified active CO.
#[derive(Deserialize, Default)]
pub(crate) struct DisableCryptoOfficerRequest {
    /// The user ID of the active CO to revoke. If omitted, the caller self-revokes.
    pub(crate) target_user: Option<String>,
}

/// Disable an active Crypto Officer ceremony.
///
/// **Ceremony mode only**: sets `revoked_at` on the active ceremony record.
/// Subsequent Crypto Officer lifecycle operations will be denied until a
/// new ceremony completes.
///
/// In config-only mode, Crypto Officer privileges must be removed by editing
/// the server configuration and restarting.
///
/// **Authorization**:
/// - Self-revoke (no `target_user`): caller must be an active CO.
/// - Peer revocation (`target_user` provided): caller must be a configured CO candidate;
///   target must be an active CO.
#[post("/access/crypto_officer/disable")]
pub(crate) async fn disable_crypto_officer(
    req: HttpRequest,
    body: Json<DisableCryptoOfficerRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let user = kms.get_user(&req);
    let target = body.0.target_user.as_deref().map(UserId::from);
    info!(user = %user, target = ?body.0.target_user, "POST /access/crypto_officer/disable");

    kms.disable_crypto_officer_ceremony(&user, target.as_ref())
        .await?;

    Ok(Json(SuccessResponse {
        success: "Crypto Officer ceremony activation revoked successfully".to_owned(),
    }))
}

// ── Crypto Officer ceremony activation ────────────────────────────────────────

/// Request body for `POST /access/crypto_officer/ceremony/activate`.
#[derive(Deserialize)]
pub(crate) struct CeremonyActivateRequest {
    /// UIDs of the split-key shares to reconstruct from (all n shares required).
    pub share_ids: Vec<String>,
}

/// Activate the Crypto Officer role via an XOR split-key ceremony.
///
/// Reconstructs the ceremony secret from the provided shares **in RAM only** —
/// the secret is never stored as a KMS managed object (ADP-20 / NIST SP 800-57
/// Part 2 Rev 1 §4.6). After verifying dual-control and ceremony-attribute
/// constraints, the activation record is persisted and the secret is zeroized.
///
/// **Authorization**: caller must be listed in `crypto_officer_users`.
///
/// **Ceremony mode only**: returns an error when `require_ceremony = false`.
#[post("/access/crypto_officer/ceremony/activate")]
pub(crate) async fn activate_crypto_officer_ceremony(
    req: HttpRequest,
    body: Json<CeremonyActivateRequest>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let user = kms.get_user(&req);
    trace_info!(user = %user, "POST /access/crypto_officer/ceremony/activate {user}");

    perform_crypto_officer_ceremony_activation(&kms, &body.share_ids, user.as_str()).await?;

    Ok(Json(SuccessResponse {
        success: format!("Crypto Officer ceremony activated for user '{user}'."),
    }))
}

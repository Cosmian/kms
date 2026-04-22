use std::sync::Arc;

use actix_web::{
    HttpRequest, get, post,
    web::{Data, Json, Path, Query},
};
use cosmian_kms_server_database::reexport::cosmian_kms_interfaces::Notification;
use cosmian_logger::info;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{core::KMS, error::KmsError, result::KResult};

#[derive(Deserialize)]
pub(crate) struct NotificationListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct NotificationListResponse {
    pub items: Vec<Notification>,
    pub total_unread: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Serialize)]
pub(crate) struct UnreadCountResponse {
    pub unread: i64,
}

#[derive(Serialize)]
pub(crate) struct SuccessResponse {
    pub success: bool,
}

/// List notifications for the current user (unread first, most recent first).
#[get("/notifications")]
pub(crate) async fn list_notifications(
    req: HttpRequest,
    query: Query<NotificationListQuery>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<NotificationListResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "GET /notifications {user}");

    let page = query.page.unwrap_or(0);
    let page_size = query.page_size.unwrap_or(20).min(100);
    let offset = page * page_size;

    let items = kms
        .database
        .list_notifications(&user, page_size, offset)
        .await
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    let total_unread = kms
        .database
        .count_unread_notifications(&user)
        .await
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    Ok(Json(NotificationListResponse {
        items,
        total_unread,
        page,
        page_size,
    }))
}

/// Return the number of unread notifications for the current user.
#[get("/notifications/count")]
pub(crate) async fn count_unread_notifications(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<UnreadCountResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "GET /notifications/count {user}");

    let unread = kms
        .database
        .count_unread_notifications(&user)
        .await
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    Ok(Json(UnreadCountResponse { unread }))
}

/// Mark a single notification as read.
#[post("/notifications/{id}/read")]
pub(crate) async fn mark_notification_read(
    req: HttpRequest,
    id: Path<i64>,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let user = kms.get_user(&req);
    let id = id.into_inner();
    info!(user = user, "POST /notifications/{id}/read {user}");

    let success = kms
        .database
        .mark_notification_read(id, &user, OffsetDateTime::now_utc())
        .await
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    Ok(Json(SuccessResponse { success }))
}

/// Mark all notifications as read for the current user.
#[post("/notifications/read-all")]
pub(crate) async fn mark_all_notifications_read(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<SuccessResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "POST /notifications/read-all {user}");

    kms.database
        .mark_all_notifications_read(&user, OffsetDateTime::now_utc())
        .await
        .map_err(|e| KmsError::ServerError(e.to_string()))?;

    Ok(Json(SuccessResponse { success: true }))
}

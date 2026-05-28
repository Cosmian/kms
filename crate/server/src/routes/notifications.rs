use std::sync::Arc;

use actix_web::{
    HttpRequest, get, post,
    web::{Data, Json, Path, Query},
};
use cosmian_logger::info;
use serde::{Deserialize, Serialize};

use crate::{core::KMS, result::KResult};

/// Query parameters for listing notifications.
#[derive(Debug, Deserialize)]
pub(crate) struct ListNotificationsParams {
    /// Maximum number of notifications to return (default: 50).
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: i64,
}

const fn default_limit() -> i64 {
    50
}

/// Response for listing notifications.
#[derive(Serialize)]
pub(crate) struct ListNotificationsResponse {
    pub notifications: Vec<NotificationItem>,
}

/// A single notification item returned by the API.
#[derive(Serialize)]
pub(crate) struct NotificationItem {
    pub id: i64,
    pub event_type: String,
    pub message: String,
    pub object_id: Option<String>,
    pub created_at: String,
    pub read_at: Option<String>,
}

/// Response for the unread count endpoint.
#[derive(Serialize)]
pub(crate) struct UnreadCountResponse {
    pub count: i64,
}

/// Response for mark-read operations.
#[derive(Serialize)]
pub(crate) struct MarkReadResponse {
    pub success: bool,
}

/// List notifications for the current user.
#[get("/notifications")]
pub(crate) async fn list_notifications(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    params: Query<ListNotificationsParams>,
) -> KResult<Json<ListNotificationsResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "GET /notifications");

    let notifications = kms
        .database
        .list_notifications(&user, params.limit, params.offset)
        .await?;

    let items = notifications
        .into_iter()
        .map(|n| NotificationItem {
            id: n.id,
            event_type: n.event_type,
            message: n.message,
            object_id: n.object_id,
            created_at: n
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            read_at: n.read_at.and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            }),
        })
        .collect();

    Ok(Json(ListNotificationsResponse {
        notifications: items,
    }))
}

/// Count unread notifications for the current user.
#[get("/notifications/unread/count")]
pub(crate) async fn count_unread_notifications(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<UnreadCountResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "GET /notifications/unread/count");

    let count = kms.database.count_unread_notifications(&user).await?;
    Ok(Json(UnreadCountResponse { count }))
}

/// Mark a single notification as read.
#[post("/notifications/{id}/read")]
pub(crate) async fn mark_notification_read(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<i64>,
) -> KResult<Json<MarkReadResponse>> {
    let user = kms.get_user(&req);
    let notification_id = path.into_inner();
    info!(user = user, "POST /notifications/{notification_id}/read");

    let now = time::OffsetDateTime::now_utc();
    kms.database
        .mark_notification_read(notification_id, &user, now)
        .await?;
    Ok(Json(MarkReadResponse { success: true }))
}

/// Mark all notifications as read for the current user.
#[post("/notifications/read-all")]
pub(crate) async fn mark_all_notifications_read(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<MarkReadResponse>> {
    let user = kms.get_user(&req);
    info!(user = user, "POST /notifications/read-all");

    let now = time::OffsetDateTime::now_utc();
    kms.database.mark_all_notifications_read(&user, now).await?;
    Ok(Json(MarkReadResponse { success: true }))
}

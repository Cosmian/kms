use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::InterfaceResult;

/// A persisted notification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: i64,
    pub user_id: String,
    pub event_type: String,
    pub message: String,
    pub object_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub read_at: Option<OffsetDateTime>,
}

#[async_trait(?Send)]
pub trait NotificationsStore {
    /// Persist a new notification record and return its auto-generated id.
    async fn create_notification(
        &self,
        user_id: &str,
        event_type: &str,
        message: &str,
        object_id: Option<&str>,
        created_at: OffsetDateTime,
    ) -> InterfaceResult<i64>;

    /// List notifications for a user (unread first, then by descending creation date).
    async fn list_notifications(
        &self,
        user_id: &str,
        limit: i64,
        offset: i64,
    ) -> InterfaceResult<Vec<Notification>>;

    /// Return the count of unread notifications for a user.
    async fn count_unread(&self, user_id: &str) -> InterfaceResult<i64>;

    /// Mark a single notification as read (returns false if not found or not owned by user).
    async fn mark_read(&self, id: i64, user_id: &str, now: OffsetDateTime)
    -> InterfaceResult<bool>;

    /// Mark all notifications as read for the given user.
    async fn mark_all_read(&self, user_id: &str, now: OffsetDateTime) -> InterfaceResult<()>;
}

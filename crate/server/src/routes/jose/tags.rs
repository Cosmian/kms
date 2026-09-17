use std::{collections::HashSet, sync::Arc};

use actix_web::{
    HttpRequest, delete, get, post,
    web::{Data, Json, Path},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::GetAttributes;
use cosmian_logger::trace;

use super::{CryptoApiError, TagsRequest, TagsResponse};
use crate::{core::KMS, error::KmsError, middlewares::UserId};

/// `POST /v1/crypto/keys/{kid}/tags` — add user tags to a key.
///
/// Tags are merged with the existing tag set (idempotent: duplicates are ignored).
/// System tags (prefix `_`) are rejected with `400 Bad Request`.
#[post("/keys/{kid}/tags")]
pub(crate) async fn add_tags(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    kid: Path<String>,
    body: Json<TagsRequest>,
) -> Result<Json<TagsResponse>, CryptoApiError> {
    let user = kms.get_user(&req);
    let kid = kid.into_inner();
    let body = body.into_inner();

    trace!(user = user.as_str(), "POST /v1/crypto/keys/{kid}/tags");

    validate_user_tags(&body.tags)?;

    let mut all_tags = fetch_all_tags(&kms, &kid, &user).await?;
    all_tags.extend(body.tags.into_iter());

    persist_tags(&kms, &kid, &all_tags).await?;

    Ok(Json(tags_response(kid, all_tags)))
}

/// `DELETE /v1/crypto/keys/{kid}/tags` — remove user tags from a key.
///
/// Tags not present on the key are silently ignored (idempotent).
/// System tags (prefix `_`) are rejected with `400 Bad Request`.
#[delete("/keys/{kid}/tags")]
pub(crate) async fn remove_tags(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    kid: Path<String>,
    body: Json<TagsRequest>,
) -> Result<Json<TagsResponse>, CryptoApiError> {
    let user = kms.get_user(&req);
    let kid = kid.into_inner();
    let body = body.into_inner();

    trace!(user = user.as_str(), "DELETE /v1/crypto/keys/{kid}/tags");

    validate_user_tags(&body.tags)?;

    let mut all_tags = fetch_all_tags(&kms, &kid, &user).await?;
    let to_remove: HashSet<String> = body.tags.into_iter().collect();
    all_tags.retain(|t| !to_remove.contains(t));

    persist_tags(&kms, &kid, &all_tags).await?;

    Ok(Json(tags_response(kid, all_tags)))
}

/// `GET /v1/crypto/keys/{kid}/tags` — list the current user tags on a key.
///
/// System tags (prefix `_`) are never included in the response.
#[get("/keys/{kid}/tags")]
pub(crate) async fn list_tags(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    kid: Path<String>,
) -> Result<Json<TagsResponse>, CryptoApiError> {
    let user = kms.get_user(&req);
    let kid = kid.into_inner();

    trace!(user = user.as_str(), "GET /v1/crypto/keys/{kid}/tags");

    let all_tags = fetch_all_tags(&kms, &kid, &user).await?;

    Ok(Json(tags_response(kid, all_tags)))
}

/// Validate that every tag in `tags` is non-empty and does not start with `_`.
fn validate_user_tags(tags: &[String]) -> Result<(), CryptoApiError> {
    for tag in tags {
        if tag.is_empty() {
            return Err(CryptoApiError::BadRequest(
                "Tags must not be empty strings.".to_owned(),
            ));
        }
        if tag.starts_with('_') {
            return Err(CryptoApiError::BadRequest(format!(
                "Tag '{tag}' is invalid: user tags must not start with '_' \
                 (that prefix is reserved for system tags)."
            )));
        }
    }
    Ok(())
}

/// Verify existence + ownership of `kid`, then return all current tags from the
/// DB column (includes system tags such as `_kk`).
///
/// Uses `GetAttributes` to enforce KMIP authorization (returns 404 if the key
/// does not exist for this user, 403 if the user cannot access it).
async fn fetch_all_tags(
    kms: &Arc<KMS>,
    kid: &str,
    user: &UserId,
) -> Result<HashSet<String>, CryptoApiError> {
    // Auth / existence gate.
    kms.get_attributes(GetAttributes::from(kid), user)
        .await
        .map_err(CryptoApiError::from)?;

    // Read the DB tags column (source of truth for tag searches and for
    // GetAttributes tag responses — NOT the VendorAttribute blob).
    kms.database
        .retrieve_tags(kid)
        .await
        .map_err(|e| CryptoApiError::from(KmsError::from(e)))
}

/// Persist `new_all_tags` (the complete set, including system tags) to the DB.
///
/// Requires the full `Object` struct that `update_object` needs.  We fetch it
/// here via `retrieve_object`; this is safe because `fetch_all_tags` already
/// verified access.
async fn persist_tags(
    kms: &Arc<KMS>,
    kid: &str,
    new_all_tags: &HashSet<String>,
) -> Result<(), CryptoApiError> {
    let owm = kms
        .database
        .retrieve_object(kid)
        .await
        .map_err(|e| CryptoApiError::from(KmsError::from(e)))?
        .ok_or_else(|| CryptoApiError::NotFound(format!("Key '{kid}' not found")))?;

    kms.database
        .update_object(kid, owm.object(), owm.attributes(), Some(new_all_tags))
        .await
        .map_err(|e| CryptoApiError::from(KmsError::from(e)))
}

fn tags_response(kid: String, all_tags: HashSet<String>) -> TagsResponse {
    let mut user_tags: Vec<String> = all_tags
        .into_iter()
        .filter(|t| !t.starts_with('_'))
        .collect();
    user_tags.sort_unstable();
    TagsResponse {
        kid,
        tags: user_tags,
    }
}

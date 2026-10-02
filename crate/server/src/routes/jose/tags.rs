use std::{collections::HashSet, sync::Arc};

use actix_web::{
    HttpRequest, delete, get, post,
    web::{Data, Json, Path},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_logger::trace;

use super::{CryptoApiError, TagsRequest, TagsResponse};
use crate::{
    core::{KMS, ObjectHandle, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    middlewares::UserId,
};

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

    let (uid, mut all_tags) =
        fetch_all_tags(&kms, &kid, &user, KmipOperation::AddAttribute).await?;
    all_tags.extend(body.tags.into_iter());

    persist_tags(&kms, &uid, &all_tags).await?;

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

    let (uid, mut all_tags) =
        fetch_all_tags(&kms, &kid, &user, KmipOperation::DeleteAttribute).await?;
    let to_remove: HashSet<String> = body.tags.into_iter().collect();
    all_tags.retain(|t| !to_remove.contains(t));

    persist_tags(&kms, &uid, &all_tags).await?;

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

    let (_uid, all_tags) = fetch_all_tags(&kms, &kid, &user, KmipOperation::GetAttributes).await?;

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

/// Authorize `operation` on `kid`, then return the resolved UID and all current
/// tags from the DB column (includes system tags such as `_kk`).
///
/// Reading tags only needs `GetAttributes`, which any grant on the object satisfies.
/// Changing them must require the same permission as the equivalent KMIP operation
/// (`AddAttribute` / `DeleteAttribute`): otherwise a user holding only e.g. an
/// `Encrypt` grant could rewrite tags, breaking tag-based lookups or publishing a key
/// on the unauthenticated JWKS endpoint via the `jwks` tag.
async fn fetch_all_tags(
    kms: &Arc<KMS>,
    kid: &str,
    user: &UserId,
    operation: KmipOperation,
) -> Result<(String, HashSet<String>), CryptoApiError> {
    // Auth / existence gate (Object_Not_Found when the user lacks `operation`).
    let owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(kid),
        operation,
        kms,
        user,
    ))
    .await
    .map_err(CryptoApiError::from)?;
    let uid = owm.id().to_owned();

    // Read the DB tags column (source of truth for tag searches and for
    // GetAttributes tag responses — NOT the VendorAttribute blob).
    let tags = kms
        .database
        .retrieve_tags(&uid)
        .await
        .map_err(|e| CryptoApiError::from(KmsError::from(e)))?;
    Ok((uid, tags))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic_in_result_fn)]
mod tests {
    use std::sync::Arc;

    use cosmian_kms_access::access::Access;
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        KmipOperation, extra::tagging::VENDOR_ID_COSMIAN, kmip_types::CryptographicAlgorithm,
        requests::symmetric_key_create_request,
    };

    use super::fetch_all_tags;
    use crate::{
        config::ServerParams, core::KMS, middlewares::UserId, result::KResult,
        tests::test_utils::https_clap_config,
    };

    /// A user holding only `Encrypt` may read tags but not add or remove them.
    #[tokio::test]
    async fn test_tag_changes_require_attribute_permissions() -> KResult<()> {
        let kms = Arc::new(
            KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?,
        );
        let alice = UserId::from("alice");
        let bob = UserId::from("bob");
        let request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            ["payments"],
            false,
            None,
        )?;
        let kid = kms
            .create(request, &alice)
            .await?
            .unique_identifier
            .to_string();
        kms.grant_access(
            &Access {
                unique_identifier: Some(kid.clone().into()),
                user_id: "bob".to_owned(),
                operation_types: vec![KmipOperation::Encrypt],
            },
            &alice,
        )
        .await?;

        drop(
            fetch_all_tags(&kms, &kid, &bob, KmipOperation::GetAttributes)
                .await
                .unwrap(),
        );
        for op in [KmipOperation::AddAttribute, KmipOperation::DeleteAttribute] {
            assert!(
                fetch_all_tags(&kms, &kid, &bob, op).await.is_err(),
                "an Encrypt-only grant must not allow {op:?} on tags"
            );
        }
        drop(
            fetch_all_tags(&kms, &kid, &alice, KmipOperation::AddAttribute)
                .await
                .unwrap(),
        );
        Ok(())
    }
}

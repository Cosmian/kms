//! Vault KV v2-compatible secret store (`/<kv_mount>/` and `/v1/<kv_mount>/` scopes).
//!
//! `vault`/`bao` always prefix requests with `/v1/`, write with `PUT`, and probe
//! `GET /v1/sys/internal/ui/mounts/<path>` to detect KV v2 (see [`mount_preflight`]).
//!
//! Routes (relative to the configured mount, default `kv`):
//!   `POST|PUT /data/{path}`            — create/update a secret (new version)
//!   `GET    /data/{path}[?version=N]`  — read the latest (or a specific) version
//!   `DELETE /data/{path}`              — soft-delete the latest version
//!   `GET    /metadata/{path}`          — read version/metadata bookkeeping
//!   `GET    /metadata/{prefix}?list=true` — list child keys under a prefix
//!   `DELETE /metadata/{path}`          — hard-delete all versions + metadata
//!
//! See [`metadata`] for the storage layout and ACL model.

// Clippy misdetects the actix-web `{path:.*}` tail-match syntax used by every
// route below as a format string. A per-function `#[allow]` does not work here:
// the `#[get]`/`#[post]`/`#[delete]` attribute macros consume the item and drop
// sibling attributes when they regenerate it, so the allow must be module-wide.
#![allow(clippy::literal_string_with_formatting_args)]

pub(crate) mod error;
pub(crate) mod metadata;
pub(crate) mod types;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use actix_web::{
    HttpRequest, HttpResponse, delete, get, route,
    web::{Data, Json, Path, Query},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation},
    cosmian_kms_interfaces::AtomicOperation,
};
use time::OffsetDateTime;
use uuid::Uuid;

use self::{
    error::{KvApiError, KvResult},
    metadata::{
        PathMetadata, VersionEntry, authorize, create_object_operation, find_metadata, meta_tag,
        metadata_update_operation, next_path_metadata_uid, now_rfc3339, path_tag, save_metadata,
        secret_bytes, ttl_tag, validate_path_length, version_tag,
    },
    types::{
        DataWrapper, GetSecretData, ListData, MountInfo, MountOptions, PutSecretData,
        PutSecretRequest, ReadMetadataResponseData, VersionMetadata,
    },
};
use crate::core::KMS;

/// Parse a Vault-style duration (`"30s"`, `"5m"`, `"1h"`, `"2d"`, or a bare
/// integer number of seconds) into a number of seconds.
fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let split_at = s.char_indices().last()?.0;
    let (num, suffix) = s.split_at(split_at);
    let n: i64 = num.parse().ok()?;
    match suffix {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3_600),
        "d" => n.checked_mul(86_400),
        _ => None,
    }
}

/// `POST|PUT /data/{path}` — create or update a secret (writes a new version).
///
/// `vault kv put` / `bao kv put` send `PUT`; `POST` is the documented KV v2 alias.
#[route("/data/{path:.*}", method = "POST", method = "PUT")]
pub(crate) async fn put_secret(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    body: Json<PutSecretRequest>,
) -> KvResult<Json<DataWrapper<PutSecretData>>> {
    let user = kms.get_user(&req);
    let path = path.into_inner();
    if path.is_empty() {
        return Err(KvApiError::BadRequest("path must not be empty".to_owned()));
    }
    validate_path_length(&path)?;

    let now = now_rfc3339()?;
    let ttl_expiration = body
        .options
        .ttl
        .as_deref()
        .map(|ttl| {
            let secs = parse_duration_secs(ttl)
                .ok_or_else(|| KvApiError::BadRequest(format!("invalid ttl: '{ttl}'")))?;
            OffsetDateTime::now_utc()
                .unix_timestamp()
                .checked_add(secs)
                .ok_or_else(|| KvApiError::BadRequest(format!("ttl is out of range: '{ttl}'")))
        })
        .transpose()?;
    let secret_bytes_value = serde_json::to_vec(&body.data)
        .map_err(|e| KvApiError::BadRequest(format!("invalid secret data: {e}")))?;

    let (meta_uid, owner, mut path_metadata, expected_metadata_object) =
        if let Some((uid, owm, path_metadata)) = find_metadata(&kms, &path).await? {
            authorize(&kms, &owm, &user, KmipOperation::Import).await?;
            (
                uid,
                owm.owner_id().clone(),
                path_metadata,
                Some(owm.object().clone()),
            )
        } else {
            let (uid, existing) = next_path_metadata_uid(&kms, &path).await?;
            if let Some((owm, path_metadata)) = existing {
                authorize(&kms, &owm, &user, KmipOperation::Import).await?;
                (
                    uid,
                    owm.owner_id().clone(),
                    path_metadata,
                    Some(owm.object().clone()),
                )
            } else {
                // First write to this path: the caller becomes the path owner —
                // implicitly authorized, mirroring `spire::transit::create_transit_key`.
                let path_metadata = PathMetadata {
                    path: path.clone(),
                    current_version: 0,
                    oldest_version: 1,
                    created_time: now.clone(),
                    updated_time: now.clone(),
                    versions: HashMap::new(),
                };
                (uid, user.clone(), path_metadata, None)
            }
        };

    let next_version = path_metadata
        .current_version
        .checked_add(1)
        .ok_or_else(|| KvApiError::BadRequest("KV version counter is exhausted".to_owned()))?;
    let version_uid = Uuid::new_v4().to_string();
    let mut version_tags = vec![version_tag(&path, next_version), path_tag(&path)];
    if let Some(expires_at) = ttl_expiration {
        version_tags.push(ttl_tag(expires_at));
    }
    path_metadata.current_version = next_version;
    path_metadata.updated_time.clone_from(&now);
    path_metadata.versions.insert(
        next_version.to_string(),
        VersionEntry {
            created_time: now.clone(),
            deletion_time: String::new(),
            destroyed: false,
            object_uid: Some(version_uid.clone()),
        },
    );
    let creating_metadata = expected_metadata_object.is_none();
    let metadata_operation = if let Some(expected_object) = expected_metadata_object {
        metadata_update_operation(&kms, &meta_uid, &expected_object, &path, &path_metadata)?
    } else {
        let bytes = serde_json::to_vec(&path_metadata).map_err(|e| {
            KvApiError::InternalError(format!("failed to serialize KV metadata: {e}"))
        })?;
        create_object_operation(&kms, &meta_uid, &owner, &bytes, &[meta_tag(&path)])?
    };
    let version_operation = create_object_operation(
        &kms,
        &version_uid,
        &owner,
        &secret_bytes_value,
        &version_tags,
    )?;
    let result = kms
        .database
        .atomic(&owner, &[metadata_operation, version_operation])
        .await;
    if let Err(error) = result {
        if creating_metadata && kms.database.retrieve_object(&meta_uid).await?.is_some() {
            return Err(KvApiError::Conflict(format!(
                "path '{path}' was created concurrently; retry the write"
            )));
        }
        return Err(KvApiError::from(error));
    }

    Ok(Json(DataWrapper {
        data: PutSecretData {
            version: next_version,
            created_time: now,
            deletion_time: String::new(),
            destroyed: false,
        },
    }))
}

#[derive(serde::Deserialize)]
pub(crate) struct VersionQuery {
    version: Option<u64>,
}

/// `GET /data/{path}[?version=N]` — read the latest or a specific version.
#[get("/data/{path:.*}")]
pub(crate) async fn get_secret(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    query: Query<VersionQuery>,
) -> KvResult<Json<DataWrapper<GetSecretData>>> {
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;

    let (_, owm, path_metadata) = find_metadata(&kms, &path)
        .await?
        .ok_or_else(|| KvApiError::NotFound(format!("no secret at path '{path}'")))?;
    authorize(&kms, &owm, &user, KmipOperation::Get).await?;

    let requested_version = query.version.unwrap_or(path_metadata.current_version);
    if requested_version == 0 {
        return Err(KvApiError::NotFound(format!("no secret at path '{path}'")));
    }
    let version_entry = path_metadata
        .versions
        .get(&requested_version.to_string())
        .ok_or_else(|| KvApiError::NotFound(format!("version {requested_version} not found")))?;
    if version_entry.destroyed || !version_entry.deletion_time.is_empty() {
        return Err(KvApiError::NotFound(format!(
            "version {requested_version} has been deleted"
        )));
    }

    let version_uid = if let Some(uid) = &version_entry.object_uid {
        uid.clone()
    } else {
        lookup_version_uid(&kms, &path, requested_version, owm.owner()).await?
    };
    let version_owm = kms
        .database
        .retrieve_object(&version_uid)
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?
        .ok_or_else(|| KvApiError::NotFound(format!("version {requested_version} not found")))?;
    let version_tags = version_owm.attributes().get_tags(kms.vendor_id());
    if version_owm.owner() != owm.owner()
        || !version_tags.contains(&version_tag(&path, requested_version))
    {
        return Err(KvApiError::InternalError(format!(
            "KV metadata for path '{path}' does not match version {requested_version}"
        )));
    }
    if matches!(
        version_owm.state(),
        State::Destroyed | State::Destroyed_Compromised
    ) {
        return Err(KvApiError::NotFound(format!(
            "version {requested_version} has been destroyed"
        )));
    }
    let bytes = secret_bytes(&version_owm)?;
    let data: HashMap<String, serde_json::Value> = serde_json::from_slice(&bytes)
        .map_err(|e| KvApiError::InternalError(format!("corrupt KV secret data: {e}")))?;

    Ok(Json(DataWrapper {
        data: GetSecretData {
            data,
            metadata: VersionMetadata {
                version: requested_version,
                created_time: version_entry.created_time.clone(),
                deletion_time: version_entry.deletion_time.clone(),
                destroyed: version_entry.destroyed,
            },
        },
    }))
}

/// Find the uid of the `SecretData` object holding version `version` of `path`.
async fn lookup_version_uid(
    kms: &KMS,
    path: &str,
    version: u64,
    expected_owner: &str,
) -> KvResult<String> {
    let tag = version_tag(path, version);
    let mut uids: Vec<String> = kms
        .database
        .list_uids_for_tags(&HashSet::from([tag]))
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?
        .into_iter()
        .collect();
    uids.sort();
    let mut destroyed_uid = None;
    for uid in uids {
        let owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| KvApiError::InternalError(e.to_string()))?
            .ok_or_else(|| {
                KvApiError::InternalError(format!(
                    "version {version} indexed in metadata but object missing for path '{path}'"
                ))
            })?;
        if owm.owner() != expected_owner {
            continue;
        }
        if !matches!(owm.state(), State::Destroyed | State::Destroyed_Compromised) {
            return Ok(uid);
        }
        if destroyed_uid.is_none() {
            destroyed_uid = Some(uid);
        }
    }
    if let Some(uid) = destroyed_uid {
        return Ok(uid);
    }
    Err(KvApiError::InternalError(format!(
        "version {version} indexed in metadata but object missing for path '{path}'"
    )))
}

/// `DELETE /data/{path}` — soft-delete the latest version (sets `deletion_time`;
/// the underlying object is kept — only `GET` treats it as absent).
#[delete("/data/{path:.*}")]
pub(crate) async fn soft_delete_secret(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KvResult<HttpResponse> {
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;

    let (_meta_uid, owm, mut path_metadata) = find_metadata(&kms, &path)
        .await?
        .ok_or_else(|| KvApiError::NotFound(format!("no secret at path '{path}'")))?;
    authorize(&kms, &owm, &user, KmipOperation::Destroy).await?;

    let version = path_metadata.current_version;
    let now = now_rfc3339()?;
    if let Some(entry) = path_metadata.versions.get_mut(&version.to_string()) {
        entry.deletion_time.clone_from(&now);
    }
    path_metadata.updated_time = now;
    save_metadata(&kms, &owm, &path, &path_metadata).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[derive(serde::Deserialize)]
pub(crate) struct ListQuery {
    list: Option<String>,
}

/// `GET /metadata/{path}` — read version bookkeeping, or (with `?list=true`)
/// `GET /metadata/{prefix}?list=true` — list immediate child keys under `prefix`.
#[get("/metadata/{path:.*}")]
pub(crate) async fn read_or_list_metadata(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    query: Query<ListQuery>,
) -> KvResult<Json<DataWrapper<serde_json::Value>>> {
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;

    if query.list.as_deref() == Some("true") {
        let keys = list_child_keys(&kms, &user, &path).await?;
        return Ok(Json(DataWrapper {
            data: serde_json::to_value(ListData { keys }).map_err(|e| {
                KvApiError::InternalError(format!("failed to serialize KV list: {e}"))
            })?,
        }));
    }

    let (_, owm, path_metadata) = find_metadata(&kms, &path)
        .await?
        .ok_or_else(|| KvApiError::NotFound(format!("no secret at path '{path}'")))?;
    authorize(&kms, &owm, &user, KmipOperation::Locate).await?;

    let versions = path_metadata
        .versions
        .into_iter()
        .map(|(v, entry)| {
            (
                v.clone(),
                VersionMetadata {
                    version: v.parse().unwrap_or_default(),
                    created_time: entry.created_time,
                    deletion_time: entry.deletion_time,
                    destroyed: entry.destroyed,
                },
            )
        })
        .collect();

    let data = ReadMetadataResponseData {
        current_version: path_metadata.current_version,
        oldest_version: path_metadata.oldest_version,
        created_time: path_metadata.created_time,
        updated_time: path_metadata.updated_time,
        versions,
    };
    Ok(Json(DataWrapper {
        data: serde_json::to_value(data)
            .map_err(|e| KvApiError::InternalError(format!("failed to serialize metadata: {e}")))?,
    }))
}

/// Enumerate the immediate child key names directly under `prefix`, among the
/// paths `user` can `Locate` (owned or explicitly shared).
async fn list_child_keys(
    kms: &KMS,
    user: &crate::middlewares::UserId,
    prefix: &str,
) -> KvResult<Vec<String>> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::ObjectType,
    };

    let filter = Attributes {
        object_type: Some(ObjectType::SecretData),
        ..Attributes::default()
    };
    let results = kms
        .database
        .find(Some(&filter), None, user, false, kms.vendor_id())
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?;

    let mut keys: Vec<String> = Vec::new();
    for (_uid, state, attrs) in results {
        if matches!(state, State::Destroyed | State::Destroyed_Compromised) {
            continue;
        }
        let tags = attrs.get_tags(kms.vendor_id());
        let Some(meta_tag_value) = tags.iter().find(|t| t.starts_with("_kv::meta::")) else {
            continue;
        };
        let full_path = &meta_tag_value["_kv::meta::".len()..];
        if let Some(entry) = list_entry_name(prefix, full_path) {
            if !keys.contains(&entry) {
                keys.push(entry);
            }
        }
    }
    keys.sort();
    Ok(keys)
}

/// Compute the single child-key entry name `full_path` contributes under
/// `prefix` (Vault convention: a `/`-suffixed name denotes a nested "directory").
fn list_entry_name(prefix: &str, full_path: &str) -> Option<String> {
    let prefix = prefix.trim_end_matches('/');
    let remainder = full_path.strip_prefix(prefix)?;
    let remainder = if prefix.is_empty() {
        remainder
    } else {
        remainder.strip_prefix('/')?
    };
    if remainder.is_empty() {
        return None;
    }
    Some(
        remainder
            .split_once('/')
            .map_or_else(|| remainder.to_owned(), |(head, _)| format!("{head}/")),
    )
}

/// `GET /v1/sys/internal/ui/mounts/{path}` — the pre-flight `vault`/`bao kv` sends before every
/// command to choose between KV v1 and v2.
///
/// Only the KV mount answers. Any other path is a 404, which the CLI reads as "KV v1" and which
/// keeps this scope from claiming anything else under `/v1/sys`.
#[get("/{path:.*}")]
pub(crate) async fn mount_preflight(
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KvResult<Json<DataWrapper<MountInfo>>> {
    let mount = &kms.params.kv_mount;
    let path = path.into_inner();
    let requested_mount = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    if requested_mount != mount {
        return Err(KvApiError::NotFound(format!("no mount at '{path}'")));
    }
    Ok(Json(DataWrapper {
        data: MountInfo {
            path: format!("{mount}/"),
            mount_type: "kv",
            description: "Eviden KMS KV v2-compatible secret store",
            options: MountOptions { version: "2" },
        },
    }))
}

/// `DELETE /metadata/{path}` — hard-delete every version and the metadata itself.
#[delete("/metadata/{path:.*}")]
pub(crate) async fn hard_delete_path(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KvResult<HttpResponse> {
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;

    let (meta_uid, owm, path_metadata) = find_metadata(&kms, &path)
        .await?
        .ok_or_else(|| KvApiError::NotFound(format!("no secret at path '{path}'")))?;
    authorize(&kms, &owm, &user, KmipOperation::Destroy).await?;

    let mut version_uids = HashMap::with_capacity(path_metadata.versions.len());
    for (version, entry) in &path_metadata.versions {
        let version = version.parse::<u64>().map_err(|e| {
            KvApiError::InternalError(format!(
                "invalid version '{version}' in KV metadata for path '{path}': {e}"
            ))
        })?;
        let uid = if let Some(uid) = &entry.object_uid {
            uid.clone()
        } else {
            lookup_version_uid(&kms, &path, version, owm.owner()).await?
        };
        if version_uids.insert(uid, version).is_some() {
            return Err(KvApiError::InternalError(format!(
                "multiple KV versions for path '{path}' reference the same object"
            )));
        }
    }

    let metadata_operation =
        metadata_update_operation(&kms, &meta_uid, owm.object(), &path, &path_metadata)?;
    let mut operations = Vec::with_capacity(version_uids.len() * 2 + 2);
    operations.push(metadata_operation);
    operations.push(AtomicOperation::UpdateState((meta_uid, State::Destroyed)));
    for (uid, version) in version_uids {
        let version_owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| KvApiError::InternalError(e.to_string()))?
            .ok_or_else(|| {
                KvApiError::InternalError(format!(
                    "version {version} for path '{path}' references a missing object"
                ))
            })?;
        let version_tags = version_owm.attributes().get_tags(kms.vendor_id());
        if version_owm.owner() != owm.owner()
            || !version_tags.contains(&version_tag(&path, version))
        {
            return Err(KvApiError::InternalError(format!(
                "KV metadata for path '{path}' does not match version {version}"
            )));
        }
        let object = version_owm.object();
        operations.push(AtomicOperation::CompareAndSwapObject {
            uid: uid.clone(),
            expected_object: Box::new(object.clone()),
            object: Box::new(object.clone()),
            attributes: version_owm.attributes().clone(),
            tags: None,
        });
        operations.push(AtomicOperation::UpdateState((uid, State::Destroyed)));
    }
    kms.database
        .atomic(owm.owner_id(), &operations)
        .await
        .map_err(KvApiError::from)?;

    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_secs("30"), Some(30));
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("1h"), Some(3_600));
        assert_eq!(parse_duration_secs("2d"), Some(172_800));
        assert_eq!(parse_duration_secs("bogus"), None);
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_duration_secs("9223372036854775807m"), None);
    }

    #[test]
    fn list_entry_name_direct_child() {
        assert_eq!(
            list_entry_name("myapp", "myapp/config"),
            Some("config".to_owned())
        );
    }

    #[test]
    fn list_entry_name_nested_child_is_a_directory() {
        assert_eq!(
            list_entry_name("myapp", "myapp/db/password"),
            Some("db/".to_owned())
        );
    }

    #[test]
    fn list_entry_name_exact_prefix_match_is_not_a_child() {
        assert_eq!(list_entry_name("myapp", "myapp"), None);
    }

    #[test]
    fn list_entry_name_unrelated_path_is_none() {
        assert_eq!(list_entry_name("myapp", "other/config"), None);
    }

    #[test]
    fn list_entry_name_requires_a_path_boundary() {
        assert_eq!(list_entry_name("myapp", "myapplication/config"), None);
        assert_eq!(
            list_entry_name("myapp/", "myapp/config"),
            Some("config".to_owned())
        );
    }

    // ── HTTP-level tests (issue #863 acceptance criteria) ────────────────────
    //
    // `#[get]`/`#[post]`/`#[delete]` expand each handler into an opaque
    // `HttpServiceFactory`, not a callable fn, so these go through a real
    // (middleware-free) actix `App`. Identity is injected by a tiny test-only
    // `from_fn` middleware reading `TEST_USER_HEADER` — the same extension slot
    // (`AuthenticatedUser`) the production auth middlewares populate.

    use actix_web::{
        App, HttpMessage,
        body::{BoxBody, MessageBody},
        dev::{Service, ServiceRequest, ServiceResponse},
        http::StatusCode,
        middleware::{Next, from_fn},
        test::{TestRequest, call_service, init_service, read_body_json},
    };

    use crate::{
        middlewares::{AuthMethod, AuthenticatedUser, UserId},
        result::KResult,
        tests::test_utils::test_kms,
    };

    const TEST_USER_HEADER: &str = "x-test-user";

    async fn inject_test_user<B: MessageBody + 'static>(
        req: ServiceRequest,
        next: Next<B>,
    ) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
        if let Some(user) = req
            .headers()
            .get(TEST_USER_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            req.extensions_mut().insert(AuthenticatedUser {
                username: UserId::from(user),
                auth_method: AuthMethod::DefaultUser,
            });
        }
        next.call(req)
            .await
            .map(ServiceResponse::map_into_boxed_body)
    }

    async fn kv_test_app(
        kms: Arc<KMS>,
    ) -> impl Service<
        actix_http::Request,
        Response = ServiceResponse<impl MessageBody>,
        Error = actix_web::Error,
    > {
        init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(put_secret)
                .service(get_secret)
                .service(soft_delete_secret)
                .service(read_or_list_metadata)
                .service(hard_delete_path),
        )
        .await
    }

    fn put_body(data: &serde_json::Value, ttl: Option<&str>) -> serde_json::Value {
        serde_json::json!({ "data": data, "options": { "ttl": ttl } })
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        let put_resp = call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/config")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"api_key": "xyz"}), None))
                .to_request(),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::OK);
        let put_body: serde_json::Value = read_body_json(put_resp).await;
        assert_eq!(put_body["data"]["version"], 1);

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/config")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_body: serde_json::Value = read_body_json(get_resp).await;
        assert_eq!(get_body["data"]["data"]["api_key"], "xyz");
        assert_eq!(get_body["data"]["metadata"]["version"], 1);
        Ok(())
    }

    #[tokio::test]
    async fn versioning_writes_create_new_versions() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        for value in ["one", "two"] {
            let resp = call_service(
                &app,
                TestRequest::post()
                    .uri("/data/myapp/versioned")
                    .insert_header((TEST_USER_HEADER, "alice"))
                    .set_json(put_body(&serde_json::json!({"v": value}), None))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let latest: serde_json::Value = read_body_json(
            call_service(
                &app,
                TestRequest::get()
                    .uri("/data/myapp/versioned")
                    .insert_header((TEST_USER_HEADER, "alice"))
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(latest["data"]["metadata"]["version"], 2);
        assert_eq!(latest["data"]["data"]["v"], "two");

        let first: serde_json::Value = read_body_json(
            call_service(
                &app,
                TestRequest::get()
                    .uri("/data/myapp/versioned?version=1")
                    .insert_header((TEST_USER_HEADER, "alice"))
                    .to_request(),
            )
            .await,
        )
        .await;
        assert_eq!(first["data"]["data"]["v"], "one");
        Ok(())
    }

    #[tokio::test]
    async fn get_uses_the_metadata_uid_and_ignores_forged_version_tags() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/forged-version";
        let app = kv_test_app(kms.clone()).await;
        call_service(
            &app,
            TestRequest::post()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "original"}), None))
                .to_request(),
        )
        .await;

        metadata::create_object(
            &kms,
            "00000000-0000-0000-0000-000000000001",
            &UserId::from("mallory"),
            br#"{"k":"forged"}"#,
            &[version_tag(path, 1), path_tag(path)],
        )
        .await
        .expect("foreign tagged object is created");

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body: serde_json::Value = read_body_json(get_resp).await;
        assert_eq!(body["data"]["data"]["k"], "original");
        Ok(())
    }

    #[tokio::test]
    async fn get_legacy_metadata_ignores_foreign_objects_with_forged_version_tags() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/legacy-forged-version";
        let app = kv_test_app(kms.clone()).await;
        call_service(
            &app,
            TestRequest::post()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "original"}), None))
                .to_request(),
        )
        .await;
        let (_, metadata_owm, mut path_metadata) = find_metadata(&kms, path)
            .await
            .expect("metadata lookup succeeds")
            .expect("metadata exists");
        path_metadata
            .versions
            .get_mut("1")
            .expect("version exists")
            .object_uid = None;
        save_metadata(&kms, &metadata_owm, path, &path_metadata)
            .await
            .expect("legacy metadata is saved");

        metadata::create_object(
            &kms,
            "00000000-0000-0000-0000-000000000002",
            &UserId::from("mallory"),
            br#"{"k":"forged"}"#,
            &[version_tag(path, 1), path_tag(path)],
        )
        .await
        .expect("foreign tagged object is created");

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body: serde_json::Value = read_body_json(get_resp).await;
        assert_eq!(body["data"]["data"]["k"], "original");
        Ok(())
    }

    #[tokio::test]
    async fn soft_delete_hides_latest_version_from_get() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/to-delete")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;
        let del_resp = call_service(
            &app,
            TestRequest::delete()
                .uri("/data/myapp/to-delete")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/to-delete")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn hard_delete_removes_metadata_entirely() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/hard-deleted";
        let app = kv_test_app(kms.clone()).await;

        call_service(
            &app,
            TestRequest::post()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;
        let (meta_uid, meta_owm, path_metadata) = find_metadata(&kms, path)
            .await
            .expect("metadata lookup succeeds")
            .expect("metadata exists before hard delete");
        let version_uid = lookup_version_uid(&kms, path, 1, meta_owm.owner())
            .await
            .expect("version lookup succeeds");
        let del_resp = call_service(
            &app,
            TestRequest::delete()
                .uri(&format!("/metadata/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        let list_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/metadata/myapp?list=true")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        let list_body: serde_json::Value = read_body_json(list_resp).await;
        assert_eq!(list_body["data"]["keys"], serde_json::json!([]));

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/hard-deleted")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);

        let stale_save = save_metadata(&kms, &meta_owm, path, &path_metadata).await;
        assert!(
            matches!(stale_save, Err(KvApiError::Conflict(_))),
            "stale metadata update should be rejected, got {stale_save:?}"
        );
        assert_eq!(
            kms.database
                .retrieve_object(&meta_uid)
                .await?
                .expect("metadata object remains indexed")
                .state(),
            State::Destroyed
        );
        assert_eq!(
            kms.database
                .retrieve_object(&version_uid)
                .await?
                .expect("version object remains indexed")
                .state(),
            State::Destroyed
        );
        Ok(())
    }

    #[tokio::test]
    async fn hard_delete_uses_version_uids_without_path_tag_index() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/unindexed-version";
        let now = "2026-01-01T00:00:00Z".to_owned();
        let version_uid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let path_metadata = PathMetadata {
            path: path.to_owned(),
            current_version: 1,
            oldest_version: 1,
            created_time: now.clone(),
            updated_time: now.clone(),
            versions: HashMap::from([(
                "1".to_owned(),
                VersionEntry {
                    created_time: now,
                    deletion_time: String::new(),
                    destroyed: false,
                    object_uid: Some(version_uid.to_owned()),
                },
            )]),
        };
        let metadata_bytes =
            serde_json::to_vec(&path_metadata).expect("metadata serialization succeeds");
        metadata::create_object(
            &kms,
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            &UserId::from("alice"),
            &metadata_bytes,
            &[meta_tag(path)],
        )
        .await
        .expect("metadata object is created");
        let secret_bytes = serde_json::to_vec(&serde_json::json!({"secret": "unindexed"}))
            .expect("secret serialization succeeds");
        metadata::create_object(
            &kms,
            version_uid,
            &UserId::from("alice"),
            &secret_bytes,
            &[version_tag(path, 1)],
        )
        .await
        .expect("version object is created without a path tag");

        let app = kv_test_app(kms.clone()).await;
        let response = call_service(
            &app,
            TestRequest::delete()
                .uri(&format!("/metadata/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            kms.database
                .retrieve_object(version_uid)
                .await?
                .expect("version object remains retrievable")
                .state(),
            State::Destroyed
        );
        Ok(())
    }

    #[tokio::test]
    async fn hard_delete_rejects_foreign_object_uids_from_metadata() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/foreign-version";
        let app = kv_test_app(kms.clone()).await;
        call_service(
            &app,
            TestRequest::post()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "original"}), None))
                .to_request(),
        )
        .await;
        let (_, metadata_owm, mut path_metadata) = find_metadata(&kms, path)
            .await
            .expect("metadata lookup succeeds")
            .expect("metadata exists");
        let foreign_uid = "00000000-0000-0000-0000-000000000003";
        metadata::create_object(
            &kms,
            foreign_uid,
            &UserId::from("mallory"),
            br#"{"k":"foreign"}"#,
            &[version_tag(path, 1), path_tag(path)],
        )
        .await
        .expect("foreign tagged object is created");
        path_metadata
            .versions
            .get_mut("1")
            .expect("version exists")
            .object_uid = Some(foreign_uid.to_owned());
        save_metadata(&kms, &metadata_owm, path, &path_metadata)
            .await
            .expect("metadata is updated with the foreign uid");

        let delete_resp = call_service(
            &app,
            TestRequest::delete()
                .uri(&format!("/metadata/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(delete_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(
            kms.database
                .retrieve_object(foreign_uid)
                .await?
                .expect("foreign object remains stored")
                .state(),
            State::Destroyed
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_returns_child_keys_under_prefix() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        for p in ["myapp/a", "myapp/b", "other/c"] {
            let resp = call_service(
                &app,
                TestRequest::post()
                    .uri(&format!("/data/{p}"))
                    .insert_header((TEST_USER_HEADER, "alice"))
                    .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let list_resp: serde_json::Value = read_body_json(
            call_service(
                &app,
                TestRequest::get()
                    .uri("/metadata/myapp?list=true")
                    .insert_header((TEST_USER_HEADER, "alice"))
                    .to_request(),
            )
            .await,
        )
        .await;
        let keys: Vec<String> =
            serde_json::from_value(list_resp["data"]["keys"].clone()).unwrap_or_default();
        assert_eq!(keys, vec!["a".to_owned(), "b".to_owned()]);
        Ok(())
    }

    /// Acceptance criterion: unauthorized access (no grant) returns `403`.
    #[tokio::test]
    async fn get_by_non_owner_without_grant_is_forbidden() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;

        let resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn non_owner_without_grants_cannot_write_read_metadata_or_delete() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "original"}), None))
                .to_request(),
        )
        .await;

        let put_resp = call_service(
            &app,
            TestRequest::put()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .set_json(put_body(&serde_json::json!({"k": "overwritten"}), None))
                .to_request(),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::FORBIDDEN);

        let metadata_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/metadata/myapp/private")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .to_request(),
        )
        .await;
        assert_eq!(metadata_resp.status(), StatusCode::FORBIDDEN);

        let soft_delete_resp = call_service(
            &app,
            TestRequest::delete()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .to_request(),
        )
        .await;
        assert_eq!(soft_delete_resp.status(), StatusCode::FORBIDDEN);

        let hard_delete_resp = call_service(
            &app,
            TestRequest::delete()
                .uri("/metadata/myapp/private")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .to_request(),
        )
        .await;
        assert_eq!(hard_delete_resp.status(), StatusCode::FORBIDDEN);

        let owner_get = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(owner_get.status(), StatusCode::OK);
        let owner_body: serde_json::Value = read_body_json(owner_get).await;
        assert_eq!(owner_body["data"]["data"]["k"], "original");
        Ok(())
    }

    #[tokio::test]
    async fn list_hides_paths_without_locate_grant() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/private")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;

        let list_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/metadata/myapp?list=true")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .to_request(),
        )
        .await;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_body: serde_json::Value = read_body_json(list_resp).await;
        assert_eq!(list_body["data"]["keys"], serde_json::json!([]));
        Ok(())
    }

    #[tokio::test]
    async fn ttl_out_of_range_is_rejected_without_creating_metadata() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        let put_resp = call_service(
            &app,
            TestRequest::put()
                .uri("/data/myapp/invalid-ttl")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(
                    &serde_json::json!({"k": "v"}),
                    Some("9223372036854775807s"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::BAD_REQUEST);

        let metadata_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/metadata/myapp/invalid-ttl")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(metadata_resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn path_longer_than_sql_tag_limit_is_rejected() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;
        let path = "a".repeat(metadata::MAX_KV_PATH_LENGTH + 1);
        let response = call_service(
            &app,
            TestRequest::put()
                .uri(&format!("/data/{path}"))
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn destroyed_metadata_does_not_hide_a_recreated_path() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/recreated";
        let old_uid = "00000000-0000-0000-0000-000000000001";
        let owner = UserId::from("alice");
        let now = "2026-01-01T00:00:00Z".to_owned();
        let old_metadata = PathMetadata {
            path: path.to_owned(),
            current_version: 0,
            oldest_version: 1,
            created_time: now.clone(),
            updated_time: now,
            versions: HashMap::new(),
        };
        let old_metadata_bytes =
            serde_json::to_vec(&old_metadata).expect("metadata serialization succeeds");
        metadata::create_object(
            &kms,
            old_uid,
            &owner,
            &old_metadata_bytes,
            &[meta_tag(path)],
        )
        .await
        .expect("old metadata object is created");
        kms.database
            .update_state(old_uid, State::Destroyed)
            .await
            .expect("old metadata object is destroyed");

        let app = kv_test_app(kms).await;
        let put_resp = call_service(
            &app,
            TestRequest::put()
                .uri("/data/myapp/recreated")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "new"}), None))
                .to_request(),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::OK);
        let put_body: serde_json::Value = read_body_json(put_resp).await;
        assert_eq!(put_body["data"]["version"], 1);

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/recreated")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_body: serde_json::Value = read_body_json(get_resp).await;
        assert_eq!(get_body["data"]["data"]["k"], "new");
        Ok(())
    }

    /// Acceptance criterion: a secret written with `options.ttl` is destroyed
    /// once the TTL sweep runs after it elapses.
    #[tokio::test]
    async fn ttl_expired_version_is_swept_and_destroyed() -> KResult<()> {
        let kms = test_kms().await?;
        let kms_for_sweep = kms.clone();
        let app = kv_test_app(kms).await;

        // A negative TTL is already elapsed the instant it is written.
        call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/ephemeral")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), Some("-1")))
                .to_request(),
        )
        .await;

        let swept = Box::pin(metadata::sweep_expired_versions(&kms_for_sweep)).await;
        assert_eq!(swept, 1);

        let resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/ephemeral")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    /// `vault kv put` / `bao kv put` write with `PUT`, not `POST`.
    #[tokio::test]
    async fn put_method_writes_a_new_version() -> KResult<()> {
        let kms = test_kms().await?;
        let app = kv_test_app(kms).await;

        let resp = call_service(
            &app,
            TestRequest::put()
                .uri("/data/myapp/via-put")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = read_body_json(resp).await;
        assert_eq!(body["data"]["version"], 1);
        Ok(())
    }

    /// The CLI pre-flight must report the KV mount as KV v2 (`options.version == "2"`) in the
    /// `data` envelope, with the trailing-slash path Vault uses, for the mount and any sub-path.
    #[tokio::test]
    async fn preflight_reports_kv_v2_for_the_mount() -> KResult<()> {
        let kms = test_kms().await?;
        let app = init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(
                    actix_web::web::scope("/v1/sys/internal/ui/mounts").service(mount_preflight),
                ),
        )
        .await;

        for uri in [
            "/v1/sys/internal/ui/mounts/kv",
            "/v1/sys/internal/ui/mounts/kv/myapp/config",
        ] {
            let resp = call_service(
                &app,
                TestRequest::get()
                    .uri(uri)
                    .insert_header((TEST_USER_HEADER, "alice"))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let body: serde_json::Value = read_body_json(resp).await;
            assert_eq!(body["data"]["path"], "kv/");
            assert_eq!(body["data"]["type"], "kv");
            assert_eq!(body["data"]["options"]["version"], "2");
        }
        Ok(())
    }

    /// A path outside the KV mount is a 404, which the CLI interprets as KV v1.
    #[tokio::test]
    async fn preflight_other_mount_is_not_found() -> KResult<()> {
        let kms = test_kms().await?;
        let app = init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(
                    actix_web::web::scope("/v1/sys/internal/ui/mounts").service(mount_preflight),
                ),
        )
        .await;

        let resp = call_service(
            &app,
            TestRequest::get()
                .uri("/v1/sys/internal/ui/mounts/transit/keys/x")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn version_tag_cannot_authorize_access_to_a_numeric_path() -> KResult<()> {
        let kms = test_kms().await?;
        let now = "2026-01-01T00:00:00Z".to_owned();
        let attacker = UserId::from("mallory");
        let victim = UserId::from("alice");
        let fake_metadata = PathMetadata {
            path: "1".to_owned(),
            current_version: 1,
            oldest_version: 1,
            created_time: now.clone(),
            updated_time: now.clone(),
            versions: HashMap::from([(
                "1".to_owned(),
                VersionEntry {
                    created_time: now.clone(),
                    deletion_time: String::new(),
                    destroyed: false,
                    object_uid: None,
                },
            )]),
        };
        let fake_metadata_bytes =
            serde_json::to_vec(&fake_metadata).expect("fake metadata serialization succeeds");
        metadata::create_object(
            &kms,
            "00000000-0000-0000-0000-000000000001",
            &attacker,
            &fake_metadata_bytes,
            &[version_tag("meta", 1)],
        )
        .await
        .expect("attacker version object is created");

        let victim_metadata = PathMetadata {
            path: "1".to_owned(),
            current_version: 1,
            oldest_version: 1,
            created_time: now.clone(),
            updated_time: now,
            versions: HashMap::from([(
                "1".to_owned(),
                VersionEntry {
                    created_time: "2026-01-01T00:00:00Z".to_owned(),
                    deletion_time: String::new(),
                    destroyed: false,
                    object_uid: Some("11111111-1111-1111-1111-111111111111".to_owned()),
                },
            )]),
        };
        let victim_metadata_bytes =
            serde_json::to_vec(&victim_metadata).expect("victim metadata serialization succeeds");
        metadata::create_object(
            &kms,
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            &victim,
            &victim_metadata_bytes,
            &[meta_tag("1")],
        )
        .await
        .expect("victim metadata object is created");
        let victim_secret = serde_json::to_vec(&serde_json::json!({"secret": "victim"}))
            .expect("victim secret serialization succeeds");
        metadata::create_object(
            &kms,
            "11111111-1111-1111-1111-111111111111",
            &victim,
            &victim_secret,
            &[version_tag("1", 1), path_tag("1")],
        )
        .await
        .expect("victim version object is created");

        let app = kv_test_app(kms).await;
        let response = call_service(
            &app,
            TestRequest::get()
                .uri("/data/1")
                .insert_header((TEST_USER_HEADER, "mallory"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_tag_with_mismatched_path_is_rejected() -> KResult<()> {
        let kms = test_kms().await?;
        let now = "2026-01-01T00:00:00Z".to_owned();
        let fake_metadata = PathMetadata {
            path: "other".to_owned(),
            current_version: 0,
            oldest_version: 1,
            created_time: now.clone(),
            updated_time: now,
            versions: HashMap::new(),
        };
        let bytes = serde_json::to_vec(&fake_metadata).expect("metadata serialization succeeds");
        metadata::create_object(
            &kms,
            "00000000-0000-0000-0000-000000000001",
            &UserId::from("mallory"),
            &bytes,
            &[meta_tag("1")],
        )
        .await
        .expect("metadata object is created");

        assert!(matches!(
            find_metadata(&kms, "1").await,
            Err(KvApiError::InternalError(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn get_rejects_destroyed_version_object_with_active_metadata() -> KResult<()> {
        let kms = test_kms().await?;
        let path = "myapp/destroyed-version";
        let now = "2026-01-01T00:00:00Z".to_owned();
        let path_metadata = PathMetadata {
            path: path.to_owned(),
            current_version: 1,
            oldest_version: 1,
            created_time: now.clone(),
            updated_time: now.clone(),
            versions: HashMap::from([(
                "1".to_owned(),
                VersionEntry {
                    created_time: now,
                    deletion_time: String::new(),
                    destroyed: false,
                    object_uid: None,
                },
            )]),
        };
        let metadata_bytes =
            serde_json::to_vec(&path_metadata).expect("metadata serialization succeeds");
        metadata::create_object(
            &kms,
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            &UserId::from("alice"),
            &metadata_bytes,
            &[meta_tag(path)],
        )
        .await
        .expect("metadata object is created");
        let version_uid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let version_bytes = serde_json::to_vec(&serde_json::json!({"secret": "destroyed"}))
            .expect("version serialization succeeds");
        metadata::create_object(
            &kms,
            version_uid,
            &UserId::from("alice"),
            &version_bytes,
            &[version_tag(path, 1), path_tag(path)],
        )
        .await
        .expect("version object is created");
        kms.database
            .update_state(version_uid, State::Destroyed)
            .await?;

        let app = kv_test_app(kms).await;
        let response = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/destroyed-version")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}

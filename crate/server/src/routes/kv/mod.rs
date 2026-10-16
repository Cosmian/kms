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
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::State, kmip_2_1::KmipOperation,
};
use time::OffsetDateTime;
use uuid::Uuid;

use self::{
    error::{KvApiError, KvResult},
    metadata::{
        PathMetadata, VersionEntry, authorize, create_object, find_metadata, meta_tag, now_rfc3339,
        save_metadata, secret_bytes, ttl_tag, version_tag,
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
        "m" => Some(n * 60),
        "h" => Some(n * 3_600),
        "d" => Some(n * 86_400),
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

    let now = now_rfc3339()?;
    let secret_bytes_value = serde_json::to_vec(&body.data)
        .map_err(|e| KvApiError::BadRequest(format!("invalid secret data: {e}")))?;

    let (meta_uid, owner, mut path_metadata) =
        if let Some((uid, owm, path_metadata)) = find_metadata(&kms, &path).await? {
            authorize(&kms, &owm, &user, KmipOperation::Import).await?;
            (uid, owm.owner_id().clone(), path_metadata)
        } else {
            // First write to this path: the caller becomes the path owner —
            // implicitly authorized, mirroring `spire::transit::create_transit_key`.
            let uid = Uuid::new_v4().to_string();
            let path_metadata = PathMetadata {
                path: path.clone(),
                current_version: 0,
                oldest_version: 1,
                created_time: now.clone(),
                updated_time: now.clone(),
                versions: HashMap::new(),
            };
            let bytes = serde_json::to_vec(&path_metadata).map_err(|e| {
                KvApiError::InternalError(format!("failed to serialize KV metadata: {e}"))
            })?;
            create_object(&kms, &uid, &user, &bytes, &[meta_tag(&path)]).await?;
            (uid, user.clone(), path_metadata)
        };

    let next_version = path_metadata.current_version + 1;
    let version_uid = Uuid::new_v4().to_string();
    let mut version_tags = vec![version_tag(&path, next_version)];
    if let Some(ttl) = &body.options.ttl {
        let secs = parse_duration_secs(ttl)
            .ok_or_else(|| KvApiError::BadRequest(format!("invalid ttl: '{ttl}'")))?;
        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + secs;
        version_tags.push(ttl_tag(expires_at));
    }
    create_object(
        &kms,
        &version_uid,
        &owner,
        &secret_bytes_value,
        &version_tags,
    )
    .await?;

    path_metadata.current_version = next_version;
    path_metadata.updated_time.clone_from(&now);
    path_metadata.versions.insert(
        next_version.to_string(),
        VersionEntry {
            created_time: now.clone(),
            deletion_time: String::new(),
            destroyed: false,
        },
    );
    save_metadata(&kms, &meta_uid, &owner, &path, &path_metadata).await?;

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

    let version_uid = lookup_version_uid(&kms, &path, requested_version).await?;
    let version_owm = kms
        .database
        .retrieve_object(&version_uid)
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?
        .ok_or_else(|| KvApiError::NotFound(format!("version {requested_version} not found")))?;
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
async fn lookup_version_uid(kms: &KMS, path: &str, version: u64) -> KvResult<String> {
    let tag = version_tag(path, version);
    kms.database
        .list_uids_for_tags(&HashSet::from([tag]))
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| {
            KvApiError::InternalError(format!(
                "version {version} indexed in metadata but object missing for path '{path}'"
            ))
        })
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

    let (meta_uid, owm, mut path_metadata) = find_metadata(&kms, &path)
        .await?
        .ok_or_else(|| KvApiError::NotFound(format!("no secret at path '{path}'")))?;
    authorize(&kms, &owm, &user, KmipOperation::Destroy).await?;

    let version = path_metadata.current_version;
    let now = now_rfc3339()?;
    if let Some(entry) = path_metadata.versions.get_mut(&version.to_string()) {
        entry.deletion_time.clone_from(&now);
    }
    path_metadata.updated_time = now;
    save_metadata(&kms, &meta_uid, owm.owner_id(), &path, &path_metadata).await?;

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
    for (_uid, _state, attrs) in results {
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
    let remainder = full_path.strip_prefix(prefix)?;
    let remainder = remainder.strip_prefix('/').unwrap_or(remainder);
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

    let (meta_uid, owm, path_metadata) = find_metadata(&kms, &path)
        .await?
        .ok_or_else(|| KvApiError::NotFound(format!("no secret at path '{path}'")))?;
    authorize(&kms, &owm, &user, KmipOperation::Destroy).await?;

    for version_str in path_metadata.versions.keys() {
        let Ok(version) = version_str.parse::<u64>() else {
            continue;
        };
        if let Ok(uid) = lookup_version_uid(&kms, &path, version).await {
            kms.database
                .update_state(&uid, State::Destroyed)
                .await
                .map_err(|e| KvApiError::InternalError(e.to_string()))?;
        }
    }
    kms.database
        .update_state(&meta_uid, State::Destroyed)
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?;

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
        let app = kv_test_app(kms).await;

        call_service(
            &app,
            TestRequest::post()
                .uri("/data/myapp/hard-deleted")
                .insert_header((TEST_USER_HEADER, "alice"))
                .set_json(put_body(&serde_json::json!({"k": "v"}), None))
                .to_request(),
        )
        .await;
        let del_resp = call_service(
            &app,
            TestRequest::delete()
                .uri("/metadata/myapp/hard-deleted")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        let get_resp = call_service(
            &app,
            TestRequest::get()
                .uri("/data/myapp/hard-deleted")
                .insert_header((TEST_USER_HEADER, "alice"))
                .to_request(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
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
}

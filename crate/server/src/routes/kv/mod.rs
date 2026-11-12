//! Vault KV v2-compatible secret store (`/<kv_mount>/` and `/v1/<kv_mount>/` scopes).
//!
//! `vault`/`bao` always prefix requests with `/v1/`, write with `PUT`, and probe
//! `GET /v1/sys/internal/ui/mounts/<path>` to detect KV v2 (see [`configure_mount_routes`]).
//!
//! Routes (relative to the configured mount, default `kv`), registered by [`configure_routes`]:
//!   `POST|PUT /data/{path}`            — create/update a secret (new version)
//!   `GET    /data/{path}[?version=N]`  — read the latest (`N` absent or `0`) or a specific version
//!   `DELETE /data/{path}`              — soft-delete the latest version
//!   `GET    /metadata/{path}`          — read version/metadata bookkeeping
//!   `GET    /metadata/{prefix}?list=true` — list child keys under a prefix (`404` when none)
//!   `LIST   /metadata/{prefix}`        — same, with the Vault `LIST` HTTP verb
//!   `DELETE /metadata/{path}`          — hard-delete all versions + metadata
//!
//! A path that does not exist and a path the caller may not use both answer
//! `403 permission denied`, so a caller cannot probe other identities' paths by reading them.
//! See [`metadata`] for the storage layout and ACL model.

pub(crate) mod error;
pub(crate) mod metadata;
pub(crate) mod types;

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

use actix_web::{
    HttpRequest, HttpResponse,
    error::JsonPayloadError,
    guard,
    web::{self, Data, Json, Path, Query},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation, kmip_attributes::Attributes, kmip_objects::ObjectType,
            kmip_types::OperationEnumeration,
        },
    },
    cosmian_kms_interfaces::{AtomicOperation, DestroyedFilter, FindOptions, ObjectWithMetadata},
};
use futures::{StreamExt, TryStreamExt, stream};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::{
    error::{CONCURRENT_UPDATE, KvApiError, KvResult},
    metadata::{
        MAX_KV_GENERATIONS, MAX_KV_LIST_CANDIDATES, MAX_KV_VERSIONS, PathLookup, PathMetadata,
        VersionEntry, authorize, create_object_operation, destroy_version_operations,
        find_metadata, lookup_path, meta_tag, metadata_tags, metadata_update_operation, now,
        save_metadata, secret_bytes, ttl_active_tag, validate_path_length, version_tag,
    },
    types::{
        DataWrapper, GetSecretData, KvSecretMap, ListData, MountInfo, MountOptions, PutSecretData,
        PutSecretRequest, ReadMetadataResponseData, VersionMetadata,
    },
};
use crate::{
    core::{KMS, operations::check_role_permission},
    middlewares::UserId,
    routes::parse_duration_secs,
};

/// Version objects a hard delete reads concurrently.
const HARD_DELETE_READ_CONCURRENCY: usize = 16;

/// JSON body configuration of the KV scopes: errors use the Vault `errors` envelope and never
/// echo the body. `Content-Type` is not required: the Vault Go client does not always send it.
pub(crate) fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .content_type_required(false)
        .error_handler(|error, _request| {
            let message = match error {
                JsonPayloadError::OverflowKnownLength { .. }
                | JsonPayloadError::Overflow { .. } => "request body is too large",
                JsonPayloadError::ContentType => "unsupported content type",
                _ => "invalid JSON request body",
            };
            KvApiError::BadRequest(message.to_owned()).into()
        })
}

/// Query-string configuration of the KV scopes: errors use the Vault `errors` envelope.
pub(crate) fn query_config() -> web::QueryConfig {
    web::QueryConfig::default().error_handler(|_error, _request| {
        KvApiError::BadRequest("invalid query string".to_owned()).into()
    })
}

/// Unknown route under a KV scope.
fn route_not_found() -> std::future::Ready<KvResult<HttpResponse>> {
    std::future::ready(Err(KvApiError::NotFound("unsupported path".to_owned())))
}

/// Known route, unsupported HTTP method.
fn unsupported_operation() -> std::future::Ready<KvResult<HttpResponse>> {
    std::future::ready(Err(KvApiError::UnsupportedOperation))
}

/// Register the KV routes, their extractor configuration and the scope fallback on a scope
/// mounted at `/<kv_mount>` or `/v1/<kv_mount>`.
pub(crate) fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.app_data(json_config())
        .app_data(query_config())
        .service(
            web::resource("/data/{tail}*")
                .route(web::get().to(get_secret))
                .route(web::post().to(put_secret))
                .route(web::put().to(put_secret))
                .route(web::delete().to(soft_delete_secret))
                .default_service(web::to(unsupported_operation)),
        )
        .service(
            web::resource("/metadata/{tail}*")
                .route(web::get().to(read_or_list_metadata))
                .route(
                    web::route()
                        .guard(guard::fn_guard(|ctx| ctx.head().method.as_str() == "LIST"))
                        .to(read_or_list_metadata),
                )
                .route(web::delete().to(hard_delete_path))
                .default_service(web::to(unsupported_operation)),
        )
        .default_service(web::to(route_not_found));
}

/// Register the Vault CLI KV v2 detection on the `/v1/sys/internal/ui/mounts` scope.
pub(crate) fn configure_mount_routes(cfg: &mut web::ServiceConfig) {
    cfg.app_data(query_config())
        .service(
            web::resource("/{tail}*")
                .route(web::get().to(mount_preflight))
                .default_service(web::to(unsupported_operation)),
        )
        .default_service(web::to(route_not_found));
}

/// Apply the global role policy (as the KMIP dispatcher does) for `operation`.
async fn check_role(kms: &KMS, user: &UserId, operation: OperationEnumeration) -> KvResult<()> {
    Ok(check_role_permission(kms, user.as_str(), operation, &kms.params.crypto_officer).await?)
}

/// The metadata of `path`, if it exists and `user` holds `op` on it; otherwise
/// [`KvApiError::Forbidden`], whichever of the two is missing.
async fn usable_path(
    kms: &KMS,
    path: &str,
    user: &UserId,
    op: KmipOperation,
) -> KvResult<(ObjectWithMetadata, PathMetadata)> {
    let (owm, metadata) = find_metadata(kms, path)
        .await?
        .ok_or(KvApiError::Forbidden)?;
    authorize(kms, &owm, user, op).await?;
    Ok((owm, metadata))
}

/// Absolute Unix expiry of a version written at `now` with `ttl`.
fn ttl_expiry(ttl: &str, now: i64) -> KvResult<i64> {
    parse_duration_secs(ttl)
        .and_then(|secs| i64::try_from(secs).ok())
        .and_then(|secs| now.checked_add(secs))
        .ok_or_else(|| {
            KvApiError::BadRequest(
                "invalid ttl: expected a positive duration such as 30, 30s, 5m, 1h or 2d"
                    .to_owned(),
            )
        })
}

/// Vault check-and-set: the write proceeds only when `cas` (if any) is the current version.
fn check_cas(cas: Option<u64>, current_version: u64) -> KvResult<()> {
    if cas.is_some_and(|cas| cas != current_version) {
        return Err(KvApiError::BadRequest(
            "check-and-set parameter did not match the current version".to_owned(),
        ));
    }
    Ok(())
}

/// Writing to an existing path requires the `Import` right on it and, when the path belongs to
/// another identity, an explicit `expected_owner` naming that owner: a grant alone never makes
/// a caller write its secret into a path someone else controls.
async fn authorize_write(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    expected_owner: Option<&str>,
) -> KvResult<()> {
    let owner = owm.owner();
    let owner_confirmed = if user.as_str() == owner {
        expected_owner.is_none_or(|expected| expected == owner)
    } else {
        expected_owner == Some(owner)
    };
    if !owner_confirmed {
        return Err(KvApiError::Forbidden);
    }
    authorize(kms, owm, user, KmipOperation::Import).await
}

/// Where the metadata of a write goes.
enum MetadataTarget {
    /// Compare-and-swap the existing metadata object.
    Update(Box<ObjectWithMetadata>),
    /// Create the metadata object at this UID (first write of the path).
    Create(String),
}

/// `POST|PUT /data/{path}` — create or update a secret (writes a new version).
///
/// `vault kv put` / `bao kv put` send `PUT`; `POST` is the documented KV v2 alias.
async fn put_secret(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    body: Json<PutSecretRequest>,
) -> KvResult<Json<DataWrapper<PutSecretData>>> {
    let kms: &KMS = &kms;
    let user = kms.get_user(&req);
    let path = path.into_inner();
    let body = body.into_inner();
    if path.is_empty() {
        return Err(KvApiError::BadRequest("path must not be empty".to_owned()));
    }
    validate_path_length(&path)?;
    let (now_text, now_unix) = now()?;
    let expires_at = body
        .options
        .ttl
        .as_deref()
        .map(|ttl| ttl_expiry(ttl, now_unix))
        .transpose()?;
    let secret =
        Zeroizing::new(serde_json::to_vec(&body.data).map_err(|e| {
            KvApiError::InternalError(format!("failed to serialize the secret: {e}"))
        })?);

    // Every write stores a new managed object: under role enforcement, Operators need the
    // `Create` right, as for KMIP `Import`. Checked before the lookup so that it cannot
    // reveal whether the path exists.
    check_role(kms, &user, OperationEnumeration::Import).await?;
    let (owner, target, mut metadata) = match lookup_path(kms, &path).await? {
        PathLookup::Active { owm, metadata } => {
            authorize_write(kms, &owm, &user, body.options.expected_owner.as_deref()).await?;
            check_cas(body.options.cas, metadata.current_version)?;
            if metadata.versions.len() >= MAX_KV_VERSIONS {
                return Err(KvApiError::BadRequest(format!(
                    "the path holds the maximum of {MAX_KV_VERSIONS} versions: hard-delete it \
                     (DELETE /metadata/{{path}}) before writing again"
                )));
            }
            (
                owm.owner_id().clone(),
                MetadataTarget::Update(owm),
                metadata,
            )
        }
        PathLookup::Free { generation, uid } => {
            if body
                .options
                .expected_owner
                .as_deref()
                .is_some_and(|expected| expected != user.as_str())
            {
                return Err(KvApiError::Forbidden);
            }
            check_cas(body.options.cas, 0)?;
            if generation >= MAX_KV_GENERATIONS {
                return Err(KvApiError::BadRequest(
                    "the path was deleted and re-created too many times".to_owned(),
                ));
            }
            let metadata = PathMetadata {
                path: path.clone(),
                generation,
                current_version: 0,
                oldest_version: 1,
                created_time: now_text.clone(),
                updated_time: now_text.clone(),
                versions: BTreeMap::new(),
            };
            (user.clone(), MetadataTarget::Create(uid), metadata)
        }
    };

    let next_version = metadata
        .current_version
        .checked_add(1)
        .ok_or_else(|| KvApiError::BadRequest("KV version counter is exhausted".to_owned()))?;
    let version_uid = Uuid::new_v4().to_string();
    let mut version_tags = vec![version_tag(&path, next_version)];
    if expires_at.is_some() {
        version_tags.push(ttl_active_tag(kms.internal_uid_key().await?)?);
    }
    metadata.current_version = next_version;
    metadata.updated_time.clone_from(&now_text);
    metadata.versions.insert(
        next_version,
        VersionEntry {
            created_time: now_text.clone(),
            deletion_time: String::new(),
            destroyed: false,
            object_uid: version_uid.clone(),
            expires_at,
        },
    );
    let metadata_operation = match &target {
        MetadataTarget::Update(owm) => metadata_update_operation(kms, owm, &metadata)?,
        MetadataTarget::Create(uid) => {
            let bytes = serde_json::to_vec(&metadata).map_err(|e| {
                KvApiError::InternalError(format!("failed to serialize KV metadata: {e}"))
            })?;
            create_object_operation(kms, uid, &owner, &bytes, &metadata_tags(&path))?
        }
    };
    let version_operation =
        create_object_operation(kms, &version_uid, &owner, &secret, &version_tags)?;
    if let Err(error) = kms
        .database
        .atomic(&owner, &[metadata_operation, version_operation])
        .await
    {
        // Two first writes race for the same metadata UID: the loser sees it taken.
        if let MetadataTarget::Create(uid) = &target
            && kms.database.retrieve_object_uncached(uid).await?.is_some()
        {
            return Err(KvApiError::Conflict(CONCURRENT_UPDATE.to_owned()));
        }
        return Err(error.into());
    }

    Ok(Json(DataWrapper {
        data: PutSecretData {
            version: next_version,
            created_time: now_text,
            deletion_time: String::new(),
            destroyed: false,
        },
    }))
}

#[derive(serde::Deserialize)]
struct VersionQuery {
    version: Option<u64>,
}

/// Fetch the version object `entry` of `path`, or `None` if its row no longer exists, and check
/// it belongs to `metadata_owm`'s owner.
async fn find_version_object(
    kms: &KMS,
    metadata_owm: &ObjectWithMetadata,
    path: &str,
    version: u64,
    entry: &VersionEntry,
) -> KvResult<Option<ObjectWithMetadata>> {
    let Some(version_owm) = kms.database.retrieve_object(&entry.object_uid).await? else {
        return Ok(None);
    };
    if version_owm.owner() != metadata_owm.owner()
        || !version_owm
            .attributes()
            .get_tags(kms.vendor_id())
            .contains(&version_tag(path, version))
    {
        return Err(KvApiError::InternalError(format!(
            "object {} is not version {version} of the path of metadata {}",
            entry.object_uid,
            metadata_owm.id()
        )));
    }
    Ok(Some(version_owm))
}

/// Like [`find_version_object`], but a missing row is an internal error.
async fn version_object(
    kms: &KMS,
    metadata_owm: &ObjectWithMetadata,
    path: &str,
    version: u64,
    entry: &VersionEntry,
) -> KvResult<ObjectWithMetadata> {
    find_version_object(kms, metadata_owm, path, version, entry)
        .await?
        .ok_or_else(|| {
            KvApiError::InternalError(format!(
                "KV version {version} references the missing object {}",
                entry.object_uid
            ))
        })
}

/// `GET /data/{path}[?version=N]` — read the latest (`N` absent or `0`) or a specific version.
async fn get_secret(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    query: Query<VersionQuery>,
) -> KvResult<Json<DataWrapper<GetSecretData>>> {
    let kms: &KMS = &kms;
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;
    check_role(kms, &user, OperationEnumeration::Get).await?;
    let (owm, metadata) = usable_path(kms, &path, &user, KmipOperation::Get).await?;

    let version = query
        .version
        .filter(|version| *version != 0)
        .unwrap_or(metadata.current_version);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let entry = metadata
        .versions
        .get(&version)
        .filter(|entry| !entry.is_unavailable(now))
        .ok_or_else(|| KvApiError::NotFound(format!("version {version} is not available")))?;
    let version_owm = version_object(kms, &owm, &path, version, entry).await?;
    if matches!(
        version_owm.state(),
        State::Destroyed | State::Destroyed_Compromised
    ) {
        return Err(KvApiError::NotFound(format!(
            "version {version} is not available"
        )));
    }
    // The serde message could quote the secret: only its category is kept.
    let data: KvSecretMap = serde_json::from_slice(secret_bytes(&version_owm)?).map_err(|e| {
        KvApiError::InternalError(format!("corrupt KV secret data ({:?})", e.classify()))
    })?;

    Ok(Json(DataWrapper {
        data: GetSecretData {
            data,
            metadata: VersionMetadata {
                version,
                created_time: entry.created_time.clone(),
                deletion_time: entry.deletion_time.clone(),
                destroyed: entry.destroyed,
            },
        },
    }))
}

/// `DELETE /data/{path}` — soft-delete the latest version (sets `deletion_time`;
/// the underlying object is kept — only `GET` treats it as absent).
async fn soft_delete_secret(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KvResult<HttpResponse> {
    let kms: &KMS = &kms;
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;
    check_role(kms, &user, OperationEnumeration::Destroy).await?;
    let (owm, mut metadata) = usable_path(kms, &path, &user, KmipOperation::Destroy).await?;

    let (now_text, _) = now()?;
    let version = metadata.current_version;
    if let Some(entry) = metadata.versions.get_mut(&version)
        && entry.deletion_time.is_empty()
    {
        entry.deletion_time.clone_from(&now_text);
    }
    metadata.updated_time = now_text;
    save_metadata(kms, &owm, &metadata).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[derive(serde::Deserialize)]
struct ListQuery {
    list: Option<String>,
}

/// `GET /metadata/{path}` — read version bookkeeping, or (with `?list=true`)
/// `GET /metadata/{prefix}?list=true` / `LIST /metadata/{prefix}` — list immediate child
/// keys under `prefix`. `LIST` is the HTTP verb documented by Vault; its Go client sends the
/// `GET ?list=true` form, so both are accepted.
async fn read_or_list_metadata(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    query: Query<ListQuery>,
) -> KvResult<Json<DataWrapper<serde_json::Value>>> {
    let kms: &KMS = &kms;
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;
    check_role(kms, &user, OperationEnumeration::Locate).await?;

    let data = if req.method().as_str() == "LIST" || query.list.as_deref() == Some("true") {
        let keys = list_child_keys(kms, &user, &path).await?;
        // Vault answers an empty listing with 404.
        if keys.is_empty() {
            return Err(KvApiError::NotFound("no keys under this prefix".to_owned()));
        }
        serde_json::to_value(ListData { keys })
    } else {
        let (_, metadata) = usable_path(kms, &path, &user, KmipOperation::Locate).await?;
        let versions = metadata
            .versions
            .into_iter()
            .map(|(version, entry)| {
                (
                    version,
                    VersionMetadata {
                        version,
                        created_time: entry.created_time,
                        deletion_time: entry.deletion_time,
                        destroyed: entry.destroyed,
                    },
                )
            })
            .collect();
        serde_json::to_value(ReadMetadataResponseData {
            current_version: metadata.current_version,
            oldest_version: metadata.oldest_version,
            created_time: metadata.created_time,
            updated_time: metadata.updated_time,
            versions,
        })
    }
    .map_err(|e| KvApiError::InternalError(format!("failed to serialize KV metadata: {e}")))?;
    Ok(Json(DataWrapper { data }))
}

/// Enumerate the immediate child key names directly under `prefix`, among the paths `user`
/// owns or holds `Locate` or `Get` on.
async fn list_child_keys(kms: &KMS, user: &UserId, prefix: &str) -> KvResult<Vec<String>> {
    let mut filter = Attributes {
        object_type: Some(ObjectType::SecretData),
        ..Attributes::default()
    };
    filter
        .set_tags(kms.vendor_id(), [metadata::KV_METADATA_TAG])
        .map_err(|e| KvApiError::InternalError(format!("failed to set KV tags: {e}")))?;
    let options = FindOptions {
        limit: Some(MAX_KV_LIST_CANDIDATES + 1),
        destroyed: DestroyedFilter::Exclude,
        hsm_granted_uids: None,
    };
    // Owned objects plus objects with any grant: the grants are checked below.
    let candidates = kms
        .database
        .find_with_options(Some(&filter), None, user, false, kms.vendor_id(), &options)
        .await?;
    if candidates.len() > MAX_KV_LIST_CANDIDATES {
        return Err(KvApiError::BadRequest(format!(
            "more than {MAX_KV_LIST_CANDIDATES} KV paths are visible to this identity: listing \
             is not supported beyond that"
        )));
    }
    let granted = kms.database.list_user_operations_granted(user).await?;
    let meta_tag_prefix = meta_tag("");
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for (uid, state, attributes) in candidates {
        if matches!(state, State::Destroyed | State::Destroyed_Compromised) {
            continue;
        }
        let visible = granted.get(&uid).is_none_or(|(owner, _, operations)| {
            owner == user.as_str()
                || operations.contains(&KmipOperation::Locate)
                || operations.contains(&KmipOperation::Get)
        });
        if !visible {
            continue;
        }
        let tags = attributes.get_tags(kms.vendor_id());
        if let Some(entry) = tags
            .iter()
            .find_map(|tag| tag.strip_prefix(meta_tag_prefix.as_str()))
            .and_then(|full_path| list_entry_name(prefix, full_path))
        {
            keys.insert(entry);
        }
    }
    Ok(keys.into_iter().collect())
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
async fn mount_preflight(
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KvResult<Json<DataWrapper<MountInfo>>> {
    let mount = &kms.params.kv.mount;
    let path = path.into_inner();
    let requested_mount = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    if requested_mount != mount {
        return Err(KvApiError::NotFound("no such mount".to_owned()));
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
async fn hard_delete_path(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KvResult<HttpResponse> {
    let kms: &KMS = &kms;
    let user = kms.get_user(&req);
    let path = path.into_inner();
    validate_path_length(&path)?;
    check_role(kms, &user, OperationEnumeration::Destroy).await?;
    let (owm, metadata) = usable_path(kms, &path, &user, KmipOperation::Destroy).await?;

    let mut seen = HashSet::with_capacity(metadata.versions.len());
    if !metadata
        .versions
        .values()
        .all(|entry| seen.insert(entry.object_uid.as_str()))
    {
        return Err(KvApiError::InternalError(format!(
            "several versions of metadata {} reference the same object",
            owm.id()
        )));
    }
    let version_objects: Vec<ObjectWithMetadata> = stream::iter(&metadata.versions)
        .map(|(version, entry)| find_version_object(kms, &owm, &path, *version, entry))
        .buffer_unordered(HARD_DELETE_READ_CONCURRENCY)
        .try_collect::<Vec<Option<ObjectWithMetadata>>>()
        .await?
        .into_iter()
        .flatten()
        .collect();

    let mut operations = Vec::with_capacity(version_objects.len() * 2 + 2);
    operations.push(metadata_update_operation(kms, &owm, &metadata)?);
    operations.push(AtomicOperation::UpdateState((
        owm.id().to_owned(),
        State::Destroyed,
    )));
    for version_owm in &version_objects {
        if !matches!(
            version_owm.state(),
            State::Destroyed | State::Destroyed_Compromised
        ) {
            operations.extend(destroy_version_operations(kms.vendor_id(), version_owm)?);
        }
    }
    kms.database.atomic(owm.owner_id(), &operations).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod tests;

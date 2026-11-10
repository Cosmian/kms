//! Vault-compatible Transit engine — symmetric `aes256-gcm96` keys.
//!
//! Routes (mounted under `/v1/{transit_mount}/`):
//!   `POST/PUT /encrypt/{name}`      — AES-256-GCM encrypt, returns `vault:vN:<base64>`
//!   `POST/PUT /decrypt/{name}`      — decrypt a `vault:vN:<base64>` ciphertext
//!   `POST/PUT /keys/{name}/rotate`  — add a new key version
//!
//! Both verbs are registered because Vault's Go client (used by the `transit`
//! seal of `HashiCorp` Vault) sends `PUT` for every write, whereas the Vault HTTP
//! documentation and `curl` examples use `POST`.
//!
//! Each key version is a distinct KMS `SymmetricKey` carrying two tags:
//! `vault_transit:{name}` and `vault_transit_version:{n}`. Encryption uses the
//! latest version (or `key_version` when supplied); decryption selects the
//! version embedded in the ciphertext, so ciphertexts produced before a rotation
//! remain decryptable. Keys are created `sensitive` (never exportable) and the
//! cryptography runs inside the KMS (HSM-backed when the KMS key-encryption key
//! lives in an HSM).
//!
//! Ciphertext body layout matches Vault: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.

use std::{collections::HashMap, sync::Arc};

use actix_web::{
    HttpRequest, post, put,
    web::{Data, Json, Path},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cosmian_kms_interfaces::UserId;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::{debug, trace};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    error::{SpireApiError, SpireResult},
    transit::{TransitKeyInfo, TransitKeyInfoWrapper, TransitKeyVersionEntry, transit_tag_name},
};
use crate::{core::KMS, error::KmsError};

/// Vault key type of the symmetric transit keys served by this module.
pub(crate) const AES256_GCM96: &str = "aes256-gcm96";

/// Tag prefix carrying the Vault key version of a symmetric transit key.
const TRANSIT_VERSION_TAG_PREFIX: &str = "vault_transit_version:";

/// AES-GCM nonce length used by Vault (96 bits).
const GCM_NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length used by Vault (128 bits).
const GCM_TAG_LEN: usize = 16;

/// One stored version of a symmetric transit key.
pub(crate) struct SymmetricKeyVersion {
    pub version: u32,
    pub uid: String,
    pub attributes: Attributes,
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct EncryptTransitRequest {
    /// Base64-encoded plaintext.
    pub plaintext: String,
    /// Key version to encrypt with; defaults to the latest version.
    #[serde(default)]
    pub key_version: Option<u32>,
    /// Base64-encoded AEAD associated data.
    #[serde(default)]
    pub associated_data: Option<String>,
    /// Key-derivation context: derived keys are not supported, so any value is rejected.
    #[serde(default)]
    pub context: Option<String>,
    /// Batch mode is not supported, so any value is rejected rather than silently ignored.
    #[serde(default)]
    pub batch_input: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct EncryptTransitData {
    pub ciphertext: String,
    pub key_version: u32,
}

#[derive(Serialize)]
pub(crate) struct EncryptTransitResponse {
    pub data: EncryptTransitData,
}

#[derive(Deserialize)]
pub(crate) struct DecryptTransitRequest {
    /// Vault ciphertext `vault:vN:<base64>`.
    pub ciphertext: String,
    /// Base64-encoded AEAD associated data (must match the value used to encrypt).
    #[serde(default)]
    pub associated_data: Option<String>,
    /// Key-derivation context: derived keys are not supported, so any value is rejected.
    #[serde(default)]
    pub context: Option<String>,
    /// Batch mode is not supported, so any value is rejected rather than silently ignored.
    #[serde(default)]
    pub batch_input: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct DecryptTransitData {
    pub plaintext: String,
}

#[derive(Serialize)]
pub(crate) struct DecryptTransitResponse {
    pub data: DecryptTransitData,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn version_tag(version: u32) -> String {
    format!("{TRANSIT_VERSION_TAG_PREFIX}{version}")
}

/// Format a Vault ciphertext: `vault:v{version}:{base64(nonce || ct || tag)}`.
fn format_ciphertext(version: u32, nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> String {
    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len() + tag.len());
    body.extend_from_slice(nonce);
    body.extend_from_slice(ciphertext);
    body.extend_from_slice(tag);
    format!("vault:v{version}:{}", BASE64_STANDARD.encode(body))
}

/// Parsed Vault ciphertext.
#[derive(Debug, PartialEq, Eq)]
struct ParsedCiphertext {
    version: u32,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

/// Parse `vault:v{version}:{base64(nonce || ct || tag)}`.
fn parse_ciphertext(value: &str) -> SpireResult<ParsedCiphertext> {
    let invalid =
        || SpireApiError::BadRequest("invalid ciphertext: expected vault:vN:<base64>".to_owned());
    let rest = value.strip_prefix("vault:v").ok_or_else(invalid)?;
    let (version, body) = rest.split_once(':').ok_or_else(invalid)?;
    let version: u32 = version.parse().map_err(|_e| invalid())?;
    if version == 0 {
        return Err(invalid());
    }
    let raw = BASE64_STANDARD.decode(body).map_err(|_e| invalid())?;
    if raw.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err(invalid());
    }
    let (nonce, rest) = raw.split_at(GCM_NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - GCM_TAG_LEN);
    Ok(ParsedCiphertext {
        version,
        nonce: nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
        tag: tag.to_vec(),
    })
}

/// Reject the Vault options this implementation does not support.
fn reject_unsupported_options(
    context: Option<&str>,
    batch_input: Option<&serde_json::Value>,
) -> SpireResult<()> {
    if context.is_some_and(|c| !c.is_empty()) {
        return Err(SpireApiError::BadRequest(
            "'context' is not supported: transit keys are not derived keys".to_owned(),
        ));
    }
    if batch_input.is_some_and(|b| !b.is_null()) {
        return Err(SpireApiError::BadRequest(
            "'batch_input' is not supported".to_owned(),
        ));
    }
    Ok(())
}

fn decode_associated_data(value: Option<&str>) -> SpireResult<Option<Vec<u8>>> {
    value
        .filter(|v| !v.is_empty())
        .map(|v| {
            BASE64_STANDARD.decode(v).map_err(|_e| {
                SpireApiError::BadRequest("invalid base64 in 'associated_data' field".to_owned())
            })
        })
        .transpose()
}

fn aes_gcm_parameters() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCM),
        ..Default::default()
    }
}

/// Return every version of the symmetric transit key `name` **owned by** `user`,
/// sorted by ascending version.
///
/// Ownership is required for the same key-substitution reason as
/// [`super::transit`]'s asymmetric lookup. Should two objects carry the same
/// version (concurrent rotations), the lowest UID wins so every request resolves
/// the same key.
pub(crate) async fn find_owned_symmetric_versions(
    kms: &KMS,
    user: &UserId,
    name: &str,
) -> SpireResult<Vec<SymmetricKeyVersion>> {
    let mut filter = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };
    filter
        .set_tags(kms.vendor_id(), [transit_tag_name(name)])
        .map_err(|e| {
            SpireApiError::InternalError(format!("failed to build transit key tag filter: {e}"))
        })?;
    let mut results = kms
        .database
        .find(Some(&filter), None, user, true, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;
    results.sort_by(|a, b| a.0.cmp(&b.0));

    let mut versions: Vec<SymmetricKeyVersion> = Vec::new();
    for (uid, _state, attributes) in results {
        let Some(version) = attributes.get_tags(kms.vendor_id()).iter().find_map(|t| {
            t.strip_prefix(TRANSIT_VERSION_TAG_PREFIX)?
                .parse::<u32>()
                .ok()
        }) else {
            continue;
        };
        if versions.iter().any(|v| v.version == version) {
            continue;
        }
        versions.push(SymmetricKeyVersion {
            version,
            uid,
            attributes,
        });
    }
    versions.sort_by_key(|v| v.version);
    Ok(versions)
}

/// Create version `version` of the symmetric transit key `name` for `user`.
pub(crate) async fn create_symmetric_version(
    kms: &KMS,
    user: &UserId,
    name: &str,
    version: u32,
) -> SpireResult<()> {
    let name_tag = transit_tag_name(name);
    let version_tag = version_tag(version);
    // sensitive = true → the key can never be exported (Get/Export are refused);
    // encryption and decryption happen server-side and are unaffected.
    let create_req = symmetric_key_create_request(
        kms.vendor_id(),
        None,
        256,
        CryptographicAlgorithm::AES,
        [name_tag.as_str(), version_tag.as_str()],
        true,
        None,
    )
    .map_err(|e| SpireApiError::InternalError(e.to_string()))?;
    kms.create(create_req, user)
        .await
        .map_err(SpireApiError::from)?;
    debug!("vault transit: created {AES256_GCM96} key '{name}' version {version}");
    Ok(())
}

/// Build the Vault key-info response for a symmetric key.
///
/// For symmetric keys Vault maps each version to its creation time as a Unix timestamp.
pub(crate) fn symmetric_key_info(
    name: String,
    versions: &[SymmetricKeyVersion],
) -> TransitKeyInfoWrapper {
    let keys: HashMap<String, TransitKeyVersionEntry> = versions
        .iter()
        .map(|v| {
            let created = v
                .attributes
                .initial_date
                .map_or(0, time::OffsetDateTime::unix_timestamp);
            (
                v.version.to_string(),
                TransitKeyVersionEntry::Symmetric(created),
            )
        })
        .collect();
    TransitKeyInfoWrapper {
        data: TransitKeyInfo {
            name,
            key_type: AES256_GCM96.to_owned(),
            exportable: false,
            allow_deletion: true,
            latest_version: versions.last().map_or(1, |v| v.version),
            keys,
        },
    }
}

/// Map a KMS decryption failure to a client error without leaking oracle details.
fn decrypt_error(e: KmsError) -> SpireApiError {
    match e {
        KmsError::Unauthorized(_) => SpireApiError::Forbidden(e.to_string()),
        other => {
            debug!("vault transit: decryption failed: {other}");
            SpireApiError::BadRequest("cipher: message authentication failed".to_owned())
        }
    }
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// `POST /encrypt/{name}` — encrypt with the latest (or requested) key version.
#[post("/encrypt/{name}")]
pub(crate) async fn encrypt_with_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<EncryptTransitRequest>,
) -> SpireResult<Json<EncryptTransitResponse>> {
    encrypt_impl(&req, &kms, &name.into_inner(), body.into_inner()).await
}

/// `PUT /encrypt/{name}` — same as `POST` (Vault's Go client writes with `PUT`).
#[put("/encrypt/{name}")]
pub(crate) async fn encrypt_with_transit_key_put(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<EncryptTransitRequest>,
) -> SpireResult<Json<EncryptTransitResponse>> {
    encrypt_impl(&req, &kms, &name.into_inner(), body.into_inner()).await
}

async fn encrypt_impl(
    req: &HttpRequest,
    kms: &KMS,
    name: &str,
    body: EncryptTransitRequest,
) -> SpireResult<Json<EncryptTransitResponse>> {
    let user = kms.get_user(req);
    trace!(user = %user, "{} vault transit encrypt/{name}", req.method());

    reject_unsupported_options(body.context.as_deref(), body.batch_input.as_ref())?;
    let plaintext = Zeroizing::new(BASE64_STANDARD.decode(&body.plaintext).map_err(|_e| {
        SpireApiError::BadRequest("invalid base64 in 'plaintext' field".to_owned())
    })?);
    let associated_data = decode_associated_data(body.associated_data.as_deref())?;

    let versions = find_owned_symmetric_versions(kms, &user, name).await?;
    let key = match body.key_version.filter(|v| *v != 0) {
        Some(requested) => versions
            .iter()
            .find(|v| v.version == requested)
            .ok_or_else(|| {
                SpireApiError::BadRequest(format!(
                    "key version {requested} does not exist for transit key '{name}'"
                ))
            })?,
        None => versions
            .last()
            .ok_or_else(|| SpireApiError::NotFound(format!("encryption key '{name}' not found")))?,
    };

    let resp = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(UniqueIdentifier::TextString(key.uid.clone())),
                cryptographic_parameters: Some(aes_gcm_parameters()),
                data: Some(plaintext),
                authenticated_encryption_additional_data: associated_data,
                ..Default::default()
            },
            &user,
        )
        .await
        .map_err(SpireApiError::from)?;

    let missing =
        |field: &str| SpireApiError::InternalError(format!("Encrypt response missing {field}"));
    let nonce = resp.i_v_counter_nonce.ok_or_else(|| missing("nonce"))?;
    let tag = resp
        .authenticated_encryption_tag
        .ok_or_else(|| missing("authentication tag"))?;
    let ciphertext = resp.data.unwrap_or_default();
    if nonce.len() != GCM_NONCE_LEN || tag.len() != GCM_TAG_LEN {
        return Err(SpireApiError::InternalError(format!(
            "unexpected AES-GCM nonce/tag length {}/{}",
            nonce.len(),
            tag.len()
        )));
    }

    Ok(Json(EncryptTransitResponse {
        data: EncryptTransitData {
            ciphertext: format_ciphertext(key.version, &nonce, &ciphertext, &tag),
            key_version: key.version,
        },
    }))
}

/// `POST /decrypt/{name}` — decrypt a `vault:vN:` ciphertext.
#[post("/decrypt/{name}")]
pub(crate) async fn decrypt_with_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<DecryptTransitRequest>,
) -> SpireResult<Json<DecryptTransitResponse>> {
    decrypt_impl(&req, &kms, &name.into_inner(), body.into_inner()).await
}

/// `PUT /decrypt/{name}` — same as `POST` (Vault's Go client writes with `PUT`).
#[put("/decrypt/{name}")]
pub(crate) async fn decrypt_with_transit_key_put(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<DecryptTransitRequest>,
) -> SpireResult<Json<DecryptTransitResponse>> {
    decrypt_impl(&req, &kms, &name.into_inner(), body.into_inner()).await
}

async fn decrypt_impl(
    req: &HttpRequest,
    kms: &KMS,
    name: &str,
    body: DecryptTransitRequest,
) -> SpireResult<Json<DecryptTransitResponse>> {
    let user = kms.get_user(req);
    trace!(user = %user, "{} vault transit decrypt/{name}", req.method());

    reject_unsupported_options(body.context.as_deref(), body.batch_input.as_ref())?;
    let parsed = parse_ciphertext(&body.ciphertext)?;
    let associated_data = decode_associated_data(body.associated_data.as_deref())?;

    let versions = find_owned_symmetric_versions(kms, &user, name).await?;
    if versions.is_empty() {
        return Err(SpireApiError::NotFound(format!(
            "encryption key '{name}' not found"
        )));
    }
    let key = versions
        .iter()
        .find(|v| v.version == parsed.version)
        .ok_or_else(|| SpireApiError::BadRequest("invalid key version".to_owned()))?;

    let resp = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(UniqueIdentifier::TextString(key.uid.clone())),
                cryptographic_parameters: Some(aes_gcm_parameters()),
                data: Some(parsed.ciphertext),
                i_v_counter_nonce: Some(parsed.nonce),
                authenticated_encryption_additional_data: associated_data,
                authenticated_encryption_tag: Some(parsed.tag),
                ..Default::default()
            },
            &user,
        )
        .await
        .map_err(decrypt_error)?;

    let plaintext = resp.data.unwrap_or_default();
    Ok(Json(DecryptTransitResponse {
        data: DecryptTransitData {
            plaintext: BASE64_STANDARD.encode(plaintext.as_slice()),
        },
    }))
}

/// `POST /keys/{name}/rotate` — create a new version of a symmetric transit key.
///
/// Asymmetric (signing) transit keys keep a single version and cannot be rotated.
#[post("/keys/{name}/rotate")]
pub(crate) async fn rotate_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    rotate_impl(&req, &kms, name.into_inner()).await
}

/// `PUT /keys/{name}/rotate` — same as `POST` (Vault's Go client writes with `PUT`).
#[put("/keys/{name}/rotate")]
pub(crate) async fn rotate_transit_key_put(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    rotate_impl(&req, &kms, name.into_inner()).await
}

async fn rotate_impl(
    req: &HttpRequest,
    kms: &KMS,
    name: String,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    let user = kms.get_user(req);
    trace!(user = %user, "{} vault transit keys/{name}/rotate", req.method());

    let latest = find_owned_symmetric_versions(kms, &user, &name)
        .await?
        .last()
        .map(|v| v.version);
    let Some(latest) = latest else {
        if super::transit::find_owned_transit_key(kms, &user, &name)
            .await?
            .is_some()
        {
            return Err(SpireApiError::BadRequest(format!(
                "transit key '{name}' is an asymmetric signing key; rotation is only supported \
                 for {AES256_GCM96} keys"
            )));
        }
        return Err(SpireApiError::NotFound(format!(
            "transit key '{name}' not found"
        )));
    };
    let next = latest.checked_add(1).ok_or_else(|| {
        SpireApiError::BadRequest(format!("transit key '{name}' cannot be rotated further"))
    })?;
    create_symmetric_version(kms, &user, &name, next).await?;

    let versions = find_owned_symmetric_versions(kms, &user, &name).await?;
    Ok(Json(symmetric_key_info(name, &versions)))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test code: failures must abort the test"
)]
mod tests {
    use std::sync::Arc;

    use actix_web::{
        App, HttpMessage,
        dev::Service,
        test as actix_test,
        web::{Data, JsonConfig},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use cosmian_kms_interfaces::UserId;
    use serde_json::{Value, json};

    use super::{
        GCM_NONCE_LEN, GCM_TAG_LEN, decrypt_with_transit_key, decrypt_with_transit_key_put,
        encrypt_with_transit_key, encrypt_with_transit_key_put, find_owned_symmetric_versions,
        format_ciphertext, parse_ciphertext, rotate_transit_key, rotate_transit_key_put,
    };
    use crate::{
        core::KMS,
        middlewares::{AuthMethod, AuthenticatedUser},
        result::KResult,
        routes::spire::transit::{create_transit_key, get_transit_key, list_transit_keys},
        tests::test_utils::test_kms,
    };

    #[test]
    fn ciphertext_format_roundtrip() {
        let nonce = [1_u8; GCM_NONCE_LEN];
        let tag = [2_u8; GCM_TAG_LEN];
        let ct = format_ciphertext(7, &nonce, b"secret", &tag);
        assert!(ct.starts_with("vault:v7:"));
        let parsed = parse_ciphertext(&ct).unwrap();
        assert_eq!(parsed.version, 7);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.ciphertext, b"secret");
        assert_eq!(parsed.tag, tag);
        // Empty plaintext is valid: nonce || tag only.
        let empty = parse_ciphertext(&format_ciphertext(1, &nonce, b"", &tag)).unwrap();
        assert_eq!(empty.ciphertext, Vec::<u8>::new());
    }

    #[test]
    fn ciphertext_parse_rejects_malformed_values() {
        let short = BASE64_STANDARD.encode([0_u8; GCM_NONCE_LEN + GCM_TAG_LEN - 1]);
        let ok_body = BASE64_STANDARD.encode([0_u8; GCM_NONCE_LEN + GCM_TAG_LEN]);
        for bad in [
            String::new(),
            "vault:v1".to_owned(),
            format!("vault:1:{ok_body}"),
            format!("vault:v0:{ok_body}"),
            format!("vault:vx:{ok_body}"),
            format!("vault:v-1:{ok_body}"),
            format!("vault:v1:{short}"),
            "vault:v1:!!notbase64".to_owned(),
            format!("other:v1:{ok_body}"),
        ] {
            assert!(parse_ciphertext(&bad).is_err(), "accepted {bad:?}");
        }
    }

    /// Call one transit route as `user` (injected as the authenticated identity).
    async fn call(
        kms: &Arc<KMS>,
        user: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let username = UserId::from(user);
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms.clone()))
                .app_data(JsonConfig::default().content_type_required(false))
                .wrap_fn(move |req, srv| {
                    req.extensions_mut().insert(AuthenticatedUser {
                        username: username.clone(),
                        auth_method: AuthMethod::SpireToken,
                    });
                    srv.call(req)
                })
                .service(create_transit_key)
                .service(get_transit_key)
                .service(list_transit_keys)
                .service(rotate_transit_key)
                .service(rotate_transit_key_put)
                .service(encrypt_with_transit_key)
                .service(encrypt_with_transit_key_put)
                .service(decrypt_with_transit_key)
                .service(decrypt_with_transit_key_put),
        )
        .await;
        let req = match method {
            "PUT" => actix_test::TestRequest::put(),
            "GET" => actix_test::TestRequest::get(),
            _ => actix_test::TestRequest::post(),
        }
        .uri(uri);
        let req = match body {
            Some(b) => req.set_json(b),
            None => req,
        };
        let resp = actix_test::call_service(&app, req.to_request()).await;
        let status = resp.status().as_u16();
        let bytes = actix_test::read_body(resp).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn b64(data: &[u8]) -> String {
        BASE64_STANDARD.encode(data)
    }

    async fn encrypt(kms: &Arc<KMS>, user: &str, key: &str, body: Value) -> (u16, Value) {
        call(kms, user, "PUT", &format!("/encrypt/{key}"), Some(body)).await
    }

    async fn decrypt(kms: &Arc<KMS>, user: &str, key: &str, body: Value) -> (u16, Value) {
        call(kms, user, "PUT", &format!("/decrypt/{key}"), Some(body)).await
    }

    fn ciphertext(resp: &Value) -> String {
        resp["data"]["ciphertext"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_with_vault_format() -> KResult<()> {
        let kms = test_kms().await?;
        // An empty body creates Vault's default key type.
        let (status, created) = call(&kms, "alice", "POST", "/keys/unseal", Some(json!({}))).await;
        assert_eq!(status, 200, "{created}");
        assert_eq!(created["data"]["type"], "aes256-gcm96");

        let (status, enc) = encrypt(
            &kms,
            "alice",
            "unseal",
            json!({"plaintext": b64(b"root key")}),
        )
        .await;
        assert_eq!(status, 200, "{enc}");
        let ct = ciphertext(&enc);
        assert!(ct.starts_with("vault:v1:"), "{ct}");
        assert_eq!(enc["data"]["key_version"], 1);
        // Vault's transit seal splits on ':' and expects exactly 3 parts.
        assert_eq!(ct.split(':').count(), 3);

        // POST and PUT are both accepted.
        let (status, dec) = call(
            &kms,
            "alice",
            "POST",
            "/decrypt/unseal",
            Some(json!({"ciphertext": ct})),
        )
        .await;
        assert_eq!(status, 200, "{dec}");
        assert_eq!(dec["data"]["plaintext"], b64(b"root key"));

        // Fresh nonce per call.
        let (_, enc2) = encrypt(
            &kms,
            "alice",
            "unseal",
            json!({"plaintext": b64(b"root key")}),
        )
        .await;
        assert_ne!(ciphertext(&enc2), ct);
        Ok(())
    }

    #[tokio::test]
    async fn rotation_keeps_old_ciphertexts_decryptable() -> KResult<()> {
        let kms = test_kms().await?;
        call(
            &kms,
            "alice",
            "POST",
            "/keys/k",
            Some(json!({"type": "aes256-gcm96"})),
        )
        .await;
        let (_, enc_v1) = encrypt(&kms, "alice", "k", json!({"plaintext": b64(b"v1 data")})).await;

        let (status, rotated) = call(&kms, "alice", "PUT", "/keys/k/rotate", None).await;
        assert_eq!(status, 200, "{rotated}");
        assert_eq!(rotated["data"]["latest_version"], 2);

        let (_, enc_v2) = encrypt(&kms, "alice", "k", json!({"plaintext": b64(b"v2 data")})).await;
        assert!(ciphertext(&enc_v2).starts_with("vault:v2:"));

        // Explicit older version.
        let (status, enc_old) = encrypt(
            &kms,
            "alice",
            "k",
            json!({"plaintext": b64(b"x"), "key_version": 1}),
        )
        .await;
        assert_eq!(status, 200, "{enc_old}");
        assert!(ciphertext(&enc_old).starts_with("vault:v1:"));

        for (enc, expected) in [(&enc_v1, b"v1 data"), (&enc_v2, b"v2 data")] {
            let (status, dec) =
                decrypt(&kms, "alice", "k", json!({"ciphertext": ciphertext(enc)})).await;
            assert_eq!(status, 200, "{dec}");
            assert_eq!(dec["data"]["plaintext"], b64(expected));
        }

        let (status, info) = call(&kms, "alice", "GET", "/keys/k", None).await;
        assert_eq!(status, 200);
        assert_eq!(info["data"]["latest_version"], 2);
        assert!(info["data"]["keys"]["1"].is_i64());
        assert!(info["data"]["keys"]["2"].is_i64());

        let (_, list) = call(&kms, "alice", "GET", "/keys", None).await;
        assert_eq!(list["data"]["keys"], json!(["k"]));
        Ok(())
    }

    #[tokio::test]
    async fn invalid_requests_are_rejected() -> KResult<()> {
        let kms = test_kms().await?;
        call(
            &kms,
            "alice",
            "POST",
            "/keys/k",
            Some(json!({"type": "aes256-gcm96"})),
        )
        .await;
        let (_, enc) = encrypt(
            &kms,
            "alice",
            "k",
            json!({"plaintext": b64(b"data"), "associated_data": b64(b"aad")}),
        )
        .await;
        let ct = ciphertext(&enc);

        // AAD must match.
        let (status, dec) = decrypt(
            &kms,
            "alice",
            "k",
            json!({"ciphertext": ct, "associated_data": b64(b"aad")}),
        )
        .await;
        assert_eq!(status, 200, "{dec}");
        let (status, _) = decrypt(&kms, "alice", "k", json!({"ciphertext": ct})).await;
        assert_eq!(status, 400);

        // Tampered ciphertext body.
        let mut raw = BASE64_STANDARD
            .decode(ct.trim_start_matches("vault:v1:"))
            .unwrap();
        raw[GCM_NONCE_LEN] ^= 1;
        let tampered = format!("vault:v1:{}", b64(&raw));
        let (status, _) = decrypt(
            &kms,
            "alice",
            "k",
            json!({"ciphertext": tampered, "associated_data": b64(b"aad")}),
        )
        .await;
        assert_eq!(status, 400);

        // Unknown version, unknown key, unsupported options, bad base64.
        let other_version = ct.replacen("vault:v1:", "vault:v9:", 1);
        assert_eq!(
            decrypt(&kms, "alice", "k", json!({"ciphertext": other_version}))
                .await
                .0,
            400
        );
        assert_eq!(
            encrypt(&kms, "alice", "nope", json!({"plaintext": b64(b"x")}))
                .await
                .0,
            404
        );
        assert_eq!(
            encrypt(
                &kms,
                "alice",
                "k",
                json!({"plaintext": b64(b"x"), "key_version": 5})
            )
            .await
            .0,
            400
        );
        assert_eq!(
            encrypt(
                &kms,
                "alice",
                "k",
                json!({"plaintext": b64(b"x"), "context": "Y3R4"})
            )
            .await
            .0,
            400
        );
        assert_eq!(
            encrypt(
                &kms,
                "alice",
                "k",
                json!({"plaintext": "x", "batch_input": [{}]})
            )
            .await
            .0,
            400
        );
        assert_eq!(
            encrypt(&kms, "alice", "k", json!({"plaintext": "%%"}))
                .await
                .0,
            400
        );
        assert_eq!(
            call(&kms, "alice", "POST", "/keys/nope/rotate", None)
                .await
                .0,
            404
        );
        Ok(())
    }

    #[tokio::test]
    async fn asymmetric_keys_cannot_encrypt_or_rotate() -> KResult<()> {
        let kms = test_kms().await?;
        call(
            &kms,
            "alice",
            "POST",
            "/keys/sig",
            Some(json!({"type": "ecdsa-p256"})),
        )
        .await;
        assert_eq!(
            call(&kms, "alice", "POST", "/keys/sig/rotate", None)
                .await
                .0,
            400
        );
        assert_eq!(
            encrypt(&kms, "alice", "sig", json!({"plaintext": b64(b"x")}))
                .await
                .0,
            404
        );
        // Re-creating with another type is a no-op that reports the existing type.
        let (_, again) = call(&kms, "alice", "POST", "/keys/sig", Some(json!({}))).await;
        assert_eq!(again["data"]["type"], "ecdsa-p256");
        Ok(())
    }

    #[tokio::test]
    async fn keys_are_isolated_between_owners() -> KResult<()> {
        let kms = test_kms().await?;
        call(
            &kms,
            "tenant-a",
            "POST",
            "/keys/shared-name",
            Some(json!({})),
        )
        .await;
        let (_, enc) = encrypt(
            &kms,
            "tenant-a",
            "shared-name",
            json!({"plaintext": b64(b"a")}),
        )
        .await;

        assert!(
            find_owned_symmetric_versions(&kms, &UserId::from("tenant-b"), "shared-name")
                .await
                .unwrap()
                .is_empty()
        );
        let ct = ciphertext(&enc);
        assert_eq!(
            decrypt(&kms, "tenant-b", "shared-name", json!({"ciphertext": ct}))
                .await
                .0,
            404
        );
        assert_eq!(
            encrypt(
                &kms,
                "tenant-b",
                "shared-name",
                json!({"plaintext": b64(b"b")})
            )
            .await
            .0,
            404
        );
        assert_eq!(
            call(&kms, "tenant-b", "POST", "/keys/shared-name/rotate", None)
                .await
                .0,
            404
        );

        // Tenant B's own key of the same name cannot decrypt tenant A's ciphertext.
        call(
            &kms,
            "tenant-b",
            "POST",
            "/keys/shared-name",
            Some(json!({})),
        )
        .await;
        assert_eq!(
            decrypt(&kms, "tenant-b", "shared-name", json!({"ciphertext": ct}))
                .await
                .0,
            400
        );
        Ok(())
    }
}

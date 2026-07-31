//! SPIRE-compatible Transit engine — key management and signing.
//!
//! Routes:
//!   `POST/PUT /keys/{name}`           — create transit key (PUT: SPIRE 1.15+
//!                                       `vault` `KeyManager` plugin)
//!   `POST   /keys/{name}/config`      — update key config (`deletion_allowed`; no-op)
//!   `GET    /keys/{name}`             — read transit key info (public key + version map)
//!   `GET    /keys`                    — list transit keys
//!   `DELETE /keys/{name}`             — delete transit key
//!   `POST   /sign/{name}/{alg}`       — sign (prehashed)
//!
//! Key names are stored in the KMS as user tags `vault_transit:{name}`.
//! Each transit key is an asymmetric key pair (`PrivateKey` + `PublicKey`).
//!
//! Supported key types:
//!   - `ecdsa-p256`  — EC P-256 (FIPS + non-FIPS)
//!   - `ecdsa-p384`  — EC P-384 (FIPS + non-FIPS)
//!   - `rsa-2048`    — RSA 2048 (FIPS + non-FIPS)
//!   - `rsa-4096`    — RSA 4096 (FIPS + non-FIPS)
//!   - `ed25519`     — Ed25519 (non-FIPS only)
//!   - `ml-dsa-65`   — ML-DSA 65 (non-FIPS only)

use std::{collections::HashMap, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::{Destroy, Revoke, Sign},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
                LinkType, LinkedObjectIdentifier, RecommendedCurve, UniqueIdentifier,
            },
            requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
        },
    },
    cosmian_kms_crypto::openssl::kmip_public_key_to_openssl,
};
use cosmian_logger::{debug, trace};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    error::KmsError,
    result::KResult,
    routes::spire::error::{SpireApiError, SpireResult},
};

/// Tag prefix used to identify transit keys in the KMS object store.
/// Tag value stored in KMIP: `vault_transit:{name}` (no brackets).
pub(crate) const TRANSIT_TAG_PREFIX: &str = "vault_transit:";

/// Build the KMIP tag string for a transit key name.
pub(crate) fn transit_tag_name(name: &str) -> String {
    format!("{TRANSIT_TAG_PREFIX}{name}")
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct CreateTransitKeyRequest {
    #[serde(rename = "type")]
    pub key_type: String,
    /// `exportable` is accepted in the JSON body but always forced to `false`.
    #[serde(default)]
    #[allow(dead_code)]
    pub exportable: bool,
    /// Vault's key auto-rotation interval. The KMS performs **no** time-based
    /// key rotation, so only a disabled value (absent, `0`, `"0"`, `""` or
    /// `null`) is accepted; any non-zero interval is rejected with `400` rather
    /// than silently ignored. SPIRE always sends `0`.
    #[serde(default)]
    pub auto_rotate_period: Option<serde_json::Value>,
}

/// Per-version metadata returned inside the `keys` map.
#[derive(Serialize)]
pub(crate) struct TransitKeyVersion {
    /// SPKI PEM public key (`-----BEGIN PUBLIC KEY-----`).
    pub public_key: String,
    /// RFC 3339 creation timestamp.
    pub creation_time: String,
}

/// Full transit key metadata as expected by the Vault API.
#[derive(Serialize)]
pub(crate) struct TransitKeyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub exportable: bool,
    pub allow_deletion: bool,
    /// Always `1` — we don't support in-place Vault-style key versioning.
    pub latest_version: u32,
    /// Map from version number string to key version metadata.
    pub keys: HashMap<String, TransitKeyVersion>,
}

#[derive(Serialize)]
pub(crate) struct TransitKeyInfoWrapper {
    pub data: TransitKeyInfo,
}

#[derive(Serialize)]
pub(crate) struct TransitKeyListData {
    pub keys: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct TransitKeyListWrapper {
    pub data: TransitKeyListData,
}

#[derive(Deserialize)]
pub(crate) struct SignTransitRequest {
    /// Base64-encoded data to sign.
    pub input: String,
    /// When `true` (default), `input` is already a hash digest (prehashed).
    #[serde(default = "default_true")]
    pub prehashed: bool,
    /// RSA signature scheme requested by the client: `"pss"` (default) or
    /// `"pkcs1v15"`.
    ///
    /// This field applies to RSA keys only and is ignored for other key types,
    /// matching Vault (which documents it as RSA-only). When absent the default is
    /// `"pss"`, mirroring Vault's own documented default. SPIRE's `vault`
    /// key manager always sends this field explicitly for RSA keys.
    #[serde(default)]
    pub signature_algorithm: Option<String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub(crate) struct SignTransitData {
    pub signature: String,
}

#[derive(Serialize)]
pub(crate) struct SignTransitResponse {
    pub data: SignTransitData,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Non-FIPS-only key-type mappings.
//
// These are isolated behind function-level `#[cfg(feature = "non-fips")]` (with
// FIPS-build stubs) so that no feature gate sits inside another function's body,
// per the cardinal rule in AGENTS.md §4. In a FIPS build the stubs return `None`,
// making `ed25519`/`ml-dsa-65` genuinely unreachable at compile time.

/// Map an OpenSSL key `Id` to a non-FIPS transit key type (`ed25519`).
#[cfg(feature = "non-fips")]
fn nonfips_transit_key_type_from_pkey_id(id: openssl::pkey::Id) -> Option<&'static str> {
    (id == openssl::pkey::Id::ED25519).then_some("ed25519")
}

/// FIPS-build stub: no non-FIPS key `Id` mapping exists.
#[cfg(not(feature = "non-fips"))]
const fn nonfips_transit_key_type_from_pkey_id(_id: openssl::pkey::Id) -> Option<&'static str> {
    None
}

/// Map a KMIP `RecommendedCurve` to a non-FIPS transit key type (`ed25519`).
#[cfg(feature = "non-fips")]
fn nonfips_transit_key_type_from_curve(curve: Option<RecommendedCurve>) -> Option<&'static str> {
    matches!(curve, Some(RecommendedCurve::CURVEED25519)).then_some("ed25519")
}

/// FIPS-build stub: no non-FIPS curve mapping exists.
#[cfg(not(feature = "non-fips"))]
const fn nonfips_transit_key_type_from_curve(
    _curve: Option<RecommendedCurve>,
) -> Option<&'static str> {
    None
}

/// Map a KMIP `CryptographicAlgorithm` to a non-FIPS transit key type (`ml-dsa-65`).
#[cfg(feature = "non-fips")]
fn nonfips_transit_key_type_from_alg(alg: Option<CryptographicAlgorithm>) -> Option<&'static str> {
    matches!(alg, Some(CryptographicAlgorithm::MLDSA_65)).then_some("ml-dsa-65")
}

/// FIPS-build stub: no non-FIPS algorithm mapping exists.
#[cfg(not(feature = "non-fips"))]
const fn nonfips_transit_key_type_from_alg(
    _alg: Option<CryptographicAlgorithm>,
) -> Option<&'static str> {
    None
}

/// Map a Vault key type string to a non-FIPS `RecommendedCurve` (`ed25519`).
#[cfg(feature = "non-fips")]
fn nonfips_curve_from_key_type(key_type: &str) -> Option<RecommendedCurve> {
    (key_type == "ed25519").then_some(RecommendedCurve::CURVEED25519)
}

/// FIPS-build stub: no non-FIPS key type maps to a curve.
#[cfg(not(feature = "non-fips"))]
const fn nonfips_curve_from_key_type(_key_type: &str) -> Option<RecommendedCurve> {
    None
}

/// Derive the Vault transit key type string from an OpenSSL `PKey<Public>`.
///
/// Reading the curve from the actual key material is authoritative; the
/// `find` result's `Attributes` often omits `cryptographic_domain_parameters`
/// for keys created via `create_ec_key_pair_request`, causing P-384 keys to
/// be incorrectly reported as `ecdsa-p256` when relying on stored attrs alone.
fn transit_key_type_from_pkey(pkey: &openssl::pkey::PKey<openssl::pkey::Public>) -> &'static str {
    use openssl::pkey::Id;

    match pkey.id() {
        Id::EC => pkey
            .ec_key()
            .map_or("ecdsa-p256", |ec| match ec.group().curve_name() {
                Some(openssl::nid::Nid::SECP384R1) => "ecdsa-p384",
                _ => "ecdsa-p256",
            }),
        Id::RSA => match pkey.rsa().map(|r| r.size() * 8) {
            Ok(4096) => "rsa-4096",
            _ => "rsa-2048",
        },
        other => nonfips_transit_key_type_from_pkey_id(other).unwrap_or("ecdsa-p256"),
    }
}

/// Derive a Vault transit key type string from KMIP `Attributes` (G3 fix).
///
/// Used by `GET /keys/{name}` to reconstruct the type from stored metadata.
fn transit_key_type_from_attrs(attrs: &Attributes) -> &'static str {
    match attrs.cryptographic_algorithm {
        Some(CryptographicAlgorithm::EC) => {
            let curve = attrs
                .cryptographic_domain_parameters
                .as_ref()
                .and_then(|p| p.recommended_curve);
            match curve {
                Some(RecommendedCurve::P256) => "ecdsa-p256",
                Some(RecommendedCurve::P384) => "ecdsa-p384",
                other => nonfips_transit_key_type_from_curve(other).unwrap_or("ecdsa-p256"),
            }
        }
        Some(CryptographicAlgorithm::RSA) => match attrs.cryptographic_length {
            Some(4096) => "rsa-4096",
            _ => "rsa-2048",
        },
        other => nonfips_transit_key_type_from_alg(other).unwrap_or("ecdsa-p256"),
    }
}

/// Map a Vault key type string to a KMS `RecommendedCurve` (for EC keys).
fn transit_curve_from_key_type(key_type: &str) -> Option<RecommendedCurve> {
    match key_type {
        "ecdsa-p256" => Some(RecommendedCurve::P256),
        "ecdsa-p384" => Some(RecommendedCurve::P384),
        other => nonfips_curve_from_key_type(other),
    }
}

/// Map a Vault key type string to an RSA bit count.
fn transit_rsa_bits_from_key_type(key_type: &str) -> Option<usize> {
    match key_type {
        "rsa-2048" => Some(2048),
        "rsa-4096" => Some(4096),
        _ => None,
    }
}

/// Map a Vault `hash_algorithm` URL path segment to a KMIP `HashingAlgorithm`.
fn transit_hash_alg_to_kmip(
    hash_alg: &str,
) -> cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
    match hash_alg {
        "sha2-384" | "sha-384" => HashingAlgorithm::SHA384,
        "sha2-512" | "sha-512" => HashingAlgorithm::SHA512,
        _ => HashingAlgorithm::SHA256,
    }
}

/// Map a Vault `signature_algorithm` value to a KMIP `DigitalSignatureAlgorithm`
/// for RSA keys.
///
/// - `Some("pkcs1v15")` → `SHA{256,384,512}WithRSAEncryption` (PKCS#1 v1.5),
///   selected from the request's hashing algorithm.
/// - `Some("pss")` or `None` → `RSASSAPSS` (Vault's documented default).
///
/// Returns a `BadRequest` error for any other value, or for a hashing algorithm
/// that has no PKCS#1 v1.5 mapping.
fn rsa_digital_signature_algorithm(
    signature_algorithm: Option<&str>,
    hash_alg: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm,
) -> SpireResult<DigitalSignatureAlgorithm> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
    match signature_algorithm {
        Some("pkcs1v15") => match hash_alg {
            HashingAlgorithm::SHA256 => Ok(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            HashingAlgorithm::SHA384 => Ok(DigitalSignatureAlgorithm::SHA384WithRSAEncryption),
            HashingAlgorithm::SHA512 => Ok(DigitalSignatureAlgorithm::SHA512WithRSAEncryption),
            other => Err(SpireApiError::BadRequest(format!(
                "unsupported hashing algorithm {other:?} for pkcs1v15 RSA signing"
            ))),
        },
        Some("pss") | None => Ok(DigitalSignatureAlgorithm::RSASSAPSS),
        Some(other) => Err(SpireApiError::BadRequest(format!(
            "unsupported signature_algorithm '{other}'. Supported: pss, pkcs1v15"
        ))),
    }
}

/// Build an `Attributes` filter for finding private keys with a given transit tag.
fn transit_key_filter(kms: &KMS, name: &str) -> KResult<Attributes> {
    let mut filter = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };
    filter
        .set_tags(kms.vendor_id(), [transit_tag_name(name)])
        .map_err(|e| {
            KmsError::ServerError(format!("failed to build transit key tag filter: {e}"))
        })?;
    Ok(filter)
}

/// Return `true` when a Vault `auto_rotate_period` value disables rotation.
///
/// Vault accepts the interval as either an integer number of seconds or a
/// duration string. Since the KMS performs no time-based rotation, only a value
/// that unambiguously means "no rotation" is accepted; anything else is treated
/// as an unsupported request by the caller.
fn auto_rotate_disabled(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Number(n)) => n.as_f64() == Some(0.0),
        Some(serde_json::Value::String(s)) => matches!(s.trim(), "" | "0" | "0s" | "0m" | "0h"),
        Some(_) => false,
    }
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// Create a non-FIPS-only transit key (currently ML-DSA-65).
///
/// Returns `Some(response)` when `body.key_type` names a non-FIPS key type this
/// function handles, or `None` to let the caller fall through to the
/// FIPS-approved key types. Isolated behind a function-level `#[cfg]` so no
/// feature gate sits inside `create_transit_key`'s body (AGENTS.md §4).
#[cfg(feature = "non-fips")]
async fn create_nonfips_transit_key(
    kms: &KMS,
    user: &str,
    name: &str,
    body: &CreateTransitKeyRequest,
    tags: [&str; 1],
) -> SpireResult<Option<Json<TransitKeyInfoWrapper>>> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::requests::create_pqc_key_pair_request;

    if body.key_type != "ml-dsa-65" {
        return Ok(None);
    }

    let create_req = create_pqc_key_pair_request(
        kms.vendor_id(),
        tags,
        CryptographicAlgorithm::MLDSA_65,
        // sensitive = true → non-exportable at KMIP level (see EC branch).
        true,
    )
    .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    kms.create_key_pair(create_req, user)
        .await
        .map_err(SpireApiError::from)?;

    debug!("vault transit: created ML-DSA-65 key '{name}'");
    Ok(Some(key_created_response(
        name.to_owned(),
        body.key_type.clone(),
    )))
}

/// FIPS-build stub: no non-FIPS transit key types exist.
#[cfg(not(feature = "non-fips"))]
#[allow(clippy::unused_async)] // async required to match the non-fips signature awaited by the caller
async fn create_nonfips_transit_key(
    _kms: &KMS,
    _user: &str,
    _name: &str,
    _body: &CreateTransitKeyRequest,
    _tags: [&str; 1],
) -> SpireResult<Option<Json<TransitKeyInfoWrapper>>> {
    Ok(None)
}

/// `POST /keys/{name}` — create a new transit signing key.
///
/// `exportable` is silently forced to `false` — transit keys cannot be exported.
#[post("/keys/{name}")]
pub(crate) async fn create_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<CreateTransitKeyRequest>,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    create_transit_key_impl(req, kms, name, body).await
}

/// `PUT /keys/{name}` — same as `POST /keys/{name}` (see below).
///
/// SPIRE's `vault` `KeyManager` plugin (landed in SPIRE 1.15.0) issues
/// `PUT /v1/transit/keys/{name}` to create its signing keys, while the Vault
/// HTTP API itself (and this KMS's own negative-scenario tests) use `POST` —
/// both must create the same key.
#[put("/keys/{name}")]
pub(crate) async fn create_transit_key_put(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<CreateTransitKeyRequest>,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    create_transit_key_impl(req, kms, name, body).await
}

/// Build a transit key creation response with default values.
fn key_created_response(name: String, key_type: String) -> Json<TransitKeyInfoWrapper> {
    Json(TransitKeyInfoWrapper {
        data: TransitKeyInfo {
            name,
            key_type,
            exportable: false,
            allow_deletion: true,
            latest_version: 1,
            keys: HashMap::new(),
        },
    })
}

async fn create_transit_key_impl(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<CreateTransitKeyRequest>,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    let user = kms.get_user(&req);
    let name = name.into_inner();
    let body = body.into_inner();

    trace!(
        user = user,
        "{} vault transit keys/{name} type={}",
        req.method(),
        body.key_type
    );

    // The KMS performs no time-based key rotation; reject a non-zero
    // auto_rotate_period rather than silently ignoring it. SPIRE sends `0`.
    if !auto_rotate_disabled(body.auto_rotate_period.as_ref()) {
        return Err(SpireApiError::BadRequest(
            "auto_rotate_period is not supported: the KMS performs no time-based key rotation \
             (send 0 or omit the field)"
                .to_owned(),
        ));
    }

    let tag = transit_tag_name(&name);
    let tags = [tag.as_str()];

    // EC key types (also handles ed25519 in non-FIPS via curve matching)
    if let Some(curve) = transit_curve_from_key_type(&body.key_type) {
        // `sensitive = true` marks the private key as non-exportable at the KMIP
        // level: the `Get`/`Export` guard in `core::operations::export_get` denies
        // retrieval whenever `sensitive == Some(true)`. This enforces the
        // `exportable: false` invariant server-side for *all* API surfaces (KMIP,
        // `ckms`), not just the Vault-compatible HTTP dialect. Signing happens
        // server-side and does not require export, so it is unaffected.
        let create_req = create_ec_key_pair_request(kms.vendor_id(), None, tags, curve, true, None)
            .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

        kms.create_key_pair(create_req, &user)
            .await
            .map_err(SpireApiError::from)?;

        debug!(
            "vault transit: created EC key '{name}' type={}",
            body.key_type
        );
        return Ok(key_created_response(name, body.key_type));
    }

    // ML-DSA (non-FIPS only) — handled by a #[cfg]-gated free function so no
    // feature gate sits inside this function body.
    if let Some(resp) = create_nonfips_transit_key(&kms, &user, &name, &body, tags).await? {
        return Ok(resp);
    }

    // RSA key types
    if let Some(bits) = transit_rsa_bits_from_key_type(&body.key_type) {
        // sensitive = true → non-exportable at KMIP level (see EC branch).
        let create_req = create_rsa_key_pair_request(kms.vendor_id(), None, tags, bits, true, None)
            .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

        kms.create_key_pair(create_req, &user)
            .await
            .map_err(SpireApiError::from)?;

        debug!("vault transit: created RSA key '{name}' bits={bits}");
        return Ok(key_created_response(name, body.key_type));
    }

    Err(SpireApiError::BadRequest(format!(
        "unsupported transit key type '{}'. Supported: ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096{}",
        body.key_type,
        if cfg!(feature = "non-fips") {
            ", ed25519, ml-dsa-65"
        } else {
            ""
        }
    )))
}

/// `GET /keys/{name}` — read transit key metadata including the public key.
///
/// Returns the Vault-compatible response with `latest_version`, `type`,
/// and `keys["1"].public_key` (SPKI PEM) that SPIRE's `KeyManager` plugin
/// requires at startup to warm its in-memory key cache.
#[get("/keys/{name}")]
pub(crate) async fn get_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
) -> SpireResult<Json<TransitKeyInfoWrapper>> {
    let user = kms.get_user(&req);
    let name = name.into_inner();

    let filter = transit_key_filter(&kms, &name).map_err(SpireApiError::from)?;

    let results = kms
        .database
        .find(Some(&filter), None, &user, false, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    let (_priv_uid, _state, attrs) = results
        .into_iter()
        .next()
        .ok_or_else(|| SpireApiError::NotFound(format!("transit key '{name}' not found")))?;

    // Creation timestamp (RFC3339) for the key version map
    let creation_time = attrs
        .initial_date
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| {
            time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default()
        });

    // Retrieve linked public key; derive key type from the PKey object (not from
    // stored Attributes, which may lack cryptographic_domain_parameters after find).
    let fallback = || {
        (
            String::new(),
            transit_key_type_from_attrs(&attrs).to_owned(),
        )
    };
    let (public_key_pem, key_type) = match attrs.get_link(LinkType::PublicKeyLink) {
        Some(LinkedObjectIdentifier::TextString(pub_uid)) => {
            match kms.database.retrieve_object(&pub_uid).await {
                Ok(Some(owm)) => kmip_public_key_to_openssl(owm.object()).map_or_else(
                    |_| fallback(),
                    |pkey| {
                        let ktype = transit_key_type_from_pkey(&pkey).to_owned();
                        let pem = pkey
                            .public_key_to_pem()
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                            .unwrap_or_default();
                        (pem, ktype)
                    },
                ),
                _ => fallback(),
            }
        }
        _ => fallback(),
    };

    let mut keys = HashMap::new();
    keys.insert(
        "1".to_owned(),
        TransitKeyVersion {
            public_key: public_key_pem,
            creation_time,
        },
    );

    Ok(Json(TransitKeyInfoWrapper {
        data: TransitKeyInfo {
            name,
            key_type,
            exportable: false,
            allow_deletion: true,
            latest_version: 1,
            keys,
        },
    }))
}

/// `POST /keys/{name}/config` — update transit key configuration.
///
/// Vault requires callers to POST `{"deletion_allowed": true}` before a key
/// can be deleted.  In Cosmian KMS, deletion policy is controlled server-side;
/// this endpoint accepts the request and returns `204 No Content` so SPIRE's
/// background delete worker can proceed to the actual `DELETE /keys/{name}` call.
///
/// This is an intentional no-op: it deliberately does **not** verify that the
/// named key exists (nor that the caller owns it). The subsequent
/// `DELETE /keys/{name}` performs the real owner-scoped lookup and returns
/// `404` if the key is absent, so nothing is leaked by always answering `204`.
#[post("/keys/{name}/config")]
pub(crate) async fn configure_transit_key(
    _req: HttpRequest,
    _kms: Data<Arc<KMS>>,
    name: Path<String>,
    _body: Json<serde_json::Value>,
) -> SpireResult<HttpResponse> {
    trace!(
        "POST vault transit keys/{}/config (no-op)",
        name.into_inner()
    );
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /keys` — list all transit key names.
///
/// Note: unlike Vault — whose `LIST` on an empty/absent path returns
/// `404` — this endpoint always returns `200` with a (possibly empty) `keys`
/// array. This is an intentional, SPIRE-compatible superset: SPIRE's Go SDK
/// treats an empty list and a 404 identically, and a plain `200` avoids the
/// ambiguity of a 404 that could also mean "route not found".
#[get("/keys")]
pub(crate) async fn list_transit_keys(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> SpireResult<Json<TransitKeyListWrapper>> {
    let user = kms.get_user(&req);

    let filter = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    let results = kms
        .database
        .find(Some(&filter), None, &user, false, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    let mut names = Vec::new();
    for (_uid, _state, attrs) in results {
        let tags = attrs.get_tags(kms.vendor_id());
        for tag in &tags {
            if let Some(key_name) = tag.strip_prefix(TRANSIT_TAG_PREFIX) {
                names.push(key_name.to_owned());
            }
        }
    }
    names.sort();
    names.dedup();

    Ok(Json(TransitKeyListWrapper {
        data: TransitKeyListData { keys: names },
    }))
}

/// `DELETE /keys/{name}` — delete a transit key.
#[delete("/keys/{name}")]
pub(crate) async fn delete_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
) -> SpireResult<HttpResponse> {
    let user = kms.get_user(&req);
    let name = name.into_inner();

    let filter = transit_key_filter(&kms, &name).map_err(SpireApiError::from)?;

    let results = kms
        .database
        .find(Some(&filter), None, &user, false, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    if results.is_empty() {
        return Err(SpireApiError::NotFound(format!(
            "transit key '{name}' not found"
        )));
    }

    for (uid, _state, _attrs) in results {
        let revoke_req = Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        };
        drop(kms.revoke(revoke_req, &user).await);

        let destroy_req = Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(uid)),
            remove: true,
            cascade: true,
            ..Default::default()
        };
        kms.destroy(destroy_req, &user)
            .await
            .map_err(SpireApiError::from)?;
    }

    debug!("vault transit: deleted key '{name}'");
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /sign/{name}/{hash_alg}` — sign prehashed data.
///
/// SPIRE passes a SHA-256 digest; the response signature is prefixed with `vault:v1:`.
/// ECDSA signatures are returned in ASN.1 DER format (as produced by OpenSSL).
#[post("/sign/{name}/{hash_alg}")]
pub(crate) async fn sign_with_transit_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<(String, String)>,
    body: Json<SignTransitRequest>,
) -> SpireResult<Json<SignTransitResponse>> {
    sign_with_transit_key_impl(req, kms, path, body).await
}

/// `PUT /sign/{name}/{hash_alg}` — same as `POST /sign/{name}/{hash_alg}` (see below).
///
/// SPIRE's `vault` `KeyManager` plugin issues `PUT` for its transit
/// sign calls, while the Vault HTTP API itself uses `POST`.
#[put("/sign/{name}/{hash_alg}")]
pub(crate) async fn sign_with_transit_key_put(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<(String, String)>,
    body: Json<SignTransitRequest>,
) -> SpireResult<Json<SignTransitResponse>> {
    sign_with_transit_key_impl(req, kms, path, body).await
}

async fn sign_with_transit_key_impl(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<(String, String)>,
    body: Json<SignTransitRequest>,
) -> SpireResult<Json<SignTransitResponse>> {
    let user = kms.get_user(&req);
    let (name, hash_alg_path) = path.into_inner();
    let body = body.into_inner();

    trace!(
        user = user,
        "{} vault transit sign/{name}/{hash_alg_path}",
        req.method()
    );

    let input_bytes = BASE64_STANDARD
        .decode(&body.input)
        .map_err(|_e| SpireApiError::BadRequest("invalid base64 in 'input' field".to_owned()))?;

    let filter = transit_key_filter(&kms, &name).map_err(SpireApiError::from)?;

    let results = kms
        .database
        .find(Some(&filter), None, &user, false, kms.vendor_id())
        .await
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

    let (private_key_uid, _state, attrs) = results
        .into_iter()
        .next()
        .ok_or_else(|| SpireApiError::NotFound(format!("transit key '{name}' not found")))?;

    let hash_alg = transit_hash_alg_to_kmip(&hash_alg_path);

    // The Vault `signature_algorithm` field (pss | pkcs1v15) is RSA-only. For RSA
    // keys, translate it into the KMIP `DigitalSignatureAlgorithm` so the requested
    // scheme is actually honored; without this the RSA default (RSASSA-PSS) would be
    // used regardless of what the client asked for. Non-RSA keys ignore the field.
    let digital_signature_algorithm =
        if attrs.cryptographic_algorithm == Some(CryptographicAlgorithm::RSA) {
            Some(rsa_digital_signature_algorithm(
                body.signature_algorithm.as_deref(),
                hash_alg,
            )?)
        } else {
            None
        };

    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_uid)),
        cryptographic_parameters: Some(CryptographicParameters {
            hashing_algorithm: Some(hash_alg),
            digital_signature_algorithm,
            ..Default::default()
        }),
        digested_data: if body.prehashed {
            Some(input_bytes.clone())
        } else {
            None
        },
        data: if body.prehashed {
            None
        } else {
            Some(Zeroizing::new(input_bytes))
        },
        ..Default::default()
    };

    let resp = kms
        .sign(sign_req, &user)
        .await
        .map_err(SpireApiError::from)?;

    let sig_bytes = resp.signature_data.ok_or_else(|| {
        SpireApiError::InternalError("Sign response missing signature_data".to_owned())
    })?;

    // Vault signature format: vault:v1:<base64(raw_sig)>
    let signature = format!("vault:v1:{}", BASE64_STANDARD.encode(&sig_bytes));

    Ok(Json(SignTransitResponse {
        data: SignTransitData { signature },
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_types::{
                CryptographicAlgorithm, CryptographicDomainParameters, DigitalSignatureAlgorithm,
                RecommendedCurve,
            },
        },
    };

    use super::{
        auto_rotate_disabled, rsa_digital_signature_algorithm, transit_curve_from_key_type,
        transit_hash_alg_to_kmip, transit_key_type_from_attrs, transit_rsa_bits_from_key_type,
        transit_tag_name,
    };

    #[test]
    fn auto_rotate_disabled_accepts_zero_forms() {
        use serde_json::json;
        assert!(auto_rotate_disabled(None));
        assert!(auto_rotate_disabled(Some(&json!(null))));
        assert!(auto_rotate_disabled(Some(&json!(0))));
        assert!(auto_rotate_disabled(Some(&json!("0"))));
        assert!(auto_rotate_disabled(Some(&json!("0s"))));
        assert!(auto_rotate_disabled(Some(&json!(""))));
        // Any real rotation interval is rejected.
        assert!(!auto_rotate_disabled(Some(&json!(3600))));
        assert!(!auto_rotate_disabled(Some(&json!("24h"))));
        assert!(!auto_rotate_disabled(Some(&json!("720h"))));
    }

    #[test]
    fn tag_name_is_prefixed() {
        assert_eq!(transit_tag_name("my-key"), "vault_transit:my-key");
    }

    #[test]
    fn curve_from_key_type_maps_fips_curves() {
        assert_eq!(
            transit_curve_from_key_type("ecdsa-p256"),
            Some(RecommendedCurve::P256)
        );
        assert_eq!(
            transit_curve_from_key_type("ecdsa-p384"),
            Some(RecommendedCurve::P384)
        );
        assert_eq!(transit_curve_from_key_type("rsa-2048"), None);
        assert_eq!(transit_curve_from_key_type("unknown"), None);
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn curve_from_key_type_maps_ed25519_in_non_fips() {
        assert_eq!(
            transit_curve_from_key_type("ed25519"),
            Some(RecommendedCurve::CURVEED25519)
        );
    }

    #[cfg(not(feature = "non-fips"))]
    #[test]
    fn curve_from_key_type_rejects_ed25519_in_fips() {
        assert_eq!(transit_curve_from_key_type("ed25519"), None);
    }

    #[test]
    fn rsa_bits_from_key_type_maps_supported_sizes() {
        assert_eq!(transit_rsa_bits_from_key_type("rsa-2048"), Some(2048));
        assert_eq!(transit_rsa_bits_from_key_type("rsa-4096"), Some(4096));
        assert_eq!(transit_rsa_bits_from_key_type("rsa-1024"), None);
        assert_eq!(transit_rsa_bits_from_key_type("ecdsa-p256"), None);
    }

    #[test]
    fn hash_alg_to_kmip_maps_vault_names() {
        assert_eq!(
            transit_hash_alg_to_kmip("sha2-256"),
            HashingAlgorithm::SHA256
        );
        assert_eq!(
            transit_hash_alg_to_kmip("sha2-384"),
            HashingAlgorithm::SHA384
        );
        assert_eq!(
            transit_hash_alg_to_kmip("sha-384"),
            HashingAlgorithm::SHA384
        );
        assert_eq!(
            transit_hash_alg_to_kmip("sha2-512"),
            HashingAlgorithm::SHA512
        );
        assert_eq!(
            transit_hash_alg_to_kmip("sha-512"),
            HashingAlgorithm::SHA512
        );
        // Unknown values fall back to SHA-256.
        assert_eq!(transit_hash_alg_to_kmip("md5"), HashingAlgorithm::SHA256);
    }

    fn ec_attrs(curve: Option<RecommendedCurve>) -> Attributes {
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                recommended_curve: curve,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn key_type_from_attrs_maps_ec_and_rsa() {
        assert_eq!(
            transit_key_type_from_attrs(&ec_attrs(Some(RecommendedCurve::P256))),
            "ecdsa-p256"
        );
        assert_eq!(
            transit_key_type_from_attrs(&ec_attrs(Some(RecommendedCurve::P384))),
            "ecdsa-p384"
        );
        // Missing curve defaults to P-256.
        assert_eq!(transit_key_type_from_attrs(&ec_attrs(None)), "ecdsa-p256");

        let rsa4096 = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(4096),
            ..Default::default()
        };
        assert_eq!(transit_key_type_from_attrs(&rsa4096), "rsa-4096");

        let rsa_default = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            ..Default::default()
        };
        assert_eq!(transit_key_type_from_attrs(&rsa_default), "rsa-2048");
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn key_type_from_attrs_maps_non_fips_algorithms() {
        assert_eq!(
            transit_key_type_from_attrs(&ec_attrs(Some(RecommendedCurve::CURVEED25519))),
            "ed25519"
        );
        let mldsa = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::MLDSA_65),
            ..Default::default()
        };
        assert_eq!(transit_key_type_from_attrs(&mldsa), "ml-dsa-65");
    }

    #[test]
    fn rsa_signature_algorithm_defaults_to_pss() {
        assert_eq!(
            rsa_digital_signature_algorithm(None, HashingAlgorithm::SHA256).unwrap(),
            DigitalSignatureAlgorithm::RSASSAPSS
        );
        assert_eq!(
            rsa_digital_signature_algorithm(Some("pss"), HashingAlgorithm::SHA512).unwrap(),
            DigitalSignatureAlgorithm::RSASSAPSS
        );
    }

    #[test]
    fn rsa_signature_algorithm_maps_pkcs1v15_per_hash() {
        assert_eq!(
            rsa_digital_signature_algorithm(Some("pkcs1v15"), HashingAlgorithm::SHA256).unwrap(),
            DigitalSignatureAlgorithm::SHA256WithRSAEncryption
        );
        assert_eq!(
            rsa_digital_signature_algorithm(Some("pkcs1v15"), HashingAlgorithm::SHA384).unwrap(),
            DigitalSignatureAlgorithm::SHA384WithRSAEncryption
        );
        assert_eq!(
            rsa_digital_signature_algorithm(Some("pkcs1v15"), HashingAlgorithm::SHA512).unwrap(),
            DigitalSignatureAlgorithm::SHA512WithRSAEncryption
        );
    }

    #[test]
    fn rsa_signature_algorithm_rejects_unknown_scheme() {
        let result = rsa_digital_signature_algorithm(Some("nope"), HashingAlgorithm::SHA256);
        assert!(matches!(
            result,
            Err(crate::routes::spire::error::SpireApiError::BadRequest(_))
        ));
    }
}

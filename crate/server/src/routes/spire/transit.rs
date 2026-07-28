//! SPIRE-compatible Transit engine — key management and signing.
//!
//! Routes:
//!   `POST   /keys/{name}`             — create transit key
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
    HttpRequest, HttpResponse, delete, get, post,
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
                CryptographicAlgorithm, CryptographicParameters, LinkType, LinkedObjectIdentifier,
                RecommendedCurve, UniqueIdentifier,
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
        #[cfg(feature = "non-fips")]
        Id::ED25519 => "ed25519",
        _ => "ecdsa-p256",
    }
}

/// Derive a Vault transit key type string from KMIP `Attributes` (G3 fix).
///
/// Used by `GET /keys/{name}` to reconstruct the type from stored metadata.
fn transit_key_type_from_attrs(attrs: &Attributes) -> &'static str {
    match attrs.cryptographic_algorithm {
        Some(CryptographicAlgorithm::EC) => {
            match attrs
                .cryptographic_domain_parameters
                .as_ref()
                .and_then(|p| p.recommended_curve)
            {
                Some(RecommendedCurve::P256) => "ecdsa-p256",
                Some(RecommendedCurve::P384) => "ecdsa-p384",
                #[cfg(feature = "non-fips")]
                Some(RecommendedCurve::CURVEED25519) => "ed25519",
                _ => "ecdsa-p256",
            }
        }
        Some(CryptographicAlgorithm::RSA) => match attrs.cryptographic_length {
            Some(4096) => "rsa-4096",
            _ => "rsa-2048",
        },
        #[cfg(feature = "non-fips")]
        Some(CryptographicAlgorithm::MLDSA_65) => "ml-dsa-65",
        _ => "ecdsa-p256",
    }
}

/// Map a Vault key type string to a KMS `RecommendedCurve` (for EC keys).
fn transit_curve_from_key_type(key_type: &str) -> Option<RecommendedCurve> {
    match key_type {
        "ecdsa-p256" => Some(RecommendedCurve::P256),
        "ecdsa-p384" => Some(RecommendedCurve::P384),
        #[cfg(feature = "non-fips")]
        "ed25519" => Some(RecommendedCurve::CURVEED25519),
        _ => None,
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

// ── Route handlers ────────────────────────────────────────────────────────────

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
    let user = kms.get_user(&req);
    let name = name.into_inner();
    let body = body.into_inner();

    trace!(
        user = user,
        "POST vault transit keys/{name} type={}", body.key_type
    );

    let tag = transit_tag_name(&name);
    let tags = [tag.as_str()];

    // EC key types (also handles ed25519 in non-FIPS via curve matching)
    if let Some(curve) = transit_curve_from_key_type(&body.key_type) {
        let create_req =
            create_ec_key_pair_request(kms.vendor_id(), None, tags, curve, false, None)
                .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

        kms.create_key_pair(create_req, &user)
            .await
            .map_err(SpireApiError::from)?;

        debug!(
            "vault transit: created EC key '{name}' type={}",
            body.key_type
        );
        return Ok(Json(TransitKeyInfoWrapper {
            data: TransitKeyInfo {
                name,
                key_type: body.key_type,
                exportable: false,
                allow_deletion: true,
                latest_version: 1,
                keys: HashMap::new(),
            },
        }));
    }

    // ML-DSA (non-FIPS only)
    #[cfg(feature = "non-fips")]
    if body.key_type == "ml-dsa-65" {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_types::CryptographicAlgorithm, requests::create_pqc_key_pair_request,
        };

        let create_req = create_pqc_key_pair_request(
            kms.vendor_id(),
            tags,
            CryptographicAlgorithm::MLDSA_65,
            false,
        )
        .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

        kms.create_key_pair(create_req, &user)
            .await
            .map_err(SpireApiError::from)?;

        debug!("vault transit: created ML-DSA-65 key '{name}'");
        return Ok(Json(TransitKeyInfoWrapper {
            data: TransitKeyInfo {
                name,
                key_type: body.key_type,
                exportable: false,
                allow_deletion: true,
                latest_version: 1,
                keys: HashMap::new(),
            },
        }));
    }

    // RSA key types
    if let Some(bits) = transit_rsa_bits_from_key_type(&body.key_type) {
        let create_req =
            create_rsa_key_pair_request(kms.vendor_id(), None, tags, bits, false, None)
                .map_err(|e| SpireApiError::InternalError(e.to_string()))?;

        kms.create_key_pair(create_req, &user)
            .await
            .map_err(SpireApiError::from)?;

        debug!("vault transit: created RSA key '{name}' bits={bits}");
        return Ok(Json(TransitKeyInfoWrapper {
            data: TransitKeyInfo {
                name,
                key_type: body.key_type,
                exportable: false,
                allow_deletion: true,
                latest_version: 1,
                keys: HashMap::new(),
            },
        }));
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
    let user = kms.get_user(&req);
    let (name, hash_alg_path) = path.into_inner();
    let body = body.into_inner();

    trace!(
        user = user,
        "POST vault transit sign/{name}/{hash_alg_path}"
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

    let (private_key_uid, _state, _attrs) = results
        .into_iter()
        .next()
        .ok_or_else(|| SpireApiError::NotFound(format!("transit key '{name}' not found")))?;

    let hash_alg = transit_hash_alg_to_kmip(&hash_alg_path);

    let sign_req = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_uid)),
        cryptographic_parameters: Some(CryptographicParameters {
            hashing_algorithm: Some(hash_alg),
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

//! `GET /.well-known/jwks.json` — RFC 7517 JSON Web Key Set endpoint.
//!
//! Serves all public keys owned by (or granted to) the server's
//! `default_username` that are tagged [`JWKS_TAG`] and in `Active` or
//! `Deactivated` state (rotation-overlap support).  The endpoint is
//! intentionally **unauthenticated**.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, State},
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::{Object, ObjectType},
        },
    },
    cosmian_kms_crypto::openssl::kmip_public_key_to_openssl,
};
use cosmian_logger::{info, trace, warn};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, KeyAlgorithm, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    pkey::{Id, PKey, Public},
};
use serde::Serialize;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// User tag that marks a public key for inclusion in the JWKS endpoint.
///
/// REST-created key pairs are auto-tagged by default; disable globally with
/// `--jwks-endpoint-auto-tag=false` (`KMS_JWKS_ENDPOINT_AUTO_TAG=false`).
/// Remove this tag from an individual key to opt it out.
pub(crate) const JWKS_TAG: &str = "jwks";

/// JSON Web Key Set envelope (RFC 7517 §5).
///
/// Built from raw [`serde_json::Value`] entries rather than the `jsonwebtoken`
/// crate's typed `JwkSet` because that crate's `EllipticCurve` enum has no
/// `X25519` variant — an OKP/X25519 key-agreement JWK must be hand-built as
/// raw JSON (see [`x25519_to_jwk`]). Typed entries (RSA/EC/Ed25519) are
/// converted via `serde_json::to_value`, so the wire format is unaffected.
#[derive(Serialize)]
struct RawJwkSet {
    keys: Vec<serde_json::Value>,
}

/// `GET /.well-known/jwks.json` — RFC 7517 public key endpoint.
///
/// Returns the JWK Set of all public keys accessible to the server's
/// default user that have `Verify` in their `CryptographicUsageMask`.
/// Only keys in `Active` or `Deactivated` state are included (rotation
/// overlap: verifiers still need old public keys while tokens signed with
/// the retired private key are in circulation).
///
/// The route is only registered when `jwks_endpoint_enabled = true` in server config.
/// The handler is registered inside a `web::scope("/.well-known")` scope so the
/// full request path is `/.well-known/jwks.json`.
#[get("/jwks.json")]
pub(crate) async fn get_jwks(req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    info!("GET /.well-known/jwks.json");

    let (jwk_set, truncated) = Box::pin(build_jwk_set(&kms)).await?;
    let json = serde_json::to_string(&jwk_set)
        .map_err(|e| KmsError::ServerError(format!("JWKS serialization failed: {e}")))?;

    // RFC 7232: return 304 when the client's cached copy is current.
    let etag = format!(
        "W/\"{}\"",
        hex::encode(openssl::sha::sha256(json.as_bytes()))
    ); // weak ETag with SHA-256 of the JSON body
    if req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag)
    {
        return Ok(HttpResponse::NotModified().finish());
    }

    let mut response = HttpResponse::Ok();
    response
        .content_type("application/jwk-set+json")
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("ETag", etag));
    if truncated {
        warn!(
            "JWKS response truncated: more than {} eligible public keys found",
            kms.params.jwks_endpoint.jwks_endpoint_max_keys
        );
        response.insert_header(("X-JWKS-Truncated", "true"));
    }
    Ok(response.body(json))
}

/// Build the JWK Set and a boolean indicating whether the result was truncated.
async fn build_jwk_set(kms: &KMS) -> KResult<(RawJwkSet, bool)> {
    let objects = Box::pin(discover_eligible_public_keys(kms)).await?;
    let max_keys = kms.params.jwks_endpoint.jwks_endpoint_max_keys;
    let truncated = objects.len() > max_keys;

    let mut keys = Vec::with_capacity(objects.len().min(max_keys));
    for (uid, object, attributes) in objects.into_iter().take(max_keys) {
        match object_to_jwk(&uid, &object, &attributes) {
            Ok(Some(jwk)) => keys.push(jwk),
            Ok(None) => {
                // Unsupported key type — silently skip (e.g., Ed448).
            }
            Err(e) => {
                // One bad key must not poison the entire JWKS.
                warn!("Skipping key uid={uid} from JWKS (conversion failed): {e}");
            }
        }
    }
    Ok((RawJwkSet { keys }, truncated))
}

/// Query the database for all public keys eligible for JWKS inclusion.
///
/// Eligibility criteria:
/// - `ObjectType::PublicKey`
/// - Tagged [`JWKS_TAG`] (`"jwks"`)
/// - `State` is `Active` or `Deactivated`
///
/// **Key ordering**: keys are returned in database insertion order (for `SQLite`).
/// The order is stable within a session but is not guaranteed to be stable across
/// server restarts or across different database backends (`PostgreSQL`, `MySQL`).
/// JWKS consumers **must not** rely on position — always match keys by `kid`.
async fn discover_eligible_public_keys(kms: &KMS) -> KResult<Vec<(String, Object, Attributes)>> {
    let mut filter = Attributes {
        object_type: Some(ObjectType::PublicKey),
        ..Default::default()
    };
    filter
        .set_tags(kms.vendor_id(), [JWKS_TAG])
        .map_err(|e| KmsError::ServerError(format!("Failed to build JWKS tag filter: {e}")))?;

    let results = kms
        .database
        .find(
            Some(&filter),
            None, // no state pre-filter: filter client-side to include both Active and Deactivated
            &UserId::from(kms.params.default_username.as_str()),
            false,
            kms.vendor_id(),
        )
        .await?;

    let mut objects = Vec::new();
    for (uid, state, _attrs) in results {
        // Include Active (in service) and Deactivated (retired, rotation overlap).
        // Exclude Compromised, Destroyed, and Destroyed_Compromised.
        if !matches!(state, State::Active | State::Deactivated) {
            continue;
        }
        match kms.database.retrieve_object(&uid).await? {
            Some(owm) => objects.push((uid, owm.object().clone(), owm.attributes().clone())),
            None => {
                warn!("Key uid={uid} found by Locate but missing on retrieve — skipping");
            }
        }
    }
    trace!(
        "JWKS key order is database insertion order — not stable across restarts or backends. \
         Returning {} eligible key(s); consumers must match by `kid`, not position.",
        objects.len()
    );
    Ok(objects)
}

/// Convert a KMIP `PublicKey` object to a JWK, serialized as raw JSON.
///
/// Returns `Ok(None)` for key types not representable in RFC 7517
/// (e.g., Ed448, which is absent from the `jsonwebtoken` crate's
/// `EllipticCurve` enum).
fn object_to_jwk(
    uid: &str,
    object: &Object,
    attributes: &Attributes,
) -> KResult<Option<serde_json::Value>> {
    let pkey = kmip_public_key_to_openssl(object).map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to convert public key uid={uid} to OpenSSL: {e}"
        ))
    })?;

    let usage_mask = attributes.cryptographic_usage_mask;

    match pkey.id() {
        Id::RSA => rsa_to_jwk(uid, &pkey).map(|jwk| to_json_value(uid, &jwk)),
        Id::EC => Ok(ec_to_jwk(uid, &pkey, usage_mask)?.and_then(|jwk| to_json_value(uid, &jwk))),
        #[cfg(feature = "non-fips")]
        Id::ED25519 => Ok(eddsa_to_jwk(uid, &pkey)?.and_then(|jwk| to_json_value(uid, &jwk))),
        #[cfg(feature = "non-fips")]
        Id::X25519 => x25519_to_jwk(uid, &pkey),
        _ => Ok(None),
    }
}

/// Serialize a typed [`Jwk`] to a raw [`serde_json::Value`].
///
/// Returns `None` (logging the failure, but not propagating it) if
/// serialization fails, so the caller can skip the key entirely rather than
/// emit an invalid `null` entry in the JWKS `keys` array.
fn to_json_value(uid: &str, jwk: &Jwk) -> Option<serde_json::Value> {
    serde_json::to_value(jwk)
        .inspect_err(|e| warn!("JWK serialization failed uid={uid}: {e}"))
        .ok()
}

/// Serialize an RSA public key to JWK.
///
/// Encodes the modulus (`n`) and public exponent (`e`) as unsigned big-endian
/// base64url strings.  The `alg` field is inferred from the modulus bit length:
/// 2048 → `RS256`, 3072 → `RS384`, 4096 → `RS512`.
fn rsa_to_jwk(uid: &str, pkey: &PKey<Public>) -> KResult<Jwk> {
    let rsa = pkey
        .rsa()
        .map_err(|e| KmsError::ServerError(format!("Failed to extract RSA key uid={uid}: {e}")))?;

    let rsa_size = usize::try_from(rsa.size())
        .map_err(|e| KmsError::ServerError(format!("RSA key size out of range uid={uid}: {e}")))?;
    let key_bits = rsa_size * 8;
    let expected_n_len = rsa_size;

    let n_bytes = rsa
        .n()
        .to_vec_padded(i32::try_from(expected_n_len).map_err(|e| {
            KmsError::ServerError(format!("RSA key size out of range uid={uid}: {e}"))
        })?)
        .map_err(|e| KmsError::ServerError(format!("RSA modulus encoding error uid={uid}: {e}")))?;
    // Exponent is typically 3 bytes (65537 = 0x010001) — no padding needed.
    let e_bytes = rsa.e().to_vec();

    let alg = match key_bits {
        2048 => Some(KeyAlgorithm::RS256),
        3072 => Some(KeyAlgorithm::RS384),
        4096 => Some(KeyAlgorithm::RS512),
        _ => None,
    };

    Ok(Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: alg,
            key_id: Some(uid.to_owned()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: URL_SAFE_NO_PAD.encode(&n_bytes),
            e: URL_SAFE_NO_PAD.encode(&e_bytes),
        }),
    })
}

/// Serialize an EC public key to JWK.
///
/// Supported NIST curves: P-256 (`ES256`), P-384 (`ES384`), P-521 (no `alg`
/// because `ES512` is absent from the `jsonwebtoken` crate's [`KeyAlgorithm`]).
///
/// `use`/`alg` are derived from the key's actual `CryptographicUsageMask`
/// (this function operates on the *public* key, so signature usage is denoted
/// by `Verify`, not `Sign`, which only appears on the private-key mask):
/// - `KeyAgreement` (and not `Verify`) → `use=enc`, no `alg` (no ECDH-ES variant
///   exists in the `jsonwebtoken` crate's `KeyAlgorithm` enum either).
/// - Otherwise (default / `Verify`) → `use=sig`, `alg=ES256/ES384` (unchanged
///   pre-existing behavior).
///
/// Returns `Ok(None)` for any other curve (e.g., secp256k1).
fn ec_to_jwk(
    uid: &str,
    pkey: &PKey<Public>,
    usage_mask: Option<CryptographicUsageMask>,
) -> KResult<Option<Jwk>> {
    let ec_key = pkey
        .ec_key()
        .map_err(|e| KmsError::ServerError(format!("Failed to extract EC key uid={uid}: {e}")))?;

    let group = ec_key.group();
    let nid = group
        .curve_name()
        .ok_or_else(|| KmsError::ServerError(format!("EC key uid={uid} has no named curve")))?;

    // Key-agreement-only keys (ECDH-ES) never carry a signature `alg`, regardless
    // of curve, since `jsonwebtoken::KeyAlgorithm` has no ECDH-ES variant.
    // NOTE: this function operates on the *public* key, whose signature usage is
    // denoted by `Verify` (not `Sign`, which only appears on the private-key mask).
    let is_key_agreement_only = usage_mask.is_some_and(|mask| {
        mask.contains(CryptographicUsageMask::KeyAgreement)
            && !mask.contains(CryptographicUsageMask::Verify)
    });

    let (curve, coord_len, sig_alg) = match nid {
        openssl::nid::Nid::X9_62_PRIME256V1 => {
            (EllipticCurve::P256, 32_usize, Some(KeyAlgorithm::ES256))
        }
        openssl::nid::Nid::SECP384R1 => (EllipticCurve::P384, 48_usize, Some(KeyAlgorithm::ES384)),
        // ES512 does not exist in KeyAlgorithm — omit `alg` per RFC 7517 §4.4.
        openssl::nid::Nid::SECP521R1 => (EllipticCurve::P521, 66_usize, None),
        _ => return Ok(None),
    };

    let (public_key_use, alg) = if is_key_agreement_only {
        (Some(PublicKeyUse::Encryption), None)
    } else {
        (Some(PublicKeyUse::Signature), sig_alg)
    };

    let mut ctx = BigNumContext::new().map_err(|e| {
        KmsError::ServerError(format!("BigNumContext creation failed uid={uid}: {e}"))
    })?;
    let mut x_bn = BigNum::new()
        .map_err(|e| KmsError::ServerError(format!("BigNum alloc failed uid={uid}: {e}")))?;
    let mut y_bn = BigNum::new()
        .map_err(|e| KmsError::ServerError(format!("BigNum alloc failed uid={uid}: {e}")))?;

    ec_key
        .public_key()
        .affine_coordinates_gfp(group, &mut x_bn, &mut y_bn, &mut ctx)
        .map_err(|e| {
            KmsError::ServerError(format!("Failed to extract EC coordinates uid={uid}: {e}"))
        })?;

    // CRITICAL: left-pad to the exact curve byte length.
    // OpenSSL's BigNum::to_vec() strips leading zeros; JWK requires
    // exactly `coord_len` bytes (RFC 7518 §6.2.1.2).
    let coord_len_i32 = i32::try_from(coord_len).map_err(|e| {
        KmsError::ServerError(format!("EC coord length out of range uid={uid}: {e}"))
    })?;
    let x_bytes = x_bn.to_vec_padded(coord_len_i32).map_err(|e| {
        KmsError::ServerError(format!("EC x-coordinate encoding error uid={uid}: {e}"))
    })?;
    let y_bytes = y_bn.to_vec_padded(coord_len_i32).map_err(|e| {
        KmsError::ServerError(format!("EC y-coordinate encoding error uid={uid}: {e}"))
    })?;

    Ok(Some(Jwk {
        common: CommonParameters {
            public_key_use,
            key_algorithm: alg,
            key_id: Some(uid.to_owned()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve,
            x: URL_SAFE_NO_PAD.encode(&x_bytes),
            y: URL_SAFE_NO_PAD.encode(&y_bytes),
        }),
    }))
}

/// Serialize an Ed25519 public key to JWK (OKP, non-FIPS only).
///
/// Uses the raw public key bytes (RFC 8037 §2): 32 bytes for Ed25519.
/// Ed448 is not supported because `jsonwebtoken` v10 lacks the `Ed448` variant
/// in its [`EllipticCurve`] enum; those keys are silently skipped.
#[cfg(feature = "non-fips")]
fn eddsa_to_jwk(uid: &str, pkey: &PKey<Public>) -> KResult<Option<Jwk>> {
    use jsonwebtoken::jwk::{OctetKeyPairParameters, OctetKeyPairType};

    let x_bytes = pkey.raw_public_key().map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to extract OKP raw public key uid={uid}: {e}"
        ))
    })?;

    Ok(Some(Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some(uid.to_owned()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(&x_bytes),
        }),
    }))
}

/// Serialize an X25519 static public key to a raw JWK JSON object (OKP,
/// non-FIPS only, ECDH-ES key agreement).
///
/// Hand-built as raw JSON because `jsonwebtoken` v10's `EllipticCurve` enum
/// has no `X25519` variant — the typed `Jwk`/`AlgorithmParameters::OctetKeyPair`
/// structs cannot represent this curve. Format per RFC 8037 §2: raw 32-byte
/// public point, base64url-encoded, no `alg` (ECDH-ES has no registered
/// `jsonwebtoken` equivalent either way).
#[cfg(feature = "non-fips")]
fn x25519_to_jwk(uid: &str, pkey: &PKey<Public>) -> KResult<Option<serde_json::Value>> {
    let x_bytes = pkey.raw_public_key().map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to extract X25519 raw public key uid={uid}: {e}"
        ))
    })?;

    Ok(Some(serde_json::json!({
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "kid": uid,
        "x": URL_SAFE_NO_PAD.encode(&x_bytes),
    })))
}

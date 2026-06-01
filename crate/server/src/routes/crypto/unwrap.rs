use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::CryptographicUsageMask,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::Object,
            kmip_types::{CryptographicAlgorithm, LinkType, UniqueIdentifier},
            requests::create_symmetric_key_kmip_object,
        },
        time_normalize,
    },
    cosmian_kms_crypto::{
        crypto::rsa::ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_unwrap,
        openssl::kmip_private_key_to_openssl,
    },
};
use cosmian_logger::trace;
use zeroize::Zeroizing;

use super::{
    CryptoApiError, CryptoResult, JoseAlgorithm, JoseEncAlgorithm, KeyUnwrapRequest,
    KeyUnwrapResponse, b64_decode, cek_size_bytes, jose_oaep_hashes,
};
use crate::core::{KMS, retrieve_object_utils::retrieve_object_for_operation};

/// `POST /v1/crypto/keys/unwrap` — import a wrapped symmetric key (CEK) without
/// ever exposing it to the caller.
///
/// Accepts a subset of a JWE Flattened JSON: `protected` header (containing `alg`,
/// `enc`, `kid`) and `encrypted_key`. The KMS unwraps the CEK using the private key
/// identified by `kid`, validates the resulting key size against `enc`, stores it in
/// the database, and returns the new key's identifier.
///
/// The caller never sees the plaintext key material.
#[post("/keys/unwrap")]
pub(crate) async fn unwrap_key(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<KeyUnwrapRequest>,
) -> CryptoResult<KeyUnwrapResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/keys/unwrap");

    // Parse the protected header
    let header_bytes = b64_decode("protected", &body.protected)?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        CryptoApiError::BadRequest(format!(
            "Field 'protected' is not valid JSON after base64url decode: {e}"
        ))
    })?;

    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest("Protected header missing required 'kid' field".to_owned())
        })?
        .to_owned();

    let alg: JoseAlgorithm = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest("Protected header missing required 'alg' field".to_owned())
        })?
        .parse()
        .map_err(CryptoApiError::UnsupportedAlgorithm)?;

    let enc: JoseEncAlgorithm = header_json
        .get("enc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest("Protected header missing required 'enc' field".to_owned())
        })?
        .parse()
        .map_err(CryptoApiError::UnsupportedAlgorithm)?;

    // Only RSA-OAEP algorithms are supported for key unwrapping
    match alg {
        JoseAlgorithm::RsaOaep | JoseAlgorithm::RsaOaep256 => {}
        _ => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Algorithm '{alg}' is not supported for key unwrapping. \
                 Supported: RSA-OAEP, RSA-OAEP-256."
            )));
        }
    }

    // Decode the encrypted key
    let encrypted_key_bytes = b64_decode("encrypted_key", &body.encrypted_key)?;
    if encrypted_key_bytes.is_empty() {
        return Err(CryptoApiError::BadRequest(
            "'encrypted_key' must be non-empty".to_owned(),
        ));
    }

    // Resolve the private key
    let owm = retrieve_object_for_operation(&kid, KmipOperation::Decrypt, kms.as_ref(), &user)
        .await
        .map_err(CryptoApiError::from)?;

    let private_key_owm = match owm.object() {
        Object::PrivateKey { .. } => owm,
        Object::PublicKey { .. } => {
            let priv_key_uid = owm
                .attributes()
                .get_link(LinkType::PrivateKeyLink)
                .ok_or_else(|| {
                    CryptoApiError::CryptoFailure(
                        "Key unwrap: public key has no linked private key".to_owned(),
                    )
                })?;
            retrieve_object_for_operation(
                &priv_key_uid.to_string(),
                KmipOperation::Decrypt,
                kms.as_ref(),
                &user,
            )
            .await
            .map_err(CryptoApiError::from)?
        }
        _ => {
            return Err(CryptoApiError::CryptoFailure(format!(
                "Key unwrap: key '{kid}' is not an RSA key pair (got {:?})",
                owm.object().object_type()
            )));
        }
    };

    // Convert to OpenSSL private key
    let private_key = kmip_private_key_to_openssl(private_key_owm.object()).map_err(|e| {
        CryptoApiError::CryptoFailure(format!("Key unwrap: failed to load private key: {e}"))
    })?;

    // Validate RSA key type and minimum size
    if private_key.id() != openssl::pkey::Id::RSA {
        return Err(CryptoApiError::CryptoFailure(format!(
            "Key unwrap: key '{kid}' is not an RSA key (got {:?})",
            private_key.id()
        )));
    }
    if private_key.bits() < 2048 {
        return Err(CryptoApiError::CryptoFailure(format!(
            "Key unwrap: RSA key too small ({} bits). Minimum: 2048 bits.",
            private_key.bits()
        )));
    }

    // Perform the RSA-OAEP unwrap
    let (oaep_hash, mgf1_hash) = jose_oaep_hashes(alg)?;
    let expected_cek_len = cek_size_bytes(enc);

    let cek: Zeroizing<Vec<u8>> = ckm_rsa_pkcs_oaep_key_unwrap(
        &private_key,
        oaep_hash,
        mgf1_hash,
        None,
        &encrypted_key_bytes,
    )
    .map_err(|e| {
        CryptoApiError::CryptoFailure(format!("Key unwrap: RSA-OAEP unwrap failed: {e}"))
    })?;

    // Validate unwrapped key size matches enc expectation
    if cek.len() != expected_cek_len {
        return Err(CryptoApiError::CryptoFailure(format!(
            "Key unwrap: unwrapped key size ({} bytes) does not match expected size \
             for {enc} ({expected_cek_len} bytes)",
            cek.len()
        )));
    }

    // Build attributes for the imported symmetric key
    let enc_str = enc.to_string();
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        // Set activation_date to now so the key is immediately Active.
        activation_date: Some(time_normalize().map_err(|e| {
            CryptoApiError::InternalError(format!("Failed to get current time: {e}"))
        })?),
        ..Default::default()
    };

    // Create the KMIP symmetric key object
    let object = create_symmetric_key_kmip_object(kms.vendor_id(), &cek, &attributes)
        .map_err(|e| CryptoApiError::InternalError(format!("Failed to build key object: {e}")))?;

    // Import via the KMIP Import pipeline (handles wrapping-at-rest, DB storage)
    let import_request = cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Import {
        unique_identifier: UniqueIdentifier::TextString(String::new()),
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes,
        object,
    };

    let import_response = kms
        .import(import_request, &user, None)
        .await
        .map_err(CryptoApiError::from)?;

    let new_kid = import_response.unique_identifier.to_string();

    Ok(Json(KeyUnwrapResponse {
        kid: new_kid,
        kty: "oct".to_owned(),
        alg: enc_str,
        key_ops: vec!["encrypt".to_owned(), "decrypt".to_owned()],
    }))
}

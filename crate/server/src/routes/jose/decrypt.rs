use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::elliptic_curves::operation::x25519_key_agreement;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::CryptographicUsageMask,
        kmip_2_1::{
            KmipOperation,
            kmip_objects::Object,
            kmip_operations::Decrypt,
            kmip_types::{LinkType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::{
        crypto::{
            elliptic_curves::operation::ecdh_key_agreement, kdf::concat_kdf::concat_kdf,
            rsa::ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_unwrap,
            symmetric::rfc3394::rfc3394_unwrap,
        },
        openssl::kmip_private_key_to_openssl,
    },
};
use cosmian_logger::{debug, trace};
use openssl::rand::rand_bytes;
use zeroize::Zeroizing;

use super::{
    CryptoApiError, CryptoResult, DecryptRequest, DecryptResponse as CryptoDecryptResponse,
    JoseAlgorithm, JoseEncAlgorithm, aes_gcm::aes_gcm_decrypt, b64_decode, b64_encode, cek_cache,
    cek_size_bytes, encrypt::build_jwe_aad, jose_oaep_hashes, jose_to_kmip_params,
    keys::nid_from_crv,
};
use crate::{
    core::{KMS, ObjectHandle, retrieve_object_utils::retrieve_object_for_operation},
    middlewares::UserId,
};

/// `POST /v1/crypto/decrypt` — JOSE content decryption (JWE Flattened JSON).
///
/// Supports:
/// - `alg=dir`: direct AES-GCM decryption using the symmetric key referenced by `kid`
/// - `alg=RSA-OAEP` / `alg=RSA-OAEP-256`: RSA-OAEP unwrapping of the CEK, then AES-GCM decrypt
/// - `alg=ECDH-ES` / `alg=ECDH-ES+A128KW` / `alg=ECDH-ES+A256KW`: ECDH-ES key agreement
///   (RFC 7518 §4.6), then AES-GCM decrypt
///
/// Follows RFC 7516 §5.2 step 15 for AAD reconstruction.
#[post("/decrypt")]
pub(crate) async fn decrypt(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<DecryptRequest>,
) -> CryptoResult<CryptoDecryptResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user.as_str(), "POST /v1/crypto/decrypt");

    // Parse protected header
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

    match alg {
        JoseAlgorithm::Dir => decrypt_dir(&kms, &user, kid, alg, enc, &body).await,
        JoseAlgorithm::RsaOaep | JoseAlgorithm::RsaOaep256 => {
            Box::pin(decrypt_rsa_oaep(&kms, &user, kid, alg, enc, &body)).await
        }
        JoseAlgorithm::EcdhEs | JoseAlgorithm::EcdhEsA128KW | JoseAlgorithm::EcdhEsA256KW => {
            Box::pin(decrypt_ecdh_es(
                &kms,
                &user,
                kid,
                alg,
                enc,
                &header_json,
                &body,
            ))
            .await
        }
        _ => Err(CryptoApiError::UnsupportedAlgorithm(format!(
            "Algorithm '{alg}' is not a key-management algorithm. Supported: dir, RSA-OAEP, \
             RSA-OAEP-256, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A256KW."
        ))),
    }
}

/// Direct AES-GCM decryption — delegates to the KMIP Decrypt pipeline.
async fn decrypt_dir(
    kms: &KMS,
    user: &UserId,
    kid: String,
    alg: JoseAlgorithm,
    enc: JoseEncAlgorithm,
    body: &DecryptRequest,
) -> CryptoResult<CryptoDecryptResponse> {
    // 'dir' transmits no key material — encrypted_key must be absent or empty.
    if let Some(ref ek) = body.encrypted_key {
        if !ek.is_empty() {
            return Err(CryptoApiError::BadRequest(
                "'encrypted_key' must be absent or empty for 'dir' key management".to_owned(),
            ));
        }
    }

    let kmip_params = jose_to_kmip_params(alg, Some(enc))?;

    let iv_bytes = b64_decode("iv", &body.iv)?;
    if iv_bytes.len() != 12 {
        return Err(CryptoApiError::BadRequest(format!(
            "GCM initialization vector must be exactly 96 bits (12 bytes), got {} bytes",
            iv_bytes.len()
        )));
    }
    let ciphertext_bytes = b64_decode("ciphertext", &body.ciphertext)?;
    let tag_bytes = b64_decode("tag", &body.tag)?;
    if tag_bytes.len() != 16 {
        return Err(CryptoApiError::BadRequest(format!(
            "GCM authentication tag must be exactly 128 bits (16 bytes), got {} bytes",
            tag_bytes.len()
        )));
    }

    let aad_bytes = build_jwe_aad(&body.protected, body.aad.as_deref())?;

    let decrypt_req = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(ciphertext_bytes),
        i_v_counter_nonce: Some(iv_bytes),
        authenticated_encryption_additional_data: Some(aad_bytes),
        authenticated_encryption_tag: Some(tag_bytes),
        ..Default::default()
    };

    let resp = kms
        .decrypt(decrypt_req, user)
        .await
        .map_err(CryptoApiError::from)?;

    let plaintext_bytes = resp.data.ok_or_else(|| {
        CryptoApiError::InternalError("Decrypt response missing plaintext".to_owned())
    })?;

    Ok(Json(CryptoDecryptResponse {
        kid,
        data: b64_encode(&plaintext_bytes),
    }))
}

/// RSA-OAEP decrypt with implicit rejection (RFC 7516 §11.5 countermeasure).
///
/// 1. Unwrap `encrypted_key` with RSA private key to recover CEK
/// 2. On OAEP failure: substitute a random CEK (do NOT return an error)
/// 3. AES-GCM decrypt with the CEK (real or random)
/// 4. Return uniform "Decryption failed" on any failure
async fn decrypt_rsa_oaep(
    kms: &KMS,
    user: &UserId,
    kid: String,
    alg: JoseAlgorithm,
    enc: JoseEncAlgorithm,
    body: &DecryptRequest,
) -> CryptoResult<CryptoDecryptResponse> {
    // RSA-OAEP requires a non-empty encrypted_key
    let encrypted_key_b64 = body
        .encrypted_key
        .as_deref()
        .filter(|ek| !ek.is_empty())
        .ok_or_else(|| {
            CryptoApiError::BadRequest(
                "'encrypted_key' must be present and non-empty for RSA-OAEP key management"
                    .to_owned(),
            )
        })?;

    let encrypted_key_bytes = b64_decode("encrypted_key", encrypted_key_b64)?;
    let iv_bytes = b64_decode("iv", &body.iv)?;
    let ciphertext_bytes = b64_decode("ciphertext", &body.ciphertext)?;
    let tag_bytes = b64_decode("tag", &body.tag)?;

    // Resolve the private key — accept either private or public key UID
    let owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&kid),
        KmipOperation::Decrypt,
        kms,
        user,
    ))
    .await
    .map_err(CryptoApiError::from)?;

    // Determine the private key object
    let private_key_owm = match owm.object() {
        Object::PrivateKey { .. } => owm,
        Object::PublicKey { .. } => {
            // Resolve linked private key
            let priv_key_uid = owm
                .attributes()
                .get_link(LinkType::PrivateKeyLink)
                .ok_or_else(|| {
                    CryptoApiError::CryptoFailure(
                        "RSA-OAEP decrypt: public key has no linked private key".to_owned(),
                    )
                })?;
            Box::pin(retrieve_object_for_operation(
                ObjectHandle::from(&priv_key_uid.to_string()),
                KmipOperation::Decrypt,
                kms,
                user,
            ))
            .await
            .map_err(CryptoApiError::from)?
        }
        _ => {
            return Err(CryptoApiError::CryptoFailure(format!(
                "RSA-OAEP decrypt: key '{}' is not an RSA key pair (got {:?})",
                kid,
                owm.object().object_type()
            )));
        }
    };

    // Convert KMIP private key to OpenSSL PKey<Private>
    let private_key = kmip_private_key_to_openssl(private_key_owm.object()).map_err(|e| {
        CryptoApiError::CryptoFailure(format!("RSA-OAEP decrypt: failed to load private key: {e}"))
    })?;

    // Validate RSA key type and minimum size
    if private_key.id() != openssl::pkey::Id::RSA {
        return Err(CryptoApiError::CryptoFailure(format!(
            "RSA-OAEP decrypt: key '{}' is not an RSA key (got {:?})",
            kid,
            private_key.id()
        )));
    }
    if private_key.bits() < 2048 {
        return Err(CryptoApiError::CryptoFailure(format!(
            "RSA-OAEP decrypt: RSA key too small ({} bits). Minimum: 2048 bits.",
            private_key.bits()
        )));
    }

    let (oaep_hash, mgf1_hash) = jose_oaep_hashes(alg)?;
    let expected_cek_len = cek_size_bytes(enc);

    // Check the CEK cache before attempting the expensive RSA-OAEP private-key
    // operation. A cache hit means this exact JWE token was already decrypted
    // (or encrypted) on this server and the CEK is still valid.
    //
    // RFC 7516 §11.5 implicit rejection is preserved: the cache is only
    // populated with genuine CEKs; random substitute keys are never inserted.
    let cek: Zeroizing<Vec<u8>> =
        match cek_cache::peek_cek(kms, &encrypted_key_bytes, private_key_owm.object()).await {
            Some(cached_cek) => cached_cek,
            None => {
                // Cache miss — perform RSA-OAEP unwrap.
                // Implicit rejection: attempt unwrap; on failure substitute random CEK.
                // This prevents padding oracle attacks (Manger 2001, RFC 7516 §11.5).
                match ckm_rsa_pkcs_oaep_key_unwrap(
                    &private_key,
                    oaep_hash,
                    mgf1_hash,
                    None,
                    &encrypted_key_bytes,
                ) {
                    Ok(unwrapped) if unwrapped.len() == expected_cek_len => {
                        // Cache the CEK for subsequent decryptions of this JWE token.
                        cek_cache::insert_cek(
                            kms,
                            &encrypted_key_bytes,
                            private_key_owm.object(),
                            &unwrapped,
                        )
                        .await;
                        unwrapped
                    }
                    _ => {
                        // Substitute random CEK — AES-GCM will fail on tag verification
                        debug!(
                            "RSA-OAEP unwrap failed or CEK size mismatch — using implicit rejection"
                        );
                        let mut random_cek = Zeroizing::new(vec![0_u8; expected_cek_len]);
                        rand_bytes(&mut random_cek).map_err(|e| {
                            CryptoApiError::InternalError(format!(
                                "Failed to generate random CEK for implicit rejection: {e}"
                            ))
                        })?;
                        random_cek
                    }
                }
            }
        };

    // AAD reconstruction (RFC 7516 §5.2 step 15)
    let aad_bytes = build_jwe_aad(&body.protected, body.aad.as_deref())?;

    // AES-GCM decrypt — will fail with DecryptionFailed if CEK is wrong (implicit rejection)
    let plaintext = aes_gcm_decrypt(
        &cek,
        enc,
        &iv_bytes,
        &ciphertext_bytes,
        &tag_bytes,
        &aad_bytes,
    )?;

    Ok(Json(CryptoDecryptResponse {
        kid,
        data: b64_encode(&plaintext),
    }))
}

/// ECDH-ES decrypt (RFC 7518 §4.6).
///
/// 1. Resolve the static private key (`kid`); accept EC (P-256/384/521, FIPS-available)
///    or, non-FIPS, OKP/X25519. Reject keys whose usage mask lacks `KeyAgreement`.
/// 2. Parse the ephemeral public key (`epk`) from the protected header and validate its
///    `crv` matches the static key's curve.
/// 3. Compute the shared secret `Z` via ECDH (EC) or X25519 key agreement (OKP).
/// 4. Derive the CEK directly via Concat KDF (`ECDH-ES`) or derive a KEK and unwrap the
///    CEK with AES Key Wrap (`ECDH-ES+A128KW` / `ECDH-ES+A256KW`).
/// 5. AES-GCM decrypt with the CEK.
///
/// Per RFC 7518 §4.6.2, the Concat KDF `AlgorithmID` is the `enc` header value for bare
/// `ECDH-ES` (the derived key *is* the CEK), but the `alg` header value for the
/// `+A1{28,256}KW` variants (the derived key is a KEK wrapping a separately-generated CEK).
async fn decrypt_ecdh_es(
    kms: &KMS,
    user: &UserId,
    kid: String,
    alg: JoseAlgorithm,
    enc: JoseEncAlgorithm,
    header_json: &serde_json::Value,
    body: &DecryptRequest,
) -> CryptoResult<CryptoDecryptResponse> {
    let epk = header_json.get("epk").ok_or_else(|| {
        CryptoApiError::BadRequest(
            "Protected header missing required 'epk' field for ECDH-ES".to_owned(),
        )
    })?;
    let epk_kty = epk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
        CryptoApiError::BadRequest("'epk' is missing required 'kty' field".to_owned())
    })?;
    let epk_crv = epk.get("crv").and_then(|v| v.as_str()).ok_or_else(|| {
        CryptoApiError::BadRequest("'epk' is missing required 'crv' field".to_owned())
    })?;

    let iv_bytes = b64_decode("iv", &body.iv)?;
    if iv_bytes.len() != 12 {
        return Err(CryptoApiError::BadRequest(format!(
            "GCM initialization vector must be exactly 96 bits (12 bytes), got {} bytes",
            iv_bytes.len()
        )));
    }
    let ciphertext_bytes = b64_decode("ciphertext", &body.ciphertext)?;
    let tag_bytes = b64_decode("tag", &body.tag)?;
    if tag_bytes.len() != 16 {
        return Err(CryptoApiError::BadRequest(format!(
            "GCM authentication tag must be exactly 128 bits (16 bytes), got {} bytes",
            tag_bytes.len()
        )));
    }

    // Resolve the private key — accept either private or public key UID
    let owm = Box::pin(retrieve_object_for_operation(
        ObjectHandle::from(&kid),
        KmipOperation::Decrypt,
        kms,
        user,
    ))
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
                        "ECDH-ES decrypt: public key has no linked private key".to_owned(),
                    )
                })?;
            Box::pin(retrieve_object_for_operation(
                ObjectHandle::from(&priv_key_uid.to_string()),
                KmipOperation::Decrypt,
                kms,
                user,
            ))
            .await
            .map_err(CryptoApiError::from)?
        }
        _ => {
            return Err(CryptoApiError::CryptoFailure(format!(
                "ECDH-ES decrypt: key '{}' is not an EC/OKP key (got {:?})",
                kid,
                owm.object().object_type()
            )));
        }
    };

    // Reject a static key that is not authorized for key agreement — prevents a
    // signature-only EC/OKP key from being reused for decryption (key confusion).
    let usage_authorized = private_key_owm
        .attributes()
        .is_usage_authorized_for(CryptographicUsageMask::KeyAgreement)
        .map_err(|e| CryptoApiError::InternalError(e.to_string()))?;
    if !usage_authorized {
        return Err(CryptoApiError::Forbidden(format!(
            "ECDH-ES decrypt: key '{kid}' is not authorized for KeyAgreement usage"
        )));
    }

    let private_key = kmip_private_key_to_openssl(private_key_owm.object()).map_err(|e| {
        CryptoApiError::CryptoFailure(format!("ECDH-ES decrypt: failed to load private key: {e}"))
    })?;

    let z: Zeroizing<Vec<u8>> = match epk_kty {
        "EC" => {
            if private_key.id() != openssl::pkey::Id::EC {
                return Err(CryptoApiError::CryptoFailure(format!(
                    "ECDH-ES decrypt: key '{kid}' is not an EC key (got {:?})",
                    private_key.id()
                )));
            }
            let nid = nid_from_crv(epk_crv)?;
            let ec_key = private_key.ec_key().map_err(|e| {
                CryptoApiError::InternalError(format!(
                    "ECDH-ES decrypt: failed to load EC key: {e}"
                ))
            })?;
            let static_curve_nid = ec_key.group().curve_name().ok_or_else(|| {
                CryptoApiError::InternalError(
                    "ECDH-ES decrypt: static EC key has no named curve".to_owned(),
                )
            })?;
            if static_curve_nid != nid {
                return Err(CryptoApiError::BadRequest(format!(
                    "ECDH-ES decrypt: 'epk.crv' ({epk_crv}) does not match static key curve"
                )));
            }

            let x_b64 = epk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                CryptoApiError::BadRequest("'epk' is missing required 'x' field".to_owned())
            })?;
            let y_b64 = epk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                CryptoApiError::BadRequest("'epk' is missing required 'y' field".to_owned())
            })?;
            let x_bytes = b64_decode("epk.x", x_b64)?;
            let y_bytes = b64_decode("epk.y", y_b64)?;

            let mut peer_point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
            peer_point.push(0x04);
            peer_point.extend_from_slice(&x_bytes);
            peer_point.extend_from_slice(&y_bytes);

            let scalar_bytes = ec_key.private_key().to_vec();
            ecdh_key_agreement(nid, &scalar_bytes, &peer_point)
                .map_err(|e| CryptoApiError::CryptoFailure(e.to_string()))?
        }
        #[cfg(feature = "non-fips")]
        "OKP" if epk_crv == "X25519" => {
            if private_key.id() != openssl::pkey::Id::X25519 {
                return Err(CryptoApiError::CryptoFailure(format!(
                    "ECDH-ES decrypt: key '{kid}' is not an X25519 key (got {:?})",
                    private_key.id()
                )));
            }
            let x_b64 = epk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                CryptoApiError::BadRequest("'epk' is missing required 'x' field".to_owned())
            })?;
            let peer_public_bytes = b64_decode("epk.x", x_b64)?;
            let priv_raw = private_key.raw_private_key().map_err(|e| {
                CryptoApiError::InternalError(format!(
                    "ECDH-ES decrypt: failed to load X25519 private key: {e}"
                ))
            })?;
            x25519_key_agreement(&priv_raw, &peer_public_bytes)
                .map_err(|e| CryptoApiError::CryptoFailure(e.to_string()))?
        }
        other => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "ECDH-ES decrypt: unsupported 'epk.kty'/'epk.crv' combination \
                 ({other}/{epk_crv})"
            )));
        }
    };

    // Party U/V info (RFC 7518 §4.6.1) — optional, default to empty per Concat KDF.
    // Per RFC 7159/7518, if present these header members MUST be base64url-encoded
    // strings; a present-but-non-string value (e.g. a number or boolean) is a
    // malformed header and must be rejected rather than silently treated as absent.
    let apu = match header_json.get("apu") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::String(s)) => b64_decode("apu", s)?,
        Some(_) => {
            return Err(CryptoApiError::BadRequest(
                "'apu' must be a base64url-encoded string".to_owned(),
            ));
        }
    };
    let apv = match header_json.get("apv") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::String(s)) => b64_decode("apv", s)?,
        Some(_) => {
            return Err(CryptoApiError::BadRequest(
                "'apv' must be a base64url-encoded string".to_owned(),
            ));
        }
    };
    // RFC 7518 §4.6.2: PartyUInfo and PartyVInfo, when both present, are
    // expected to identify the two parties and therefore must be distinct;
    // accepting equal, non-empty values would allow a degenerate/replayable
    // KDF input.
    if !apu.is_empty() && !apv.is_empty() && apu == apv {
        return Err(CryptoApiError::BadRequest(
            "'apu' and 'apv' must not be equal when both are present".to_owned(),
        ));
    }

    let cek: Zeroizing<Vec<u8>> = match alg {
        JoseAlgorithm::EcdhEs => {
            // Direct agreement: encrypted_key must be absent or empty, and the
            // Concat KDF AlgorithmID is the "enc" value (the derived key is the CEK).
            if let Some(ref ek) = body.encrypted_key {
                if !ek.is_empty() {
                    return Err(CryptoApiError::BadRequest(
                        "'encrypted_key' must be absent or empty for 'ECDH-ES' key management"
                            .to_owned(),
                    ));
                }
            }
            let key_data_len_bits = u32::try_from(cek_size_bytes(enc) * 8).map_err(|e| {
                CryptoApiError::InternalError(format!("ECDH-ES decrypt: CEK size overflow: {e}"))
            })?;
            concat_kdf(
                &z,
                key_data_len_bits,
                enc.to_string().as_bytes(),
                &apu,
                &apv,
            )
            .map_err(|e| CryptoApiError::CryptoFailure(e.to_string()))?
        }
        JoseAlgorithm::EcdhEsA128KW | JoseAlgorithm::EcdhEsA256KW => {
            // Key wrapping: encrypted_key must be present, and the Concat KDF
            // AlgorithmID is the "alg" value (the derived key is a KEK, not the CEK).
            let encrypted_key_b64 = body
                .encrypted_key
                .as_deref()
                .filter(|ek| !ek.is_empty())
                .ok_or_else(|| {
                    CryptoApiError::BadRequest(format!(
                        "'encrypted_key' must be present and non-empty for '{alg}' key \
                         management"
                    ))
                })?;
            let encrypted_key_bytes = b64_decode("encrypted_key", encrypted_key_b64)?;

            let kek_bits: u32 = if matches!(alg, JoseAlgorithm::EcdhEsA128KW) {
                128
            } else {
                256
            };
            let kek = concat_kdf(&z, kek_bits, alg.to_string().as_bytes(), &apu, &apv)
                .map_err(|e| CryptoApiError::CryptoFailure(e.to_string()))?;

            rfc3394_unwrap(&encrypted_key_bytes, &kek)
                .map_err(|e| CryptoApiError::CryptoFailure(e.to_string()))?
        }
        _ => {
            return Err(CryptoApiError::InternalError(
                "decrypt_ecdh_es called with a non-ECDH-ES algorithm".to_owned(),
            ));
        }
    };

    // AAD reconstruction (RFC 7516 §5.2 step 15)
    let aad_bytes = build_jwe_aad(&body.protected, body.aad.as_deref())?;

    let plaintext = aes_gcm_decrypt(
        &cek,
        enc,
        &iv_bytes,
        &ciphertext_bytes,
        &tag_bytes,
        &aad_bytes,
    )?;

    Ok(Json(CryptoDecryptResponse {
        kid,
        data: b64_encode(&plaintext),
    }))
}

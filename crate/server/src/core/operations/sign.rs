#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::Object,
            kmip_operations::{Sign, SignResponse},
            kmip_types::{KeyFormatType, UniqueIdentifier},
        },
        time_normalize,
    },
    cosmian_kms_crypto::{
        crypto::{
            elliptic_curves::sign::{ecdsa_sign, eddsa_sign},
            rsa::sign::sign_rsa_with_pkey,
        },
        openssl::kmip_private_key_to_openssl,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, info, trace};
use openssl::pkey::{Id, PKey, Private};

use crate::{
    core::{
        KMS,
        operations::{
            algorithm_policy::enforce_kmip_algorithm_policy_for_retrieved_key,
            is_user_authorized_for_operation, select_unique_key_for_operation,
        },
        uid_utils::{has_prefix, uids_from_unique_identifier},
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn sign(kms: &KMS, request: Sign, user: &str) -> KResult<SignResponse> {
    debug!("{request}");

    // KMIP 2.1 §6.30: data and digested_data are mutually exclusive
    if request.data.is_some() && request.digested_data.is_some() {
        kms_bail!(KmsError::InvalidRequest(
            "Sign request must not set both 'data' and 'digested_data' simultaneously".to_owned()
        ));
    }

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let uids = uids_from_unique_identifier(unique_identifier, kms)
        .await
        .context("sign")?;
    trace!("candidate uids: {uids:?}");

    // Determine which UID to select. The decision process mirrors encrypt.rs:
    // Phase 1: If any UID has a prefix (signing oracle), use that key immediately.
    // Phase 2: Call the shared selection function for the standard database path; it enforces
    //          Active state, permissions, and uniqueness (fail on multiple eligible keys).

    // Phase 1 — Oracle (prefix) UIDs.  Collect all eligible ones and enforce uniqueness.
    let mut eligible_oracles: Vec<(&str, &str)> = Vec::new(); // (uid, prefix)
    for uid in &uids {
        if let Some(prefix) = has_prefix(uid) {
            if !is_user_authorized_for_operation(&kms.database, uid, user, KmipOperation::Sign)
                .await?
            {
                continue;
            }
            eligible_oracles.push((uid, prefix));
        }
    }
    match eligible_oracles.as_slice() {
        [] => {} // fall through to Phase 2
        &[(uid, prefix)] => {
            debug!("user: {user} is authorized to sign using: {uid} from signing oracle");
            return sign_using_crypto_oracle(kms, &request, uid, prefix).await;
        }
        multiple => {
            let ids: Vec<&str> = multiple.iter().map(|(uid, _)| *uid).collect();
            return Err(KmsError::InvalidRequest(format!(
                "Sign: identifier {unique_identifier} resolves to {} valid oracle keys \
                 {ids:?}; use a unique identifier",
                multiple.len()
            )));
        }
    }

    // Phase 2 — Standard database path via shared selection function.
    let mut owm = select_unique_key_for_operation(
        "Sign",
        &uids,
        unique_identifier,
        KmipOperation::Sign,
        kms,
        user,
        |owm| {
            if let Object::PrivateKey { .. } = owm.object() {
                let attributes = owm
                    .object()
                    .attributes()
                    .unwrap_or_else(|_| owm.attributes());
                trace!("attributes: {attributes}");
                return Ok(attributes.is_usage_authorized_for(CryptographicUsageMask::Sign)?);
            }
            Ok(false)
        },
    )
    .await
    .map_err(|e| match e {
        // Sign must report Item_Not_Found via the KMIP Kmip21Error variant.
        KmsError::ItemNotFound(_) | KmsError::Unauthorized(_) => KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            format!("sign: no valid private key for id: {unique_identifier}"),
        ),
        other => other,
    })?;

    // Lifecycle gating for mandatory profile vector CS-AC-M-8-21: a key that is Active but whose
    // ProcessStartDate is in the future (not yet usable) or whose ProtectStopDate is in the past
    // (no longer protected) must cause Sign to return Wrong_Key_Lifecycle_State / "DENIED".
    {
        let attributes = owm
            .object()
            .attributes()
            .unwrap_or_else(|_| owm.attributes());
        let now = time_normalize()?;
        let activation_ok = attributes
            .activation_date
            .map_or_else(|| owm.state() == State::Active, |ad| ad <= now);
        let process_window_ok = attributes.process_start_date.is_none_or(|psd| psd <= now)
            && attributes.protect_stop_date.is_none_or(|psd| psd > now);
        if !(activation_ok && process_window_ok) {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                "DENIED".to_owned(),
            ));
        }
    }

    // unwrap if wrapped
    owm.set_object(kms.get_unwrapped(owm.id(), owm.object(), user).await?);

    // Second-stage enforcement: validate the retrieved key's stored attributes.
    enforce_kmip_algorithm_policy_for_retrieved_key(&kms.params, "Sign", owm.id(), &owm)?;

    // Only private keys can be used for signing
    let res = match owm.object() {
        Object::PrivateKey { .. } => sign_with_private_key(&request, &owm),
        other => kms_bail!(KmsError::NotSupported(format!(
            "signing with keys of type: {} is not supported",
            other.object_type()
        ))),
    }?;

    info!(uid = owm.id(), user = user, "sign response = {res}");
    Ok(res)
}

/// Sign using a signing oracle (external key store / HSM identified by a prefix UID).
///
/// This mirrors `encrypt_using_crypto_oracle` in `encrypt.rs`. The oracle is looked up by
/// its prefix in `kms.crypto_oracles`.
///
/// # Arguments
/// * `kms` - the KMS instance
/// * `request` - the Sign request
/// * `uid` - the full prefixed UID (e.g. `"hsm0::key-id"`)
/// * `prefix` - the prefix part used to look up the oracle (e.g. `"hsm0"`)
async fn sign_using_crypto_oracle(
    kms: &KMS,
    request: &Sign,
    uid: &str,
    prefix: &str,
) -> KResult<SignResponse> {
    let lock = kms.crypto_oracles.read().await;
    let crypto_oracle = lock.get(prefix).ok_or_else(|| {
        KmsError::InvalidRequest(format!("Sign: unknown crypto oracle prefix: {prefix}"))
    })?;
    let data: &[u8] = request
        .data
        .as_ref()
        .map(|d| d.as_slice())
        .or(request.digested_data.as_deref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Sign: no data or digested data provided for oracle signing".to_owned(),
            )
        })?;
    let signature = crypto_oracle
        .sign(uid, data, request.cryptographic_parameters.as_ref())
        .await
        .map_err(|e| KmsError::InvalidRequest(format!("Sign: crypto oracle error: {e}")))?;
    debug!("user signed data via crypto oracle using: {uid}");
    Ok(SignResponse {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        signature_data: Some(signature),
        correlation_value: request.correlation_value.clone(),
    })
}

fn sign_with_private_key(request: &Sign, owm: &ObjectWithMetadata) -> KResult<SignResponse> {
    // Make sure that the key used to sign can be used to sign.
    if !owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes())
        .is_usage_authorized_for(CryptographicUsageMask::Sign)?
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Sign".to_owned(),
        ));
    }

    let key_block = owm.object().key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
                kms_bail!(
                    "Invalid request: init_indicator and final_indicator cannot both be true"
                );
            }

            trace!(
                "matching on key format type: {:?}",
                key_block.key_format_type
            );
            let private_key = kmip_private_key_to_openssl(owm.object())?;
            trace!("OpenSSL Private Key instantiated before signing");

            // ML-DSA: handle PQC signing before the classic dispatch
            #[cfg(feature = "non-fips")]
            {
                let key_algo = key_block
                    .cryptographic_algorithm()
                    .copied()
                    .or_else(|| owm.attributes().cryptographic_algorithm);
                if matches!(
                    key_algo,
                    Some(
                        CryptographicAlgorithm::MLDSA_44
                            | CryptographicAlgorithm::MLDSA_65
                            | CryptographicAlgorithm::MLDSA_87
                            | CryptographicAlgorithm::SLHDSA_SHA2_128s
                            | CryptographicAlgorithm::SLHDSA_SHA2_128f
                            | CryptographicAlgorithm::SLHDSA_SHA2_192s
                            | CryptographicAlgorithm::SLHDSA_SHA2_192f
                            | CryptographicAlgorithm::SLHDSA_SHA2_256s
                            | CryptographicAlgorithm::SLHDSA_SHA2_256f
                            | CryptographicAlgorithm::SLHDSA_SHAKE_128s
                            | CryptographicAlgorithm::SLHDSA_SHAKE_128f
                            | CryptographicAlgorithm::SLHDSA_SHAKE_192s
                            | CryptographicAlgorithm::SLHDSA_SHAKE_192f
                            | CryptographicAlgorithm::SLHDSA_SHAKE_256s
                            | CryptographicAlgorithm::SLHDSA_SHAKE_256f
                    )
                ) {
                    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::ml_dsa::ml_dsa_sign;
                    let data: &[u8] = if let Some(d) = request.data.as_ref() {
                        d.as_slice()
                    } else if let Some(d) = request.digested_data.as_ref() {
                        d.as_slice()
                    } else {
                        return Err(KmsError::InvalidRequest(
                            "Sign ML-DSA: data must be provided".to_owned(),
                        ));
                    };
                    let signature = ml_dsa_sign(&private_key, data)?;
                    return Ok(SignResponse {
                        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                        signature_data: Some(signature),
                        correlation_value: None,
                    });
                }
            }

            // Resolve effective cryptographic parameters: request overrides, stored attributes fill missing
            let effective_cp = {
                let stored_cp = owm
                    .object()
                    .attributes()
                    .ok()
                    .and_then(|a| a.cryptographic_parameters.clone())
                    .unwrap_or_default();
                match request.cryptographic_parameters.clone() {
                    None => stored_cp,
                    Some(mut req_cp) => {
                        if req_cp.cryptographic_algorithm.is_none() {
                            req_cp.cryptographic_algorithm = stored_cp.cryptographic_algorithm;
                        }
                        if req_cp.padding_method.is_none() {
                            req_cp.padding_method = stored_cp.padding_method;
                        }
                        if req_cp.hashing_algorithm.is_none() {
                            req_cp.hashing_algorithm = stored_cp.hashing_algorithm;
                        }
                        if req_cp.digital_signature_algorithm.is_none() {
                            req_cp.digital_signature_algorithm =
                                stored_cp.digital_signature_algorithm;
                        }
                        if req_cp.mask_generator.is_none() {
                            req_cp.mask_generator = stored_cp.mask_generator;
                        }
                        if req_cp.mask_generator_hashing_algorithm.is_none() {
                            req_cp.mask_generator_hashing_algorithm =
                                stored_cp.mask_generator_hashing_algorithm;
                        }
                        if req_cp.p_source.is_none() {
                            req_cp.p_source = stored_cp.p_source;
                        }
                        req_cp
                    }
                }
            };

            // Streaming support: if init or a correlation_value is present, accumulate data
            if request.init_indicator == Some(true) || request.correlation_value.is_some() {
                let mut req_for_stream = request.clone();
                req_for_stream.cryptographic_parameters = Some(effective_cp);
                return handle_streaming_sign(req_for_stream, &private_key, owm.id());
            }

            // One-shot signing
            let mut req_for_sign = request.clone();
            req_for_sign.cryptographic_parameters = Some(effective_cp);
            let signature = sign_with_pkey(&req_for_sign, &private_key)?;
            Ok(SignResponse {
                unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                signature_data: Some(signature),
                correlation_value: None,
            })
        }
        other => Err(KmsError::NotSupported(format!(
            "signing with private keys of format: {other}"
        ))),
    }
}

fn handle_streaming_sign(
    request: Sign,
    private_key: &PKey<Private>,
    uid: &str,
) -> KResult<SignResponse> {
    // Extract or initialize correlation data
    let correlation_data = if let Some(corr) = &request.correlation_value {
        corr.clone()
    } else if request.init_indicator == Some(true) {
        Vec::new()
    } else {
        return Err(KmsError::InvalidRequest(
            "Correlation value required for non-initial streaming operations".to_owned(),
        ));
    };

    // Determine input chunk
    let data_to_process = match (&request.data, &request.digested_data) {
        (Some(data), None) => data.clone(),
        (None, Some(_)) => {
            return Err(KmsError::InvalidRequest(
                "Streaming sign supports non-digested data only".to_owned(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(KmsError::InvalidRequest(
                "Cannot provide both data and digested_data".to_owned(),
            ));
        }
        (None, None) if request.final_indicator == Some(true) => Vec::new().into(),
        (None, None) => {
            return Err(KmsError::InvalidRequest(
                "Must provide data for streaming sign".to_owned(),
            ));
        }
    };

    if request.final_indicator == Some(true) {
        // Final call: sign accumulated data
        let mut all_data = correlation_data;
        all_data.extend_from_slice(data_to_process.as_ref());
        let mut final_req = request;
        final_req.data = Some(all_data.into());
        final_req.digested_data = None;
        final_req.correlation_value = None;
        let signature = sign_with_pkey(&final_req, private_key)?;
        Ok(SignResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            signature_data: Some(signature),
            correlation_value: None,
        })
    } else {
        // Intermediate call: accumulate data and return as correlation_value
        let mut accumulated = correlation_data;
        accumulated.extend_from_slice(data_to_process.as_ref());
        Ok(SignResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            signature_data: None,
            correlation_value: Some(accumulated),
        })
    }
}

fn sign_with_pkey(request: &Sign, private_key: &PKey<Private>) -> KResult<Vec<u8>> {
    let signature = match private_key.id() {
        Id::RSA => sign_rsa_with_pkey(request, private_key)
            .map_err(|e| KmsError::NotSupported(format!("rsa sign error: {e}")))?,
        Id::EC => ecdsa_sign(request, private_key)?,
        Id::ED25519 | Id::ED448 => eddsa_sign(request, private_key)?,
        other => {
            kms_bail!("sign_with_pkey: private key type not supported: {other:?}")
        }
    };
    Ok(signature)
}

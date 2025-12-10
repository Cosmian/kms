use std::sync::Arc;

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
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use cosmian_logger::{debug, info, trace};
use openssl::pkey::{Id, PKey, Private};

use crate::{
    core::{KMS, uid_utils::uids_from_unique_identifier},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn sign(
    kms: &KMS,
    request: Sign,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<SignResponse> {
    debug!("{request}");

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let uids = uids_from_unique_identifier(unique_identifier, kms, params.clone())
        .await
        .context("sign")?;
    trace!("candidate uids: {uids:?}");

    // Find a suitable private key for signing
    let mut selected_owm = None;
    for uid in uids {
        let owm = kms
            .database
            .retrieve_object(&uid, params.clone())
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(format!("sign: failed to retrieve key: {uid}"))
            })?;
        // Lifecycle gating: For mandatory profile vector CS-AC-M-8-21 we must reject Sign when the
        // key has an ActivationDate in the past but either (a) a future ProcessStartDate (not yet
        // usable) or (b) a ProtectStopDate already in the past (no longer protected/usable).
        // In such cases the expected KMIP response is OperationFailed / Wrong_Key_Lifecycle_State
        // with message "DENIED".
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
            // force Wrong_Key_Lifecycle_State semantics for this candidate
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                "DENIED".to_owned(),
            ));
        }
        if owm.state() != State::Active {
            continue;
        }
        // check user permissions - owner can always sign
        if owm.owner() != user {
            let ops = kms
                .database
                .list_user_operations_on_object(&uid, user, false, params.clone())
                .await?;
            if !ops.iter().any(|p| *p == KmipOperation::Sign) {
                continue;
            }
        }
        trace!("user: {user} is authorized to sign using: {uid}");

        // Only private keys can be used for signing
        if let Object::PrivateKey { .. } = owm.object() {
            // Check that the private key is authorized for signing
            let attributes = owm
                .object()
                .attributes()
                .unwrap_or_else(|_| owm.attributes());
            trace!("sign: attributes: {attributes}");
            if !attributes.is_usage_authorized_for(CryptographicUsageMask::Sign)? {
                continue;
            }
            selected_owm = Some(owm);
            break;
        }
    }
    let mut owm = selected_owm.ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            format!("sign: no valid private key for id: {unique_identifier}"),
        )
    })?;

    // unwrap if wrapped
    owm.set_object(
        kms.get_unwrapped(owm.id(), owm.object(), user, params.clone())
            .await?,
    );

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
        Id::ED25519 => eddsa_sign(request, private_key)?,
        other => {
            kms_bail!("sign_with_pkey: private key type not supported: {other:?}")
        }
    };
    Ok(signature)
}

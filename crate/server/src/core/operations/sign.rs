use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::Object,
            kmip_operations::{Sign, SignResponse},
            kmip_types::{KeyFormatType, UniqueIdentifier},
        },
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
        operations::{CryptoOpSpec, ResolvedKey, resolve_key_for_operation},
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Marker type for the Sign operation's key selection requirements.
pub(crate) struct SignOp;

impl CryptoOpSpec for SignOp {
    const KMIP_OP: KmipOperation = KmipOperation::Sign;
    const OP_NAME: &'static str = "Sign";
    const SUPPORTS_ORACLE: bool = true;

    fn is_key_eligible(owm: &ObjectWithMetadata) -> bool {
        if let Object::PrivateKey { .. } = owm.object() {
            let attributes = owm
                .object()
                .attributes()
                .unwrap_or_else(|_| owm.attributes());
            return attributes
                .is_usage_authorized_for(CryptographicUsageMask::Sign)
                .unwrap_or(false);
        }
        false
    }

    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        _user: &str,
    ) -> KmsError {
        match e {
            KmsError::ItemNotFound(_) | KmsError::Unauthorized(_) => KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("sign: no valid private key for id: {unique_identifier}"),
            ),
            other => other,
        }
    }
}

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

    match resolve_key_for_operation::<SignOp>(unique_identifier, kms, user).await? {
        ResolvedKey::Oracle { uid, prefix } => {
            debug!("user: {user} is authorized to sign using: {uid} from signing oracle");
            return sign_using_crypto_oracle(kms, &request, &uid, &prefix).await;
        }
        ResolvedKey::Local(owm) => {
            let mut owm = *owm;

            // Unwrap + second-stage enforcement.
            super::unwrap_and_enforce_policy(kms, &mut owm, "Sign", user).await?;

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
    }
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

            // ML-DSA / SLH-DSA: handle PQC signing before the classic dispatch
            #[cfg(feature = "non-fips")]
            {
                if super::is_pqc_signature_algorithm(super::resolve_key_algorithm(owm)) {
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
            let effective_cp = super::state_utils::merge_crypto_params(
                request.cryptographic_parameters.clone(),
                owm.object(),
            );

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

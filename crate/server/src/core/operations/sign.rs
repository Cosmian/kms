use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::Object,
            kmip_operations::{Sign, SignResponse},
            kmip_types::{CryptographicParameters, KeyFormatType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::{
        crypto::{
            elliptic_curves::sign::{ecdsa_sign, eddsa_sign},
            rsa::sign::sign_rsa_with_pkey,
        },
        openssl::kmip_private_key_to_openssl,
    },
    cosmian_kms_interfaces::{InterfaceError, ObjectWithMetadata},
};
use cosmian_logger::{debug, trace};
use openssl::pkey::{Id, PKey, Private};

use super::pgp_ops;
use crate::{
    core::{
        KMS,
        operations::{
            CryptoOpSpec,
            key_ops::multi_part::{
                BoundedBuffer, Part, StreamOwner, append_bounded, reject_multi_part_for_oracle,
            },
        },
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

/// Marker type for the Sign operation's key selection requirements.
pub(crate) struct SignOp;

impl CryptoOpSpec for SignOp {
    type Request = Sign;
    type Response = SignResponse;

    const KMIP_OP: KmipOperation = KmipOperation::Sign;
    const OP_NAME: &'static str = "Sign";

    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier> {
        request.unique_identifier.as_ref()
    }

    fn usage_data_len(request: &Self::Request) -> usize {
        request
            .data
            .as_ref()
            .map_or(0, |d| d.len())
            .max(request.digested_data.as_ref().map_or(0, Vec::len))
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        if let Object::PrivateKey { .. } = owm.object() {
            return owm.has_usage_mask(CryptographicUsageMask::Sign, false);
        }
        if let Object::PGPKey { .. } = owm.object() {
            return owm.has_usage_mask(CryptographicUsageMask::Sign, false);
        }
        false
    }

    fn execute_local(
        kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        user: &UserId,
    ) -> KResult<Self::Response> {
        let part = Part::classify(
            request.init_indicator,
            request.final_indicator,
            request.correlation_value.as_deref(),
        )?;
        match owm.object() {
            Object::PrivateKey { .. } => sign_with_private_key(kms, owm, request, part, user),
            Object::PGPKey { .. } => {
                reject_multi_part(part, "PGP keys")?;
                pgp_ops::pgp_sign(owm, request, &kms.rng)
            }
            other => Err(KmsError::NotSupported(format!(
                "signing with keys of type: {} is not supported",
                other.object_type()
            ))),
        }
    }

    async fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> KResult<Self::Response> {
        reject_multi_part_for_oracle(
            Self::OP_NAME,
            Part::classify(
                request.init_indicator,
                request.final_indicator,
                request.correlation_value.as_deref(),
            )?,
        )?;
        let lock = kms.crypto_oracles.read().await;
        let crypto_oracle = lock.get(prefix).ok_or_else(|| {
            KmsError::InvalidRequest(format!("Sign: unknown crypto oracle prefix: {prefix}"))
        })?;
        let (data, input_is_digest): (&[u8], bool) = match (&request.data, &request.digested_data) {
            (Some(data), None) => (data.as_slice(), false),
            (None, Some(digested_data)) => (digested_data.as_slice(), true),
            (Some(_), Some(_)) => {
                return Err(KmsError::InvalidRequest(
                    "Sign request must not set both 'data' and 'digested_data' simultaneously"
                        .to_owned(),
                ));
            }
            (None, None) => {
                return Err(KmsError::InvalidRequest(
                    "Sign: no data or digested data provided for oracle signing".to_owned(),
                ));
            }
        };
        let signature = crypto_oracle
            .sign(
                uid,
                data,
                request.cryptographic_parameters.as_ref(),
                input_is_digest,
            )
            .await
            .map_err(|e| {
                let reason = if matches!(e, InterfaceError::InvalidRequest(_)) {
                    ErrorReason::Invalid_Field
                } else {
                    ErrorReason::Cryptographic_Failure
                };
                KmsError::Kmip21Error(reason, format!("Sign: crypto oracle error: {e}"))
            })?;
        debug!("user signed data via crypto oracle using: {uid}");
        Ok(SignResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            signature_data: Some(signature),
            correlation_value: None,
        })
    }
}

pub(crate) async fn sign(kms: &KMS, request: Sign, user: &UserId) -> KResult<SignResponse> {
    trace!("Sign request");

    // KMIP 2.1 §6.30: data and digested_data are mutually exclusive
    if request.data.is_some() && request.digested_data.is_some() {
        kms_bail!(KmsError::InvalidRequest(
            "Sign request must not set both 'data' and 'digested_data' simultaneously".to_owned()
        ));
    }

    Box::pin(kms.perform_crypto_operation::<SignOp>(request, user)).await
}

/// Multi-part support is optional (KMIP 2.1 §6.1); reject it where the server lacks it.
fn reject_multi_part(part: Part<'_>, what: &str) -> KResult<()> {
    if part.is_multi_part() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            format!("Sign: streaming is not supported for {what} (multi-part signing)"),
        ));
    }
    Ok(())
}

/// State of a multi-part Sign: the message buffered so far (the signature schemes in use need
/// the whole message, e.g. `EdDSA` and ML-DSA) and the parameters fixed by the initial part.
struct SignState {
    data: BoundedBuffer,
    cryptographic_parameters: Option<CryptographicParameters>,
}

fn sign_with_private_key(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    request: &Sign,
    part: Part<'_>,
    user: &UserId,
) -> KResult<SignResponse> {
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
        | KeyFormatType::PKCS8 => {}
        other => {
            return Err(KmsError::NotSupported(format!(
                "signing with private keys of format: {other}"
            )));
        }
    }

    if part == Part::Single {
        if request.data.is_none() && request.digested_data.is_none() {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "Sign: Data or Digested Data is required for a single-part operation".to_owned(),
            ));
        }
        let signature = sign_message(owm, request)?;
        return Ok(SignResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            signature_data: Some(signature),
            correlation_value: None,
        });
    }

    if request.digested_data.is_some() {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            "Sign: multi-part signing takes Data, not Digested Data".to_owned(),
        ));
    }
    let owner = StreamOwner {
        op: SignOp::OP_NAME,
        user,
        key_uid: owm.id(),
    };
    let (signature_data, correlation_value) = kms.multi_part.run(
        &kms.rng,
        part,
        owner,
        || {
            Ok(SignState {
                data: kms.multi_part.buffer(user),
                cryptographic_parameters: request.cryptographic_parameters.clone(),
            })
        },
        |state, last| {
            append_bounded(
                &mut state.data,
                request.data.as_deref().map_or(&[][..], Vec::as_slice),
                SignOp::OP_NAME,
            )?;
            if !last {
                return Ok(None);
            }
            let whole = Sign {
                unique_identifier: request.unique_identifier.clone(),
                cryptographic_parameters: state.cryptographic_parameters.take(),
                data: Some(state.data.take()),
                ..Sign::default()
            };
            sign_message(owm, &whole).map(Some)
        },
    )?;
    Ok(SignResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        signature_data,
        correlation_value,
    })
}

/// Sign a complete message (or digest) with the private key of `owm`.
fn sign_message(owm: &ObjectWithMetadata, request: &Sign) -> KResult<Vec<u8>> {
    let private_key = kmip_private_key_to_openssl(owm.object())?;
    trace!("OpenSSL Private Key instantiated before signing");

    // ML-DSA / SLH-DSA: handle PQC signing before the classic dispatch
    #[cfg(feature = "non-fips")]
    {
        if owm
            .resolve_key_algorithm()
            .is_some_and(|a| a.is_pqc_signature())
        {
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
            return Ok(ml_dsa_sign(&private_key, data)?);
        }
    }

    // Resolve effective cryptographic parameters: request overrides, stored attributes fill missing
    let effective = Sign {
        unique_identifier: None,
        cryptographic_parameters: Some(CryptographicParameters::merged_with_object(
            request.cryptographic_parameters.clone(),
            owm.object(),
        )),
        data: request.data.clone(),
        digested_data: request.digested_data.clone(),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };
    sign_with_pkey(&effective, &private_key)
}

fn sign_with_pkey(request: &Sign, private_key: &PKey<Private>) -> KResult<Vec<u8>> {
    let signature = match private_key.id() {
        Id::RSA => sign_rsa_with_pkey(request, private_key)?,
        Id::EC => ecdsa_sign(request, private_key)?,
        Id::ED25519 | Id::ED448 => eddsa_sign(request, private_key)?,
        other => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Unsupported_Cryptographic_Parameters,
                format!("Sign: private key type not supported: {other:?}"),
            ));
        }
    };
    Ok(signature)
}

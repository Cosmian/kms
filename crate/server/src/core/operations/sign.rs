use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::Object,
            kmip_operations::{Sign, SignResponse},
            kmip_types::{DigitalSignatureAlgorithm, KeyFormatType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::{
        crypto::rsa::default_cryptographic_parameters, openssl::kmip_private_key_to_openssl,
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use cosmian_logger::{debug, info, trace};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    rsa::Padding,
    sign::Signer,
};

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
    trace!("sign: candidate uids: {uids:?}");

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
        trace!("sign: user: {user} is authorized to sign using: {uid}");

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
            "sign: signing with keys of type: {} is not supported",
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
                "sign_with_private_key: matching on key format type: {:?}",
                key_block.key_format_type
            );
            let private_key = kmip_private_key_to_openssl(owm.object())?;
            trace!("OpenSSL Private Key instantiated before signing");

            let signature = sign_with_pkey(request.clone(), &private_key)?;

            let response = SignResponse {
                unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                signature_data: (!request.init_indicator.unwrap_or(false))
                    .then_some(signature.clone()),
                correlation_value: request.init_indicator.unwrap_or(false).then_some(signature),
            };
            Ok(response)
        }
        other => Err(KmsError::NotSupported(format!(
            "signing with private keys of format: {other}"
        ))),
    }
}

fn sign_with_pkey(request: Sign, private_key: &PKey<Private>) -> KResult<Vec<u8>> {
    let signature = match private_key.id() {
        Id::RSA => sign_with_rsa(request, private_key)?,
        Id::EC => sign_with_ecdsa(request, private_key)?,
        Id::ED25519 => sign_with_eddsa(request, private_key)?,
        other => {
            kms_bail!("Sign: private key type not supported: {other:?}")
        }
    };
    Ok(signature)
}

fn sign_with_rsa(request: Sign, private_key: &PKey<Private>) -> KResult<Vec<u8>> {
    let (_algorithm, _padding, _hashing_fn, digital_signature_algorithm) =
        default_cryptographic_parameters(request.cryptographic_parameters.as_ref());
    debug!("signing with {digital_signature_algorithm}");

    // Matches the hashing algorithm to use
    let digest = match digital_signature_algorithm {
        DigitalSignatureAlgorithm::RSASSAPSS
        | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => MessageDigest::sha256(),
        DigitalSignatureAlgorithm::SHA384WithRSAEncryption => MessageDigest::sha384(),
        DigitalSignatureAlgorithm::SHA512WithRSAEncryption => MessageDigest::sha512(),
        DigitalSignatureAlgorithm::SHA3256WithRSAEncryption => MessageDigest::sha3_256(),
        DigitalSignatureAlgorithm::SHA3384WithRSAEncryption => MessageDigest::sha3_384(),
        DigitalSignatureAlgorithm::SHA3512WithRSAEncryption => MessageDigest::sha3_512(),
        _ => kms_bail!(KmsError::NotSupported(format!(
            "sign_with_rsa: not supported: {digital_signature_algorithm:?}"
        ))),
    };

    let mut signer = Signer::new(digest, private_key)?;

    if DigitalSignatureAlgorithm::RSASSAPSS == digital_signature_algorithm {
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
    }
    if let Some(corr) = request.correlation_value {
        signer.update(&corr)?;
    }
    let signature = if let Some(digested_data) = &request.digested_data {
        signer.sign_oneshot_to_vec(digested_data)
    } else {
        let data_to_sign = request.data.unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)
    }?;

    debug!(
        "sign_with_rsa: signed: message signature length: {}",
        signature.len()
    );

    Ok(signature)
}

fn sign_with_ecdsa(request: Sign, private_key: &PKey<Private>) -> KResult<Vec<u8>> {
    let digital_signature_algorithm = request.cryptographic_parameters.as_ref().map_or_else(
        || DigitalSignatureAlgorithm::ECDSAWithSHA256,
        |cp| {
            cp.digital_signature_algorithm
                .unwrap_or(DigitalSignatureAlgorithm::ECDSAWithSHA256)
        },
    );

    debug!("signing with ECDSA {digital_signature_algorithm}");

    // For ECDSA signatures, we use the appropriate hash function
    let digest = match digital_signature_algorithm {
        DigitalSignatureAlgorithm::ECDSAWithSHA256 => MessageDigest::sha256(),
        DigitalSignatureAlgorithm::ECDSAWithSHA384 => MessageDigest::sha384(),
        DigitalSignatureAlgorithm::ECDSAWithSHA512 => MessageDigest::sha512(),
        _ => kms_bail!(KmsError::NotSupported(format!(
            "sign_with_ecdsa: not supported: {digital_signature_algorithm:?}"
        ))),
    };

    let mut signer = Signer::new(digest, private_key)?;

    if let Some(corr) = request.correlation_value {
        signer.update(&corr)?;
    }
    let signature = if let Some(digested_data) = &request.digested_data {
        signer.sign_oneshot_to_vec(digested_data)
    } else {
        let data_to_sign = request.data.unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)
    }?;

    debug!(
        "sign_with_ecdsa: signed: message signature length: {}",
        signature.len()
    );

    Ok(signature)
}

fn sign_with_eddsa(request: Sign, private_key: &PKey<Private>) -> KResult<Vec<u8>> {
    debug!("signing with EDDSA");
    let mut signer = Signer::new_without_digest(private_key)?;

    if let Some(corr) = request.correlation_value {
        signer.update(&corr)?;
    }
    let signature = if let Some(digested_data) = &request.digested_data {
        signer.sign_oneshot_to_vec(digested_data)
    } else {
        let data_to_sign = request.data.unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)
    }?;

    debug!(
        "sign_with_eddsa: signed: message signature length: {}",
        signature.len()
    );

    Ok(signature)
}

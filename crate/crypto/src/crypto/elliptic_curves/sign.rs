use cosmian_kmip::kmip_2_1::{kmip_operations::Sign, kmip_types::DigitalSignatureAlgorithm};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};

use crate::error::CryptoError;

/// ECDSA signature helper implementing RFC6979 determinism for NIST P-256 + SHA-256 in non-fips builds,
/// falling back to OpenSSL Signer otherwise.
pub fn ecdsa_sign(request: &Sign, private_key: &PKey<Private>) -> Result<Vec<u8>, CryptoError> {
    let digital_signature_algorithm = request.cryptographic_parameters.as_ref().map_or(
        DigitalSignatureAlgorithm::ECDSAWithSHA256,
        |cp| {
            cp.digital_signature_algorithm
                .unwrap_or(DigitalSignatureAlgorithm::ECDSAWithSHA256)
        },
    );

    let digest = match digital_signature_algorithm {
        DigitalSignatureAlgorithm::ECDSAWithSHA256 => MessageDigest::sha256(),
        DigitalSignatureAlgorithm::ECDSAWithSHA384 => MessageDigest::sha384(),
        DigitalSignatureAlgorithm::ECDSAWithSHA512 => MessageDigest::sha512(),
        _ => {
            return Err(CryptoError::NotSupported(format!(
                "ecdsa_sign: not supported: {digital_signature_algorithm:?}"
            )));
        }
    };

    // RFC6979 path for non-fips builds
    #[cfg(feature = "non-fips")]
    {
        if digital_signature_algorithm == DigitalSignatureAlgorithm::ECDSAWithSHA256 {
            if let Ok(ec_key) = private_key.ec_key() {
                if matches!(
                    ec_key.group().curve_name(),
                    Some(openssl::nid::Nid::X9_62_PRIME256V1)
                ) {
                    use p256::ecdsa::{Signature, SigningKey, signature::DigestSigner};
                    use sha2::{Digest, Sha256};

                    let mut msg_bytes = Vec::new();
                    if let Some(corr) = request.correlation_value.clone() {
                        msg_bytes.extend_from_slice(&corr);
                    }
                    if let Some(digested_data) = &request.digested_data {
                        msg_bytes.extend_from_slice(digested_data);
                    } else if let Some(data) = &request.data {
                        msg_bytes.extend_from_slice(data.as_ref());
                    }

                    // Private scalar d
                    let mut d_bytes = ec_key.private_key().to_vec();
                    if d_bytes.len() < 32 {
                        let mut padded = vec![0_u8; 32 - d_bytes.len()];
                        padded.extend_from_slice(&d_bytes);
                        d_bytes = padded;
                    } else if d_bytes.len() > 32 {
                        let start = d_bytes.len().saturating_sub(32);
                        d_bytes = d_bytes.get(start..).unwrap_or(&d_bytes[..]).to_vec();
                    }

                    let signing_key = SigningKey::from_slice(&d_bytes).map_err(|e| {
                        CryptoError::NotSupported(format!("p256 SigningKey error: {e}"))
                    })?;

                    let mut hasher = Sha256::new();
                    hasher.update(&msg_bytes);
                    let signature: Signature = signing_key.sign_digest(hasher);
                    let sig_der = signature.to_der();
                    return Ok(sig_der.as_bytes().to_vec());
                }
            }
        }
    }

    // Default OpenSSL path
    let mut signer = Signer::new(digest, private_key)?;
    if let Some(corr) = request.correlation_value.clone() {
        signer.update(&corr)?;
    }
    let signature = if let Some(digested_data) = &request.digested_data {
        signer.sign_oneshot_to_vec(digested_data)?
    } else {
        let data_to_sign = request.data.clone().unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)?
    };
    Ok(signature)
}

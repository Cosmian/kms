use cosmian_kms_client::kmip_2_1::kmip_types::CryptographicParameters;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm;
use cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::{SymCipher, random_key};
use zeroize::Zeroizing;

use crate::error::{KmsCliError, result::KmsCliResult};

/// Resolve the Additional Authenticated Data (AAD) based on the data encryption algorithm.
/// XTS and CBC modes do not use AAD; AEAD modes (GCM, ChaCha20-Poly1305, GCM-SIV) use it.
#[must_use]
pub(crate) fn resolve_aad(
    data_encryption_algorithm: DataEncryptionAlgorithm,
    aad: Option<Vec<u8>>,
) -> Vec<u8> {
    match data_encryption_algorithm {
        DataEncryptionAlgorithm::AesXts | DataEncryptionAlgorithm::AesCbc => vec![],
        DataEncryptionAlgorithm::AesGcm => aad.unwrap_or_default(),
        #[cfg(feature = "non-fips")]
        DataEncryptionAlgorithm::Chacha20Poly1305 | DataEncryptionAlgorithm::AesGcmSiv => {
            aad.unwrap_or_default()
        }
    }
}

/// Build a `SymCipher` from the data encryption algorithm and the DEK length.
pub(crate) fn build_cipher(
    data_encryption_algorithm: DataEncryptionAlgorithm,
    dek_len: usize,
) -> KmsCliResult<SymCipher> {
    let cryptographic_parameters: CryptographicParameters = data_encryption_algorithm.into();
    SymCipher::from_algorithm_and_key_size(
        cryptographic_parameters
            .cryptographic_algorithm
            .ok_or_else(|| {
                KmsCliError::Default(
                    "No data encryption cryptographic algorithm specified".to_owned(),
                )
            })?,
        cryptographic_parameters.block_cipher_mode,
        dek_len,
    )
    .map_err(Into::into)
}

/// Generate a random Data Encryption Key (DEK) with the appropriate size
/// for the given data encryption algorithm.
pub(crate) fn generate_dek(
    data_encryption_algorithm: DataEncryptionAlgorithm,
) -> KmsCliResult<Zeroizing<Vec<u8>>> {
    let cipher = match data_encryption_algorithm {
        DataEncryptionAlgorithm::AesGcm => SymCipher::Aes256Gcm,
        DataEncryptionAlgorithm::AesCbc => SymCipher::Aes256Cbc,
        DataEncryptionAlgorithm::AesXts => SymCipher::Aes256Xts,
        #[cfg(feature = "non-fips")]
        DataEncryptionAlgorithm::Chacha20Poly1305 => SymCipher::Chacha20Poly1305,
        #[cfg(feature = "non-fips")]
        DataEncryptionAlgorithm::AesGcmSiv => SymCipher::Aes256Gcm,
    };
    Ok(random_key(cipher)?)
}

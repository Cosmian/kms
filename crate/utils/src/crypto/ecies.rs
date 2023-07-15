use std::ops::{Add, Div, Mul, Sub};

use cloudproof::reexport::crypto_core::{
    asymmetric_crypto::DhKeyPair,
    kdf,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{
        aes_256_gcm_pure::{decrypt_combined, encrypt_combined, Aes256GcmCrypto},
        nonce::NonceTrait,
        Dem,
    },
    KeyTrait,
};

use crate::error::KmipUtilsError;

/// Encrypts a message using Elliptic Curve Integrated Encryption Scheme (ECIES).
/// This implementation uses SHAKE128 (XOF) as a KDF and AES256-GCM as a symmetric cipher.
///
/// This function encrypts a given message using ECIES with the provided receiver's public key.
/// The encrypted message is returned as a `Result<Vec<u8>, KmipUtilsError>`.
///
/// # Arguments
///
/// * `rng: &mut R` - A mutable reference to a cryptographically secure random number generator.
/// * `receiver_public_key: &DH::PublicKey` - A reference to the receiver's public key.
/// * `msg: &[u8]` - A byte slice representing the message to be encrypted.
/// * `shared_encapsulation_data: Option<&[u8]>` - An optional byte slice of shared encapsulation data.
/// * `shared_authentication_data: Option<&[u8]>` - An optional byte slice of shared authentication data.
///
/// # Returns
///
/// * `Result<Vec<u8>, KmipUtilsError>` - The encrypted message as a `Vec<u8>`, or a `KmipUtilsError` if an error occurs.
///
/// # Example
///
/// ```
/// use cloudproof::reexport::crypto_core::{
///    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
///    reexport::rand_core::SeedableRng,
///    CsRng,
/// };
/// use cosmian_kms_utils::crypto::ecies::ecies_encrypt;
/// use cosmian_kms_utils::error::KmipUtilsError;
///
/// let mut rng = CsRng::from_entropy();
/// let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);
/// let msg = b"Hello, World!";
///
/// let _encrypted_message = ecies_encrypt::<
///         CsRng,
///         X25519KeyPair,
///         { X25519KeyPair::PUBLIC_KEY_LENGTH },
///         { X25519KeyPair::PRIVATE_KEY_LENGTH },
///     >(
///     &mut rng,
///     &key_pair.public_key(),
///     msg,
///     None,
///     None
/// ).unwrap();
/// ```
///
pub fn ecies_encrypt<R, DH, const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize>(
    rng: &mut R,
    receiver_public_key: &DH::PublicKey,
    msg: &[u8],
    shared_encapsulation_data: Option<&[u8]>,
    shared_authentication_data: Option<&[u8]>,
) -> Result<Vec<u8>, KmipUtilsError>
where
    R: CryptoRngCore,
    DH: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    DH::PublicKey: From<DH::PrivateKey>,
    for<'a, 'b> &'a DH::PublicKey: Add<&'b DH::PublicKey, Output = DH::PublicKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PublicKey>,
    for<'a, 'b> &'a DH::PrivateKey: Add<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Sub<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Div<&'b DH::PrivateKey, Output = DH::PrivateKey>,
{
    // Generate an ephemeral key pair (r, R) where R = r.G
    let ephemeral_key_pair = DH::new(rng);

    // Calculate the shared secret point (Px, Py) = P = r.Y
    let shared: DH::PublicKey = receiver_public_key * ephemeral_key_pair.private_key();

    // S. Note: ECIES formally uses S = Px rather than the serialization of P
    let mut shared_bytes = shared.to_bytes().to_vec();
    // S||S1: if the user provided shared_encapsulation_data S1, then we append it to the shared_bytes S
    if let Some(s1) = shared_encapsulation_data {
        shared_bytes.extend(s1);
    }

    // Generate the 256-bit symmetric encryption key k, derived using Shake128 XOF
    const SYMMETRIC_KEY_LENGTH: usize = Aes256GcmCrypto::KEY_LENGTH;
    let key = kdf!(SYMMETRIC_KEY_LENGTH, &shared_bytes);

    // Encrypt the message using AES-256-GCM
    let nonce = <Aes256GcmCrypto as Dem<SYMMETRIC_KEY_LENGTH>>::Nonce::new(rng);

    // Encrypt and authenticate the message, returning the ciphertext and MAC
    let c_d = encrypt_combined(&key, msg, nonce.as_bytes(), shared_authentication_data)?;

    // Assemble the final encrypted message: R || nonce || c || d
    let mut ciphertext = ephemeral_key_pair.public_key().to_bytes().to_vec();
    ciphertext.extend(nonce.as_bytes());
    ciphertext.extend(c_d);

    Ok(ciphertext)
}

/// Decrypts a message using Elliptic Curve Integrated Encryption Scheme (ECIES).
/// This implementation uses SHAKE128 (XOF) as a KDF and AES256-GCM as a symmetric cipher.
///
/// This function decrypts a given message using ECIES with the provided receiver's private key.
/// The decrypted message is returned as a `Result<Vec<u8>, KmipUtilsError>`.
///
/// # Arguments
///
/// * `receiver_private_key: &DH::PrivateKey` - A reference to the receiver's private key.
/// * `ciphertext: &[u8]` - A byte slice representing the ciphertext to be decrypted.
/// * `shared_encapsulation_data: Option<&[u8]>` - An optional byte slice of shared encapsulation data.
/// * `shared_authentication_data: Option<&[u8]>` - An optional byte slice of shared authentication data.
///
/// # Returns
///
/// * `Result<Vec<u8>, KmipUtilsError>` - The decrypted message as a `Vec<u8>`, or a `KmipUtilsError` if an error occurs.
///
/// # Example
///
/// ```
/// use cloudproof::reexport::crypto_core::{
///     asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
///     reexport::rand_core::SeedableRng,
///     CsRng,
/// };
/// use cosmian_kms_utils::error::KmipUtilsError;
/// use cosmian_kms_utils::crypto::ecies::{ecies_encrypt, ecies_decrypt};
///
/// let mut rng = CsRng::from_entropy();
/// let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);
/// let msg = b"Hello, World!";
///
/// // Encrypt the message
/// let encrypted_message = ecies_encrypt::<
///     CsRng,
///     X25519KeyPair,
///     { X25519KeyPair::PUBLIC_KEY_LENGTH },
///     { X25519KeyPair::PRIVATE_KEY_LENGTH },
/// >(
///     &mut rng,
///     &key_pair.public_key(),
///     msg,
///     None,
///     None
/// ).unwrap();
///
/// // Decrypt the encrypted message
/// let decrypted_message = ecies_decrypt::<
///     X25519KeyPair,
///     { X25519KeyPair::PUBLIC_KEY_LENGTH },
///     { X25519KeyPair::PRIVATE_KEY_LENGTH },
/// >(
///     &key_pair.private_key(),
///     &encrypted_message,
///     None,
///     None
/// ).unwrap();
///
/// // Check if the decrypted message is the same as the original message
/// assert_eq!(msg, &decrypted_message[..]);
/// ```
///
pub fn ecies_decrypt<DH, const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize>(
    receiver_private_key: &DH::PrivateKey,
    ciphertext: &[u8],
    shared_encapsulation_data: Option<&[u8]>,
    shared_authentication_data: Option<&[u8]>,
) -> Result<Vec<u8>, KmipUtilsError>
where
    DH: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    DH::PublicKey: From<DH::PrivateKey>,
    for<'a, 'b> &'a DH::PublicKey: Add<&'b DH::PublicKey, Output = DH::PublicKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PublicKey>,
    for<'a, 'b> &'a DH::PrivateKey: Add<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Sub<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Div<&'b DH::PrivateKey, Output = DH::PrivateKey>,
{
    // Extract the sender's ephemeral public key R from the ciphertext
    let ephemeral_public_key = &ciphertext[..PUBLIC_KEY_LENGTH];
    let sender_public_key = DH::PublicKey::try_from_bytes(ephemeral_public_key)?;

    // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
    let shared: DH::PublicKey = &sender_public_key * receiver_private_key;

    // S. Note: ECIES formally uses S = Px rather than the serialization of P
    let mut shared_bytes = shared.to_bytes().to_vec();
    // S||S1: if the user provided shared_encapsulation_data S1, then we append it to the shared_bytes S
    if let Some(s1) = shared_encapsulation_data {
        shared_bytes.extend(s1);
    }

    // Generate the 256-bit symmetric decryption key k, derived using Shake128 XOF
    const SYMMETRIC_KEY_LENGTH: usize = Aes256GcmCrypto::KEY_LENGTH;
    let key = kdf!(SYMMETRIC_KEY_LENGTH, &shared_bytes);

    // Extract the nonce from the ciphertext
    let nonce_start = PUBLIC_KEY_LENGTH;
    let nonce_end = nonce_start + <Aes256GcmCrypto as Dem<SYMMETRIC_KEY_LENGTH>>::Nonce::LENGTH;
    let nonce = &ciphertext[nonce_start..nonce_end];

    // Separate the encrypted message and MAC from the ciphertext
    let c_d = &ciphertext[nonce_end..];

    // Decrypt and verify the message using AES-256-GCM
    let decrypted_message = decrypt_combined(&key, c_d, nonce, shared_authentication_data)?;

    Ok(decrypted_message)
}

#[cfg(test)]
mod tests {
    use cloudproof::reexport::crypto_core::{
        asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
        reexport::rand_core::SeedableRng,
        CsRng,
    };

    use super::{ecies_decrypt, ecies_encrypt, KmipUtilsError};

    #[test]
    fn test_encrypt_decrypt() -> Result<(), KmipUtilsError> {
        let mut rng = CsRng::from_entropy();
        let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);
        let msg = b"Hello, World!";

        // Encrypt the message
        let encrypted_message = ecies_encrypt::<
            CsRng,
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(&mut rng, key_pair.public_key(), msg, None, None)?;

        // Decrypt the message
        let decrypted_message = ecies_decrypt::<
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(key_pair.private_key(), &encrypted_message, None, None)?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(msg, &decrypted_message[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_optional_data() -> Result<(), KmipUtilsError> {
        let mut rng = CsRng::from_entropy();
        let key_pair: X25519KeyPair = X25519KeyPair::new(&mut rng);
        let msg = b"Hello, World!";
        let encapsulated_data = b"Optional Encapsulated Data";
        let authentication_data = b"Optional Authentication Data";

        // Encrypt the message with encapsulated_data and authentication_data
        let encrypted_message = ecies_encrypt::<
            CsRng,
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            &mut rng,
            key_pair.public_key(),
            msg,
            Some(encapsulated_data),
            Some(authentication_data),
        )?;

        // Decrypt the message with encapsulated_data and authentication_data
        let decrypted_message = ecies_decrypt::<
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            key_pair.private_key(),
            &encrypted_message,
            Some(encapsulated_data),
            Some(authentication_data),
        )?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(msg, &decrypted_message[..]);

        Ok(())
    }
}

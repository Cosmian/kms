use num_bigint_dig::algorithms::idiv_ceil;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroupRef, EcKey, EcPoint, EcPointRef, PointConversionForm},
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private, Public},
};
use zeroize::Zeroizing;

use crate::{
    crypto::symmetric::symmetric_ciphers::{SymCipher, decrypt, encrypt},
    crypto_bail,
    error::{CryptoError, result::CryptoResultHelper},
};

/// Derive an initialization vector from recipient public key `Q` and
/// ephemeral public key `R` using the supplied hashing algorithm.
fn ecies_get_iv(
    recipient_public: &EcPointRef,
    ephemeral_public: &EcPointRef,
    curve: &EcGroupRef,
    iv_size: usize,
    message_digest: MessageDigest,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = BigNumContext::new()?;
    let recipient_public_bytes =
        recipient_public.to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;
    let ephemeral_public_bytes =
        ephemeral_public.to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;

    let mut iv = vec![0; iv_size];

    let mut hasher = Hasher::new(message_digest)?;
    hasher.update(&ephemeral_public_bytes)?;
    hasher.update(&recipient_public_bytes)?;
    hasher.finish_xof(&mut iv)?;

    Ok(iv)
}

/// Derive the symmetric secret key from the shared point using SHAKE128.
fn ecies_get_key(
    shared_point: &EcPointRef,
    curve: &EcGroupRef,
    key_size: usize,
    message_digest: MessageDigest,
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = BigNumContext::new_secure()?;
    let shared_point_bytes =
        shared_point.to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;

    let mut key = vec![0; key_size];

    let mut hasher = Hasher::new(message_digest)?;
    hasher.update(&shared_point_bytes)?;
    hasher.finish_xof(&mut key)?;

    Ok(key)
}

/// When using standard curves, the hashing algorithm is SHAKE128, the
/// AEAD is AES 128 GCM and the following ECIES algorithm is used:
///
/// Generate a random `r` and compute `R = rG` with `G` the curve generator.
/// Using target pubic key `pubkey` we will call `Q`, compute `S = rQ`. `S` is
/// the shared key used to symmetrically encrypt data using AES-256-GCM.
///
/// Return `R | ct | tag` with `|` the concatenation operator, `R` the ephemeral
/// public key on the curve, `ct` the encrypted data and `tag` the
/// authentication tag forged during encryption.
///
/// Notice we don't send the IV since it is derived by hashing the public key as
/// well as the ephemeral public key.
pub(super) fn ecies_encrypt(
    pubkey: &PKey<Public>,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = BigNumContext::new_secure()?;
    let recipient_public = pubkey.ec_key()?;
    let curve = recipient_public.group();
    let (aead, md) = aead_and_digest(curve)?;

    // Generating random ephemeral private key `r` and associated public key
    // `R`.
    let r = EcKey::generate(curve)?;
    let ephemeral_public = EcKey::from_public_key(curve, r.public_key())?;

    // Compute shared secret from recipient public key `S = rQ`.
    let mut shared_point = EcPoint::new(curve)?;
    shared_point.mul2(
        curve,
        recipient_public.public_key(),
        r.private_key(),
        &mut ctx,
    )?;

    let key = ecies_get_key(&shared_point, curve, aead.key_size(), md)?;
    let iv = ecies_get_iv(
        recipient_public.public_key(),
        ephemeral_public.public_key(),
        curve,
        aead.nonce_size(),
        md,
    )?;

    // Encrypt data using the provided.
    let (ciphertext, tag) = encrypt(aead, &key, &iv, &[], plaintext, None)?;

    let ephemeral_public_bytes =
        ephemeral_public
            .public_key()
            .to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;

    Ok([ephemeral_public_bytes, ciphertext, tag].concat())
}

/// When using standard curves, the hashing algorithm is SHAKE128, the
/// AEAD is AES 128 GCM and the following ECIES algorithm is used:
///
/// `ciphertext` is a concatenation of `R | ct | tag` with `|` the concatenation
/// operator, `R` the ephemeral public key on the curve, `ct` the encrypted data
/// and `tag` the authentication tag forged during encryption.
///
/// The IV for decryption is computed by taking the hash of the recipient public
/// key and the ephemeral public key.
pub(super) fn ecies_decrypt(
    private_key: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut ctx = BigNumContext::new_secure()?;
    let d = private_key.ec_key()?;
    let curve = d.group();
    let (aead, md) = aead_and_digest(curve)?;

    // OpenSSL stored compressed coordinates with one extra byte for some
    // reason hence the + 1 at the end.
    let pubkey_vec_size = idiv_ceil(usize::try_from(curve.order_bits())?, 8) + 1;
    if ciphertext.len() <= pubkey_vec_size + aead.tag_size() {
        crypto_bail!("ECIES: Decryption error: invalid ciphertext")
    }

    // Ciphertext received is a concatenation of `R | ct | tag` with `R`
    // and `ct` of variable size and `tag` of size 128 bits.
    let ephemeral_public_bytes = ciphertext.get(..pubkey_vec_size).ok_or_else(|| {
        CryptoError::IndexingSlicing("ecies_decrypt: ephemeral_public_bytes".to_owned())
    })?;

    let ct_offset = ciphertext.len() - aead.tag_size();
    let ct = ciphertext
        .get(pubkey_vec_size..ct_offset)
        .ok_or_else(|| CryptoError::IndexingSlicing("ecies_decrypt: ciphertext".to_owned()))?;

    let tag = ciphertext
        .get(ct_offset..)
        .ok_or_else(|| CryptoError::IndexingSlicing("ecies_decrypt: tag".to_owned()))?;

    let ephemeral_public = EcPoint::from_bytes(curve, ephemeral_public_bytes, &mut ctx)?;

    // Compute secret key from recipient public key `S = rQ = rdG = dR`.
    let mut shared_point = EcPoint::new(curve)?;
    shared_point.mul2(curve, &ephemeral_public, d.private_key(), &mut ctx)?;

    let iv = ecies_get_iv(
        d.public_key(),
        &ephemeral_public,
        curve,
        aead.nonce_size(),
        md,
    )?;
    let key = ecies_get_key(&shared_point, curve, aead.key_size(), md)?;

    // We could use ou own aead to offer more DEM options.
    let plaintext = decrypt(aead, &key, &iv, &[], ct, tag, None)?;

    Ok(plaintext)
}

fn aead_and_digest(curve: &EcGroupRef) -> Result<(SymCipher, MessageDigest), CryptoError> {
    let (aead, md) = match curve.curve_name().context("Unsupported curve")? {
        Nid::SECP384R1 | Nid::SECP521R1 => (SymCipher::Aes256Gcm, MessageDigest::shake_256()),
        Nid::X9_62_PRIME256V1 | Nid::SECP224R1 | Nid::X9_62_PRIME192V1 => {
            (SymCipher::Aes128Gcm, MessageDigest::shake_128())
        }
        other => crypto_bail!("Unsupported curve: {:?}", other),
    };
    Ok((aead, md))
}

#[cfg(test)]
mod tests {

    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };

    use super::{ecies_decrypt, ecies_encrypt};

    fn test_ecies_encrypt_decrypt(nid: Nid) {
        let curve = EcGroup::from_curve_name(nid).unwrap();
        let ec_privkey = EcKey::generate(&curve).unwrap();
        let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key()).unwrap();

        let pubkey = PKey::from_ec_key(ec_pubkey).unwrap();
        let privkey = PKey::from_ec_key(ec_privkey).unwrap();

        let plaintext = b"i love pancakes";

        let ct = ecies_encrypt(&pubkey, plaintext).unwrap();
        let pt = ecies_decrypt(&privkey, &ct).unwrap();

        assert_eq!(plaintext.to_vec(), *pt);
    }

    #[test]
    #[cfg(feature = "non-fips")]
    fn test_ecies_encrypt_decrypt_p_curves() {
        test_ecies_encrypt_decrypt(Nid::X9_62_PRIME192V1);
        test_ecies_encrypt_decrypt(Nid::SECP224R1);
        test_ecies_encrypt_decrypt(Nid::X9_62_PRIME256V1);
        test_ecies_encrypt_decrypt(Nid::SECP384R1);
        test_ecies_encrypt_decrypt(Nid::SECP521R1);
    }
}

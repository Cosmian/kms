use num_bigint_dig::algorithms::idiv_ceil;
#[cfg(feature = "fips")]
use openssl::nid::Nid;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroupRef, EcKey, EcPoint, EcPointRef, PointConversionForm},
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private, Public},
    symm::{decrypt_aead, encrypt_aead, Cipher},
};

#[cfg(feature = "fips")]
use crate::kmip_utils_bail;
use crate::{
    crypto::symmetric::{AES_256_GCM_IV_LENGTH, AES_256_GCM_KEY_LENGTH, AES_256_GCM_MAC_LENGTH},
    error::KmipUtilsError,
};

/// Derive initialization vector from recipient public key `Q` and ephemeral
/// public key `R` using SHAKE128-128.
#[allow(non_snake_case)]
fn ecies_get_iv(
    Q: &EcPointRef,
    R: &EcPointRef,
    curve: &EcGroupRef,
) -> Result<Vec<u8>, KmipUtilsError> {
    let mut ctx = BigNumContext::new_secure()?;
    let Q_vec = Q.to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;
    let R_vec = R.to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;

    let mut iv = vec![0; AES_256_GCM_IV_LENGTH];

    let mut hasher = Hasher::new(MessageDigest::shake_128())?;
    hasher.update(&Q_vec)?;
    hasher.update(&R_vec)?;
    hasher.finish_xof(&mut iv)?;

    Ok(iv)
}

/// Derive S into the symmetric secret key using SHAKE128-256.
#[allow(non_snake_case)]
fn ecies_get_key(S: &EcPointRef, curve: &EcGroupRef) -> Result<Vec<u8>, KmipUtilsError> {
    let mut ctx = BigNumContext::new_secure()?;
    let S_vec = S.to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;

    let mut key = vec![0; AES_256_GCM_KEY_LENGTH];

    let mut hasher = Hasher::new(MessageDigest::shake_128())?;
    hasher.update(&S_vec)?;
    hasher.finish_xof(&mut key)?;

    Ok(key)
}

/// Encrypt `plaintext` data using `pubkey` public key following the ECIES
/// principle.
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
#[allow(non_snake_case)]
pub fn ecies_encrypt(pubkey: &PKey<Public>, plaintext: &[u8]) -> Result<Vec<u8>, KmipUtilsError> {
    let mut ctx = BigNumContext::new_secure()?;
    let Q = pubkey.ec_key()?;
    let curve = Q.group();

    #[cfg(feature = "fips")]
    if curve.curve_name() == Some(Nid::X9_62_PRIME192V1) {
        kmip_utils_bail!("Curve P-192 not allowed in FIPS mode.")
    }

    // Generating random ephemeral private key `r` and associated public key
    // `R`.
    let r = EcKey::generate(curve)?;
    let R = EcKey::from_public_key(curve, r.public_key())?;

    // Compute secret key from recipient public key `S = rQ`.
    let mut S = EcPoint::new(curve)?;
    S.mul(curve, Q.public_key(), r.private_key(), &ctx)?;

    let key = ecies_get_key(&S, curve)?;
    let iv = ecies_get_iv(Q.public_key(), R.public_key(), curve)?;

    // Allocating memory for AES-GCM to write the tag at.
    let mut tag = vec![0; AES_256_GCM_MAC_LENGTH];

    // Encryption using AES-256-GCM.
    let ct: Vec<u8> = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&iv),
        &[],
        plaintext,
        tag.as_mut(),
    )?;

    let R_vec = R
        .public_key()
        .to_bytes(curve, PointConversionForm::COMPRESSED, &mut ctx)?;

    Ok([R_vec, ct, tag].concat())
}

/// Decrypt `ciphertext` data using `privkey` private key following the ECIES
/// principle.
///
/// `ciphertext` is a concatanation of `R | ct | tag` with `|` the concatenation
/// operator, `R` the ephemeral public key on the curve, `ct` the encrypted data
/// and `tag` the authentication tag forged during encryption.
///
/// The IV for decryption is computed by taking the hash of the recipient public
/// key and the ephemeral public key.
///
/// Return the plaintext.
#[allow(non_snake_case)]
pub fn ecies_decrypt(
    privkey: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let mut ctx = BigNumContext::new_secure()?;
    let d = privkey.ec_key()?;
    let curve = d.group();

    #[cfg(feature = "fips")]
    if curve.curve_name() == Some(Nid::X9_62_PRIME192V1) {
        kmip_utils_bail!("Curve P-192 not allowed in FIPS mode.")
    }

    // OpenSSL stored compressed coordinates with one extra byte for some
    // reason hence the + 1 at the end.
    let pubkey_vec_size = idiv_ceil(curve.order_bits() as usize, 8) + 1;

    // Ciphertext received is a concatenation of `R | ct | tag` with `R`
    // and `ct` of variable size and `tag` of size 128 bits.
    let R_vec = &ciphertext[..pubkey_vec_size];

    let ct_offset = ciphertext.len() - AES_256_GCM_MAC_LENGTH;
    let ct = &ciphertext[pubkey_vec_size..ct_offset];

    let tag = &ciphertext[ct_offset..];

    let R = EcPoint::from_bytes(curve, R_vec, &mut ctx)?;

    // Compute secret key from recipient public key `S = rQ = rdG = dR`.
    let mut S = EcPoint::new(curve)?;
    S.mul(curve, &R, d.private_key(), &ctx)?;

    let iv = ecies_get_iv(d.public_key(), &R, curve)?;
    let key = ecies_get_key(&S, curve)?;

    // Decrypt data using AES-256-GCM with freshly computed key.
    let plaintext = decrypt_aead(Cipher::aes_256_gcm(), &key, Some(&iv), &[], ct, tag)?;

    Ok(plaintext)
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

        let plaintext = "i love pancakes".as_bytes();

        let ct = ecies_encrypt(&pubkey, plaintext).unwrap();
        let pt = ecies_decrypt(&privkey, &ct).unwrap();

        assert_eq!(plaintext, &pt);
    }

    #[test]
    fn test_ecies_encrypt_decrypt_p_curves() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        #[cfg(not(feature = "fips"))]
        test_ecies_encrypt_decrypt(Nid::X9_62_PRIME192V1);
        test_ecies_encrypt_decrypt(Nid::SECP224R1);
        test_ecies_encrypt_decrypt(Nid::X9_62_PRIME256V1);
        test_ecies_encrypt_decrypt(Nid::SECP384R1);
        test_ecies_encrypt_decrypt(Nid::SECP521R1);
    }
}

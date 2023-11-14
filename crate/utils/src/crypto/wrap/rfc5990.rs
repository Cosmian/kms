/*
 * Asymmetrically wrap keys using RFC 5990 available at:
 * -> https://datatracker.ietf.org/doc/html/rfc5990
 *
 * This RFC describes how to wrap keys of any size using asymmetric encryption
 * and the RSA algorithm. Since old similar wrapping methods based on RSA used
 * naive RSA encryption and could present some flaws, this RFC aims at a
 * generally more secure method to wrap keys.
 *
 * Let `m` be the key/message to wrap, `<n, e>` the RSA public key and `d`
 * the RSA private key.
 * First generate a random integer `z` in the range [1, n-1]. Encrypt it using
 * the public key: `c = z^e mod n``
 * Derive `kek` from `z` (here SHA-256).
 *
 * Encrypt `c' = AES(kek, m)` using the key `kek` with AES-256-GCM.
 *
 * Send `c|iv|c'|mac` where `|` is the concatenation operator, `iv` the IV used
 * and `mac` the authentication tag for GCM.
 */
use openssl::{
    bn::BigNum,
    pkey::{PKey, Private, Public},
    rsa::Padding,
    sha::sha256,
};

use super::rfc5649::{key_unwrap, key_wrap};
use crate::{error::KmipUtilsError, kmip_utils_bail};

const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 2048;

pub fn rfc5990_encrypt(pubkey: PKey<Public>, plaintext: &[u8]) -> Result<Vec<u8>, KmipUtilsError> {
    if pubkey.rsa().is_err() {
        kmip_utils_bail!("Error: keypair is not RSA, RFC 5990 specifies for RSA keypairs.")
    }

    if pubkey.bits() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_utils_bail!(
            "RSA key has insufficient size: expected >= {} and got {}",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            pubkey.bits()
        )
    }

    let rsa_pubkey = pubkey.rsa()?;
    let encapsulation_bytes_len = rsa_pubkey.size() as usize;

    let mut z = BigNum::new_secure()?;
    rsa_pubkey.n().rand_range(&mut z)?;
    let z = z.to_vec();

    // XXX - Does not implement Zeroize.
    let mut c = vec![0u8; encapsulation_bytes_len];
    // XXX - Since the encrypted value is uniformly generated at random in the
    // range [1, n-1], no padding is needed here.
    let encrypted_len = rsa_pubkey.public_encrypt(&z, &mut c, Padding::NONE)?;
    c.truncate(encrypted_len);

    // Derive symmetric key using SHA-256.
    let kek = sha256(&z);

    // Wrap key according to RFC 5649 and as recommended in RFC 5990.
    let wk = key_wrap(plaintext, &kek)?;

    Ok([c, wk].concat())
}

pub fn rfc5990_decrypt(p_key: PKey<Private>, ciphertext: &[u8]) -> Result<Vec<u8>, KmipUtilsError> {
    if p_key.rsa().is_err() {
        kmip_utils_bail!("Error: keypair is not RSA, RFC 5990 specifies for RSA keypairs.")
    }

    if p_key.bits() < FIPS_MIN_RSA_MODULUS_LENGTH {
        kmip_utils_bail!(
            "RSA key has insufficient size: expected >= {} and got {}",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            p_key.bits()
        )
    }

    let rsa_privkey = p_key.rsa()?;
    let encapsulation_bytes_len = rsa_privkey.size() as usize;
    if ciphertext.len() <= encapsulation_bytes_len {
        kmip_utils_bail!(
            "Encrypted data of insufficient length: got {}",
            ciphertext.len()
        );
    }

    let c: &[u8] = &ciphertext[..encapsulation_bytes_len];
    let wk = &ciphertext[encapsulation_bytes_len..];

    // XXX - Does not implement Zeroize.
    let mut z = vec![0u8; encapsulation_bytes_len];
    // XXX - No padding was used at encryption.
    let decrypted_len = rsa_privkey.private_decrypt(c, &mut z, Padding::NONE)?;
    z.truncate(decrypted_len);

    // Derive symmetric key using SHA-256.
    let kek = sha256(&z);

    // Unwrap key according to RFC 5649 and as recommended in RFC 5990.
    let plaintext = key_unwrap(wk, &kek)?;

    Ok(plaintext)
}

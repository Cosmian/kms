use openssl::pkey::{Id, PKey, Private, Public};
use zeroize::Zeroizing;

use crate::{error::KmipError, kmip_bail};

mod salsa_sealbox;
mod standard_curves;

/// Encrypt `plaintext` data using `pubkey` public key following ECIES.
///
/// When using Curve25519 (X25519 or Ed25519 which is converted to X25519),
/// `SalsaSealBox` is used. The implementation is compatible with that of libsodium:
/// the hashing algorithm is set to Blake2b and the AEAD to `Salsa20Poly1305`.
///
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
pub fn ecies_encrypt(public_key: &PKey<Public>, plaintext: &[u8]) -> Result<Vec<u8>, KmipError> {
    let ciphertext = match public_key.id() {
        Id::EC => standard_curves::ecies_encrypt(public_key, plaintext)?,
        Id::ED25519 | Id::X25519 => salsa_sealbox::sealbox_encrypt(public_key, plaintext)?,
        _ => {
            kmip_bail!(
                "Public key id not supported for ECIES encryption: {:?}",
                public_key.id()
            );
        }
    };
    Ok(ciphertext)
}

/// Decrypt `ciphertext` data using `privkey` private key following ECIES.
///
/// When using Curve25519 (X25519 or Ed25519 which is converted to X25519),
/// `SalsaSealBox` is used. The implementation is compatible with that of libsodium:
/// the hashing algorithm is set to Blake2b and the AEAD to `Salsa20Poly1305`.
///
/// When using standard curves, the hashing algorithm is SHAKE128, the
/// AEAD is AES 128 GCM and the following ECIES algorithm is used:
///
/// `ciphertext` is a concatenation of `R | ct | tag` with `|` the concatenation
/// operator, `R` the ephemeral public key on the curve, `ct` the encrypted data
/// and `tag` the authentication tag forged during encryption.
///
/// The IV for decryption is computed by taking the hash of the recipient public
/// key and the ephemeral public key.
///
/// Return the plaintext.
pub fn ecies_decrypt(
    private_key: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipError> {
    let plaintext = match private_key.id() {
        Id::EC => standard_curves::ecies_decrypt(private_key, ciphertext)?,
        Id::ED25519 | Id::X25519 => salsa_sealbox::sealbox_decrypt(private_key, ciphertext)?,
        x => {
            kmip_bail!("private key id not supported yet: {:?}", x);
        }
    };
    Ok(plaintext)
}

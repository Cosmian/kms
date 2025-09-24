use cosmian_crypto_core::{
    CsRng, Ecies, EciesSalsaSealBox, Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey,
    X25519PublicKey, reexport::rand_core::SeedableRng,
};
use cosmian_logger::trace;
use openssl::pkey::{Id, PKey, Private, Public};
use zeroize::Zeroizing;

use crate::{
    crypto::elliptic_curves::{
        ED25519_PRIVATE_KEY_LENGTH, ED25519_PUBLIC_KEY_LENGTH, X25519_PRIVATE_KEY_LENGTH,
        X25519_PUBLIC_KEY_LENGTH,
    },
    crypto_bail,
    error::CryptoError,
};

/// Encrypt `plaintext` data using `pubkey`, a Curve 25519 public key, following ECIES
/// in a way that is compatible with libsodium `SalsaSealBox`.
pub(super) fn sealbox_encrypt(
    public_key: &PKey<Public>,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let ciphertext = match public_key.id() {
        Id::ED25519 => {
            trace!("Ed25519");
            let mut rng = CsRng::from_entropy();
            // The raw public key happens to be the (compressed) value of the Montgomery point
            let raw_bytes = public_key.raw_public_key()?;
            let public_key_bytes: [u8; ED25519_PUBLIC_KEY_LENGTH] = raw_bytes.try_into()?;
            let public_key = X25519PublicKey::from_ed25519_public_key(
                &Ed25519PublicKey::try_from_bytes(public_key_bytes)?,
            );
            EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None)?
        }
        Id::X25519 => {
            trace!("X25519");
            let mut rng = CsRng::from_entropy();
            // The raw public key happens to be the (compressed) value of the Montgomery point
            let raw_bytes = public_key.raw_public_key()?;
            let public_key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] = raw_bytes.try_into()?;
            let public_key = X25519PublicKey::try_from_bytes(public_key_bytes)?;
            EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None)?
        }
        _ => {
            crypto_bail!(
                "Public key id not supported for SalsaSealbox encryption: {:?}",
                public_key.id()
            );
        }
    };
    Ok(ciphertext)
}

/// Decrypt `ciphertext` data using `privkey`, a curve 25519 private key following ECIES
/// in a way compatible with Salsa `SealBox` provided by libsodium.
pub(super) fn sealbox_decrypt(
    private_key: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let plaintext = match private_key.id() {
        Id::ED25519 => {
            let raw_bytes = private_key.raw_private_key()?;
            let private_key_bytes: [u8; ED25519_PRIVATE_KEY_LENGTH] = raw_bytes.try_into()?;
            let private_key = Ed25519PrivateKey::try_from_bytes(private_key_bytes)?;
            let private_key = X25519PrivateKey::from_ed25519_private_key(&private_key);
            Zeroizing::new(EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?)
        }
        Id::X25519 => {
            let raw_bytes = private_key.raw_private_key()?;
            let private_key_bytes: [u8; X25519_PRIVATE_KEY_LENGTH] = raw_bytes.try_into()?;
            let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes)?;
            Zeroizing::new(EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?)
        }
        x => {
            crypto_bail!(
                "Private key id not supported for Salsa SealedBox decryption: {:?}",
                x
            );
        }
    };
    Ok(plaintext)
}

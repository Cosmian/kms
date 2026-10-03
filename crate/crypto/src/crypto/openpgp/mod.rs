use cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use pgp::{
    composed::{
        ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, KeyType, Message,
        MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
        SubkeyParamsBuilder,
    },
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::KeyFlags,
    ser::Serialize,
    types::{KeyDetails, Password, PublicParams},
};
use zeroize::Zeroizing;

use crate::{crypto_bail, crypto_error, error::CryptoError};

/// `OpenPGP` key profile to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgpKeyProfile {
    /// RSA primary (Sign+Certify) + RSA subkey (Encrypt); `bits` ∈ {2048, 3072, 4096}.
    Rsa { bits: u32 },
    /// `Ed25519Legacy` primary (Sign+Certify) + ECDH Curve25519 subkey (Encrypt).
    Ed25519,
}

/// Armored Transferable Secret Key, RFC 9580 v4.
pub fn generate_openpgp_secret_key(
    profile: PgpKeyProfile,
    user_id: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut builder = SecretKeyParamsBuilder::default();
    match profile {
        PgpKeyProfile::Rsa { bits } => {
            if bits < 2048 {
                crypto_bail!("RSA key size must be at least 2048 bits");
            }
            builder
                .key_type(KeyType::Rsa(bits))
                .can_sign(true)
                .can_certify(true)
                .can_encrypt(EncryptionCaps::None)
                .primary_user_id(user_id.to_owned())
                .subkeys(vec![
                    SubkeyParamsBuilder::default()
                        .key_type(KeyType::Rsa(bits))
                        .can_encrypt(EncryptionCaps::All)
                        .build()
                        .map_err(|e| crypto_error!("failed to build RSA subkey params: {e}"))?,
                ]);
        }
        PgpKeyProfile::Ed25519 => {
            builder
                .key_type(KeyType::Ed25519Legacy)
                .can_sign(true)
                .can_certify(true)
                .can_encrypt(EncryptionCaps::None)
                .primary_user_id(user_id.to_owned())
                .subkeys(vec![
                    SubkeyParamsBuilder::default()
                        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                        .can_encrypt(EncryptionCaps::All)
                        .build()
                        .map_err(|e| crypto_error!("failed to build Ed25519 subkey params: {e}"))?,
                ]);
        }
    }

    let params = builder
        .build()
        .map_err(|e| crypto_error!("failed to build secret key params: {e}"))?;

    let signed_secret = params
        .generate(rand_08::rngs::OsRng)
        .map_err(|e| crypto_error!("failed to generate OpenPGP key: {e}"))?;

    let armored = signed_secret
        .to_armored_bytes(ArmorOptions::default())
        .map_err(|e| crypto_error!("failed to armor secret key: {e}"))?;

    Ok(Zeroizing::new(armored))
}

/// Accepts armored or binary, secret or public input.
/// Returns `(armored_bytes, is_secret_key)`.
pub fn openpgp_normalize(input: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool), CryptoError> {
    // Try secret key binary then armor
    if let Ok(ssk) = SignedSecretKey::from_bytes(std::io::Cursor::new(input)) {
        let armored = ssk
            .to_armored_bytes(ArmorOptions::default())
            .map_err(|e| crypto_error!("failed to armor secret key: {e}"))?;
        return Ok((Zeroizing::new(armored), true));
    }
    if let Ok((ssk, _)) = SignedSecretKey::from_armor_single(std::io::Cursor::new(input)) {
        let armored = ssk
            .to_armored_bytes(ArmorOptions::default())
            .map_err(|e| crypto_error!("failed to armor secret key: {e}"))?;
        return Ok((Zeroizing::new(armored), true));
    }

    // Try public key binary then armor
    if let Ok(spk) = SignedPublicKey::from_bytes(std::io::Cursor::new(input)) {
        let armored = spk
            .to_armored_bytes(ArmorOptions::default())
            .map_err(|e| crypto_error!("failed to armor public key: {e}"))?;
        return Ok((Zeroizing::new(armored), false));
    }
    if let Ok((spk, _)) = SignedPublicKey::from_armor_single(std::io::Cursor::new(input)) {
        let armored = spk
            .to_armored_bytes(ArmorOptions::default())
            .map_err(|e| crypto_error!("failed to armor public key: {e}"))?;
        return Ok((Zeroizing::new(armored), false));
    }

    crypto_bail!("input is not a valid OpenPGP transferable secret or public key")
}

/// Helper to parse an armored or binary key into either `SignedSecretKey` or `SignedPublicKey`.
fn parse_secret_or_public(
    input: &[u8],
) -> Result<(Option<SignedSecretKey>, Option<SignedPublicKey>), CryptoError> {
    if let Ok(ssk) = SignedSecretKey::from_bytes(std::io::Cursor::new(input)) {
        return Ok((Some(ssk), None));
    }
    if let Ok((ssk, _)) = SignedSecretKey::from_armor_single(std::io::Cursor::new(input)) {
        return Ok((Some(ssk), None));
    }
    if let Ok(spk) = SignedPublicKey::from_bytes(std::io::Cursor::new(input)) {
        return Ok((None, Some(spk)));
    }
    if let Ok((spk, _)) = SignedPublicKey::from_armor_single(std::io::Cursor::new(input)) {
        return Ok((None, Some(spk)));
    }
    crypto_bail!("failed to parse OpenPGP certificate")
}

/// Helper to parse a secret key specifically from armored or binary bytes.
fn parse_secret_key(input: &[u8]) -> Result<SignedSecretKey, CryptoError> {
    if let Ok(ssk) = SignedSecretKey::from_bytes(std::io::Cursor::new(input)) {
        return Ok(ssk);
    }
    if let Ok((ssk, _)) = SignedSecretKey::from_armor_single(std::io::Cursor::new(input)) {
        return Ok(ssk);
    }
    crypto_bail!("input is not a valid OpenPGP secret key")
}

/// Strips secret material; input MUST be a secret key, output is an armored TPK.
pub fn openpgp_public_from_secret(armored_secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret = parse_secret_key(armored_secret)?;
    let public = secret.to_public_key();
    let armored = public
        .to_armored_bytes(ArmorOptions::default())
        .map_err(|e| crypto_error!("failed to armor public key: {e}"))?;
    Ok(armored)
}

/// `(algorithm, cryptographic_length_bits, pgp_key_version)` read from the primary key packet.
/// `algorithm` is `CryptographicAlgorithm::RSA` or `CryptographicAlgorithm::Ed25519`;
/// any other primary algorithm is reported as-is where a mapping exists, else `None`.
pub fn openpgp_key_metadata(
    armored: &[u8],
) -> Result<(Option<CryptographicAlgorithm>, Option<i32>, u32), CryptoError> {
    let (secret_opt, public_opt) = parse_secret_or_public(armored)?;
    let (version, params) = if let Some(sec) = &secret_opt {
        (sec.primary_key.version(), sec.primary_key.public_params())
    } else if let Some(pubk) = &public_opt {
        (pubk.primary_key.version(), pubk.primary_key.public_params())
    } else {
        crypto_bail!("no key parsed");
    };

    let version_u32 = match version {
        pgp::types::KeyVersion::V2 | pgp::types::KeyVersion::V3 => 3,
        pgp::types::KeyVersion::V5 => 5,
        pgp::types::KeyVersion::V6 => 6,
        pgp::types::KeyVersion::V4 | pgp::types::KeyVersion::Other(_) => 4,
    };

    let (alg, len) = match params {
        PublicParams::RSA(rsa) => {
            // RSA public parameters are serialized as MPI(n) || MPI(e).
            // MPI is a 2-byte BE bit length followed by the big-endian integer bytes.
            let mut buf = Vec::new();
            rsa.to_writer(&mut buf)
                .map_err(|e| crypto_error!("failed to serialize RSA public params: {e}"))?;
            let bits = if let (Some(&b0), Some(&b1)) = (buf.first(), buf.get(1)) {
                i32::from(u16::from_be_bytes([b0, b1]))
            } else {
                0
            };
            (Some(CryptographicAlgorithm::RSA), Some(bits))
        }
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => {
            (Some(CryptographicAlgorithm::Ed25519), Some(256))
        }
        PublicParams::ECDSA(_) => (Some(CryptographicAlgorithm::ECDSA), None),
        PublicParams::ECDH(_) => (Some(CryptographicAlgorithm::ECDH), None),
        _ => (None, None),
    };

    Ok((alg, len, version_u32))
}

/// Binary `OpenPGP` message (PKESK + SEIPD) encrypted to the key's encryption-capable subkey.
/// Accepts a secret or public armored certificate.
pub fn openpgp_encrypt(armored_cert: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (secret_opt, public_opt) = parse_secret_or_public(armored_cert)?;
    let public = match (secret_opt, public_opt) {
        (Some(sec), _) => sec.to_public_key(),
        (None, Some(pubk)) => pubk,
        (None, None) => crypto_bail!("no OpenPGP key parsed"),
    };

    // Keep the signed subkey wrapper as the recipient. Its key identity and
    // binding signature must remain coupled to the public-key material used
    // in the PKESK packet.
    let encryption_subkey = public.public_subkeys.iter().find(|subkey| {
        subkey.signatures.iter().any(|sig| {
            let key_flags: KeyFlags = sig.key_flags();
            key_flags.encrypt_comms() || key_flags.encrypt_storage()
        })
    });

    let mut rng = rand_08::rngs::OsRng;
    let mut msg_builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    if let Some(subkey) = encryption_subkey {
        msg_builder
            .encrypt_to_key(&mut rng, subkey)
            .map_err(|e| crypto_error!("failed to encrypt to subkey: {e}"))?;
    } else {
        // Check primary key capability in direct signatures or user binding signatures
        let is_primary_enc = public
            .details
            .direct_signatures
            .iter()
            .chain(public.details.users.iter().flat_map(|u| &u.signatures))
            .any(|sig| {
                let kf: KeyFlags = sig.key_flags();
                kf.encrypt_comms() || kf.encrypt_storage()
            });
        if is_primary_enc {
            msg_builder
                .encrypt_to_key(&mut rng, &public.primary_key)
                .map_err(|e| crypto_error!("failed to encrypt to primary key: {e}"))?;
        } else {
            crypto_bail!("OpenPGP certificate has no encryption-capable key");
        }
    }

    let bytes = msg_builder
        .to_vec(rng)
        .map_err(|e| crypto_error!("failed to serialize encrypted message: {e}"))?;

    Ok(bytes)
}

/// Accepts binary or armored message. Errors if the key is public-only or passphrase-protected.
pub fn openpgp_decrypt(
    armored_secret: &[u8],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let secret = parse_secret_key(armored_secret)?;

    // Check if primary key or any secret subkey is passphrase-protected
    if secret.primary_key.secret_params().is_encrypted()
        || secret
            .secret_subkeys
            .iter()
            .any(|s| s.key.secret_params().is_encrypted())
    {
        crypto_bail!("OpenPGP secret key is passphrase-protected; Decrypt/Sign are not supported");
    }

    // Try parsing message as binary first, then armor
    let parsed_msg = if let Ok(m) = Message::from_bytes(std::io::Cursor::new(message)) {
        m
    } else if let Ok((m, _)) =
        Message::from_armor(std::io::BufReader::new(std::io::Cursor::new(message)))
    {
        m
    } else {
        crypto_bail!("failed to parse OpenPGP message");
    };

    let decrypted_msg = parsed_msg
        .decrypt(&Password::empty(), &secret)
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.to_lowercase().contains("password")
                || err_str.to_lowercase().contains("passphrase")
            {
                crypto_error!(
                    "OpenPGP secret key is passphrase-protected; Decrypt/Sign are not supported"
                )
            } else {
                crypto_error!("failed to decrypt OpenPGP message: {e}")
            }
        })?;

    let mut decrypted_msg = decrypted_msg
        .decompress()
        .map_err(|e| crypto_error!("failed to decompress OpenPGP message: {e}"))?;

    let ptx = decrypted_msg
        .as_data_vec()
        .map_err(|e| crypto_error!("failed to read decrypted plaintext: {e}"))?;

    Ok(Zeroizing::new(ptx))
}

/// Binary detached signature over `data`, made with the primary key.
pub fn openpgp_sign_detached(armored_secret: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret = parse_secret_key(armored_secret)?;
    if secret.primary_key.secret_params().is_encrypted() {
        crypto_bail!("OpenPGP secret key is passphrase-protected; Decrypt/Sign are not supported");
    }

    let sig = DetachedSignature::sign_binary_data(
        rand_08::rngs::OsRng,
        &secret.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        data,
    )
    .map_err(|e| crypto_error!("failed to create detached signature: {e}"))?;

    let mut out = Vec::new();
    sig.to_writer(&mut out)
        .map_err(|e| crypto_error!("failed to serialize signature: {e}"))?;

    Ok(out)
}

/// Accepts binary or armored signature. Resolves the signing component key by the
/// signature's issuer key-ID/fingerprint, trying the primary key and every signing-capable
/// subkey, so signatures produced by `GnuPG` (which may use a signing subkey) verify.
/// Returns `Ok(false)` on cryptographic mismatch; `Err` only on malformed input.
pub fn openpgp_verify_detached(
    armored_cert: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let (secret_opt, public_opt) = parse_secret_or_public(armored_cert)?;
    let public = match (secret_opt, public_opt) {
        (Some(sec), _) => sec.to_public_key(),
        (None, Some(pubk)) => pubk,
        (None, None) => crypto_bail!("no OpenPGP key parsed"),
    };

    let sig = if let Ok(s) = DetachedSignature::from_bytes(std::io::Cursor::new(signature)) {
        s
    } else if let Ok((s, _)) = DetachedSignature::from_armor_single(std::io::Cursor::new(signature))
    {
        s
    } else {
        crypto_bail!("failed to parse OpenPGP detached signature");
    };

    // Try primary key first
    if sig.verify(&public.primary_key, data).is_ok() {
        return Ok(true);
    }

    // Try every public subkey
    for subkey in &public.public_subkeys {
        if sig.verify(&subkey.key, data).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openpgp_rsa_keygen_roundtrip() {
        let user_id = "Alice <alice@example.com>";
        let secret_armored =
            generate_openpgp_secret_key(PgpKeyProfile::Rsa { bits: 2048 }, user_id).unwrap();

        assert!(secret_armored.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        let public_armored = openpgp_public_from_secret(&secret_armored).unwrap();
        assert!(public_armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        let (norm_armored, is_secret) = openpgp_normalize(&secret_armored).unwrap();
        assert!(is_secret);
        assert!(norm_armored.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        let (meta_alg, meta_len, meta_ver) = openpgp_key_metadata(&secret_armored).unwrap();
        assert_eq!(meta_alg, Some(CryptographicAlgorithm::RSA));
        assert_eq!(meta_len, Some(2048));
        assert_eq!(meta_ver, 4);

        let plaintext = b"Hello OpenPGP RSA encryption test!";
        let ciphertext = openpgp_encrypt(&public_armored, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = openpgp_decrypt(&secret_armored, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        let signature = openpgp_sign_detached(&secret_armored, plaintext).unwrap();
        let valid = openpgp_verify_detached(&public_armored, plaintext, &signature).unwrap();
        assert!(valid);

        let mut tampered = plaintext.to_vec();
        if let Some(first) = tampered.first_mut() {
            *first ^= 0xFF;
        }
        let invalid = openpgp_verify_detached(&public_armored, &tampered, &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_openpgp_ed25519_keygen_roundtrip() {
        let user_id = "Bob <bob@example.com>";
        let secret_armored = generate_openpgp_secret_key(PgpKeyProfile::Ed25519, user_id).unwrap();

        assert!(secret_armored.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));

        let public_armored = openpgp_public_from_secret(&secret_armored).unwrap();
        assert!(public_armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        let (norm_armored, is_secret) = openpgp_normalize(&public_armored).unwrap();
        assert!(!is_secret);
        assert!(norm_armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        let (meta_alg, meta_len, meta_ver) = openpgp_key_metadata(&public_armored).unwrap();
        assert_eq!(meta_alg, Some(CryptographicAlgorithm::Ed25519));
        assert_eq!(meta_len, Some(256));
        assert_eq!(meta_ver, 4);

        let plaintext = b"Hello OpenPGP Ed25519/Curve25519 encryption test!";
        let ciphertext = openpgp_encrypt(&public_armored, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = openpgp_decrypt(&secret_armored, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        let signature = openpgp_sign_detached(&secret_armored, plaintext).unwrap();
        let valid = openpgp_verify_detached(&public_armored, plaintext, &signature).unwrap();
        assert!(valid);
        let mut tampered = plaintext.to_vec();
        if let Some(first) = tampered.first_mut() {
            *first ^= 0xFF;
        }
        let invalid = openpgp_verify_detached(&public_armored, &tampered, &signature).unwrap();
        assert!(!invalid);
    }
}

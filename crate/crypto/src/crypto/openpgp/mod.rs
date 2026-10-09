use cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client_utils::openpgp_format::parse_secret_or_public;
use openssl::bn::{BigNum, BigNumContext};
use pgp::{
    composed::{
        ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, KeyType, Message,
        MessageBuilder, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::KeyFlags,
    ser::Serialize,
    types::{KeyDetails, Mpi, Password, PlainSecretParams, PublicParams, SecretParams},
};
use rand_08::SeedableRng;
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

fn normalize_rsa_secret_params(
    public_key: &impl KeyDetails,
    secret_params: &SecretParams,
) -> Result<Option<SecretParams>, CryptoError> {
    let (PublicParams::RSA(_), SecretParams::Plain(PlainSecretParams::RSA(secret))) =
        (public_key.public_params(), secret_params)
    else {
        return Ok(None);
    };

    let (d_bytes, p_bytes, q_bytes, old_u_bytes) = secret.to_bytes();
    let d_bytes = Zeroizing::new(d_bytes);
    let p_bytes = Zeroizing::new(p_bytes);
    let q_bytes = Zeroizing::new(q_bytes);
    let _old_u_bytes = Zeroizing::new(old_u_bytes);
    // RFC 9580 Section 5.5.5.1 requires RSA secret-key factors to be ordered p < q.
    if p_bytes.len() < q_bytes.len()
        || (p_bytes.len() == q_bytes.len() && p_bytes.as_slice() < q_bytes.as_slice())
    {
        return Ok(None);
    }

    let mut normalized_p = BigNum::new_secure()
        .map_err(|e| crypto_error!("failed to allocate normalized RSA prime: {e}"))?;
    normalized_p
        .copy_from_slice(&q_bytes)
        .map_err(|e| crypto_error!("failed to load normalized RSA prime: {e}"))?;
    let mut normalized_q = BigNum::new_secure()
        .map_err(|e| crypto_error!("failed to allocate normalized RSA prime: {e}"))?;
    normalized_q
        .copy_from_slice(&p_bytes)
        .map_err(|e| crypto_error!("failed to load normalized RSA prime: {e}"))?;
    let mut inverse = BigNum::new_secure()
        .map_err(|e| crypto_error!("failed to allocate RSA CRT coefficient: {e}"))?;
    let mut context = BigNumContext::new_secure()
        .map_err(|e| crypto_error!("failed to allocate RSA BIGNUM context: {e}"))?;
    inverse
        .mod_inverse(&normalized_p, &normalized_q, &mut context)
        .map_err(|e| crypto_error!("failed to calculate RSA CRT coefficient: {e}"))?;
    let inverse_bytes = Zeroizing::new(inverse.to_vec());

    let mut encoded_secret = Zeroizing::new(vec![0_u8]);
    for value in [
        d_bytes.as_slice(),
        q_bytes.as_slice(),
        p_bytes.as_slice(),
        inverse_bytes.as_slice(),
    ] {
        Mpi::from_slice(value)
            .to_writer(&mut *encoded_secret)
            .map_err(|e| crypto_error!("failed to encode reordered RSA secret MPI: {e}"))?;
    }
    let checksum = encoded_secret
        .iter()
        .skip(1)
        .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
    encoded_secret.extend_from_slice(&checksum.to_be_bytes());

    let normalized = SecretParams::from_slice(
        &encoded_secret,
        public_key.version(),
        public_key.algorithm(),
        public_key.public_params(),
    )
    .map_err(|e| crypto_error!("failed to rebuild OpenPGP RSA secret key: {e}"))?;

    Ok(Some(normalized))
}

// The PGP crate uses rand 0.8 traits; seed its RNG stream from OpenSSL's CSPRNG.
fn openssl_seeded_rng() -> Result<rand_08::rngs::StdRng, CryptoError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    openssl::rand::rand_bytes(&mut seed[..])
        .map_err(|e| crypto_error!("failed to seed OpenPGP RNG with OpenSSL: {e}"))?;

    Ok(rand_08::rngs::StdRng::from_seed(std::mem::take(&mut *seed)))
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

    let mut signed_secret = params
        .generate(openssl_seeded_rng()?)
        .map_err(|e| crypto_error!("failed to generate OpenPGP key: {e}"))?;

    // Rebuilding private packets leaves the public key components and signatures unchanged.
    if let Some(secret_params) = normalize_rsa_secret_params(
        signed_secret.primary_key.public_key(),
        signed_secret.primary_key.secret_params(),
    )? {
        let public_key = signed_secret.primary_key.public_key().clone();
        signed_secret.primary_key = pgp::packet::SecretKey::new(public_key, secret_params)
            .map_err(|e| crypto_error!("failed to normalize RSA primary key packet: {e}"))?;
    }
    for subkey in &mut signed_secret.secret_subkeys {
        if let Some(secret_params) =
            normalize_rsa_secret_params(subkey.key.public_key(), subkey.key.secret_params())?
        {
            let public_key = subkey.key.public_key().clone();
            subkey.key = pgp::packet::SecretSubkey::new(public_key, secret_params)
                .map_err(|e| crypto_error!("failed to normalize RSA subkey packet: {e}"))?;
        }
    }

    let armored = signed_secret
        .to_armored_bytes(ArmorOptions::default())
        .map_err(|e| crypto_error!("failed to armor secret key: {e}"))?;

    Ok(Zeroizing::new(armored))
}

/// Accepts armored or binary, secret or public input.
/// Returns `(armored_bytes, is_secret_key)`.
pub fn openpgp_normalize(input: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool), CryptoError> {
    let (secret, public) = parse_secret_or_public(input)?;
    match (secret, public) {
        (Some(secret), None) => {
            let armored = secret
                .to_armored_bytes(ArmorOptions::default())
                .map_err(|e| crypto_error!("failed to armor secret key: {e}"))?;
            Ok((Zeroizing::new(armored), true))
        }
        (None, Some(public)) => {
            let armored = public
                .to_armored_bytes(ArmorOptions::default())
                .map_err(|e| crypto_error!("failed to armor public key: {e}"))?;
            Ok((Zeroizing::new(armored), false))
        }
        _ => crypto_bail!("input is not a valid OpenPGP transferable secret or public key"),
    }
}

/// Serialize an armored or binary `OpenPGP` transferable key as binary packets.
///
/// # Errors
///
/// Returns an error if the input is not a valid transferable secret or public key
/// or if the key cannot be serialized.
pub fn openpgp_key_to_binary(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    Ok(cosmian_kms_client_utils::openpgp_format::openpgp_key_to_binary(input)?)
}

/// Helper to parse a secret key specifically from armored or binary bytes.
fn parse_secret_key(input: &[u8]) -> Result<SignedSecretKey, CryptoError> {
    let (secret, public) = parse_secret_or_public(input)?;
    match (secret, public) {
        (Some(secret), None) => Ok(secret),
        _ => crypto_bail!("input is not a valid OpenPGP secret key"),
    }
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

    let mut rng = openssl_seeded_rng()?;
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
        openssl_seeded_rng()?,
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
    fn check_rsa_prime_order(secret_params: &pgp::types::SecretParams) -> Result<(), &'static str> {
        let pgp::types::SecretParams::Plain(pgp::types::PlainSecretParams::RSA(rsa)) =
            secret_params
        else {
            return Err("generated RSA key packet must contain plain RSA secret parameters");
        };
        let (_, p, q, _) = rsa.to_bytes();
        if p >= q {
            return Err("OpenPGP RSA secret parameters require p < q");
        }
        Ok(())
    }

    #[test]
    fn test_rsa_prime_order_check_rejects_non_rsa_secret_params() {
        let user_id = "Alice <alice@example.com>";
        let secret_armored = generate_openpgp_secret_key(PgpKeyProfile::Ed25519, user_id).unwrap();
        let parsed_secret = pgp::composed::SignedSecretKey::from_armor_single(
            std::io::Cursor::new(secret_armored.as_slice()),
        )
        .unwrap()
        .0;

        assert!(check_rsa_prime_order(parsed_secret.primary_key.secret_params()).is_err());
    }

    #[test]
    fn test_openpgp_rsa_keygen_roundtrip() {
        let user_id = "Alice <alice@example.com>";
        let secret_armored =
            generate_openpgp_secret_key(PgpKeyProfile::Rsa { bits: 2048 }, user_id).unwrap();

        let parsed_secret = pgp::composed::SignedSecretKey::from_armor_single(
            std::io::Cursor::new(secret_armored.as_slice()),
        )
        .unwrap()
        .0;
        assert_eq!(
            check_rsa_prime_order(parsed_secret.primary_key.secret_params()),
            Ok(())
        );
        for subkey in &parsed_secret.secret_subkeys {
            assert_eq!(check_rsa_prime_order(subkey.key.secret_params()), Ok(()));
        }
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

    #[test]
    fn test_openpgp_binary_key_encoding() {
        let secret_armored = generate_openpgp_secret_key(
            PgpKeyProfile::Ed25519,
            "Binary Format Test <binary@example.com>",
        )
        .unwrap();
        let secret_binary = openpgp_key_to_binary(&secret_armored).unwrap();
        assert!(!secret_binary.starts_with(b"-----BEGIN PGP "));
        assert!(openpgp_normalize(&secret_binary).unwrap().1);

        let public_armored = openpgp_public_from_secret(&secret_armored).unwrap();
        let public_binary = openpgp_key_to_binary(&public_armored).unwrap();
        assert!(!public_binary.starts_with(b"-----BEGIN PGP "));
        let (normalized_public, is_secret) = openpgp_normalize(&public_binary).unwrap();
        assert!(!is_secret);
        assert!(normalized_public.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        let error = openpgp_key_to_binary(b"not an OpenPGP key").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("failed to parse OpenPGP certificate")
        );
    }
    #[test]
    fn test_openpgp_v6_key_encrypt_decrypt_roundtrip() {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .version(pgp::types::KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id("V6 OpenPGP <v6@example.com>".to_owned())
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .version(pgp::types::KeyVersion::V6)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            ]);
        let params = key_params.build().unwrap();
        let secret = params.generate(openssl_seeded_rng().unwrap()).unwrap();
        let secret_armored = secret.to_armored_bytes(ArmorOptions::default()).unwrap();
        let public_armored = secret
            .to_public_key()
            .to_armored_bytes(ArmorOptions::default())
            .unwrap();

        let (algorithm, _, version) = openpgp_key_metadata(&secret_armored).unwrap();
        assert_eq!(algorithm, Some(CryptographicAlgorithm::Ed25519));
        assert_eq!(version, 6);

        let plaintext = b"Hello OpenPGP v6 encryption test!";
        let ciphertext = openpgp_encrypt(&public_armored, plaintext).unwrap();
        let decrypted = openpgp_decrypt(&secret_armored, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }
}

use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

use cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client_utils::openpgp_format::parse_secret_or_public;
use openssl::{
    bn::{BigNum, BigNumContext, BigNumRef},
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use pgp::{
    composed::{
        ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, Esk,
        KeyDetails as CertificateDetails, KeyType, Message, MessageBuilder, PlainSessionKey,
        SecretKeyParamsBuilder, SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
        SignedSecretSubKey, SubkeyParamsBuilder,
    },
    crypto::{
        ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{
        Features, KeyFlags, PubKeyInner, PublicKey, PublicSubkey, SecretKey, SecretSubkey,
        Signature, SignatureType, UserId,
    },
    ser::Serialize,
    types::{
        DecryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Mpi,
        PacketHeaderVersion, Password, PkeskBytes, PkeskVersion, PlainSecretParams, PublicParams,
        RsaPublicParams, SecretParams, SignatureBytes, SigningKey, Tag, Timestamp,
    },
};
use zeroize::Zeroizing;

use crate::{
    crypto::{KmsRng, rng::SeededCsRng, rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_decrypt},
    crypto_bail, crypto_error,
    error::CryptoError,
};

/// Upper bound on the decrypted, decompressed plaintext of an `OpenPGP` message. Equal to the
/// server's 64 MiB request-body cap, so a compressed message cannot expand beyond what a client
/// could have sent uncompressed.
pub const MAX_OPENPGP_PLAINTEXT_LEN: u64 = 64 * 1024 * 1024;

/// `OpenPGP` key profile to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgpKeyProfile {
    /// RSA primary (Sign+Certify) + RSA subkey (Encrypt); `bits` ∈ {2048, 3072, 4096}.
    Rsa { bits: u32 },
    /// `Ed25519Legacy` primary (Sign+Certify) + ECDH Curve25519 subkey (Encrypt).
    Ed25519,
}

// The PGP crate requires an infallible rand 0.8 `CryptoRng` (rand_core 0.6) and offers no
// direct-seed entry point, so its RNG stream is `KmsRng::seeded_csrng`, overwritten when dropped.
fn openssl_seeded_rng(rng: &KmsRng) -> Result<SeededCsRng, CryptoError> {
    rng.seeded_csrng()
        .map_err(|e| crypto_error!("failed to seed OpenPGP RNG with KmsRng: {e}"))
}

fn secure_bignum(bytes: &[u8]) -> Result<BigNum, CryptoError> {
    let mut value = BigNum::new_secure()?;
    value.copy_from_slice(bytes)?;
    Ok(value)
}

/// RSA CRT exponent `d mod (prime - 1)`.
fn crt_exponent(
    d: &BigNumRef,
    prime: &BigNumRef,
    context: &mut BigNumContext,
) -> Result<BigNum, CryptoError> {
    let one = BigNum::from_u32(1)?;
    let mut prime_minus_one = BigNum::new_secure()?;
    prime_minus_one.checked_sub(prime, &one)?;
    let mut exponent = BigNum::new_secure()?;
    exponent.nnmod(d, &prime_minus_one, context)?;
    Ok(exponent)
}

/// `OpenPGP` public and unencrypted secret RSA parameters of an OpenSSL key.
fn openpgp_rsa_params(rsa: &Rsa<Private>) -> Result<(PublicParams, SecretParams), CryptoError> {
    let (Some(first), Some(second)) = (rsa.p(), rsa.q()) else {
        crypto_bail!("RSA key has no prime factors");
    };
    // RFC 9580 Section 5.5.5.1 requires p < q and u = p^-1 mod q.
    let (p, q) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    let mut context = BigNumContext::new_secure()?;
    let mut u = BigNum::new_secure()?;
    u.mod_inverse(p, q, &mut context)?;

    let mut public_bytes = Vec::new();
    for value in [rsa.n(), rsa.e()] {
        Mpi::from_slice(&value.to_vec())
            .to_writer(&mut public_bytes)
            .map_err(|e| crypto_error!("failed to encode RSA public MPI: {e}"))?;
    }
    let public_params = PublicParams::RSA(
        RsaPublicParams::try_from_reader(public_bytes.as_slice())
            .map_err(|e| crypto_error!("failed to build OpenPGP RSA public key: {e}"))?,
    );

    // S2K usage 0 (unencrypted), MPIs d, p, q, u, then their 16-bit checksum.
    let mut encoded_secret = Zeroizing::new(vec![0_u8]);
    for value in [rsa.d(), p, q, &*u] {
        let bytes = Zeroizing::new(value.to_vec());
        Mpi::from_slice(&bytes)
            .to_writer(&mut *encoded_secret)
            .map_err(|e| crypto_error!("failed to encode RSA secret MPI: {e}"))?;
    }
    let checksum = encoded_secret
        .iter()
        .skip(1)
        .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
    encoded_secret.extend_from_slice(&checksum.to_be_bytes());

    let secret_params = SecretParams::from_slice(
        &encoded_secret,
        KeyVersion::V4,
        PublicKeyAlgorithm::RSA,
        &public_params,
    )
    .map_err(|e| crypto_error!("failed to build OpenPGP RSA secret key: {e}"))?;
    Ok((public_params, secret_params))
}

/// OpenSSL key for an unlocked `OpenPGP` RSA key packet; `None` for other algorithms.
///
/// Every RSA private-key operation goes through OpenSSL (blinded, constant time, implicit
/// rejection), never through the `rsa` crate embedded in rPGP (RUSTSEC-2023-0071, Marvin).
fn openssl_rsa_private_key(
    key: &impl KeyDetails,
    secret_params: &SecretParams,
) -> Result<Option<PKey<Private>>, CryptoError> {
    let (PublicParams::RSA(public), SecretParams::Plain(PlainSecretParams::RSA(secret))) =
        (key.public_params(), secret_params)
    else {
        return Ok(None);
    };

    let mut public_bytes = Vec::new();
    public
        .to_writer(&mut public_bytes)
        .map_err(|e| crypto_error!("failed to serialize RSA public params: {e}"))?;
    let mut reader = public_bytes.as_slice();
    let modulus = Mpi::try_from_reader(&mut reader)
        .map_err(|e| crypto_error!("invalid OpenPGP RSA modulus: {e}"))?;
    let public_exponent = Mpi::try_from_reader(&mut reader)
        .map_err(|e| crypto_error!("invalid OpenPGP RSA public exponent: {e}"))?;

    let (d, p, q, u) = secret.to_bytes();
    let _u = Zeroizing::new(u);
    let d = secure_bignum(&Zeroizing::new(d))?;
    let p = secure_bignum(&Zeroizing::new(p))?;
    let q = secure_bignum(&Zeroizing::new(q))?;
    let mut context = BigNumContext::new_secure()?;
    let dmp1 = crt_exponent(&d, &p, &mut context)?;
    let dmq1 = crt_exponent(&d, &q, &mut context)?;
    let mut iqmp = BigNum::new_secure()?;
    iqmp.mod_inverse(&q, &p, &mut context)?;

    let rsa = Rsa::from_private_components(
        BigNum::from_slice(modulus.as_ref())?,
        BigNum::from_slice(public_exponent.as_ref())?,
        d,
        p,
        q,
        dmp1,
        dmq1,
        iqmp,
    )?;
    Ok(Some(PKey::from_rsa(rsa)?))
}

/// RSA signing key whose metadata comes from rPGP and whose private-key operation is OpenSSL's.
#[derive(Debug)]
struct OpensslRsaSigner<'a, K> {
    key: &'a K,
    private_key: PKey<Private>,
}

impl<K: KeyDetails> KeyDetails for OpensslRsaSigner<'_, K> {
    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.key.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }
}

impl<K: KeyDetails> SigningKey for OpensslRsaSigner<'_, K> {
    fn sign(
        &self,
        _key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        let md = match hash {
            HashAlgorithm::Sha256 => Md::sha256(),
            HashAlgorithm::Sha384 => Md::sha384(),
            HashAlgorithm::Sha512 => Md::sha512(),
            other => {
                return Err(format!("unsupported OpenPGP RSA signature hash: {other:?}").into());
            }
        };
        let signature = openssl_rsa_sign(&self.private_key, md, data)
            .map_err(|e| pgp::errors::Error::from(format!("RSA signature failed: {e}")))?;
        Ok(SignatureBytes::Mpis(vec![Mpi::from_slice(&signature)]))
    }

    fn hash_alg(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

/// RSASSA-PKCS1-v1_5 signature of a pre-computed `digest`.
fn openssl_rsa_sign(
    private_key: &PKey<Private>,
    md: &openssl::md::MdRef,
    digest: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut ctx = PkeyCtx::new(private_key)?;
    ctx.sign_init()?;
    ctx.set_signature_md(md)?;
    ctx.set_rsa_padding(Padding::PKCS1)?;
    let mut signature = Vec::new();
    ctx.sign_to_vec(digest, &mut signature)?;
    Ok(signature)
}

/// Session key from a decrypted PKESK payload: `[algorithm] || key || checksum`
/// (RFC 9580 Sections 5.1.3 and 5.1.4; the algorithm octet only exists in v3 PKESKs).
fn decode_session_key(decrypted: &[u8], typ: EskType) -> Result<PlainSessionKey, CryptoError> {
    let (sym_alg, key_and_checksum) = match typ {
        EskType::V3_4 => {
            let Some((&algorithm, rest)) = decrypted.split_first() else {
                crypto_bail!("invalid OpenPGP session key");
            };
            let sym_alg = SymmetricKeyAlgorithm::from(algorithm);
            if sym_alg == SymmetricKeyAlgorithm::Plaintext
                || Some(rest.len()) != sym_alg.key_size().checked_add(2)
            {
                crypto_bail!("invalid OpenPGP session key");
            }
            (Some(sym_alg), rest)
        }
        EskType::V6 => (None, decrypted),
    };
    let Some((key, checksum)) =
        key_and_checksum.split_at_checked(key_and_checksum.len().saturating_sub(2))
    else {
        crypto_bail!("invalid OpenPGP session key");
    };
    let sum = key
        .iter()
        .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
    if checksum != sum.to_be_bytes() {
        crypto_bail!("invalid OpenPGP session key");
    }
    Ok(sym_alg.map_or_else(
        || PlainSessionKey::V6 { key: key.into() },
        |sym_alg| PlainSessionKey::V3_4 {
            sym_alg,
            key: key.into(),
        },
    ))
}

/// Decrypt one PKESK with one secret key component.
fn component_session_key<K: DecryptionKey>(
    key: &K,
    secret_params: &SecretParams,
    values: &PkeskBytes,
    typ: EskType,
) -> Result<PlainSessionKey, CryptoError> {
    match (openssl_rsa_private_key(key, secret_params)?, values) {
        (Some(private_key), PkeskBytes::Rsa { mpi }) => {
            // The MPI drops leading zero octets; restore the modulus-length ciphertext.
            let modulus_len = private_key.size();
            let mut ciphertext = vec![0_u8; modulus_len];
            let offset = modulus_len
                .checked_sub(mpi.len())
                .ok_or_else(|| crypto_error!("RSA session key ciphertext exceeds the modulus"))?;
            ciphertext
                .get_mut(offset..)
                .ok_or_else(|| crypto_error!("RSA session key ciphertext exceeds the modulus"))?
                .copy_from_slice(mpi.as_ref());
            // OpenSSL >= 3.2 applies implicit rejection to PKCS#1 v1.5 decryption: invalid
            // padding yields a pseudo-random payload that then fails the checksum below.
            decode_session_key(&ckm_rsa_pkcs_decrypt(&private_key, &ciphertext)?, typ)
        }
        (Some(_), _) => crypto_bail!("RSA key cannot decrypt a non-RSA session key"),
        (None, _) => DecryptionKey::decrypt(key, &Password::empty(), values, typ)
            .and_then(|session_key| session_key)
            .map_err(|e| crypto_error!("failed to decrypt OpenPGP session key: {e}")),
    }
}

/// Session key of the first PKESK addressed to a component of `secret` that decrypts it.
fn decrypt_session_key(
    secret: &SignedSecretKey,
    esks: &[Esk],
) -> Result<PlainSessionKey, CryptoError> {
    let primary = &secret.primary_key;
    for esk in esks {
        let Esk::PublicKeyEncryptedSessionKey(pkesk) = esk else {
            continue;
        };
        let typ = match pkesk.version() {
            PkeskVersion::V3 => EskType::V3_4,
            PkeskVersion::V6 => EskType::V6,
            PkeskVersion::Other(_) => continue,
        };
        let Ok(values) = pkesk.values() else {
            continue;
        };
        if pkesk.match_identity(primary.public_key())
            && let Ok(session_key) =
                component_session_key(primary, primary.secret_params(), values, typ)
        {
            return Ok(session_key);
        }
        for subkey in &secret.secret_subkeys {
            if pkesk.match_identity(subkey.key.public_key())
                && let Ok(session_key) =
                    component_session_key(&subkey.key, subkey.key.secret_params(), values, typ)
            {
                return Ok(session_key);
            }
        }
    }
    crypto_bail!("failed to decrypt OpenPGP message: no matching secret key")
}

/// Whether a component created at `created_at` is past the Key Expiration Time of its
/// self-signature `sig` (RFC 9580 Section 5.2.3.13: absent or zero means it never expires).
fn is_expired(created_at: Timestamp, sig: &Signature) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    sig.key_expiration_time().is_some_and(|validity| {
        validity.as_secs() != 0
            && u64::from(created_at.as_secs()) + u64::from(validity.as_secs()) <= now
    })
}

/// Subkeys of `public` that are usable now, paired with the Key Flags of their newest Subkey
/// Binding signature that verifies against the primary key (RFC 9580 Section 10.1.3). A binding
/// that flags the subkey for signing only counts if its embedded Primary Key Binding signature
/// (type 0x19), made by the subkey, also verifies (RFC 9580 Section 5.2.1.8). A subkey is skipped
/// when the primary key revoked it (type 0x28, RFC 9580 Section 5.2.1.12) or when that newest
/// binding's Key Expiration Time is past (RFC 9580 Section 5.2.3.13).
fn bound_subkeys(
    public: &SignedPublicKey,
) -> impl Iterator<Item = (&SignedPublicSubKey, KeyFlags)> {
    let primary = &public.primary_key;
    public.public_subkeys.iter().filter_map(move |subkey| {
        let signed_by_primary = |sig: &Signature, typ: SignatureType| {
            sig.typ() == Some(typ) && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
        };
        if subkey
            .signatures
            .iter()
            .any(|sig| signed_by_primary(sig, SignatureType::SubkeyRevocation))
        {
            return None;
        }
        let binding = subkey
            .signatures
            .iter()
            .filter(|sig| {
                signed_by_primary(sig, SignatureType::SubkeyBinding)
                    && (!sig.key_flags().sign()
                        || sig.embedded_signature().is_some_and(|back_signature| {
                            back_signature
                                .verify_primary_key_binding(&subkey.key, primary)
                                .is_ok()
                        }))
            })
            .max_by_key(|sig| sig.created())?;
        (!is_expired(subkey.key.created_at(), binding)).then(|| (subkey, binding.key_flags()))
    })
}

/// Direct-key and User ID self-signatures over the primary key that verify against it.
fn primary_self_signatures(public: &SignedPublicKey) -> impl Iterator<Item = &Signature> {
    let primary = &public.primary_key;
    let direct = public.details.direct_signatures.iter().filter(move |sig| {
        sig.typ() == Some(SignatureType::Key) && sig.verify_key(primary).is_ok()
    });
    let certifications = public.details.users.iter().flat_map(move |user| {
        user.signatures.iter().filter(move |sig| {
            sig.typ() != Some(SignatureType::CertRevocation)
                && sig
                    .verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
        })
    });
    direct.chain(certifications)
}

/// Errors if the primary key revoked itself (type 0x20, RFC 9580 Section 5.2.1.11) or is past the
/// Key Expiration Time of its newest self-signature (RFC 9580 Section 5.2.3.13): no component of
/// such a certificate may be used.
fn check_certificate_valid(public: &SignedPublicKey) -> Result<(), CryptoError> {
    let primary = &public.primary_key;
    if public.details.revocation_signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::KeyRevocation) && sig.verify_key(primary).is_ok()
    }) {
        crypto_bail!("OpenPGP certificate is revoked");
    }
    if primary_self_signatures(public)
        .max_by_key(|sig| sig.created())
        .is_some_and(|sig| is_expired(primary.created_at(), sig))
    {
        crypto_bail!("OpenPGP certificate is expired");
    }
    Ok(())
}

/// Whether a self-signature that verifies against the primary key flags it for encryption.
fn primary_key_can_encrypt(public: &SignedPublicKey) -> bool {
    primary_self_signatures(public).any(|sig| {
        let flags = sig.key_flags();
        flags.encrypt_comms() || flags.encrypt_storage()
    })
}

/// RSA primary (Sign+Certify) and RSA subkey (Encrypt), generated and self-signed by OpenSSL.
fn generate_rsa_secret_key(
    rng: &KmsRng,
    bits: u32,
    user_id: &str,
) -> Result<SignedSecretKey, CryptoError> {
    let mut rng = openssl_seeded_rng(rng)?;
    let created_at = Timestamp::now();

    let primary_rsa = Rsa::generate(bits)?;
    let (public_params, secret_params) = openpgp_rsa_params(&primary_rsa)?;
    let primary_public = PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::RSA,
        created_at,
        None,
        public_params,
    )
    .and_then(PublicKey::from_inner)
    .map_err(|e| crypto_error!("failed to build RSA primary key packet: {e}"))?;
    let primary_key = SecretKey::new(primary_public, secret_params)
        .map_err(|e| crypto_error!("failed to build RSA primary key packet: {e}"))?;

    let (public_params, secret_params) = openpgp_rsa_params(&Rsa::generate(bits)?)?;
    let subkey_public = PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::RSA,
        created_at,
        None,
        public_params,
    )
    .and_then(PublicSubkey::from_inner)
    .map_err(|e| crypto_error!("failed to build RSA subkey packet: {e}"))?;
    let subkey = SecretSubkey::new(subkey_public, secret_params)
        .map_err(|e| crypto_error!("failed to build RSA subkey packet: {e}"))?;

    let mut primary_flags = KeyFlags::default();
    primary_flags.set_sign(true);
    primary_flags.set_certify(true);
    let mut subkey_flags = KeyFlags::default();
    subkey_flags.set_encrypt_comms(true);
    subkey_flags.set_encrypt_storage(true);
    let mut features = Features::default();
    features.set_seipd_v1(true);
    let user_id = UserId::from_str(PacketHeaderVersion::default(), user_id)
        .map_err(|e| crypto_error!("invalid OpenPGP user ID: {e}"))?;

    let signer = OpensslRsaSigner {
        key: primary_key.public_key(),
        private_key: PKey::from_rsa(primary_rsa)?,
    };
    let details = CertificateDetails::new(
        Some(user_id),
        Vec::new(),
        Vec::new(),
        primary_flags,
        features,
        std::iter::empty().collect(),
        std::iter::empty().collect(),
        std::iter::empty().collect(),
        std::iter::empty().collect(),
    )
    .sign(
        &mut rng,
        &signer,
        primary_key.public_key(),
        &Password::empty(),
    )
    .map_err(|e| crypto_error!("failed to self-sign RSA primary key: {e}"))?;
    let binding = subkey
        .sign(
            &mut rng,
            &signer,
            primary_key.public_key(),
            &Password::empty(),
            subkey_flags,
            None,
        )
        .map_err(|e| crypto_error!("failed to bind RSA subkey: {e}"))?;
    drop(signer);

    Ok(SignedSecretKey::new(
        primary_key,
        details,
        Vec::new(),
        vec![SignedSecretSubKey::new(subkey, vec![binding])],
    ))
}

/// Armored Transferable Secret Key, RFC 9580 v4.
pub fn generate_openpgp_secret_key(
    rng: &KmsRng,
    profile: PgpKeyProfile,
    user_id: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let signed_secret = match profile {
        PgpKeyProfile::Rsa { bits } => {
            if bits < 2048 {
                crypto_bail!("RSA key size must be at least 2048 bits");
            }
            generate_rsa_secret_key(rng, bits, user_id)?
        }
        PgpKeyProfile::Ed25519 => {
            let mut builder = SecretKeyParamsBuilder::default();
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
            builder
                .build()
                .map_err(|e| crypto_error!("failed to build secret key params: {e}"))?
                .generate(openssl_seeded_rng(rng)?)
                .map_err(|e| crypto_error!("failed to generate OpenPGP key: {e}"))?
        }
    };

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
/// Accepts a secret or public armored certificate. Only subkeys bound to the primary key by a
/// verified binding signature, neither revoked nor expired, are used; errors if the certificate
/// is revoked or expired, or has no such encryption key.
pub fn openpgp_encrypt(
    rng: &KmsRng,
    armored_cert: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (secret_opt, public_opt) = parse_secret_or_public(armored_cert)?;
    let public = match (secret_opt, public_opt) {
        (Some(sec), _) => sec.to_public_key(),
        (None, Some(pubk)) => pubk,
        (None, None) => crypto_bail!("no OpenPGP key parsed"),
    };
    check_certificate_valid(&public)?;

    // Keep the signed subkey wrapper as the recipient. Its key identity and
    // binding signature must remain coupled to the public-key material used
    // in the PKESK packet.
    let encryption_subkey = bound_subkeys(&public)
        .find(|(_, flags)| flags.encrypt_comms() || flags.encrypt_storage())
        .map(|(subkey, _)| subkey);

    let mut rng = openssl_seeded_rng(rng)?;
    let mut msg_builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    if let Some(subkey) = encryption_subkey {
        msg_builder
            .encrypt_to_key(&mut rng, subkey)
            .map_err(|e| crypto_error!("failed to encrypt to subkey: {e}"))?;
    } else if primary_key_can_encrypt(&public) {
        msg_builder
            .encrypt_to_key(&mut rng, &public.primary_key)
            .map_err(|e| crypto_error!("failed to encrypt to primary key: {e}"))?;
    } else {
        crypto_bail!("OpenPGP certificate has no encryption-capable key");
    }

    let bytes = msg_builder
        .to_vec(rng)
        .map_err(|e| crypto_error!("failed to serialize encrypted message: {e}"))?;

    Ok(bytes)
}

/// Accepts binary or armored message. Errors if the key is public-only or passphrase-protected,
/// or if the decrypted plaintext exceeds [`MAX_OPENPGP_PLAINTEXT_LEN`].
pub fn openpgp_decrypt(
    armored_secret: &[u8],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    openpgp_decrypt_bounded(armored_secret, message, MAX_OPENPGP_PLAINTEXT_LEN)
}

fn openpgp_decrypt_bounded(
    armored_secret: &[u8],
    message: &[u8],
    max_plaintext_len: u64,
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

    // The session key is recovered here rather than by rPGP so that RSA PKESKs are decrypted
    // by OpenSSL, not by the `rsa` crate.
    let Message::Encrypted { esk, .. } = &parsed_msg else {
        crypto_bail!("OpenPGP message is not encrypted");
    };
    let session_key = decrypt_session_key(&secret, esk)?;
    let decrypted_msg = parsed_msg
        .decrypt_with_session_key(session_key)
        .map_err(|e| crypto_error!("failed to decrypt OpenPGP message: {e}"))?;

    let mut decrypted_msg = decrypted_msg
        .decompress()
        .map_err(|e| crypto_error!("failed to decompress OpenPGP message: {e}"))?;

    // Bound the output: a compressed message could otherwise expand without limit.
    let mut ptx = Zeroizing::new(Vec::new());
    (&mut decrypted_msg)
        .take(max_plaintext_len.saturating_add(1))
        .read_to_end(&mut ptx)
        .map_err(|e| crypto_error!("failed to read decrypted plaintext: {e}"))?;
    if !u64::try_from(ptx.len()).is_ok_and(|len| len <= max_plaintext_len) {
        crypto_bail!("decrypted OpenPGP plaintext exceeds the {max_plaintext_len}-byte limit");
    }

    Ok(ptx)
}

/// Binary detached signature over `data`, made with the primary key.
pub fn openpgp_sign_detached(
    rng: &KmsRng,
    armored_secret: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let secret = parse_secret_key(armored_secret)?;
    if secret.primary_key.secret_params().is_encrypted() {
        crypto_bail!("OpenPGP secret key is passphrase-protected; Decrypt/Sign are not supported");
    }

    let rng = openssl_seeded_rng(rng)?;
    let primary = &secret.primary_key;
    let sig = match openssl_rsa_private_key(primary, primary.secret_params())? {
        Some(private_key) => DetachedSignature::sign_binary_data(
            rng,
            &OpensslRsaSigner {
                key: primary.public_key(),
                private_key,
            },
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        ),
        None => DetachedSignature::sign_binary_data(
            rng,
            primary,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        ),
    }
    .map_err(|e| crypto_error!("failed to create detached signature: {e}"))?;

    let mut out = Vec::new();
    sig.to_writer(&mut out)
        .map_err(|e| crypto_error!("failed to serialize signature: {e}"))?;

    Ok(out)
}

/// Accepts binary or armored signature. Tries the primary key, then every signing subkey whose
/// binding to the primary key verifies (including its back-signature), so signatures produced
/// by `GnuPG` with a signing subkey verify while subkeys grafted onto the certificate do not.
/// Signatures by a revoked or expired certificate or subkey are invalid.
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
    if check_certificate_valid(&public).is_err() {
        return Ok(false);
    }

    let sig = if let Ok(s) = DetachedSignature::from_bytes(std::io::Cursor::new(signature)) {
        s
    } else if let Ok((s, _)) = DetachedSignature::from_armor_single(std::io::Cursor::new(signature))
    {
        s
    } else {
        crypto_bail!("failed to parse OpenPGP detached signature");
    };

    if sig.verify(&public.primary_key, data).is_ok() {
        return Ok(true);
    }

    Ok(bound_subkeys(&public)
        .any(|(subkey, flags)| flags.sign() && sig.verify(&subkey.key, data).is_ok()))
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
        let secret_armored =
            generate_openpgp_secret_key(&KmsRng::new(), PgpKeyProfile::Ed25519, user_id).unwrap();
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
            generate_openpgp_secret_key(&KmsRng::new(), PgpKeyProfile::Rsa { bits: 2048 }, user_id)
                .unwrap();

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
        // The OpenSSL-made self-signatures verify with rPGP.
        parsed_secret.verify_bindings().unwrap();
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
        let ciphertext = openpgp_encrypt(&KmsRng::new(), &public_armored, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = openpgp_decrypt(&secret_armored, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        let signature = openpgp_sign_detached(&KmsRng::new(), &secret_armored, plaintext).unwrap();
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
        let secret_armored =
            generate_openpgp_secret_key(&KmsRng::new(), PgpKeyProfile::Ed25519, user_id).unwrap();

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
        let ciphertext = openpgp_encrypt(&KmsRng::new(), &public_armored, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = openpgp_decrypt(&secret_armored, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        let signature = openpgp_sign_detached(&KmsRng::new(), &secret_armored, plaintext).unwrap();
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
            &KmsRng::new(),
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
        let secret = params
            .generate(openssl_seeded_rng(&KmsRng::new()).unwrap())
            .unwrap();
        let secret_armored = secret.to_armored_bytes(ArmorOptions::default()).unwrap();
        let public_armored = secret
            .to_public_key()
            .to_armored_bytes(ArmorOptions::default())
            .unwrap();

        let (algorithm, _, version) = openpgp_key_metadata(&secret_armored).unwrap();
        assert_eq!(algorithm, Some(CryptographicAlgorithm::Ed25519));
        assert_eq!(version, 6);

        let plaintext = b"Hello OpenPGP v6 encryption test!";
        let ciphertext = openpgp_encrypt(&KmsRng::new(), &public_armored, plaintext).unwrap();
        let decrypted = openpgp_decrypt(&secret_armored, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    /// An RSA key generated by rPGP itself (as an imported `GnuPG` key would be) decrypts and
    /// signs through the OpenSSL path.
    #[test]
    fn test_openpgp_rsa_imported_key_uses_openssl() {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .can_certify(true)
            .primary_user_id("Imported <imported@example.com>".to_owned())
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Rsa(2048))
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            ]);
        let secret = key_params
            .build()
            .unwrap()
            .generate(openssl_seeded_rng(&KmsRng::new()).unwrap())
            .unwrap();
        let secret_armored = secret.to_armored_bytes(ArmorOptions::default()).unwrap();
        let public_armored = openpgp_public_from_secret(&secret_armored).unwrap();

        let plaintext = b"Hello imported RSA key";
        let ciphertext = openpgp_encrypt(&KmsRng::new(), &public_armored, plaintext).unwrap();
        assert_eq!(
            &openpgp_decrypt(&secret_armored, &ciphertext).unwrap()[..],
            plaintext
        );
        let signature = openpgp_sign_detached(&KmsRng::new(), &secret_armored, plaintext).unwrap();
        assert!(openpgp_verify_detached(&public_armored, plaintext, &signature).unwrap());

        // A corrupted RSA session-key ciphertext fails cleanly (implicit rejection, no panic).
        let mut tampered = ciphertext;
        if let Some(byte) = tampered.get_mut(40) {
            *byte ^= 0x01;
        }
        openpgp_decrypt(&secret_armored, &tampered).unwrap_err();
    }

    /// Subkeys grafted onto a certificate without a binding signature by its primary key are
    /// neither used to verify signatures nor chosen as encryption recipients.
    #[test]
    fn test_openpgp_forged_subkeys_are_ignored() {
        let alice_secret = generate_openpgp_secret_key(
            &KmsRng::new(),
            PgpKeyProfile::Ed25519,
            "Alice <alice@example.com>",
        )
        .unwrap();
        let mut mallory_params = SecretKeyParamsBuilder::default();
        mallory_params
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id("Mallory <mallory@example.com>".to_owned())
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .can_sign(true)
                    .build()
                    .unwrap(),
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            ]);
        let mallory = mallory_params
            .build()
            .unwrap()
            .generate(openssl_seeded_rng(&KmsRng::new()).unwrap())
            .unwrap();
        let mallory_public = mallory.to_public_key();

        // Mallory's subkeys keep their (valid) binding signatures, made by Mallory's primary key
        // instead of Alice's; they come first so that a naive lookup picks them.
        let alice_public = parse_secret_key(&alice_secret).unwrap().to_public_key();
        let mut forged = alice_public.clone();
        forged.public_subkeys = mallory_public
            .public_subkeys
            .iter()
            .chain(&alice_public.public_subkeys)
            .cloned()
            .collect();
        let forged_armored = forged.to_armored_bytes(ArmorOptions::default()).unwrap();

        let data = b"pay Mallory";
        let mut signature = Vec::new();
        DetachedSignature::sign_binary_data(
            openssl_seeded_rng(&KmsRng::new()).unwrap(),
            &mallory.secret_subkeys.first().unwrap().key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &data[..],
        )
        .unwrap()
        .to_writer(&mut signature)
        .unwrap();
        let mallory_armored = mallory_public
            .to_armored_bytes(ArmorOptions::default())
            .unwrap();
        assert!(openpgp_verify_detached(&mallory_armored, data, &signature).unwrap());
        assert!(!openpgp_verify_detached(&forged_armored, data, &signature).unwrap());

        let ciphertext = openpgp_encrypt(&KmsRng::new(), &forged_armored, data).unwrap();
        assert_eq!(
            &openpgp_decrypt(&alice_secret, &ciphertext).unwrap()[..],
            data
        );
        let mallory_secret = mallory.to_armored_bytes(ArmorOptions::default()).unwrap();
        openpgp_decrypt(&mallory_secret, &ciphertext).unwrap_err();

        // Only forged subkeys left: no valid encryption key, so encryption is refused.
        let mut only_forged = alice_public;
        only_forged.public_subkeys = mallory_public.public_subkeys;
        let only_forged_armored = only_forged
            .to_armored_bytes(ArmorOptions::default())
            .unwrap();
        openpgp_encrypt(&KmsRng::new(), &only_forged_armored, data).unwrap_err();
    }

    /// A compressed message whose plaintext exceeds the limit fails instead of expanding.
    #[test]
    fn test_openpgp_decrypt_rejects_oversized_plaintext() {
        let secret_armored = generate_openpgp_secret_key(
            &KmsRng::new(),
            PgpKeyProfile::Ed25519,
            "Bomb <bomb@example.com>",
        )
        .unwrap();
        let public = parse_secret_key(&secret_armored).unwrap().to_public_key();
        let plaintext = vec![0_u8; 64 * 1024];
        let mut rng = openssl_seeded_rng(&KmsRng::new()).unwrap();
        let mut builder = MessageBuilder::from_bytes("", plaintext.clone())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.compression(pgp::types::CompressionAlgorithm::ZLIB);
        builder
            .encrypt_to_key(&mut rng, public.public_subkeys.first().unwrap())
            .unwrap();
        let ciphertext = builder.to_vec(&mut rng).unwrap();
        assert!(ciphertext.len() < plaintext.len() / 10);

        let limit = u64::try_from(plaintext.len()).unwrap();
        assert_eq!(
            openpgp_decrypt_bounded(&secret_armored, &ciphertext, limit)
                .unwrap()
                .len(),
            plaintext.len()
        );
        let error = openpgp_decrypt_bounded(&secret_armored, &ciphertext, limit - 1).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    /// Ed25519 certificate created an hour ago, its primary key flagged sign + certify only.
    fn hour_old_certificate(subkeys: Vec<pgp::composed::SubkeyParams>) -> SignedSecretKey {
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .created_at(Timestamp::from_secs(Timestamp::now().as_secs() - 3600))
            .primary_user_id("Carol <carol@example.com>".to_owned())
            .subkeys(subkeys);
        params
            .build()
            .unwrap()
            .generate(openssl_seeded_rng(&KmsRng::new()).unwrap())
            .unwrap()
    }

    fn encryption_subkey() -> pgp::composed::SubkeyParams {
        SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_encrypt(EncryptionCaps::All)
            .created_at(Timestamp::from_secs(Timestamp::now().as_secs() - 3600))
            .build()
            .unwrap()
    }

    /// Signature config of type `typ` by the primary key of `secret`, with `extra` hashed
    /// subpackets. Created one second in the future so it is newer than the generated ones.
    fn self_signature(
        secret: &SignedSecretKey,
        typ: SignatureType,
        extra: Vec<pgp::packet::SubpacketData>,
    ) -> pgp::packet::SignatureConfig {
        use pgp::packet::{Subpacket, SubpacketData};
        let primary = &secret.primary_key;
        let mut config = pgp::packet::SignatureConfig::from_key(
            openssl_seeded_rng(&KmsRng::new()).unwrap(),
            primary,
            typ,
        )
        .unwrap();
        config.hashed_subpackets = [
            SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                Timestamp::now().as_secs() + 1,
            )),
            SubpacketData::IssuerFingerprint(primary.fingerprint()),
        ]
        .into_iter()
        .chain(extra)
        .map(|data| Subpacket::regular(data).unwrap())
        .collect();
        config
    }

    fn armored(public: &SignedPublicKey) -> Vec<u8> {
        public.to_armored_bytes(ArmorOptions::default()).unwrap()
    }

    /// A subkey revoked by the primary key (type 0x28) is never an encryption recipient.
    #[test]
    fn test_openpgp_encrypt_skips_revoked_subkey() {
        let secret = hour_old_certificate(vec![encryption_subkey(), encryption_subkey()]);
        let mut public = secret.to_public_key();
        let revoked = public.public_subkeys.first_mut().unwrap();
        let revocation = self_signature(&secret, SignatureType::SubkeyRevocation, vec![])
            .sign_subkey_binding(
                &secret.primary_key,
                secret.primary_key.public_key(),
                &Password::empty(),
                &revoked.key,
            )
            .unwrap();
        revoked.signatures.push(revocation);

        let data = b"for the second subkey only";
        let ciphertext = openpgp_encrypt(&KmsRng::new(), &armored(&public), data).unwrap();
        let with_subkey = |subkey: Option<&SignedSecretSubKey>| {
            let mut only = secret.clone();
            only.secret_subkeys = vec![subkey.unwrap().clone()];
            only.to_armored_bytes(ArmorOptions::default()).unwrap()
        };
        openpgp_decrypt(&with_subkey(secret.secret_subkeys.first()), &ciphertext).unwrap_err();
        assert_eq!(
            &openpgp_decrypt(&with_subkey(secret.secret_subkeys.last()), &ciphertext).unwrap()[..],
            data
        );
    }

    /// A certificate whose only encryption subkey is past its Key Expiration Time is refused.
    #[test]
    fn test_openpgp_encrypt_refuses_expired_subkey() {
        let secret = hour_old_certificate(vec![encryption_subkey()]);
        let mut public = secret.to_public_key();
        let subkey = public.public_subkeys.first_mut().unwrap();
        let mut flags = KeyFlags::default();
        flags.set_encrypt_comms(true);
        flags.set_encrypt_storage(true);
        let expired_binding = self_signature(
            &secret,
            SignatureType::SubkeyBinding,
            vec![
                pgp::packet::SubpacketData::KeyFlags(flags),
                pgp::packet::SubpacketData::KeyExpirationTime(pgp::types::Duration::from_secs(60)),
            ],
        )
        .sign_subkey_binding(
            &secret.primary_key,
            secret.primary_key.public_key(),
            &Password::empty(),
            &subkey.key,
        )
        .unwrap();
        let data = b"expired";
        // The newest binding is the one that applies, so the older non-expiring one is ignored.
        subkey.signatures.push(expired_binding);
        let error = openpgp_encrypt(&KmsRng::new(), &armored(&public), data).unwrap_err();
        assert!(
            error.to_string().contains("no encryption-capable key"),
            "{error}"
        );

        // Control: the same certificate encrypts without the expired binding.
        public.public_subkeys.first_mut().unwrap().signatures.pop();
        openpgp_encrypt(&KmsRng::new(), &armored(&public), data).unwrap();
    }

    /// A signature made by a signing subkey that the primary key revoked is invalid.
    #[test]
    fn test_openpgp_verify_rejects_revoked_signing_subkey() {
        let secret = hour_old_certificate(vec![
            SubkeyParamsBuilder::default()
                .key_type(KeyType::Ed25519Legacy)
                .can_sign(true)
                .build()
                .unwrap(),
        ]);
        let data = b"signed by the subkey";
        let mut signature = Vec::new();
        DetachedSignature::sign_binary_data(
            openssl_seeded_rng(&KmsRng::new()).unwrap(),
            &secret.secret_subkeys.first().unwrap().key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &data[..],
        )
        .unwrap()
        .to_writer(&mut signature)
        .unwrap();
        let mut public = secret.to_public_key();
        assert!(openpgp_verify_detached(&armored(&public), data, &signature).unwrap());

        let subkey = public.public_subkeys.first_mut().unwrap();
        let revocation = self_signature(&secret, SignatureType::SubkeyRevocation, vec![])
            .sign_subkey_binding(
                &secret.primary_key,
                secret.primary_key.public_key(),
                &Password::empty(),
                &subkey.key,
            )
            .unwrap();
        subkey.signatures.push(revocation);
        assert!(!openpgp_verify_detached(&armored(&public), data, &signature).unwrap());
    }

    /// A certificate revoked by its primary key (type 0x20), or whose primary key is past its Key
    /// Expiration Time, neither encrypts nor verifies.
    #[test]
    fn test_openpgp_refuses_revoked_or_expired_certificate() {
        let secret = hour_old_certificate(vec![encryption_subkey()]);
        let secret_armored = secret.to_armored_bytes(ArmorOptions::default()).unwrap();
        let data = b"certificate validity";
        let signature = openpgp_sign_detached(&KmsRng::new(), &secret_armored, data).unwrap();
        let public = secret.to_public_key();
        openpgp_encrypt(&KmsRng::new(), &armored(&public), data).unwrap();
        assert!(openpgp_verify_detached(&armored(&public), data, &signature).unwrap());

        let mut revoked = public.clone();
        revoked.details.revocation_signatures.push(
            self_signature(&secret, SignatureType::KeyRevocation, vec![])
                .sign_key(
                    &secret.primary_key,
                    &Password::empty(),
                    secret.primary_key.public_key(),
                )
                .unwrap(),
        );
        let error = openpgp_encrypt(&KmsRng::new(), &armored(&revoked), data).unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");
        assert!(!openpgp_verify_detached(&armored(&revoked), data, &signature).unwrap());

        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        flags.set_certify(true);
        let mut expired = public;
        expired.details.direct_signatures.push(
            self_signature(
                &secret,
                SignatureType::Key,
                vec![
                    pgp::packet::SubpacketData::KeyFlags(flags),
                    pgp::packet::SubpacketData::KeyExpirationTime(pgp::types::Duration::from_secs(
                        60,
                    )),
                ],
            )
            .sign_key(
                &secret.primary_key,
                &Password::empty(),
                secret.primary_key.public_key(),
            )
            .unwrap(),
        );
        let error = openpgp_encrypt(&KmsRng::new(), &armored(&expired), data).unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");
        assert!(!openpgp_verify_detached(&armored(&expired), data, &signature).unwrap());
    }
}

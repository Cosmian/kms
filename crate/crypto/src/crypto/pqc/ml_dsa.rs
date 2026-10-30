use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::kmip_types::{CryptographicAlgorithm, KeyFormatType},
};
use openssl::{
    pkey::{PKey, Private, Public},
    sign::{Signer, Verifier},
};

use super::{PqcKeyMaterial, PqcKeyPolicy, create_pqc_key_pair, ml_dsa_algorithm_name, pqc_keygen};
use crate::{
    crypto::{KeyPair, KeyPairIdentity},
    error::CryptoError,
};

/// Create an ML-DSA key pair.
///
/// Supports ML-DSA-44, ML-DSA-65, ML-DSA-87 via OpenSSL 3.4+.
///
/// When `rng` is supplied, a 32-byte seed is drawn from `KmsRng` and passed to OpenSSL's
/// key generation context (per FIPS 204 §6.1 and OpenSSL `ml_dsa_kmgmt.c`), generating
/// the key pair deterministically from that seed. When `None`, OpenSSL draws entropy
/// directly from its own default DRBG.
pub fn create_ml_dsa_key_pair(
    algorithm: CryptographicAlgorithm,
    identity: KeyPairIdentity<'_>,
    rng: Option<&crate::crypto::KmsRng>,
) -> Result<KeyPair, CryptoError> {
    let algorithm_name = ml_dsa_algorithm_name(algorithm)?;
    let (private_key_der, public_key_der, num_bits) = pqc_keygen(algorithm_name, rng, None)?;
    create_pqc_key_pair(
        identity,
        PqcKeyMaterial {
            private_key_der: &private_key_der,
            public_key_der: &public_key_der,
            cryptographic_length: i32::try_from(num_bits)?,
            key_format_type: KeyFormatType::PKCS8,
        },
        PqcKeyPolicy {
            cryptographic_algorithm: algorithm,
            private_key_usage_mask: CryptographicUsageMask::Sign,
            public_key_usage_mask: CryptographicUsageMask::Verify,
        },
    )
}

/// Sign data using an ML-DSA private key.
///
/// ML-DSA uses an internal hash, so we use `Signer::new_without_digest` (same pattern as `EdDSA`).
pub fn ml_dsa_sign(private_key: &PKey<Private>, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut signer = Signer::new_without_digest(private_key)?;
    let signature = signer.sign_oneshot_to_vec(data)?;
    Ok(signature)
}

/// Verify a signature using an ML-DSA public key.
pub fn ml_dsa_verify(
    public_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let mut verifier = Verifier::new_without_digest(public_key)?;
    let ok = verifier.verify_oneshot(signature, data)?;
    Ok(ok)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;

    use super::*;

    #[test]
    fn ml_dsa_44_sign_verify() {
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-DSA-44", None, None).expect("keygen");

        let priv_key = PKey::private_key_from_der(&priv_der).expect("priv from der");
        let pub_key = PKey::public_key_from_der(&pub_der).expect("pub from der");

        let message = b"test message for ML-DSA-44";
        let signature = ml_dsa_sign(&priv_key, message).expect("sign");
        assert!(!signature.is_empty());

        let valid = ml_dsa_verify(&pub_key, message, &signature).expect("verify");
        assert!(valid);

        // Verify with wrong message
        let wrong = ml_dsa_verify(&pub_key, b"wrong message", &signature).expect("verify wrong");
        assert!(!wrong);
    }

    #[test]
    fn ml_dsa_65_sign_verify() {
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-DSA-65", None, None).expect("keygen");

        let priv_key = PKey::private_key_from_der(&priv_der).expect("priv from der");
        let pub_key = PKey::public_key_from_der(&pub_der).expect("pub from der");

        let message = b"test message for ML-DSA-65";
        let signature = ml_dsa_sign(&priv_key, message).expect("sign");
        let valid = ml_dsa_verify(&pub_key, message, &signature).expect("verify");
        assert!(valid);
    }
    #[test]
    fn ml_dsa_65_sign_verify_with_kms_rng_seed() {
        let rng = crate::crypto::KmsRng::new();
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-DSA-65", Some(&rng), None).expect("seeded keygen");

        let priv_key = PKey::private_key_from_der(&priv_der).expect("priv from der");
        let pub_key = PKey::public_key_from_der(&pub_der).expect("pub from der");

        let message = b"test message for ML-DSA-65 seeded with KmsRng";
        let signature = ml_dsa_sign(&priv_key, message).expect("sign");
        let valid = ml_dsa_verify(&pub_key, message, &signature).expect("verify");
        assert!(valid, "signature on seeded key must verify");
    }

    #[test]
    fn ml_dsa_87_sign_verify() {
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-DSA-87", None, None).expect("keygen");

        let priv_key = PKey::private_key_from_der(&priv_der).expect("priv from der");
        let pub_key = PKey::public_key_from_der(&pub_der).expect("pub from der");

        let message = b"test message for ML-DSA-87";
        let signature = ml_dsa_sign(&priv_key, message).expect("sign");
        let valid = ml_dsa_verify(&pub_key, message, &signature).expect("verify");
        assert!(valid);
    }

    #[test]
    fn ml_dsa_create_key_pair() {
        let key_pair = create_ml_dsa_key_pair(
            CryptographicAlgorithm::MLDSA_65,
            KeyPairIdentity {
                vendor_id: "cosmian",
                private_key_uid: "sk-uid",
                public_key_uid: "pk-uid",
                common_attributes: Attributes::default(),
                private_key_attributes: None,
                public_key_attributes: None,
            },
            None,
        )
        .expect("create key pair");

        let (sk, pk) = (key_pair.0.0, key_pair.0.1);
        assert!(matches!(
            sk,
            cosmian_kmip::kmip_2_1::kmip_objects::Object::PrivateKey(_)
        ));
        assert!(matches!(
            pk,
            cosmian_kmip::kmip_2_1::kmip_objects::Object::PublicKey(_)
        ));

        let sk_block = sk.key_block().expect("sk key block");
        assert_eq!(
            sk_block.cryptographic_algorithm,
            Some(CryptographicAlgorithm::MLDSA_65)
        );
    }
}

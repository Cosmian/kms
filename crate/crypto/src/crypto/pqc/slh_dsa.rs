use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    },
};

use super::{create_pqc_key_pair, pqc_keygen, slh_dsa_algorithm_name};
use crate::{crypto::KeyPair, error::CryptoError};

/// Create an SLH-DSA key pair.
///
/// Supports all 12 SLH-DSA variants (SHA2/SHAKE × 128/192/256 × s/f)
/// via OpenSSL 3.6+.
pub fn create_slh_dsa_key_pair(
    algorithm: CryptographicAlgorithm,
    vendor_id: &str,
    private_key_uid: &str,
    public_key_uid: &str,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let algorithm_name = slh_dsa_algorithm_name(algorithm)?;
    let (private_key_der, public_key_der, num_bits) = pqc_keygen(algorithm_name)?;

    create_pqc_key_pair(
        vendor_id,
        &private_key_der,
        &public_key_der,
        i32::try_from(num_bits)?,
        algorithm,
        KeyFormatType::PKCS8,
        private_key_uid,
        public_key_uid,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
        CryptographicUsageMask::Sign,
        CryptographicUsageMask::Verify,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use openssl::pkey::PKey;

    use super::*;
    use crate::crypto::pqc::ml_dsa::{ml_dsa_sign, ml_dsa_verify};

    fn sign_verify_roundtrip(algorithm_name: &str) {
        let (priv_der, pub_der, _bits) = super::super::pqc_keygen(algorithm_name).expect("keygen");

        let priv_key = PKey::private_key_from_der(&priv_der).expect("priv from der");
        let pub_key = PKey::public_key_from_der(&pub_der).expect("pub from der");

        let message = format!("test message for {algorithm_name}");
        let signature = ml_dsa_sign(&priv_key, message.as_bytes()).expect("sign");
        assert!(!signature.is_empty());

        let valid = ml_dsa_verify(&pub_key, message.as_bytes(), &signature).expect("verify");
        assert!(valid);

        let wrong = ml_dsa_verify(&pub_key, b"wrong message", &signature).expect("verify wrong");
        assert!(!wrong);
    }

    #[test]
    fn slh_dsa_sha2_128s() {
        sign_verify_roundtrip("SLH-DSA-SHA2-128s");
    }

    #[test]
    fn slh_dsa_sha2_128f() {
        sign_verify_roundtrip("SLH-DSA-SHA2-128f");
    }

    #[test]
    fn slh_dsa_sha2_192s() {
        sign_verify_roundtrip("SLH-DSA-SHA2-192s");
    }

    #[test]
    fn slh_dsa_sha2_192f() {
        sign_verify_roundtrip("SLH-DSA-SHA2-192f");
    }

    #[test]
    fn slh_dsa_sha2_256s() {
        sign_verify_roundtrip("SLH-DSA-SHA2-256s");
    }

    #[test]
    fn slh_dsa_sha2_256f() {
        sign_verify_roundtrip("SLH-DSA-SHA2-256f");
    }

    #[test]
    fn slh_dsa_shake_128s() {
        sign_verify_roundtrip("SLH-DSA-SHAKE-128s");
    }

    #[test]
    fn slh_dsa_shake_128f() {
        sign_verify_roundtrip("SLH-DSA-SHAKE-128f");
    }

    #[test]
    fn slh_dsa_shake_192s() {
        sign_verify_roundtrip("SLH-DSA-SHAKE-192s");
    }

    #[test]
    fn slh_dsa_shake_192f() {
        sign_verify_roundtrip("SLH-DSA-SHAKE-192f");
    }

    #[test]
    fn slh_dsa_shake_256s() {
        sign_verify_roundtrip("SLH-DSA-SHAKE-256s");
    }

    #[test]
    fn slh_dsa_shake_256f() {
        sign_verify_roundtrip("SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn slh_dsa_create_key_pair() {
        let key_pair = create_slh_dsa_key_pair(
            CryptographicAlgorithm::SLHDSA_SHA2_128s,
            "cosmian",
            "sk-uid",
            "pk-uid",
            Attributes::default(),
            None,
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
            Some(CryptographicAlgorithm::SLHDSA_SHA2_128s)
        );
    }
}

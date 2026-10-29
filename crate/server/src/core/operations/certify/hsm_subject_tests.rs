//! `Certify` by the UID of an HSM private key (e.g. the ID Placeholder after an HSM
//! `CreateKeyPair`): HSM objects carry no `PublicKeyLink`, and a sensitive RSA private key is
//! returned as a SymmetricKey-shaped stub. The subject is the `<sk>_pk` public key, retrieved
//! with the caller's own `Certify` rights.

use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use cosmian_kms_access::access::Access;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EcCurve, EcPublicKeyMaterial, EncryptedContent, HSM, HsmKeyAlgorithm,
    HsmKeyPairIds, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, HsmStore, InterfaceError,
    InterfaceResult, KeyMaterial, KeyMetadata, KeyType, RsaPublicKeyMaterial, SigningAlgorithm,
    SigningKeyMetadata,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_attributes::Attributes,
    kmip_operations::Certify,
    kmip_types::{CertificateAttributes, UniqueIdentifier},
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    rsa::Rsa,
};
use zeroize::Zeroizing;

use super::{get_subject, subject::Subject};
use crate::{
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::test_utils::{https_clap_config, test_kms_with_config},
};

const ADMIN: &str = "hsm.admin@acme.com";
const GRANTEE: &str = "grantee@acme.com";

/// Single-slot HSM holding a sensitive RSA key pair (`rsa`, `rsa_pk`) and a sensitive EC
/// P-256 key pair (`ec`, `ec_pk`): private keys cannot be exported, public keys can.
struct KeyPairHsm {
    rsa_modulus: Vec<u8>,
    rsa_public_exponent: Vec<u8>,
    ec_q: Vec<u8>,
}

impl KeyPairHsm {
    fn new() -> KResult<Self> {
        let rsa = Rsa::generate(2048)?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec = EcKey::generate(&group)?;
        let mut ctx = BigNumContext::new()?;
        let ec_q = ec
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        Ok(Self {
            rsa_modulus: rsa.n().to_vec(),
            rsa_public_exponent: rsa.e().to_vec(),
            ec_q,
        })
    }
}

fn not_supported<T>() -> InterfaceResult<T> {
    Err(InterfaceError::NotSupported("key pair HSM".to_owned()))
}

const fn key_type(id: &[u8]) -> Option<(KeyType, usize, Option<EcCurve>)> {
    match id {
        b"rsa" => Some((KeyType::RsaPrivateKey, 2048, None)),
        b"rsa_pk" => Some((KeyType::RsaPublicKey, 2048, None)),
        b"ec" => Some((KeyType::EcPrivateKey, 256, Some(EcCurve::P256))),
        b"ec_pk" => Some((KeyType::EcPublicKey, 256, Some(EcCurve::P256))),
        _ => None,
    }
}

#[async_trait]
impl HSM for KeyPairHsm {
    async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>> {
        Ok(vec![0])
    }

    async fn get_supported_algorithms(
        &self,
        _slot_id: usize,
    ) -> InterfaceResult<Vec<CryptoAlgorithm>> {
        Ok(vec![])
    }

    async fn create_key<'a>(
        &'a self,
        _slot_id: usize,
        _id: &'a [u8],
        _algorithm: HsmKeyAlgorithm,
        _key_length_in_bits: usize,
        _sensitive: bool,
        _tags: &'a HashSet<String>,
    ) -> InterfaceResult<()> {
        not_supported()
    }

    async fn create_keypair<'a>(
        &'a self,
        _slot_id: usize,
        _ids: HsmKeyPairIds<'a>,
        _algorithm: HsmKeypairAlgorithm,
        _key_length_in_bits: usize,
        _sensitive: bool,
        _tags: &'a HashSet<String>,
    ) -> InterfaceResult<()> {
        not_supported()
    }

    async fn export(
        &self,
        _slot_id: usize,
        object_id: &[u8],
    ) -> InterfaceResult<Option<HsmObject>> {
        let key_material = match object_id {
            // sensitive private keys: the store falls back to a metadata-only stub
            b"rsa" | b"ec" => return Err(InterfaceError::Default("sensitive key".to_owned())),
            b"rsa_pk" => KeyMaterial::RsaPublicKey(RsaPublicKeyMaterial {
                modulus: self.rsa_modulus.clone(),
                public_exponent: self.rsa_public_exponent.clone(),
            }),
            b"ec_pk" => KeyMaterial::EcPublicKey(EcPublicKeyMaterial {
                curve: EcCurve::P256,
                q: self.ec_q.clone(),
            }),
            _ => return Ok(None),
        };
        Ok(Some(HsmObject::new(
            key_material,
            String::from_utf8_lossy(object_id).into_owned(),
            HashSet::new(),
        )))
    }

    async fn delete(&self, _slot_id: usize, _object_id: &[u8]) -> InterfaceResult<()> {
        not_supported()
    }

    async fn find(
        &self,
        _slot_id: usize,
        _object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        Ok([&b"rsa"[..], b"rsa_pk", b"ec", b"ec_pk"]
            .map(<[u8]>::to_vec)
            .to_vec())
    }

    async fn encrypt<'a>(
        &'a self,
        _slot_id: usize,
        _key_id: &'a [u8],
        _algorithm: CryptoAlgorithm,
        _data: &'a [u8],
        _iv_counter_nonce: &'a [u8],
    ) -> InterfaceResult<EncryptedContent> {
        not_supported()
    }

    async fn decrypt(
        &self,
        _slot_id: usize,
        _key_id: &[u8],
        _algorithm: CryptoAlgorithm,
        _data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        not_supported()
    }

    async fn get_key_type(
        &self,
        _slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        Ok(key_type(key_id).map(|(key_type, _, _)| key_type))
    }

    async fn get_key_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        Ok(
            key_type(key_id).map(|(key_type, key_length_in_bits, curve)| KeyMetadata {
                sensitive: matches!(key_type, KeyType::RsaPrivateKey | KeyType::EcPrivateKey),
                key_type,
                key_length_in_bits,
                id: String::from_utf8_lossy(key_id).into_owned(),
                tags: HashSet::new(),
                curve,
                start_date: None,
                end_date: None,
                rotate_name: None,
                rotate_generation: None,
            }),
        )
    }

    async fn sign_with_metadata(
        &self,
        _slot_id: usize,
        _key_id: &[u8],
        _resolve_algorithm: Box<
            dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        _data: &[u8],
    ) -> InterfaceResult<Vec<u8>> {
        not_supported()
    }

    async fn verify_with_metadata(
        &self,
        _slot_id: usize,
        _key_id: &[u8],
        _resolve_algorithm: Box<
            dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        _data: &[u8],
        _signature: &[u8],
    ) -> InterfaceResult<bool> {
        not_supported()
    }

    async fn generate_random(&self, _slot_id: usize, _len: usize) -> InterfaceResult<Vec<u8>> {
        not_supported()
    }

    async fn seed_random(&self, _slot_id: usize, _seed: &[u8]) -> InterfaceResult<()> {
        not_supported()
    }

    async fn set_key_dates(
        &self,
        _slot_id: usize,
        _key_id: &[u8],
        _start_date: Option<time::Date>,
        _end_date: Option<time::Date>,
    ) -> InterfaceResult<()> {
        not_supported()
    }

    async fn set_key_label(
        &self,
        _slot_id: usize,
        _key_id: &[u8],
        _label: &str,
    ) -> InterfaceResult<()> {
        not_supported()
    }

    fn hsm_lib(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

async fn grant(kms: &KMS, uid: &str, user: &str) -> KResult<()> {
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        user_id: user.to_owned(),
        operation_types: vec![KmipOperation::Certify],
    };
    kms.grant_access(&access, &UserId::from(ADMIN)).await
}

#[tokio::test]
async fn test_certify_subject_of_hsm_private_key_is_its_pk() -> KResult<()> {
    let kms = Box::pin(test_kms_with_config(https_clap_config())).await?;
    let store = HsmStore::new(
        Arc::new(KeyPairHsm::new()?),
        &[ADMIN.to_owned()],
        kms.vendor_id(),
        "hsm",
    );
    kms.database
        .register_objects_store("hsm", Arc::new(store))
        .await;

    // the RSA private key is a SymmetricKey-shaped stub, the EC one a key-less PrivateKey stub
    for sk in ["hsm::0::rsa", "hsm::0::ec"] {
        let pk = format!("{sk}_pk");
        let request = Certify {
            unique_identifier: Some(UniqueIdentifier::TextString(sk.to_owned())),
            attributes: Some(Attributes {
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    "CN=HSM key",
                )?),
                ..Attributes::default()
            }),
            ..Certify::default()
        };
        let subject = get_subject(&kms, &request, &UserId::from(ADMIN)).await?;
        let Subject::PublicKeyAndSubjectName(_, public_key, _) = subject else {
            return Err(KmsError::ServerError(format!(
                "{sk}: the subject is not the public key of the pair"
            )));
        };
        assert_eq!(public_key.id(), pk);

        // the public key is retrieved with the caller's own rights
        grant(&kms, sk, GRANTEE).await?;
        let denied = get_subject(&kms, &request, &UserId::from(GRANTEE)).await;
        assert!(
            denied.is_err(),
            "{sk}: a Certify grant on the private key alone must not reach {pk}"
        );
        grant(&kms, &pk, GRANTEE).await?;
        get_subject(&kms, &request, &UserId::from(GRANTEE)).await?;
    }
    Ok(())
}

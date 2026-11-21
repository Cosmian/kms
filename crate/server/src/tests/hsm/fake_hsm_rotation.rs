//! HSM auto-rotation regression tests that run without a real HSM.
//!
//! A stateful in-memory [`HSM`] (`RotatingHsm`) accepts `C_GenerateKey` /
//! `C_GenerateKeyPair`, `CKA_LABEL` and `CKA_START_DATE` / `CKA_END_DATE` updates. It is
//! wrapped by the real [`HsmStore`] and registered on a KMS as both the `hsm` objects store
//! and crypto oracle, so the scheduler, the HSM re-key and the keyset resolution run as in
//! production.
//!
//! All keys are non-extractable (`export` fails), as on a real token: `HsmStore` serves
//! metadata-only stubs. The fake "cipher" prefixes the data with the key id, so a test can
//! read which key generation encrypted.
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use async_trait::async_trait;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EcCurve, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeyPairIds,
    HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, HsmStore, InterfaceError, InterfaceResult,
    KeyMetadata, KeyType, SigningAlgorithm, SigningKeyMetadata,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_attributes::{Attribute, Attributes},
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateKeyPair, Decrypt, Encrypt, ReKeyKeyPair, SetAttribute},
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
};
use time::{Date, Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::{
    config::{AesKeySize, ClapConfig},
    core::{
        KMS,
        operations::{dispatch_renewal_warnings, run_auto_rotation},
    },
    middlewares::UserId,
    result::KResult,
    tests::test_utils::{https_clap_config, test_kms_with_config},
};

const ADMIN: &str = "hsm.admin@acme.com";

struct FakeKey {
    key_type: KeyType,
    bits: usize,
    label: String,
    start: Option<Date>,
    end: Option<Date>,
}

/// In-memory HSM with a single slot (0) that stores keys, labels and dates.
struct RotatingHsm {
    keys: Mutex<HashMap<Vec<u8>, FakeKey>>,
}

impl RotatingHsm {
    fn keys(&self) -> MutexGuard<'_, HashMap<Vec<u8>, FakeKey>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn insert(
        &self,
        id: &str,
        key_type: KeyType,
        bits: usize,
        label: &str,
        start: Option<Date>,
        end: Option<Date>,
    ) {
        self.keys().insert(
            id.as_bytes().to_vec(),
            FakeKey {
                key_type,
                bits,
                label: label.to_owned(),
                start,
                end,
            },
        );
    }

    fn label(&self, id: &str) -> Option<String> {
        self.keys().get(id.as_bytes()).map(|key| key.label.clone())
    }

    fn dates(&self, id: &str) -> (Option<Date>, Option<Date>) {
        self.keys()
            .get(id.as_bytes())
            .map_or((None, None), |key| (key.start, key.end))
    }

    fn contains(&self, id: &str) -> bool {
        self.keys().contains_key(id.as_bytes())
    }

    fn key_type(&self, id: &str) -> Option<KeyType> {
        self.keys()
            .get(id.as_bytes())
            .map(|key| key.key_type.clone())
    }
}

fn not_supported<T>() -> InterfaceResult<T> {
    Err(InterfaceError::NotSupported("rotating fake HSM".to_owned()))
}

/// Parse `name::generation::key_id` as `parse_label_metadata` does in the PKCS#11 session.
fn parse_label(label: &str) -> (Option<String>, Option<i32>) {
    let mut parts = label.rsplitn(3, "::");
    let (Some(_key_id), Some(generation), Some(name)) = (parts.next(), parts.next(), parts.next())
    else {
        return (None, None);
    };
    generation
        .parse::<i32>()
        .map_or((None, None), |generation| {
            (Some(name.to_owned()), Some(generation))
        })
}

#[async_trait]
impl HSM for RotatingHsm {
    async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>> {
        Ok(vec![0])
    }

    async fn get_supported_algorithms(
        &self,
        _slot_id: usize,
    ) -> InterfaceResult<Vec<CryptoAlgorithm>> {
        Ok(vec![CryptoAlgorithm::AesGcm])
    }

    async fn create_key<'a>(
        &'a self,
        _slot_id: usize,
        id: &'a [u8],
        _algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        _sensitive: bool,
        _tags: &'a HashSet<String>,
    ) -> InterfaceResult<()> {
        if id.starts_with(b"broken") {
            return Err(InterfaceError::Default(
                "simulated C_GenerateKey failure".to_owned(),
            ));
        }
        let mut keys = self.keys();
        if keys.contains_key(id) {
            return Err(InterfaceError::Default(
                "A key with this ID already exists".to_owned(),
            ));
        }
        keys.insert(
            id.to_vec(),
            FakeKey {
                key_type: KeyType::AesKey,
                bits: key_length_in_bits,
                label: String::from_utf8_lossy(id).into_owned(),
                start: None,
                end: None,
            },
        );
        Ok(())
    }

    async fn create_keypair<'a>(
        &'a self,
        _slot_id: usize,
        ids: HsmKeyPairIds<'a>,
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        _sensitive: bool,
        _tags: &'a HashSet<String>,
    ) -> InterfaceResult<()> {
        let mut keys = self.keys();
        if keys.contains_key(ids.private) || keys.contains_key(ids.public) {
            return Err(InterfaceError::Default(
                "A key with this ID already exists".to_owned(),
            ));
        }
        let (private, public) = if matches!(algorithm, HsmKeypairAlgorithm::RSA) {
            (KeyType::RsaPrivateKey, KeyType::RsaPublicKey)
        } else {
            (KeyType::EcPrivateKey, KeyType::EcPublicKey)
        };
        for (id, key_type) in [(ids.private, private), (ids.public, public)] {
            keys.insert(
                id.to_vec(),
                FakeKey {
                    key_type,
                    bits: key_length_in_bits,
                    label: String::from_utf8_lossy(id).into_owned(),
                    start: None,
                    end: None,
                },
            );
        }
        Ok(())
    }

    async fn export(
        &self,
        _slot_id: usize,
        object_id: &[u8],
    ) -> InterfaceResult<Option<HsmObject>> {
        if self.keys().contains_key(object_id) {
            // non-extractable: `HsmStore::retrieve` falls back to the sensitive stub
            Err(InterfaceError::Default("non-extractable".to_owned()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, _slot_id: usize, object_id: &[u8]) -> InterfaceResult<()> {
        self.keys().remove(object_id);
        Ok(())
    }

    async fn find(
        &self,
        _slot_id: usize,
        _object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        Ok(self.keys().keys().cloned().collect())
    }

    async fn encrypt<'a>(
        &'a self,
        _slot_id: usize,
        key_id: &'a [u8],
        _algorithm: CryptoAlgorithm,
        data: &'a [u8],
        _iv_counter_nonce: &'a [u8],
    ) -> InterfaceResult<EncryptedContent> {
        if !self.keys().contains_key(key_id) {
            return Err(InterfaceError::Default("unknown key".to_owned()));
        }
        Ok(EncryptedContent {
            ciphertext: [key_id, b"|", data].concat(),
            ..EncryptedContent::default()
        })
    }

    async fn decrypt(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        _algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        // a ciphertext produced by another generation fails, like a wrong-key C_Decrypt
        data.strip_prefix(key_id)
            .and_then(|rest| rest.strip_prefix(b"|"))
            .map(|plaintext| Zeroizing::new(plaintext.to_vec()))
            .ok_or_else(|| InterfaceError::Default("wrong key".to_owned()))
    }

    async fn get_key_type(
        &self,
        _slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        Ok(self.keys().get(key_id).map(|key| key.key_type.clone()))
    }

    async fn get_key_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        Ok(self.keys().get(key_id).map(|key| {
            let (rotate_name, rotate_generation) = parse_label(&key.label);
            KeyMetadata {
                key_type: key.key_type.clone(),
                key_length_in_bits: key.bits,
                sensitive: true,
                id: key.label.clone(),
                tags: HashSet::new(),
                curve: matches!(key.key_type, KeyType::EcPrivateKey | KeyType::EcPublicKey)
                    .then_some(EcCurve::P256),
                start_date: key.start,
                end_date: key.end,
                rotate_name,
                rotate_generation,
            }
        }))
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
        key_id: &[u8],
        start_date: Option<Date>,
        end_date: Option<Date>,
    ) -> InterfaceResult<()> {
        let mut keys = self.keys();
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| InterfaceError::Default("unknown key".to_owned()))?;
        key.start = start_date;
        key.end = end_date;
        Ok(())
    }

    async fn set_key_label(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        label: &str,
    ) -> InterfaceResult<()> {
        let mut keys = self.keys();
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| InterfaceError::Default("unknown key".to_owned()))?;
        label.clone_into(&mut key.label);
        Ok(())
    }

    fn hsm_lib(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

/// KMS on a fresh `SQLite` database with an empty [`RotatingHsm`] mounted under `hsm`.
async fn kms_with_rotating_hsm() -> KResult<(Arc<KMS>, Arc<RotatingHsm>)> {
    kms_with_rotating_hsm_config(https_clap_config()).await
}

async fn kms_with_rotating_hsm_config(config: ClapConfig) -> KResult<(Arc<KMS>, Arc<RotatingHsm>)> {
    let kms = Box::pin(test_kms_with_config(config)).await?;
    let hsm = Arc::new(RotatingHsm {
        keys: Mutex::new(HashMap::new()),
    });
    let store = HsmStore::new(hsm.clone(), &[ADMIN.to_owned()], kms.vendor_id(), "hsm");
    kms.database
        .register_objects_store("hsm", Arc::new(store.clone()))
        .await;
    kms.register_crypto_oracle("hsm", Box::new(store)).await;
    Ok((kms, hsm))
}

fn today() -> Date {
    OffsetDateTime::now_utc().date()
}

fn days(n: i64) -> Duration {
    Duration::days(n)
}

fn admin() -> UserId {
    UserId::from(ADMIN)
}

fn uid(id: &str) -> UniqueIdentifier {
    UniqueIdentifier::TextString(id.to_owned())
}

/// An AES key enrolled in the keyset named after itself, as a generation-0 head.
fn seed_enrolled_aes(hsm: &RotatingHsm, id: &str, start: Date, end: Date) {
    hsm.insert(
        id,
        KeyType::AesKey,
        256,
        &format!("hsm::0::{id}::0::{id}@latest"),
        Some(start),
        Some(end),
    );
}

/// A private key `id` and its public key `{id}_pk`, both un-enrolled and without dates.
fn seed_key_pair(hsm: &RotatingHsm, id: &str) {
    hsm.insert(id, KeyType::RsaPrivateKey, 2048, id, None, None);
    hsm.insert(
        &format!("{id}_pk"),
        KeyType::RsaPublicKey,
        2048,
        &format!("{id}_pk"),
        None,
        None,
    );
}

#[tokio::test]
async fn due_hsm_aes_key_is_rotated_and_rearmed() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_enrolled_aes(&hsm, "k1", today() - days(30), today());

    run_auto_rotation(&kms).await;
    assert_eq!(
        hsm.label("k1@1").as_deref(),
        Some("hsm::0::k1::1::k1@latest")
    );
    assert_eq!(hsm.dates("k1@1"), (Some(today()), Some(today() + days(30))));
    assert_eq!(hsm.label("k1").as_deref(), Some("hsm::0::k1::0::k1"));

    // the retired generation keeps its past end date but is never rotated again
    run_auto_rotation(&kms).await;
    assert!(!hsm.contains("k1@2"));
    Ok(())
}

#[tokio::test]
async fn hsm_aes_key_not_due_is_not_rotated() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_enrolled_aes(&hsm, "k1", today() - days(29), today() + days(1));

    run_auto_rotation(&kms).await;
    assert!(!hsm.contains("k1@1"));
    assert_eq!(hsm.label("k1").as_deref(), Some("hsm::0::k1::0::k1@latest"));
    Ok(())
}

#[tokio::test]
async fn failing_hsm_key_does_not_block_others() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_enrolled_aes(&hsm, "broken", today() - days(30), today());
    seed_enrolled_aes(&hsm, "k2", today() - days(30), today());

    run_auto_rotation(&kms).await;
    assert!(hsm.contains("k2@1"));
    assert!(!hsm.contains("broken@1"));
    assert_eq!(
        hsm.label("broken").as_deref(),
        Some("hsm::0::broken::0::broken@latest")
    );
    Ok(())
}

#[tokio::test]
async fn unenrolled_hsm_key_is_enrolled_on_rotation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert(
        "k3",
        KeyType::AesKey,
        256,
        "k3",
        Some(today() - days(30)),
        Some(today()),
    );

    run_auto_rotation(&kms).await;
    assert_eq!(
        hsm.label("k3@1").as_deref(),
        Some("hsm::0::k3::1::k3@latest")
    );
    assert_eq!(hsm.label("k3").as_deref(), Some("hsm::0::k3::0::k3"));
    Ok(())
}

#[tokio::test]
async fn due_hsm_key_pair_is_rotated() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert(
        "kp",
        KeyType::RsaPrivateKey,
        2048,
        "hsm::0::kp::0::kp@latest",
        Some(today() - days(30)),
        Some(today()),
    );
    hsm.insert("kp_pk", KeyType::RsaPublicKey, 2048, "kp_pk", None, None);

    run_auto_rotation(&kms).await;
    assert_eq!(hsm.key_type("kp@1"), Some(KeyType::RsaPrivateKey));
    assert_eq!(
        hsm.label("kp@1").as_deref(),
        Some("hsm::0::kp::1::kp@latest")
    );
    assert_eq!(hsm.dates("kp@1"), (Some(today()), Some(today() + days(30))));
    assert_eq!(hsm.key_type("kp@1_pk"), Some(KeyType::RsaPublicKey));
    assert_eq!(
        hsm.label("kp@1_pk").as_deref(),
        Some("hsm::0::kp_pk::1::kp_pk@latest")
    );
    assert_eq!(hsm.dates("kp@1_pk"), (None, None));
    assert_eq!(hsm.label("kp").as_deref(), Some("hsm::0::kp::0::kp"));
    assert_eq!(
        hsm.label("kp_pk").as_deref(),
        Some("hsm::0::kp_pk::0::kp_pk")
    );
    Ok(())
}

#[tokio::test]
async fn manual_hsm_rekey_keypair_returns_new_pair() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_key_pair(&hsm, "kp");

    let response = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid("hsm::0::kp")),
                ..ReKeyKeyPair::default()
            },
            &admin(),
        )
        .await?;
    assert_eq!(
        response.private_key_unique_identifier.to_string(),
        "hsm::0::kp@1"
    );
    assert_eq!(
        response.public_key_unique_identifier.to_string(),
        "hsm::0::kp@1_pk"
    );

    let refused = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid("hsm::0::kp@1")),
                offset: Some(3600),
                ..ReKeyKeyPair::default()
            },
            &admin(),
        )
        .await;
    assert!(
        refused.as_ref().is_err_and(|e| e
            .to_string()
            .contains("not supported for HSM-resident keys")),
        "{refused:?}"
    );
    Ok(())
}

#[tokio::test]
async fn set_rotate_interval_on_hsm_public_key_is_rejected() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_key_pair(&hsm, "kp");

    let refused = kms
        .set_attribute(
            SetAttribute {
                unique_identifier: Some(uid("hsm::0::kp_pk")),
                new_attribute: Attribute::RotateInterval(86_400),
            },
            &admin(),
        )
        .await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("on the private key")),
        "{refused:?}"
    );
    assert_eq!(hsm.dates("kp_pk"), (None, None));
    Ok(())
}

#[tokio::test]
async fn renewal_warning_fires_for_hsm_key() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_enrolled_aes(&hsm, "k5", today() - days(25), today() + days(5));

    let mut warned = HashMap::new();
    dispatch_renewal_warnings(&kms, &mut warned).await;
    assert_eq!(warned.get("hsm::0::k5"), Some(&7));
    Ok(())
}

/// Keyset `hsm::0::k`: generation 0 (`k`, retired) and generation 1 (`k@1`, latest).
fn seed_two_generations(hsm: &RotatingHsm) {
    hsm.insert("k", KeyType::AesKey, 256, "hsm::0::k::0::k", None, None);
    hsm.insert(
        "k@1",
        KeyType::AesKey,
        256,
        "hsm::0::k::1::k@latest",
        None,
        None,
    );
}

async fn encrypt_with(kms: &KMS, uid_str: &str) -> KResult<Vec<u8>> {
    let response = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(uid(uid_str)),
                data: Some(Zeroizing::new(b"hi".to_vec())),
                ..Encrypt::default()
            },
            &admin(),
        )
        .await?;
    Ok(response.data.unwrap_or_default())
}

async fn decrypt_with(kms: &KMS, uid_str: &str, ciphertext: &[u8]) -> KResult<Vec<u8>> {
    let response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(uid(uid_str)),
                data: Some(ciphertext.to_vec()),
                ..Decrypt::default()
            },
            &admin(),
        )
        .await?;
    Ok(response.data.map(|d| d.to_vec()).unwrap_or_default())
}

#[tokio::test]
async fn bare_hsm_keyset_encrypts_on_hsm_with_latest() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_generations(&hsm);

    assert_eq!(encrypt_with(&kms, "hsm::0::k").await?, b"k@1|hi");
    Ok(())
}

#[tokio::test]
async fn bare_hsm_keyset_decrypts_with_older_generation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_generations(&hsm);

    // `k@1` is tried first and fails, then `k` succeeds
    assert_eq!(decrypt_with(&kms, "hsm::0::k", b"k|hi").await?, b"hi");
    Ok(())
}

#[tokio::test]
async fn hsm_keyset_version_suffixes_resolve() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_generations(&hsm);

    assert_eq!(encrypt_with(&kms, "hsm::0::k@latest").await?, b"k@1|hi");
    assert_eq!(decrypt_with(&kms, "hsm::0::k@first", b"k|hi").await?, b"hi");
    assert_eq!(decrypt_with(&kms, "hsm::0::k@0", b"k|hi").await?, b"hi");
    assert_eq!(encrypt_with(&kms, "hsm::0::k@1").await?, b"k@1|hi");
    Ok(())
}

/// The algorithm policy applies to HSM keyset members as it does to SQL keys.
#[tokio::test]
async fn hsm_keyset_members_obey_algorithm_policy() -> KResult<()> {
    let mut config = https_clap_config();
    config.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    config.kmip_policy.allowlists.aes_key_sizes = Some(vec![AesKeySize::Aes128]);
    let (kms, hsm) = kms_with_rotating_hsm_config(config).await?;
    seed_two_generations(&hsm);

    // single-member path (Encrypt -> latest), then chain-walk path (Decrypt)
    encrypt_with(&kms, "hsm::0::k").await.unwrap_err();
    decrypt_with(&kms, "hsm::0::k", b"k|hi").await.unwrap_err();
    Ok(())
}

#[tokio::test]
async fn hsm_create_with_rotation_attributes_is_rejected() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;

    let refused = kms
        .create(
            Create {
                object_type: ObjectType::SymmetricKey,
                attributes: Attributes {
                    unique_identifier: Some(uid("hsm::0::new")),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(256),
                    rotate_interval: Some(86_400),
                    ..Attributes::default()
                },
                protection_storage_masks: None,
            },
            &admin(),
        )
        .await;
    assert!(
        refused.as_ref().is_err_and(|e| e
            .to_string()
            .contains("set the rotation policy with SetAttribute")),
        "{refused:?}"
    );

    let refused = kms
        .create_key_pair(
            CreateKeyPair {
                common_attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(2048),
                    ..Attributes::default()
                }),
                private_key_attributes: Some(Attributes {
                    unique_identifier: Some(uid("hsm::0::newkp")),
                    rotate_name: Some("hsm::0::newkp".to_owned()),
                    ..Attributes::default()
                }),
                ..CreateKeyPair::default()
            },
            &admin(),
        )
        .await;
    assert!(
        refused.as_ref().is_err_and(|e| e
            .to_string()
            .contains("set the rotation policy with SetAttribute")),
        "{refused:?}"
    );
    assert!(!hsm.contains("new"));
    assert!(!hsm.contains("newkp"));
    Ok(())
}

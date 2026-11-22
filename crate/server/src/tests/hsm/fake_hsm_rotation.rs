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
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use cosmian_kms_access::access::Access;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EcCurve, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeyPairIds,
    HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, HsmStore, InterfaceError, InterfaceResult,
    KeyMetadata, KeyType, MacAlgorithm, MacKeyMetadata, SigningAlgorithm, SigningKeyMetadata,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, ErrorReason, PaddingMethod},
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::{Attribute, Attributes},
        kmip_objects::ObjectType,
        kmip_operations::{
            Create, CreateKeyPair, Decrypt, Encrypt, MAC, MACVerify, ReKey, ReKeyKeyPair,
            SetAttribute, Sign, SignatureVerify,
        },
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier, ValidityIndicator,
        },
    },
};
use time::{Date, Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::{
    config::{AesKeySize, ClapConfig},
    core::{
        KMS,
        operations::{dispatch_renewal_warnings, run_auto_rotation},
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::test_utils::{https_clap_config, test_kms_with_config},
};

const ADMIN: &str = "hsm.admin@acme.com";

struct FakeKey {
    key_type: KeyType,
    bits: usize,
    label: String,
    tags: HashSet<String>,
    start: Option<Date>,
    end: Option<Date>,
}

/// In-memory HSM with a single slot (0) that stores keys, labels and dates.
struct RotatingHsm {
    keys: Mutex<HashMap<Vec<u8>, FakeKey>>,
    fail_find: AtomicBool,
    fail_metadata: AtomicBool,
    return_empty_scan: AtomicBool,
    unauthenticated_only: AtomicBool,
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
                tags: HashSet::new(),
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

    /// `key_id|data`, the fake ciphertext / signature / MAC of `data` under `key_id`.
    fn tag(&self, key_id: &[u8], data: &[u8]) -> InterfaceResult<Vec<u8>> {
        if !self.keys().contains_key(key_id) {
            return Err(InterfaceError::Default("unknown key".to_owned()));
        }
        Ok([key_id, b"|", data].concat())
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
        if self.unauthenticated_only.load(Ordering::Relaxed) {
            return Ok(vec![CryptoAlgorithm::AesCbc, CryptoAlgorithm::RsaPkcsV15]);
        }
        Ok(vec![
            CryptoAlgorithm::AesGcm,
            CryptoAlgorithm::RsaOaepSha256,
        ])
    }

    async fn create_key<'a>(
        &'a self,
        _slot_id: usize,
        id: &'a [u8],
        _algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        _sensitive: bool,
        tags: &'a HashSet<String>,
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
                tags: tags.clone(),
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
        tags: &'a HashSet<String>,
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
                    tags: tags.clone(),
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
        if self.fail_find.load(Ordering::Relaxed) {
            return Err(InterfaceError::Default("injected find failure".to_owned()));
        }
        if self.return_empty_scan.load(Ordering::Relaxed) {
            return Ok(Vec::new());
        }
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
        let is_rsa_public = self
            .keys()
            .get(key_id)
            .ok_or_else(|| InterfaceError::Default("unknown key".to_owned()))?
            .key_type
            == KeyType::RsaPublicKey;
        let decrypting_key_id = if is_rsa_public {
            key_id.strip_suffix(b"_pk").unwrap_or(key_id)
        } else {
            key_id
        };
        Ok(EncryptedContent {
            ciphertext: [decrypting_key_id, b"|", data].concat(),
            ..EncryptedContent::default()
        })
    }

    async fn decrypt(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        if self.unauthenticated_only.load(Ordering::Relaxed) {
            if !matches!(
                algorithm,
                CryptoAlgorithm::AesCbc | CryptoAlgorithm::RsaPkcsV15
            ) {
                return Err(InterfaceError::NotSupported(
                    "authenticated decryption is not supported by this token".to_owned(),
                ));
            }
            // An unauthenticated wrong-key decryption can succeed with garbage.
            return Ok(Zeroizing::new(
                data.strip_prefix(key_id)
                    .and_then(|rest| rest.strip_prefix(b"|"))
                    .unwrap_or(b"plausible wrong-key plaintext")
                    .to_vec(),
            ));
        }
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
        if self.fail_metadata.load(Ordering::Relaxed) {
            return Err(InterfaceError::Default(
                "injected metadata failure".to_owned(),
            ));
        }
        Ok(self.keys().get(key_id).map(|key| {
            let (rotate_name, rotate_generation) = parse_label(&key.label);
            KeyMetadata {
                key_type: key.key_type.clone(),
                key_length_in_bits: key.bits,
                sensitive: true,
                id: key.label.clone(),
                tags: key.tags.clone(),
                curve: matches!(key.key_type, KeyType::EcPrivateKey | KeyType::EcPublicKey)
                    .then_some(EcCurve::P256),
                start_date: key.start,
                end_date: key.end,
                rotate_name,
                rotate_generation,
            }
        }))
    }

    // Fake signature / MAC: `key_id|data`. A public key `x_pk` verifies what `x` signed.
    async fn sign_with_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        _resolve_algorithm: Box<
            dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        data: &[u8],
    ) -> InterfaceResult<Vec<u8>> {
        self.tag(key_id, data)
    }

    async fn verify_with_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        _resolve_algorithm: Box<
            dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        data: &[u8],
        signature: &[u8],
    ) -> InterfaceResult<bool> {
        let expected = self.tag(key_id, data)?;
        let signer = key_id.strip_suffix(b"_pk").unwrap_or(key_id);
        Ok(signature == expected.as_slice() || signature == [signer, b"|", data].concat())
    }

    async fn mac_with_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        _resolve_algorithm: Box<
            dyn for<'a> Fn(&'a MacKeyMetadata) -> InterfaceResult<MacAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        data: &[u8],
    ) -> InterfaceResult<Vec<u8>> {
        self.tag(key_id, data)
    }

    async fn verify_mac_with_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
        _resolve_algorithm: Box<
            dyn for<'a> Fn(&'a MacKeyMetadata) -> InterfaceResult<MacAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        data: &[u8],
        mac_data: &[u8],
    ) -> InterfaceResult<bool> {
        Ok(mac_data == self.tag(key_id, data)?.as_slice())
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
        fail_find: AtomicBool::new(false),
        fail_metadata: AtomicBool::new(false),
        return_empty_scan: AtomicBool::new(false),
        unauthenticated_only: AtomicBool::new(false),
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
async fn unenrolled_hsm_key_is_enrolled_on_manual_rotation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert(
        "k3",
        KeyType::AesKey,
        256,
        "k3",
        Some(today() - days(30)),
        Some(today()),
    );

    assert_eq!(
        rekey_as(&kms, "hsm::0::k3", &admin()).await?,
        "hsm::0::k3@1"
    );
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
    encrypt_as(kms, uid_str, &admin()).await
}

async fn encrypt_as(kms: &KMS, uid_str: &str, user: &UserId) -> KResult<Vec<u8>> {
    let response = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(uid(uid_str)),
                data: Some(b"hi".to_vec().into()),
                ..Encrypt::default()
            },
            user,
        )
        .await?;
    Ok(response.data.map(|d| d.to_vec()).unwrap_or_default())
}

async fn decrypt_with(kms: &KMS, uid_str: &str, ciphertext: &[u8]) -> KResult<Vec<u8>> {
    decrypt_as(kms, uid_str, ciphertext, &admin()).await
}

async fn decrypt_as(
    kms: &KMS,
    uid_str: &str,
    ciphertext: &[u8],
    user: &UserId,
) -> KResult<Vec<u8>> {
    let response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(uid(uid_str)),
                data: Some(ciphertext.to_vec()),
                ..Decrypt::default()
            },
            user,
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
    let denied = |e: KmsError| {
        assert!(
            matches!(
                &e,
                KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _)
            ),
            "expected a policy denial, got {e:?}"
        );
    };
    denied(encrypt_with(&kms, "hsm::0::k").await.unwrap_err());
    denied(decrypt_with(&kms, "hsm::0::k", b"k|hi").await.unwrap_err());
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

// ─── Keyset addressing: every generation, every operation ─────────────────────

/// Assert that `result` failed with the KMIP error `reason`.
fn assert_reason<T: std::fmt::Debug>(result: &KResult<T>, reason: ErrorReason) {
    assert!(
        matches!(result, Err(KmsError::Kmip21Error(r, _)) if *r == reason),
        "expected {reason:?}, got {result:?}"
    );
}

/// Keyset `hsm::0::k`: generations 0 (`k`) and 1 (`k@1`) retired, 2 (`k@2`) the head.
fn seed_three_generations(hsm: &RotatingHsm) {
    hsm.insert("k", KeyType::AesKey, 256, "hsm::0::k::0::k", None, None);
    hsm.insert("k@1", KeyType::AesKey, 256, "hsm::0::k::1::k", None, None);
    hsm.insert(
        "k@2",
        KeyType::AesKey,
        256,
        "hsm::0::k::2::k@latest",
        None,
        None,
    );
}

/// Key pair keysets `hsm::0::kp` / `hsm::0::kp_pk`: generation 0 (`kp`, `kp_pk`) retired,
/// generation 1 (`kp@1`, `kp@1_pk`) the head.
fn seed_two_key_pair_generations(hsm: &RotatingHsm) {
    for (id, key_type, label) in [
        ("kp", KeyType::RsaPrivateKey, "hsm::0::kp::0::kp"),
        ("kp_pk", KeyType::RsaPublicKey, "hsm::0::kp_pk::0::kp_pk"),
        ("kp@1", KeyType::RsaPrivateKey, "hsm::0::kp::1::kp@latest"),
        (
            "kp@1_pk",
            KeyType::RsaPublicKey,
            "hsm::0::kp_pk::1::kp_pk@latest",
        ),
    ] {
        hsm.insert(id, key_type, 2048, label, None, None);
    }
}

async fn decrypt_with_params(
    kms: &KMS,
    uid_str: &str,
    ciphertext: &[u8],
    cryptographic_parameters: CryptographicParameters,
) -> KResult<Vec<u8>> {
    let response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(uid(uid_str)),
                data: Some(ciphertext.to_vec()),
                cryptographic_parameters: Some(cryptographic_parameters),
                ..Decrypt::default()
            },
            &admin(),
        )
        .await?;
    Ok(response.data.map(|d| d.to_vec()).unwrap_or_default())
}

async fn sign_with(kms: &KMS, uid_str: &str) -> KResult<Vec<u8>> {
    let response = kms
        .sign(
            Sign {
                unique_identifier: Some(uid(uid_str)),
                data: Some(b"msg".to_vec().into()),
                ..Sign::default()
            },
            &admin(),
        )
        .await?;
    Ok(response.signature_data.unwrap_or_default())
}

async fn verify_with(kms: &KMS, uid_str: &str, signature: &[u8]) -> KResult<ValidityIndicator> {
    let response = kms
        .signature_verify(
            SignatureVerify {
                unique_identifier: Some(uid(uid_str)),
                data: Some(b"msg".to_vec()),
                signature_data: Some(signature.to_vec()),
                ..SignatureVerify::default()
            },
            &admin(),
        )
        .await?;
    response
        .validity_indicator
        .ok_or_else(|| KmsError::ServerError("no validity indicator".to_owned()))
}

async fn mac_with(kms: &KMS, uid_str: &str) -> KResult<Vec<u8>> {
    let response = kms
        .mac(
            MAC {
                unique_identifier: Some(uid(uid_str)),
                data: Some(b"msg".to_vec()),
                ..MAC::default()
            },
            &admin(),
        )
        .await?;
    Ok(response.mac_data.unwrap_or_default())
}

async fn mac_verify_with(kms: &KMS, uid_str: &str, mac_data: &[u8]) -> KResult<ValidityIndicator> {
    let response = kms
        .mac_verify(
            MACVerify {
                unique_identifier: uid(uid_str),
                cryptographic_parameters: None,
                data: b"msg".to_vec(),
                mac_data: mac_data.to_vec(),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
            &admin(),
        )
        .await?;
    response
        .validity_indicator
        .ok_or_else(|| KmsError::ServerError("no validity indicator".to_owned()))
}

async fn rekey_as(kms: &KMS, uid_str: &str, user: &UserId) -> KResult<String> {
    Ok(kms
        .rekey(
            ReKey {
                unique_identifier: Some(uid(uid_str)),
                ..ReKey::default()
            },
            user,
        )
        .await?
        .unique_identifier
        .to_string())
}

async fn set_hsm_attribute(kms: &KMS, uid_str: &str, attribute: Attribute) -> KResult<()> {
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(uid(uid_str)),
            new_attribute: attribute,
        },
        &admin(),
    )
    .await
    .map(|_| ())
}

#[tokio::test]
async fn protect_operations_use_only_the_keyset_head() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);

    for head in ["hsm::0::k", "hsm::0::k@latest", "hsm::0::k@2"] {
        assert_eq!(encrypt_with(&kms, head).await?, b"k@2|hi", "{head}");
        assert_eq!(mac_with(&kms, head).await?, b"k@2|msg", "{head}");
    }
    for retired in ["hsm::0::k@0", "hsm::0::k@first", "hsm::0::k@1"] {
        assert_reason(
            &encrypt_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
        assert_reason(
            &mac_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    let refused = encrypt_with(&kms, "hsm::0::k@1").await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("in state Deactivated")),
        "{refused:?}"
    );
    Ok(())
}

#[tokio::test]
async fn every_generation_decrypts_by_keyset_name_and_by_its_own_address() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);

    for (ciphertext, addresses) in [
        (&b"k|hi"[..], &["hsm::0::k@0", "hsm::0::k@first"][..]),
        (b"k@1|hi", &["hsm::0::k@1"]),
        (b"k@2|hi", &["hsm::0::k@2", "hsm::0::k@latest"]),
    ] {
        // the bare name walks k@2, k@1, k: whatever generation encrypted
        assert_eq!(decrypt_with(&kms, "hsm::0::k", ciphertext).await?, b"hi");
        for address in addresses {
            assert_eq!(
                decrypt_with(&kms, address, ciphertext).await?,
                b"hi",
                "{address}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_generation_address_does_not_walk_the_keyset() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);

    for (address, foreign_ciphertext) in [
        ("hsm::0::k@latest", &b"k|hi"[..]),
        ("hsm::0::k@2", b"k@1|hi"),
        ("hsm::0::k@1", b"k@2|hi"),
        ("hsm::0::k@0", b"k@1|hi"),
        ("hsm::0::k@first", b"k@2|hi"),
    ] {
        let error = decrypt_with(&kms, address, foreign_ciphertext)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("wrong key"),
            "{address} must reject another generation's ciphertext: {error:?}"
        );
    }
    // no generation of the keyset produced this one
    let error = decrypt_with(&kms, "hsm::0::k", b"other|hi")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wrong key"), "{error:?}");
    Ok(())
}

#[tokio::test]
async fn keyset_decrypt_refuses_modes_that_cannot_detect_a_wrong_key() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);

    let refused = [
        CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::CBC),
            ..CryptographicParameters::default()
        },
        CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::ECB),
            ..CryptographicParameters::default()
        },
        CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::CTR),
            ..CryptographicParameters::default()
        },
        CryptographicParameters {
            block_cipher_mode: Some(BlockCipherMode::XTS),
            ..CryptographicParameters::default()
        },
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            ..CryptographicParameters::default()
        },
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20),
            ..CryptographicParameters::default()
        },
    ];
    for params in refused {
        assert_reason(
            &decrypt_with_params(&kms, "hsm::0::k", b"k|hi", params).await,
            ErrorReason::Feature_Not_Supported,
        );
    }

    // an authenticated mode walks the keyset
    let gcm = CryptographicParameters {
        block_cipher_mode: Some(BlockCipherMode::GCM),
        ..CryptographicParameters::default()
    };
    assert_eq!(
        decrypt_with_params(&kms, "hsm::0::k", b"k|hi", gcm).await?,
        b"hi"
    );
    // an addressed generation is not walked: any mode is the caller's choice
    let cbc = CryptographicParameters {
        block_cipher_mode: Some(BlockCipherMode::CBC),
        ..CryptographicParameters::default()
    };
    assert_eq!(
        decrypt_with_params(&kms, "hsm::0::k@0", b"k|hi", cbc).await?,
        b"hi"
    );
    Ok(())
}

#[tokio::test]
async fn mac_verify_by_keyset_name_finds_the_generation_that_computed_it() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);

    for (mac, own_address) in [
        (&b"k|msg"[..], "hsm::0::k@0"),
        (b"k@1|msg", "hsm::0::k@1"),
        (b"k@2|msg", "hsm::0::k@latest"),
    ] {
        assert_eq!(
            mac_verify_with(&kms, "hsm::0::k", mac).await?,
            ValidityIndicator::Valid
        );
        assert_eq!(
            mac_verify_with(&kms, own_address, mac).await?,
            ValidityIndicator::Valid
        );
    }
    // a generation address does not walk; a MAC of no generation is Invalid, not an error
    assert_eq!(
        mac_verify_with(&kms, "hsm::0::k@latest", b"k|msg").await?,
        ValidityIndicator::Invalid
    );
    assert_eq!(
        mac_verify_with(&kms, "hsm::0::k", b"forged").await?,
        ValidityIndicator::Invalid
    );
    Ok(())
}

#[tokio::test]
async fn key_pair_keyset_signs_with_the_head_and_verifies_every_generation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_key_pair_generations(&hsm);

    for head in ["hsm::0::kp", "hsm::0::kp@latest", "hsm::0::kp@1"] {
        assert_eq!(sign_with(&kms, head).await?, b"kp@1|msg", "{head}");
    }
    for retired in ["hsm::0::kp@0", "hsm::0::kp@first"] {
        assert_reason(
            &sign_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }

    // the public keyset walks kp@1_pk then kp_pk
    for signature in [&b"kp|msg"[..], b"kp@1|msg"] {
        assert_eq!(
            verify_with(&kms, "hsm::0::kp_pk", signature).await?,
            ValidityIndicator::Valid
        );
    }
    assert_eq!(
        verify_with(&kms, "hsm::0::kp_pk@0", b"kp|msg").await?,
        ValidityIndicator::Valid
    );
    assert_eq!(
        verify_with(&kms, "hsm::0::kp_pk@latest", b"kp|msg").await?,
        ValidityIndicator::Invalid
    );
    assert_eq!(
        verify_with(&kms, "hsm::0::kp_pk", b"forged").await?,
        ValidityIndicator::Invalid
    );
    Ok(())
}

/// Auto-rotation, then the whole life of the keyset: protect with the head only, process
/// with any generation, re-key only the head.
#[tokio::test]
async fn rotated_keyset_lifecycle_end_to_end() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_enrolled_aes(&hsm, "k", today() - days(30), today());
    let c0 = encrypt_with(&kms, "hsm::0::k").await?;
    assert_eq!(c0, b"k|hi");

    run_auto_rotation(&kms).await;
    let c1 = encrypt_with(&kms, "hsm::0::k").await?;
    assert_eq!(c1, b"k@1|hi");
    for retired in ["hsm::0::k@0", "hsm::0::k@first"] {
        assert_reason(
            &encrypt_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    for ciphertext in [&c0, &c1] {
        assert_eq!(decrypt_with(&kms, "hsm::0::k", ciphertext).await?, b"hi");
    }

    // re-key: an addressed retired generation is refused, the keyset name rotates the head
    for retired in ["hsm::0::k@0", "hsm::0::k@first"] {
        let refused = rekey_as(&kms, retired, &admin()).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.to_string().contains("is not the latest in its keyset")),
            "{retired}: {refused:?}"
        );
    }
    assert!(!hsm.contains("k@2"));
    assert_eq!(rekey_as(&kms, "hsm::0::k", &admin()).await?, "hsm::0::k@2");
    assert_eq!(hsm.dates("k@2"), (Some(today()), Some(today() + days(30))));

    assert_reason(
        &encrypt_with(&kms, "hsm::0::k@1").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    let c2 = encrypt_with(&kms, "hsm::0::k").await?;
    assert_eq!(c2, b"k@2|hi");
    for ciphertext in [&c0, &c1, &c2] {
        assert_eq!(decrypt_with(&kms, "hsm::0::k", ciphertext).await?, b"hi");
    }
    Ok(())
}

#[tokio::test]
async fn rekey_addresses_resolve_to_the_head_or_are_refused() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);

    for retired in ["hsm::0::k@0", "hsm::0::k@first", "hsm::0::k@1"] {
        let refused = rekey_as(&kms, retired, &admin()).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.to_string().contains("is not the latest in its keyset")),
            "{retired}: {refused:?}"
        );
    }
    assert!(!hsm.contains("k@3"));
    assert_eq!(
        rekey_as(&kms, "hsm::0::k@2", &admin()).await?,
        "hsm::0::k@3"
    );
    assert_eq!(
        rekey_as(&kms, "hsm::0::k@latest", &admin()).await?,
        "hsm::0::k@4"
    );
    assert_eq!(rekey_as(&kms, "hsm::0::k", &admin()).await?, "hsm::0::k@5");
    // the previous heads are retired in CKA_LABEL
    assert_eq!(hsm.label("k@4").as_deref(), Some("hsm::0::k::4::k"));
    assert_eq!(hsm.label("k@5").as_deref(), Some("hsm::0::k::5::k@latest"));
    Ok(())
}

#[tokio::test]
async fn rekey_key_pair_refuses_a_retired_generation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_key_pair_generations(&hsm);

    for retired in ["hsm::0::kp@0", "hsm::0::kp@first"] {
        let refused = kms
            .rekey_keypair(
                ReKeyKeyPair {
                    private_key_unique_identifier: Some(uid(retired)),
                    ..ReKeyKeyPair::default()
                },
                &admin(),
            )
            .await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.to_string().contains("is not the latest in its keyset")),
            "{retired}: {refused:?}"
        );
    }
    assert!(!hsm.contains("kp@2"));
    Ok(())
}

#[tokio::test]
async fn hsm_rekey_error_reasons() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_key_pair(&hsm, "kp");
    hsm.insert("aes", KeyType::AesKey, 256, "aes", None, None);

    for missing in [
        "hsm::0::missing",
        "hsm::0::missing@latest",
        "hsm::0::missing@first",
        "hsm::0::missing@0",
    ] {
        assert_reason(
            &rekey_as(&kms, missing, &admin()).await,
            ErrorReason::Item_Not_Found,
        );
        assert_reason(
            &kms.rekey_keypair(
                ReKeyKeyPair {
                    private_key_unique_identifier: Some(uid(missing)),
                    ..ReKeyKeyPair::default()
                },
                &admin(),
            )
            .await,
            ErrorReason::Item_Not_Found,
        );
    }
    assert_reason(
        &rekey_as(&kms, "hsm::0::kp", &admin()).await,
        ErrorReason::Invalid_Object_Type,
    );
    for not_a_private_key in ["hsm::0::aes", "hsm::0::kp_pk"] {
        let refused = kms
            .rekey_keypair(
                ReKeyKeyPair {
                    private_key_unique_identifier: Some(uid(not_a_private_key)),
                    ..ReKeyKeyPair::default()
                },
                &admin(),
            )
            .await;
        assert_reason(&refused, ErrorReason::Invalid_Object_Type);
    }
    assert!(!hsm.contains("aes@1"));
    assert!(!hsm.contains("kp@1"));
    Ok(())
}

/// A user without any grant cannot tell an existing HSM key from a missing one, nor learn
/// its object type; a user with another grant is told it lacks the Rekey permission.
#[tokio::test]
async fn hsm_rekey_by_a_non_owner_reveals_nothing() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_key_pair(&hsm, "kp");
    hsm.insert("aes", KeyType::AesKey, 256, "aes", None, None);
    let bob = UserId::from("bob@acme.com");

    for uid_str in ["hsm::0::missing", "hsm::0::aes", "hsm::0::kp"] {
        assert_reason(
            &rekey_as(&kms, uid_str, &bob).await,
            ErrorReason::Item_Not_Found,
        );
    }

    // Resolving a keyset must not leak its head's UID in a not-found error.
    seed_three_generations(&hsm);
    seed_two_key_pair_generations(&hsm);
    kms.database.invalidate_rotate_name_cache("hsm::0::kp");
    for requested in [
        "hsm::0::k",
        "hsm::0::k@latest",
        "hsm::0::k@first",
        "hsm::0::kp",
        "hsm::0::kp@latest",
        "hsm::0::kp@first",
    ] {
        let missing = requested.replacen("::k", "::unknown", 1);
        let inaccessible = rekey_as(&kms, requested, &bob).await.unwrap_err();
        let absent = rekey_as(&kms, &missing, &bob).await.unwrap_err();
        assert_eq!(
            inaccessible.to_string().replace(requested, "<requested>"),
            absent.to_string().replace(&missing, "<requested>"),
            "ReKey must not distinguish an inaccessible keyset from a missing one"
        );
        let request = |id: &str| ReKeyKeyPair {
            private_key_unique_identifier: Some(uid(id)),
            ..ReKeyKeyPair::default()
        };
        let inaccessible = kms
            .rekey_keypair(request(requested), &bob)
            .await
            .unwrap_err();
        let absent = kms
            .rekey_keypair(request(&missing), &bob)
            .await
            .unwrap_err();
        assert_eq!(
            inaccessible.to_string().replace(requested, "<requested>"),
            absent.to_string().replace(&missing, "<requested>"),
            "ReKeyKeyPair must not disclose a resolved generation"
        );
    }

    kms.grant_access(
        &Access {
            unique_identifier: Some(uid("hsm::0::aes")),
            user_id: "bob@acme.com".to_owned(),
            operation_types: vec![KmipOperation::Encrypt],
        },
        &admin(),
    )
    .await?;
    let refused = rekey_as(&kms, "hsm::0::aes", &bob).await;
    assert!(
        matches!(refused, Err(KmsError::Unauthorized(_))),
        "{refused:?}"
    );
    assert!(!hsm.contains("aes@1"));
    Ok(())
}

#[tokio::test]
async fn hsm_rekey_at_the_maximum_generation_fails_cleanly() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert(
        "big@2147483647",
        KeyType::AesKey,
        256,
        "hsm::0::big::2147483647::big@latest",
        Some(today() - days(30)),
        Some(today()),
    );

    // the scheduler must neither panic nor rotate
    run_auto_rotation(&kms).await;
    assert_eq!(hsm.keys().len(), 1);

    let refused = rekey_as(&kms, "hsm::0::big@2147483647", &admin()).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("maximum generation")),
        "{refused:?}"
    );
    Ok(())
}

/// Validity dates without KMS keyset membership never opt a foreign key into rotation.
#[tokio::test]
async fn hsm_key_without_a_full_schedule_is_never_due() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    // e.g. a validity end date written by another PKCS#11 application
    hsm.insert(
        "lone",
        KeyType::AesKey,
        256,
        "lone",
        None,
        Some(today() - days(1)),
    );
    hsm.insert(
        "flat",
        KeyType::AesKey,
        256,
        "flat",
        Some(today() - days(1)),
        Some(today() - days(1)),
    );
    hsm.insert(
        "foreign",
        KeyType::AesKey,
        256,
        "foreign",
        Some(today() - days(30)),
        Some(today()),
    );

    run_auto_rotation(&kms).await;
    let mut warned = HashMap::new();
    dispatch_renewal_warnings(&kms, &mut warned).await;

    assert_eq!(hsm.keys().len(), 3);
    assert_eq!(hsm.label("lone").as_deref(), Some("lone"));
    assert_eq!(hsm.label("flat").as_deref(), Some("flat"));
    assert_eq!(hsm.label("foreign").as_deref(), Some("foreign"));
    assert_eq!(
        hsm.dates("foreign"),
        (Some(today() - days(30)), Some(today()))
    );
    assert!(warned.is_empty(), "{warned:?}");
    Ok(())
}

#[tokio::test]
async fn set_rotation_attributes_on_hsm_key() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert("solo", KeyType::AesKey, 256, "solo", None, None);

    // keyset membership: the name must be the base UID
    let error = set_hsm_attribute(
        &kms,
        "hsm::0::solo",
        Attribute::RotateName("other".to_owned()),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, KmsError::InvalidRequest(_))
            && error.to_string().contains("must be the key's base UID"),
        "{error:?}"
    );
    set_hsm_attribute(
        &kms,
        "hsm::0::solo",
        Attribute::RotateName("hsm::0::solo".to_owned()),
    )
    .await?;
    assert_eq!(
        hsm.label("solo").as_deref(),
        Some("hsm::0::solo::0::solo@latest")
    );

    // schedule: arm, refuse sub-day intervals, disarm
    set_hsm_attribute(&kms, "hsm::0::solo", Attribute::RotateInterval(30 * 86_400)).await?;
    let armed = (Some(today()), Some(today() + days(30)));
    assert_eq!(hsm.dates("solo"), armed);
    let error = set_hsm_attribute(&kms, "hsm::0::solo", Attribute::RotateInterval(3600))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, KmsError::InvalidRequest(_))
            && error.to_string().contains("must be at least 86400"),
        "{error:?}"
    );
    assert_eq!(hsm.dates("solo"), armed);

    // RotateAutomatic cannot be stored on a token: refused, schedule untouched
    for flag in [true, false] {
        let refused =
            set_hsm_attribute(&kms, "hsm::0::solo", Attribute::RotateAutomatic(flag)).await;
        assert!(
            matches!(refused, Err(KmsError::NotSupported(_))),
            "{flag}: {refused:?}"
        );
    }
    assert_eq!(hsm.dates("solo"), armed);

    set_hsm_attribute(&kms, "hsm::0::solo", Attribute::RotateInterval(0)).await?;
    assert_eq!(hsm.dates("solo"), (None, None));
    Ok(())
}

/// A key armed through `SetAttribute` is rotated by the scheduler once its end date passes.
#[tokio::test]
async fn key_armed_with_set_attribute_is_auto_rotated_when_due() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert("solo", KeyType::AesKey, 256, "solo", None, None);
    set_hsm_attribute(&kms, "hsm::0::solo", Attribute::RotateInterval(7 * 86_400)).await?;
    assert_eq!(
        hsm.label("solo").as_deref(),
        Some("hsm::0::solo::0::solo@latest")
    );

    run_auto_rotation(&kms).await;
    assert!(!hsm.contains("solo@1"), "not due yet");

    // the end date has passed
    hsm.set_key_dates(0, b"solo", Some(today() - days(7)), Some(today()))
        .await?;
    run_auto_rotation(&kms).await;
    assert_eq!(
        hsm.label("solo@1").as_deref(),
        Some("hsm::0::solo::1::solo@latest")
    );
    assert_eq!(
        hsm.dates("solo@1"),
        (Some(today()), Some(today() + days(7)))
    );
    assert_reason(
        &encrypt_with(&kms, "hsm::0::solo@0").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_eq!(encrypt_with(&kms, "hsm::0::solo").await?, b"solo@1|hi");
    Ok(())
}

/// After a key pair auto-rotation, only the new private key signs; every public key
/// generation still verifies.
#[tokio::test]
async fn rotated_key_pair_signs_with_head_and_verifies_old_signatures() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert(
        "kp",
        KeyType::RsaPrivateKey,
        2048,
        "hsm::0::kp::0::kp@latest",
        Some(today() - days(30)),
        Some(today()),
    );
    hsm.insert(
        "kp_pk",
        KeyType::RsaPublicKey,
        2048,
        "hsm::0::kp_pk::0::kp_pk@latest",
        None,
        None,
    );
    let old_signature = sign_with(&kms, "hsm::0::kp").await?;

    run_auto_rotation(&kms).await;
    assert_eq!(sign_with(&kms, "hsm::0::kp").await?, b"kp@1|msg");
    assert_reason(
        &sign_with(&kms, "hsm::0::kp@0").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_eq!(
        verify_with(&kms, "hsm::0::kp_pk", &old_signature).await?,
        ValidityIndicator::Valid
    );
    Ok(())
}

fn assert_hidden<T: std::fmt::Debug>(result: &KResult<T>) {
    assert!(
        matches!(
            result,
            Err(KmsError::ItemNotFound(_) | KmsError::Kmip21Error(ErrorReason::Item_Not_Found, _))
        ),
        "an unauthorized caller must not learn the key lifecycle: {result:?}"
    );
}

fn assert_fresh_head_or_refused(result: KResult<Vec<u8>>, expected: &[u8]) {
    match result {
        Ok(data) => assert_eq!(data, expected, "a cached retired head must never protect"),
        Err(error) => assert_reason(
            &Err::<Vec<u8>, _>(error),
            ErrorReason::Wrong_Key_Lifecycle_State,
        ),
    }
}

async fn grant_operations(
    kms: &KMS,
    address: &str,
    user: &str,
    operations: &[KmipOperation],
) -> KResult<()> {
    kms.grant_access(
        &Access {
            unique_identifier: Some(uid(address)),
            user_id: user.to_owned(),
            operation_types: operations.to_vec(),
        },
        &admin(),
    )
    .await
}

#[tokio::test]
async fn cached_unenrolled_key_cannot_protect_after_external_enrollment_and_rotation() -> KResult<()>
{
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert("k", KeyType::AesKey, 256, "k", None, None);
    assert_eq!(encrypt_with(&kms, "hsm::0::k").await?, b"k|hi");
    assert_eq!(mac_with(&kms, "hsm::0::k").await?, b"k|msg");

    // Bypass the KMS so its cached stub still has no RotateName.
    hsm.set_key_label(0, b"k", "hsm::0::k::0::k").await?;
    hsm.insert(
        "k@1",
        KeyType::AesKey,
        256,
        "hsm::0::k::1::k@latest",
        None,
        None,
    );

    for retired in ["hsm::0::k@0", "hsm::0::k@first"] {
        assert_reason(
            &encrypt_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
        assert_reason(
            &mac_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    assert_fresh_head_or_refused(encrypt_with(&kms, "hsm::0::k").await, b"k@1|hi");
    assert_fresh_head_or_refused(mac_with(&kms, "hsm::0::k").await, b"k@1|msg");
    assert_eq!(decrypt_with(&kms, "hsm::0::k", b"k|hi").await?, b"hi");
    Ok(())
}

#[tokio::test]
async fn cached_bare_and_latest_heads_cannot_protect_after_external_rotation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_generations(&hsm);
    for head in ["hsm::0::k", "hsm::0::k@latest", "hsm::0::k@1"] {
        assert_eq!(encrypt_with(&kms, head).await?, b"k@1|hi");
        assert_eq!(mac_with(&kms, head).await?, b"k@1|msg");
    }

    // Simulate a different KMS node rotating without invalidating this node's caches.
    seed_three_generations(&hsm);
    for head in ["hsm::0::k", "hsm::0::k@latest"] {
        assert_fresh_head_or_refused(encrypt_with(&kms, head).await, b"k@2|hi");
        assert_fresh_head_or_refused(mac_with(&kms, head).await, b"k@2|msg");
    }
    assert_reason(
        &encrypt_with(&kms, "hsm::0::k@1").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_reason(
        &mac_with(&kms, "hsm::0::k@1").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_eq!(encrypt_with(&kms, "hsm::0::k@2").await?, b"k@2|hi");
    Ok(())
}

#[tokio::test]
async fn cached_hsm_protection_fails_closed_when_live_keyset_scan_fails() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_generations(&hsm);
    let addresses = ["hsm::0::k", "hsm::0::k@latest", "hsm::0::k@1"];
    for address in addresses {
        assert_eq!(encrypt_with(&kms, address).await?, b"k@1|hi");
        assert_eq!(mac_with(&kms, address).await?, b"k@1|msg");
    }

    for (fault, message) in [
        (&hsm.fail_find, "injected find failure"),
        (&hsm.fail_metadata, "injected metadata failure"),
    ] {
        fault.store(true, Ordering::Relaxed);
        for address in addresses {
            let error = encrypt_with(&kms, address).await.unwrap_err();
            assert!(error.to_string().contains(message), "{address}: {error:?}");
            let error = mac_with(&kms, address).await.unwrap_err();
            assert!(error.to_string().contains(message), "{address}: {error:?}");
        }
        fault.store(false, Ordering::Relaxed);
        assert_eq!(encrypt_with(&kms, "hsm::0::k@1").await?, b"k@1|hi");
    }

    hsm.return_empty_scan.store(true, Ordering::Relaxed);
    assert_reason(
        &encrypt_with(&kms, "hsm::0::k@1").await,
        ErrorReason::Item_Not_Found,
    );
    assert_reason(
        &mac_with(&kms, "hsm::0::k@1").await,
        ErrorReason::Item_Not_Found,
    );
    hsm.return_empty_scan.store(false, Ordering::Relaxed);
    assert_eq!(encrypt_with(&kms, "hsm::0::k@1").await?, b"k@1|hi");
    Ok(())
}

#[tokio::test]
async fn hsm_encrypt_grants_are_per_member_and_never_a_get_wildcard() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);
    let bob = UserId::from("bob@acme.com");

    for hidden in ["hsm::0::k@0", "hsm::0::k@1", "hsm::0::missing@1"] {
        assert_hidden(&encrypt_as(&kms, hidden, &bob).await);
    }
    for member in ["hsm::0::k", "hsm::0::k@1", "hsm::0::k@2"] {
        grant_operations(&kms, member, "bob@acme.com", &[KmipOperation::Get]).await?;
    }
    for address in [
        "hsm::0::k",
        "hsm::0::k@latest",
        "hsm::0::k@2",
        "hsm::0::k@1",
    ] {
        let refused = encrypt_as(&kms, address, &bob).await;
        assert!(
            matches!(refused, Err(KmsError::Unauthorized(_))),
            "Get must not authorize HSM Encrypt, even on a retired key: {address}: {refused:?}"
        );
    }

    grant_operations(
        &kms,
        "hsm::0::k@2",
        "bob@acme.com",
        &[KmipOperation::Encrypt],
    )
    .await?;
    for head in ["hsm::0::k", "hsm::0::k@latest", "hsm::0::k@2"] {
        assert_eq!(encrypt_as(&kms, head, &bob).await?, b"k@2|hi", "{head}");
    }
    for (member, address) in [("hsm::0::k", "hsm::0::k@0"), ("hsm::0::k@1", "hsm::0::k@1")] {
        grant_operations(&kms, member, "bob@acme.com", &[KmipOperation::Encrypt]).await?;
        assert_reason(
            &encrypt_as(&kms, address, &bob).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    Ok(())
}

#[tokio::test]
async fn hsm_keyset_decrypt_requires_permission_on_each_generation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);
    let bob = UserId::from("bob@acme.com");
    grant_operations(
        &kms,
        "hsm::0::k@2",
        "bob@acme.com",
        &[KmipOperation::Decrypt],
    )
    .await?;
    assert_eq!(decrypt_as(&kms, "hsm::0::k", b"k@2|hi", &bob).await?, b"hi");

    for (member, address, ciphertext) in [
        ("hsm::0::k@1", "hsm::0::k@1", &b"k@1|hi"[..]),
        ("hsm::0::k", "hsm::0::k@0", &b"k|hi"[..]),
    ] {
        assert_hidden(&decrypt_as(&kms, address, ciphertext, &bob).await);
        // A grant on a different member permits trying that member, not this old key.
        let error = decrypt_as(&kms, "hsm::0::k", ciphertext, &bob)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("wrong key"), "{error:?}");
        grant_operations(&kms, member, "bob@acme.com", &[KmipOperation::Decrypt]).await?;
        assert_eq!(
            decrypt_as(&kms, address, ciphertext, &bob).await?,
            b"hi",
            "{address}"
        );
        assert_eq!(
            decrypt_as(&kms, "hsm::0::k", ciphertext, &bob).await?,
            b"hi",
            "{address}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rsa_public_encrypt_checks_live_head_for_generated_public_key_ids() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_key_pair_generations(&hsm);
    for head in ["hsm::0::kp_pk", "hsm::0::kp_pk@latest", "hsm::0::kp@1_pk"] {
        assert_eq!(encrypt_with(&kms, head).await?, b"kp@1|hi", "{head}");
    }

    hsm.set_key_label(0, b"kp@1_pk", "hsm::0::kp_pk::1::kp_pk")
        .await?;
    hsm.insert(
        "kp@2_pk",
        KeyType::RsaPublicKey,
        2048,
        "hsm::0::kp_pk::2::kp_pk@latest",
        None,
        None,
    );
    for retired in ["hsm::0::kp_pk@0", "hsm::0::kp_pk@first", "hsm::0::kp@1_pk"] {
        assert_reason(
            &encrypt_with(&kms, retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    for head in ["hsm::0::kp_pk", "hsm::0::kp_pk@latest"] {
        assert_fresh_head_or_refused(encrypt_with(&kms, head).await, b"kp@2|hi");
    }
    assert_eq!(encrypt_with(&kms, "hsm::0::kp@2_pk").await?, b"kp@2|hi");
    Ok(())
}

#[tokio::test]
async fn tag_addressed_cached_hsm_key_cannot_protect_after_external_rotation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert("k", KeyType::AesKey, 256, "k", None, None);
    hsm.keys()
        .get_mut(b"k".as_slice())
        .expect("seeded key")
        .tags
        .insert("protect-key".to_owned());
    let address = r#"["protect-key"]"#;
    assert_eq!(encrypt_with(&kms, address).await?, b"k|hi");
    assert_eq!(mac_with(&kms, address).await?, b"k|msg");

    hsm.set_key_label(0, b"k", "hsm::0::k::0::k").await?;
    hsm.insert(
        "k@1",
        KeyType::AesKey,
        256,
        "hsm::0::k::1::k@latest",
        None,
        None,
    );
    assert_reason(
        &encrypt_with(&kms, address).await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_reason(
        &mac_with(&kms, address).await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    Ok(())
}

#[tokio::test]
async fn keyset_decrypt_defaults_never_fall_back_to_unauthenticated_token_algorithms() -> KResult<()>
{
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_generations(&hsm);
    seed_two_key_pair_generations(&hsm);
    hsm.unauthenticated_only.store(true, Ordering::Relaxed);

    for (keyset, ciphertext) in [("hsm::0::k", &b"k|hi"[..]), ("hsm::0::kp", &b"kp|hi"[..])] {
        let error = decrypt_with(&kms, keyset, ciphertext).await.unwrap_err();
        assert!(
            error.to_string().contains("not supported"),
            "keyset walking must not silently use CBC or PKCS#1 v1.5: {keyset}: {error:?}"
        );
    }

    for (address, ciphertext, parameters) in [
        (
            "hsm::0::k@0",
            &b"k|hi"[..],
            CryptographicParameters {
                block_cipher_mode: Some(BlockCipherMode::CBC),
                ..CryptographicParameters::default()
            },
        ),
        (
            "hsm::0::kp@0",
            &b"kp|hi"[..],
            CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::PKCS1v15),
                ..CryptographicParameters::default()
            },
        ),
    ] {
        assert_eq!(
            decrypt_with_params(&kms, address, ciphertext, parameters).await?,
            b"hi",
            "{address}: an explicit generation is not a keyset walk"
        );
    }
    Ok(())
}

#[tokio::test]
async fn cached_hsm_sign_checks_live_head_and_fails_closed_on_scan_faults() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_two_key_pair_generations(&hsm);
    let addresses = ["hsm::0::kp", "hsm::0::kp@latest", "hsm::0::kp@1"];
    for address in addresses {
        assert_eq!(sign_with(&kms, address).await?, b"kp@1|msg");
    }
    for (fault, message) in [
        (&hsm.fail_find, "injected find failure"),
        (&hsm.fail_metadata, "injected metadata failure"),
    ] {
        fault.store(true, Ordering::Relaxed);
        for address in addresses {
            let error = sign_with(&kms, address).await.unwrap_err();
            assert!(error.to_string().contains(message), "{address}: {error:?}");
        }
        fault.store(false, Ordering::Relaxed);
    }
    hsm.return_empty_scan.store(true, Ordering::Relaxed);
    assert_reason(
        &sign_with(&kms, "hsm::0::kp@1").await,
        ErrorReason::Item_Not_Found,
    );
    hsm.return_empty_scan.store(false, Ordering::Relaxed);
    assert_eq!(sign_with(&kms, "hsm::0::kp@1").await?, b"kp@1|msg");

    hsm.set_key_label(0, b"kp@1", "hsm::0::kp::1::kp").await?;
    hsm.insert(
        "kp@2",
        KeyType::RsaPrivateKey,
        2048,
        "hsm::0::kp::2::kp@latest",
        None,
        None,
    );
    for head in ["hsm::0::kp", "hsm::0::kp@latest"] {
        assert_fresh_head_or_refused(sign_with(&kms, head).await, b"kp@2|msg");
    }
    assert_reason(
        &sign_with(&kms, "hsm::0::kp@1").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_eq!(sign_with(&kms, "hsm::0::kp@2").await?, b"kp@2|msg");
    Ok(())
}

#[tokio::test]
async fn hsm_key_addressed_by_uid_obeys_algorithm_policy() -> KResult<()> {
    let mut config = https_clap_config();
    config.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    config.kmip_policy.allowlists.aes_key_sizes = Some(vec![AesKeySize::Aes128]);
    let (kms, hsm) = kms_with_rotating_hsm_config(config).await?;
    hsm.insert("solo", KeyType::AesKey, 256, "solo", None, None);

    assert_reason(
        &encrypt_with(&kms, "hsm::0::solo").await,
        ErrorReason::Constraint_Violation,
    );
    assert_reason(
        &decrypt_with(&kms, "hsm::0::solo", b"solo|hi").await,
        ErrorReason::Constraint_Violation,
    );
    Ok(())
}

#[tokio::test]
async fn rekey_missing_explicit_hsm_generation_never_rotates_the_head() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_three_generations(&hsm);
    seed_two_key_pair_generations(&hsm);

    assert_reason(
        &rekey_as(&kms, "hsm::0::k@99", &admin()).await,
        ErrorReason::Item_Not_Found,
    );
    let refused = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid("hsm::0::kp@99")),
                ..ReKeyKeyPair::default()
            },
            &admin(),
        )
        .await;
    assert_reason(&refused, ErrorReason::Item_Not_Found);

    assert!(!hsm.contains("k@3"));
    assert!(!hsm.contains("kp@2"));
    assert!(!hsm.contains("kp@2_pk"));
    assert_eq!(hsm.label("k@2").as_deref(), Some("hsm::0::k::2::k@latest"));
    assert_eq!(
        hsm.label("kp@1").as_deref(),
        Some("hsm::0::kp::1::kp@latest")
    );
    assert_eq!(
        hsm.label("kp@1_pk").as_deref(),
        Some("hsm::0::kp_pk::1::kp_pk@latest")
    );
    assert_eq!(encrypt_with(&kms, "hsm::0::k").await?, b"k@2|hi");
    assert_eq!(sign_with(&kms, "hsm::0::kp").await?, b"kp@1|msg");
    Ok(())
}

#[tokio::test]
async fn rsa_pair_rotation_preserves_decryption_with_every_private_generation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    seed_key_pair(&hsm, "kp");
    let old_ciphertext = encrypt_with(&kms, "hsm::0::kp_pk").await?;
    assert_eq!(old_ciphertext, b"kp|hi");
    assert_eq!(
        decrypt_with(&kms, "hsm::0::kp", &old_ciphertext).await?,
        b"hi"
    );

    let rotated = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid("hsm::0::kp")),
                ..ReKeyKeyPair::default()
            },
            &admin(),
        )
        .await?;
    assert_eq!(
        rotated.private_key_unique_identifier.to_string(),
        "hsm::0::kp@1"
    );
    assert_eq!(
        rotated.public_key_unique_identifier.to_string(),
        "hsm::0::kp@1_pk"
    );
    let new_ciphertext = encrypt_with(&kms, "hsm::0::kp_pk").await?;
    assert_eq!(new_ciphertext, b"kp@1|hi");

    for (address, own_ciphertext, other_ciphertext) in [
        ("hsm::0::kp@0", &old_ciphertext, &new_ciphertext),
        ("hsm::0::kp@1", &new_ciphertext, &old_ciphertext),
    ] {
        assert_eq!(
            decrypt_with(&kms, "hsm::0::kp", own_ciphertext).await?,
            b"hi",
            "{address}: the bare keyset must find this generation"
        );
        assert_eq!(
            decrypt_with(&kms, address, own_ciphertext).await?,
            b"hi",
            "{address}"
        );
        let error = decrypt_with(&kms, address, other_ciphertext)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("wrong key"),
            "{address}: {error:?}"
        );
    }
    assert_eq!(
        decrypt_with(&kms, "hsm::0::kp@latest", &new_ciphertext).await?,
        b"hi"
    );
    let error = decrypt_with(&kms, "hsm::0::kp@latest", &old_ciphertext)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wrong key"), "{error:?}");
    assert_reason(
        &encrypt_with(&kms, "hsm::0::kp_pk@0").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    Ok(())
}

#[tokio::test]
async fn ec_pair_manual_rotation_signs_with_head_and_verifies_old_signatures() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert("ec", KeyType::EcPrivateKey, 256, "ec", None, None);
    hsm.insert("ec_pk", KeyType::EcPublicKey, 256, "ec_pk", None, None);
    let old_signature = sign_with(&kms, "hsm::0::ec").await?;
    assert_eq!(old_signature, b"ec|msg");

    let rotated = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid("hsm::0::ec")),
                ..ReKeyKeyPair::default()
            },
            &admin(),
        )
        .await?;
    assert_eq!(
        rotated.private_key_unique_identifier.to_string(),
        "hsm::0::ec@1"
    );
    assert_eq!(
        rotated.public_key_unique_identifier.to_string(),
        "hsm::0::ec@1_pk"
    );
    assert_eq!(hsm.key_type("ec@1"), Some(KeyType::EcPrivateKey));
    assert_eq!(hsm.key_type("ec@1_pk"), Some(KeyType::EcPublicKey));
    let new_signature = sign_with(&kms, "hsm::0::ec@latest").await?;
    assert_eq!(new_signature, b"ec@1|msg");
    assert_reason(
        &sign_with(&kms, "hsm::0::ec@0").await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    for signature in [&old_signature, &new_signature] {
        assert_eq!(
            verify_with(&kms, "hsm::0::ec_pk", signature).await?,
            ValidityIndicator::Valid
        );
    }
    assert_eq!(
        verify_with(&kms, "hsm::0::ec_pk@latest", &old_signature).await?,
        ValidityIndicator::Invalid
    );
    Ok(())
}

#[tokio::test]
async fn rekey_pair_with_missing_public_half_creates_no_new_generation() -> KResult<()> {
    let (kms, hsm) = kms_with_rotating_hsm().await?;
    hsm.insert("kp", KeyType::RsaPrivateKey, 2048, "kp", None, None);

    let refused = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid("hsm::0::kp")),
                ..ReKeyKeyPair::default()
            },
            &admin(),
        )
        .await;
    assert_reason(&refused, ErrorReason::Object_Not_Found);
    assert!(!hsm.contains("kp@1"));
    assert!(!hsm.contains("kp@1_pk"));
    assert_eq!(hsm.label("kp").as_deref(), Some("kp"));
    assert_eq!(hsm.keys().len(), 1);
    Ok(())
}

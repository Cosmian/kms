//! HSM authorization regression tests that run without a real HSM.
//!
//! A minimal in-memory [`HSM`] (`FakeHsm`) is wrapped by the real [`HsmStore`] and
//! registered on a KMS as both the `hsm` objects store and crypto oracle, so the exact
//! server code paths (unwrap oracle, keyset resolution, permission store) are exercised.
//!
//! The fake "cipher" is a bitwise NOT: enough to tell plaintext from ciphertext.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use cosmian_kms_access::access::Access;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeyPairIds, HsmKeypairAlgorithm,
    HsmObject, HsmObjectFilter, HsmStore, InterfaceError, InterfaceResult, KeyMaterial,
    KeyMetadata, KeyType, SigningAlgorithm, SigningKeyMetadata,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        KmipOperation,
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_data_structures::{
            KeyBlock, KeyMaterial as KmipKeyMaterial, KeyValue, KeyWrappingSpecification,
        },
        kmip_objects::{Object, ObjectType, SymmetricKey},
        kmip_operations::{Encrypt, Export, Import, Register},
        kmip_types::{
            CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation, KeyFormatType,
            UniqueIdentifier,
        },
        requests::symmetric_key_create_request,
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::ClapConfig,
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::test_utils::{https_clap_config, test_kms_with_config},
};

const ADMIN: &str = "hsm.admin@acme.com";
const GRANTEE: &str = "grantee@acme.com";
const OUTSIDER: &str = "outsider@acme.com";

/// HSM key used to "wrap" imported keys.
const HSM_KEY: &str = "hsm::0::wrapping_key";
/// Server KEK, configured as `key_encryption_key`.
const HSM_KEK: &str = "hsm::0::kek";
/// Bare keyset name (= `rotate_name`) of an HSM keyset, and its single member.
const HSM_KEYSET: &str = "hsm::0::keyset";
const HSM_KEYSET_MEMBER: &str = "hsm::0::keyset_g1";

struct FakeKey {
    bytes: Zeroizing<Vec<u8>>,
    rotate_name: Option<String>,
    rotate_generation: Option<i32>,
}

/// In-memory AES-only HSM with a single slot (0).
struct FakeHsm {
    keys: HashMap<Vec<u8>, FakeKey>,
}

impl FakeHsm {
    fn new() -> Self {
        let plain = |byte| FakeKey {
            bytes: Zeroizing::new(vec![byte; 32]),
            rotate_name: None,
            rotate_generation: None,
        };
        let mut keys = HashMap::new();
        keys.insert(b"wrapping_key".to_vec(), plain(1));
        keys.insert(b"kek".to_vec(), plain(2));
        keys.insert(
            b"keyset_g1".to_vec(),
            FakeKey {
                rotate_name: Some(HSM_KEYSET.to_owned()),
                rotate_generation: Some(1),
                ..plain(3)
            },
        );
        Self { keys }
    }
}

fn not_supported<T>() -> InterfaceResult<T> {
    Err(InterfaceError::NotSupported("fake HSM".to_owned()))
}

fn bitwise_not(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| !b).collect()
}

#[async_trait]
impl HSM for FakeHsm {
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
        Ok(self.keys.get(object_id).map(|key| {
            HsmObject::new(
                KeyMaterial::AesKey(key.bytes.clone()),
                String::from_utf8_lossy(object_id).into_owned(),
                HashSet::new(),
            )
        }))
    }

    async fn delete(&self, _slot_id: usize, _object_id: &[u8]) -> InterfaceResult<()> {
        not_supported()
    }

    async fn find(
        &self,
        _slot_id: usize,
        _object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        Ok(self.keys.keys().cloned().collect())
    }

    async fn encrypt<'a>(
        &'a self,
        _slot_id: usize,
        _key_id: &'a [u8],
        _algorithm: CryptoAlgorithm,
        data: &'a [u8],
        _iv_counter_nonce: &'a [u8],
    ) -> InterfaceResult<EncryptedContent> {
        Ok(EncryptedContent {
            ciphertext: bitwise_not(data),
            ..EncryptedContent::default()
        })
    }

    async fn decrypt(
        &self,
        _slot_id: usize,
        _key_id: &[u8],
        _algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(bitwise_not(data)))
    }

    async fn get_key_type(
        &self,
        _slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        Ok(self.keys.contains_key(key_id).then_some(KeyType::AesKey))
    }

    async fn get_key_metadata(
        &self,
        _slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        Ok(self.keys.get(key_id).map(|key| KeyMetadata {
            key_type: KeyType::AesKey,
            key_length_in_bits: key.bytes.len() * 8,
            sensitive: false,
            id: String::from_utf8_lossy(key_id).into_owned(),
            tags: HashSet::new(),
            curve: None,
            start_date: None,
            end_date: None,
            rotate_name: key.rotate_name.clone(),
            rotate_generation: key.rotate_generation,
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

/// KMS on a fresh `SQLite` database with `FakeHsm` mounted under the `hsm` prefix.
async fn kms_with_fake_hsm(with_kek: bool) -> KResult<Arc<KMS>> {
    let mut conf = https_clap_config();
    if with_kek {
        conf.key_encryption_key = Some(HSM_KEK.to_owned());
        // force every read of a KEK-wrapped key through the unwrap path
        conf.db.disable_unwrapped_cache = true;
    }
    kms_with_fake_hsm_conf(conf).await
}

/// KMS built from `conf` with `FakeHsm` mounted under the `hsm` prefix.
async fn kms_with_fake_hsm_conf(conf: ClapConfig) -> KResult<Arc<KMS>> {
    let kms = Box::pin(test_kms_with_config(conf)).await?;
    let store = HsmStore::new(
        Arc::new(FakeHsm::new()),
        &[ADMIN.to_owned()],
        kms.vendor_id(),
        "hsm",
    );
    kms.database
        .register_objects_store("hsm", Arc::new(store.clone()))
        .await;
    kms.register_crypto_oracle("hsm", Box::new(store)).await;
    Ok(kms)
}

async fn grant(kms: &KMS, uid: &str, user: &str, op: KmipOperation) -> KResult<()> {
    let access = Access {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        user_id: user.to_owned(),
        operation_types: vec![op],
    };
    kms.grant_access(&access, &UserId::from(ADMIN)).await
}

/// A 32-byte "wrapped" AES key whose wrapping key is the HSM key `wrapping_key_uid`.
fn key_wrapped_by(wrapping_key_uid: &str, ciphertext: &[u8]) -> Object {
    let key_wrapping_data = KeyWrappingSpecification {
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_uid.to_owned()),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..KeyWrappingSpecification::default()
    }
    .get_key_wrapping_data();
    Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: Some(KeyValue::ByteString(Zeroizing::new(ciphertext.to_vec()))),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: Some(key_wrapping_data),
        },
    })
}

/// `Import` the object as `user`, with the requested `key_wrap_type`.
async fn import_as(
    kms: &KMS,
    user: &str,
    object: Object,
    key_wrap_type: Option<KeyWrapType>,
) -> KResult<String> {
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(Uuid::new_v4().to_string()),
        object_type: ObjectType::SymmetricKey,
        replace_existing: None,
        key_wrap_type,
        attributes: Attributes::default(),
        object,
    };
    Ok(kms
        .import(request, &UserId::from(user))
        .await?
        .unique_identifier
        .to_string())
}

/// `Import` the object, asking the server to unwrap it, as `user`.
async fn import_unwrapped(kms: &KMS, user: &str, object: Object) -> KResult<String> {
    import_as(kms, user, object, Some(KeyWrapType::NotWrapped)).await
}

async fn is_stored_wrapped_by(kms: &KMS, uid: &str, wrapping_key_uid: &str) -> KResult<bool> {
    let owm = kms
        .database
        .retrieve_object_arc(uid)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(uid.to_owned()))?;
    Ok(owm
        .object()
        .key_block()?
        .key_wrapping_data
        .as_ref()
        .and_then(|data| data.encryption_key_information.as_ref())
        .and_then(|info| info.unique_identifier.as_str())
        == Some(wrapping_key_uid))
}

async fn stored_key_bytes(kms: &KMS, uid: &str) -> KResult<Vec<u8>> {
    let owm = kms
        .database
        .retrieve_object_arc(uid)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(uid.to_owned()))?;
    Ok(owm.object().key_block()?.key_bytes()?.to_vec())
}

async fn encrypt(kms: &KMS, user: &str, uid: &str) -> KResult<()> {
    let request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        data: Some(Zeroizing::new(b"plaintext".to_vec())),
        ..Encrypt::default()
    };
    kms.encrypt(request, &UserId::from(user)).await?;
    Ok(())
}

/// Importing a key "wrapped" by an HSM key decrypts it with that key: only the HSM
/// key's owners (HSM admins) and users holding an explicit `Decrypt` grant may do so.
///
/// Guards: COSMIAN-2025-009 (HSM unwrap bypassed KMS permission checks)
#[tokio::test]
async fn test_hsm_unwrap_on_import_requires_decrypt_grant() -> KResult<()> {
    let kms = kms_with_fake_hsm(false).await?;
    let ciphertext = [0x0F_u8; 32];

    // No grant at all: denied, and nothing is decrypted
    let denied = import_unwrapped(&kms, OUTSIDER, key_wrapped_by(HSM_KEY, &ciphertext)).await;
    assert!(
        matches!(denied, Err(KmsError::Unauthorized(_))),
        "an ungranted user must not unwrap with an HSM key: {denied:?}"
    );

    // `Encrypt` (or `Get`) does not imply the right to decrypt with an HSM key
    grant(&kms, HSM_KEY, GRANTEE, KmipOperation::Encrypt).await?;
    grant(&kms, HSM_KEY, GRANTEE, KmipOperation::Get).await?;
    let denied = import_unwrapped(&kms, GRANTEE, key_wrapped_by(HSM_KEY, &ciphertext)).await;
    assert!(
        matches!(denied, Err(KmsError::Unauthorized(_))),
        "Encrypt/Get grants must not allow unwrapping with an HSM key: {denied:?}"
    );

    // Explicit `Decrypt` grant: allowed
    grant(&kms, HSM_KEY, GRANTEE, KmipOperation::Decrypt).await?;
    let uid = import_unwrapped(&kms, GRANTEE, key_wrapped_by(HSM_KEY, &ciphertext)).await?;
    assert_eq!(
        stored_key_bytes(&kms, &uid).await?,
        bitwise_not(&ciphertext)
    );

    // HSM admin (owner): allowed
    let uid = import_unwrapped(&kms, ADMIN, key_wrapped_by(HSM_KEY, &ciphertext)).await?;
    assert_eq!(
        stored_key_bytes(&kms, &uid).await?,
        bitwise_not(&ciphertext)
    );
    Ok(())
}

/// The server KEK keeps unwrapping every user's keys at rest, but it is not a
/// decryption oracle for caller-supplied ciphertexts.
#[tokio::test]
async fn test_hsm_kek_unwraps_at_rest_but_not_on_import() -> KResult<()> {
    let kms = kms_with_fake_hsm(true).await?;

    // A non-admin user's key is wrapped at rest by the HSM KEK...
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let uid = kms
        .create(request, &UserId::from(OUTSIDER))
        .await?
        .unique_identifier
        .to_string();
    let stored = kms
        .database
        .retrieve_object_arc(&uid)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(uid.clone()))?;
    assert!(
        stored.object().is_wrapped(),
        "the key must be KEK-wrapped at rest"
    );

    // ...and remains usable by that user (unwrapped cache disabled)
    encrypt(&kms, OUTSIDER, &uid).await?;

    // The same user cannot have arbitrary data decrypted by the KEK through Import
    let denied = import_unwrapped(&kms, OUTSIDER, key_wrapped_by(HSM_KEK, &[0x0F; 32])).await;
    assert!(
        matches!(denied, Err(KmsError::Unauthorized(_))),
        "Import must not turn the server KEK into a decryption oracle: {denied:?}"
    );
    Ok(())
}

/// Storing a caller-supplied key block wrapped by the server KEK amounts to decrypting it
/// with the KEK (stored keys are unwrapped with the KEK for any user, so a later
/// `Get`/`Export` returns the decryption): only users allowed to decrypt with the KEK may do
/// it. Other imports keep working.
#[tokio::test]
async fn test_kek_wrapped_import_is_refused() -> KResult<()> {
    let kms = kms_with_fake_hsm(true).await?;
    let ciphertext = [0x0F_u8; 32];

    // Import and Register of a KEK-wrapped key block (also via the KEK `_pk` alias) by a user
    // who may not decrypt with the KEK — even holding Encrypt and Get on it: refused
    grant(&kms, HSM_KEK, OUTSIDER, KmipOperation::Encrypt).await?;
    grant(&kms, HSM_KEK, OUTSIDER, KmipOperation::Get).await?;
    let kek_pk = format!("{HSM_KEK}_pk");
    for kek_uid in [HSM_KEK, kek_pk.as_str()] {
        let refused = import_as(&kms, OUTSIDER, key_wrapped_by(kek_uid, &ciphertext), None).await;
        assert!(
            matches!(refused, Err(KmsError::InvalidRequest(_))),
            "a key wrapped by the server KEK ({kek_uid}) must not be imported: {refused:?}"
        );
    }
    let register = Register {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes::default(),
        object: key_wrapped_by(HSM_KEK, &ciphertext),
        protection_storage_masks: None,
    };
    let refused = kms.register(register, &UserId::from(OUTSIDER)).await;
    assert!(
        matches!(refused, Err(KmsError::InvalidRequest(_))),
        "a key wrapped by the server KEK must not be registered: {refused:?}"
    );

    // The HSM admin, and a user granted Decrypt on the KEK: accepted, and Get unwraps it
    grant(&kms, HSM_KEK, GRANTEE, KmipOperation::Decrypt).await?;
    for user in [ADMIN, GRANTEE] {
        for kek_uid in [HSM_KEK, kek_pk.as_str()] {
            let uid = import_as(&kms, user, key_wrapped_by(kek_uid, &ciphertext), None).await?;
            assert!(is_stored_wrapped_by(&kms, &uid, kek_uid).await?);
            let export = Export {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                key_wrap_type: Some(KeyWrapType::NotWrapped),
                ..Export::default()
            };
            let exported = kms.export(export, &UserId::from(user)).await?.object;
            assert_eq!(
                exported.key_block()?.key_bytes()?.to_vec(),
                bitwise_not(&ciphertext)
            );
        }
    }

    // A plain key is imported and wrapped by the KEK at rest
    let plain = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KmipKeyMaterial::ByteString(Zeroizing::new(vec![7; 32])),
                attributes: None,
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });
    let uid = import_as(&kms, OUTSIDER, plain, None).await?;
    assert!(is_stored_wrapped_by(&kms, &uid, HSM_KEK).await?);

    // A key wrapped by another key is stored as-is
    let uid = import_as(&kms, OUTSIDER, key_wrapped_by(HSM_KEY, &ciphertext), None).await?;
    assert!(is_stored_wrapped_by(&kms, &uid, HSM_KEY).await?);
    Ok(())
}

/// A bare HSM base UID resolves to the latest keyset member: the caller must be
/// authorized on that member, and a refusal must not reveal it exists.
///
/// Guards: COSMIAN-2026-037 (existence and state oracle in key selection)
#[tokio::test]
async fn test_bare_hsm_keyset_uid_requires_grant() -> KResult<()> {
    let kms = kms_with_fake_hsm(false).await?;

    let denied = encrypt(&kms, OUTSIDER, HSM_KEYSET).await;
    assert!(
        matches!(denied, Err(KmsError::ItemNotFound(_))),
        "an ungranted user must not use a bare HSM keyset UID: {denied:?}"
    );

    grant(&kms, HSM_KEYSET_MEMBER, GRANTEE, KmipOperation::Decrypt).await?;
    let denied = encrypt(&kms, GRANTEE, HSM_KEYSET).await;
    assert!(
        matches!(denied, Err(KmsError::Unauthorized(_))),
        "a Decrypt grant must not allow Encrypt with a keyset member: {denied:?}"
    );

    grant(&kms, HSM_KEYSET_MEMBER, GRANTEE, KmipOperation::Encrypt).await?;
    encrypt(&kms, GRANTEE, HSM_KEYSET).await?;
    encrypt(&kms, ADMIN, HSM_KEYSET).await?;
    Ok(())
}

/// `Create` a 256-bit AES key wrapped at rest by the HSM key `wrapping_key_uid`, as `user`.
async fn create_key_wrapped_by(kms: &KMS, user: &str, wrapping_key_uid: &str) -> KResult<String> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        Some(&wrapping_key_uid.to_owned()),
    )?;
    Ok(kms
        .create(request, &UserId::from(user))
        .await?
        .unique_identifier
        .to_string())
}

/// Wrapping with an HSM key encrypts with it: like a direct Encrypt, it needs HSM admin
/// rights or an explicit `Encrypt` grant (`Get` is no wildcard), and using the wrapped key
/// afterwards needs `Decrypt` on the HSM key.
#[tokio::test]
async fn test_hsm_wrap_requires_encrypt_grant() -> KResult<()> {
    let kms = kms_with_fake_hsm(false).await?;

    grant(&kms, HSM_KEY, GRANTEE, KmipOperation::Get).await?;
    let denied = create_key_wrapped_by(&kms, GRANTEE, HSM_KEY).await;
    assert!(
        matches!(denied, Err(KmsError::Unauthorized(_))),
        "a Get grant must not allow wrapping with an HSM key: {denied:?}"
    );

    grant(&kms, HSM_KEY, GRANTEE, KmipOperation::Encrypt).await?;
    let uid = create_key_wrapped_by(&kms, GRANTEE, HSM_KEY).await?;
    // the creation warmed the unwrapped cache: using the key still needs Decrypt on HSM_KEY
    let denied = encrypt(&kms, GRANTEE, &uid).await;
    assert!(
        denied.is_err(),
        "using a key wrapped by an HSM key needs Decrypt on it: {denied:?}"
    );
    grant(&kms, HSM_KEY, GRANTEE, KmipOperation::Decrypt).await?;
    encrypt(&kms, GRANTEE, &uid).await?;

    create_key_wrapped_by(&kms, ADMIN, HSM_KEY).await?;
    Ok(())
}

/// The unwrapped cache is shared by all users: a hit must be authorized exactly like a
/// miss, whoever warmed the cache.
#[tokio::test]
async fn test_unwrapped_cache_hit_is_authorized_like_a_miss() -> KResult<()> {
    for disable_unwrapped_cache in [false, true] {
        let mut conf = https_clap_config();
        conf.db.disable_unwrapped_cache = disable_unwrapped_cache;
        let kms = kms_with_fake_hsm_conf(conf).await?;

        // ADMIN's key K, wrapped by the HSM key H, is read by ADMIN (warming the cache)
        let uid = create_key_wrapped_by(&kms, ADMIN, HSM_KEY).await?;
        encrypt(&kms, ADMIN, &uid).await?;

        // OUTSIDER may use K but not H: denied, cache hit or miss
        grant(&kms, &uid, OUTSIDER, KmipOperation::Encrypt).await?;
        grant(&kms, &uid, OUTSIDER, KmipOperation::Decrypt).await?;
        let denied = encrypt(&kms, OUTSIDER, &uid).await;
        assert!(
            denied
                .as_ref()
                .is_err_and(|e| e.to_string().contains("permission to unwrap")),
            "unwrapped cache disabled: {disable_unwrapped_cache}; a user without Decrypt on \
             the wrapping HSM key must not use the wrapped key: {denied:?}"
        );

        grant(&kms, HSM_KEY, OUTSIDER, KmipOperation::Decrypt).await?;
        encrypt(&kms, OUTSIDER, &uid).await?;
    }
    Ok(())
}

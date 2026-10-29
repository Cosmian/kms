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
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CertificateType, KeyWrapType},
        kmip_2_1::{
            KmipOperation,
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_data_structures::{
                KeyBlock, KeyMaterial as KmipKeyMaterial, KeyValue, KeyWrappingSpecification,
            },
            kmip_objects::{Certificate, Object, ObjectType, SymmetricKey},
            kmip_operations::{Encrypt, Export, Import, Register},
            kmip_types::{
                CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation, KeyFormatType,
                Link, LinkType, LinkedObjectIdentifier, UniqueIdentifier,
            },
            requests::{create_rsa_key_pair_request, symmetric_key_create_request},
        },
    },
    cosmian_kms_crypto::crypto::symmetric::rfc5649::rfc5649_wrap,
};
use openssl::x509::X509;
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
const VICTIM: &str = "victim@acme.com";

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
            assert_eq!(
                export_unwrapped_bytes(&kms, user, &uid).await?,
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

/// `Export` the key `uid` unwrapped (`KeyWrapType::NotWrapped`), as `user`.
async fn export_unwrapped(kms: &KMS, user: &str, uid: &str) -> KResult<Object> {
    let export = Export {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        ..Export::default()
    };
    Ok(kms.export(export, &UserId::from(user)).await?.object)
}

async fn export_unwrapped_bytes(kms: &KMS, user: &str, uid: &str) -> KResult<Vec<u8>> {
    Ok(export_unwrapped(kms, user, uid)
        .await?
        .key_block()?
        .key_bytes()?
        .to_vec())
}

/// Replace the wrapping key UID recorded in the wrapped `object`.
fn set_wrapping_key_uid(object: &mut Object, wrapping_key_uid: UniqueIdentifier) -> KResult<()> {
    object
        .key_block_mut()?
        .key_wrapping_data
        .as_mut()
        .and_then(|data| data.encryption_key_information.as_mut())
        .ok_or_else(|| KmsError::ServerError("the object is not wrapped".to_owned()))?
        .unique_identifier = wrapping_key_uid;
    Ok(())
}

/// One of `user`'s own RSA public keys.
async fn own_public_key(kms: &KMS, user: &str) -> KResult<Object> {
    let request =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let public_key = kms
        .create_key_pair(request, &UserId::from(user))
        .await?
        .public_key_unique_identifier
        .to_string();
    export_unwrapped(kms, user, &public_key).await
}

/// Any certificate (certificates are not wrapped at rest, whatever the KEK).
fn a_certificate() -> KResult<Object> {
    let pem = include_bytes!("../../../../../test_data/certificates/client_server/ca/ca.crt");
    Ok(Object::Certificate(Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: X509::from_pem(pem)?.to_der()?,
    }))
}

/// As `user`, `Import` `object` (a public key or certificate) under `uid` with a
/// `PrivateKeyLink` to `private_key_uid`: a user-made alias of that key.
async fn import_alias(
    kms: &KMS,
    user: &str,
    uid: &str,
    private_key_uid: &str,
    object: Object,
) -> KResult<()> {
    let request = Import {
        unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
        object_type: object.object_type(),
        replace_existing: None,
        key_wrap_type: None,
        attributes: Attributes {
            link: Some(vec![Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    private_key_uid.to_owned(),
                ),
            }]),
            ..Attributes::default()
        },
        object,
    };
    kms.import(request, &UserId::from(user)).await?;
    Ok(())
}

/// A user holding only `Create` and a ciphertext `wrapped` under the server KEK `kek` cannot
/// have it decrypted through an alias (`alias_object`, a public key or certificate) whose
/// `PrivateKeyLink` points at the KEK.
async fn assert_kek_alias_is_no_oracle(
    kms: &KMS,
    kek: &str,
    wrapped: &Object,
    alias_object: &Object,
) -> KResult<()> {
    let wrapped_by = |alias: &str| -> KResult<Object> {
        let mut object = wrapped.clone();
        set_wrapping_key_uid(&mut object, UniqueIdentifier::TextString(alias.to_owned()))?;
        Ok(object)
    };

    // The alias exists: storing a block wrapped by it is refused
    let alias = format!("alias-{}", Uuid::new_v4());
    import_alias(kms, OUTSIDER, &alias, kek, alias_object.clone()).await?;
    let refused = import_as(kms, OUTSIDER, wrapped_by(&alias)?, None).await;
    assert!(
        matches!(refused, Err(KmsError::InvalidRequest(_))),
        "a key wrapped by an alias of the server KEK must not be imported: {refused:?}"
    );

    // The block is stored before the alias exists: reading it unwrapped is refused
    let alias = format!("alias-{}", Uuid::new_v4());
    let uid = import_as(kms, OUTSIDER, wrapped_by(&alias)?, None).await?;
    import_alias(kms, OUTSIDER, &alias, kek, alias_object.clone()).await?;
    let leaked = export_unwrapped(kms, OUTSIDER, &uid).await.map(|_| ());
    assert!(
        leaked.is_err(),
        "the server KEK must not decrypt through a user-made alias: {leaked:?}"
    );
    Ok(())
}

/// HSM KEK (exportable): a user-made alias of the KEK is no decryption oracle.
#[tokio::test]
async fn test_hsm_kek_alias_is_no_decryption_oracle() -> KResult<()> {
    let kms = kms_with_fake_hsm(true).await?;
    // the fake HSM KEK exports its bytes ([2; 32]): unwrapping through an alias runs in software
    let wrapped = key_wrapped_by("alias", &rfc5649_wrap(&[0x5A; 32], &[2; 32])?);
    for alias_object in [own_public_key(&kms, OUTSIDER).await?, a_certificate()?] {
        assert_kek_alias_is_no_oracle(&kms, HSM_KEK, &wrapped, &alias_object).await?;
    }
    Ok(())
}

/// KMS whose `key_encryption_key` is the database key `kek` owned by `ADMIN`: an AES key, or
/// an RSA private key wrapping with RSA-OAEP.
async fn kms_with_db_kek(kek: &str, rsa: bool) -> KResult<Arc<KMS>> {
    let conf = https_clap_config();
    let sqlite_path = conf.db.sqlite_path.clone();
    let kms = Box::pin(test_kms_with_config(conf)).await?;
    let kek_uid = Some(UniqueIdentifier::TextString(kek.to_owned()));
    if rsa {
        let request =
            create_rsa_key_pair_request(VENDOR_ID_COSMIAN, kek_uid, EMPTY_TAGS, 2048, false, None)?;
        kms.create_key_pair(request, &UserId::from(ADMIN)).await?;
    } else {
        let request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            kek_uid,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        kms.create(request, &UserId::from(ADMIN)).await?;
    }
    drop(kms);

    let mut conf = https_clap_config();
    conf.db.sqlite_path = sqlite_path;
    conf.db.disable_unwrapped_cache = true;
    conf.key_encryption_key = Some(kek.to_owned());
    conf.key_encryption_key_wrapping_algorithm = rsa.then(|| "rsa-oaep".to_owned());
    Box::pin(test_kms_with_config(conf)).await
}

/// A key of `VICTIM`, wrapped at rest by the server KEK: its stored (wrapped) object, and the
/// key bytes `VICTIM` reads back.
async fn victim_key(kms: &KMS) -> KResult<(Object, Vec<u8>)> {
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
        .create(request, &UserId::from(VICTIM))
        .await?
        .unique_identifier
        .to_string();
    let stored = kms
        .database
        .retrieve_object_arc(&uid)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(uid.clone()))?
        .object()
        .clone();
    assert!(stored.is_wrapped(), "the key must be KEK-wrapped at rest");
    // the owner reads its key at rest (unwrapped cache disabled)
    Ok((stored, export_unwrapped_bytes(kms, VICTIM, &uid).await?))
}

/// Database KEK (AES, and RSA): a user-made alias of the KEK is no decryption oracle, while
/// at-rest reads and imports by users allowed to decrypt with the KEK keep working.
#[tokio::test]
async fn test_db_kek_alias_is_no_decryption_oracle() -> KResult<()> {
    for rsa in [false, true] {
        let kek = format!("kek-{}", Uuid::new_v4());
        let kms = kms_with_db_kek(&kek, rsa).await?;
        let (wrapped, secret) = victim_key(&kms).await?;
        let mut alias_objects = vec![a_certificate()?];
        // RSA-OAEP cannot wrap an RSA private key at rest: no own key pair with an RSA KEK
        if !rsa {
            alias_objects.push(own_public_key(&kms, OUTSIDER).await?);
        }
        for alias_object in &alias_objects {
            assert_kek_alias_is_no_oracle(&kms, &kek, &wrapped, alias_object).await?;
        }

        // The KEK owner, and a user granted Decrypt on the KEK: the KEK-wrapped block is
        // accepted and reads back unwrapped
        grant(&kms, &kek, GRANTEE, KmipOperation::Decrypt).await?;
        for user in [ADMIN, GRANTEE] {
            let uid = import_as(&kms, user, wrapped.clone(), None).await?;
            assert_eq!(export_unwrapped_bytes(&kms, user, &uid).await?, secret);
        }
    }
    Ok(())
}

/// A numeric `UniqueIdentifier` naming the KEK is the KEK: storing a block wrapped by it needs
/// the right to decrypt with the KEK.
#[tokio::test]
async fn test_numeric_kek_uid_wrapped_import_is_refused() -> KResult<()> {
    let kms = kms_with_db_kek("42", false).await?;
    let (mut wrapped, secret) = victim_key(&kms).await?;
    set_wrapping_key_uid(&mut wrapped, UniqueIdentifier::Integer(42))?;

    let refused = import_as(&kms, OUTSIDER, wrapped.clone(), None).await;
    assert!(
        matches!(refused, Err(KmsError::InvalidRequest(_))),
        "a key wrapped by the numeric server KEK UID must not be imported: {refused:?}"
    );
    let uid = import_as(&kms, ADMIN, wrapped, None).await?;
    assert_eq!(export_unwrapped_bytes(&kms, ADMIN, &uid).await?, secret);
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

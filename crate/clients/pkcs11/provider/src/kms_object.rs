use std::{fmt, path::PathBuf, sync::OnceLock, vec};

use ckms::{
    config::ClientConfig,
    reexport::cosmian_kms_cli_actions::reexport::{
        cosmian_kmip::{
            self,
            kmip_0::kmip_types::{
                BlockCipherMode, CryptographicUsageMask, HashingAlgorithm, MaskGenerator,
                PaddingMethod, RevocationReason, RevocationReasonCode, SecretDataType,
            },
            kmip_2_1::{
                extra::{
                    VENDOR_ID_COSMIAN,
                    tagging::{SYSTEM_TAG_SECRET_DATA, SYSTEM_TAG_SYMMETRIC_KEY},
                },
                kmip_attributes::Attributes,
                kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
                kmip_objects::{Object, ObjectType, SecretData, SymmetricKey},
                kmip_operations::{
                    Activate, Decrypt, Destroy, Encrypt, GetAttributes, Import, Locate, Query,
                    Revoke, Sign, SignatureVerify,
                },
                kmip_types::{
                    AttributeReference, CryptographicAlgorithm, CryptographicParameters,
                    DigitalSignatureAlgorithm, KeyFormatType, QueryFunction, RecommendedCurve, Tag,
                    UniqueIdentifier, ValidityIndicator,
                },
                requests::symmetric_key_create_request,
            },
        },
        cosmian_kms_client::{
            ExportObjectParams, KmsClient, KmsClientConfig, batch_export_objects, export_object,
        },
        cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            CsRng,
            reexport::rand_core::{RngCore, SeedableRng},
        },
    },
};
use cosmian_logger::{debug, error, trace};
use cosmian_pkcs11_module::{
    profiling::{self, SignPhase},
    traits::{
        DecryptContext, DigestType, EncryptContext, EncryptionAlgorithm, KeyAlgorithm,
        MessageEncryptionOutput, SignatureAlgorithm,
    },
};
use zeroize::Zeroizing;

use crate::error::{Pkcs11Error, result::Pkcs11Result};

/// The GCM authentication tag length (in bytes) used by the KMS's AES-GCM backend
/// (`AES_128_GCM_MAC_LENGTH`/`AES_192_GCM_MAC_LENGTH`/`AES_256_GCM_MAC_LENGTH` in
/// `crate/crypto` are all 16 bytes / 128 bits). `CKM_AES_GCM` mechanism parsing on the
/// module side (`cosmian_pkcs11_module`) rejects any other `ulTagBits` value, so this
/// constant is always correct for data reaching this function.
const AES_GCM_TAG_LENGTH: usize = 16;

/// Shared Tokio runtime — created once, reused for every blocking KMS call.
/// Avoids the overhead (and potential `io::Error`) of spinning up a runtime per call.
///
/// Also entered (via `RUNTIME.enter()`) around synchronous `KmsClient` construction in
/// `C_GetFunctionList`: that entrypoint is invoked directly by PKCS#11 consumers (e.g. SAP
/// ASE) with no Tokio runtime active, and the underlying `hyper` client requires one.
pub(crate) static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> =
    std::sync::LazyLock::new(|| {
        tokio::runtime::Runtime::new().unwrap_or_else(|e| {
            // Runtime creation can only fail due to OS resource exhaustion; no
            // recovery is possible, so terminate the process immediately.
            eprintln!("FATAL: failed to create Tokio runtime: {e}");
            std::process::abort()
        })
    });

/// Query the KMS server for its vendor identification string.
///
/// Falls back to `VENDOR_ID_COSMIAN` if the server doesn't report one.
pub(crate) fn query_vendor_id(client: &KmsClient) -> String {
    RUNTIME
        .block_on(async {
            let request = Query {
                query_function: Some(vec![QueryFunction::QueryServerInformation]),
            };
            client
                .query(request)
                .await
                .ok()
                .and_then(|resp| resp.vendor_identification)
        })
        .unwrap_or_else(|| VENDOR_ID_COSMIAN.to_owned())
}

/// Write-once, read-many holder for sensitive key material.
///
/// Replaces the `Arc<RwLock<Zeroizing<Vec<u8>>>>` + empty-vec sentinel pattern
/// with a lock-free `OnceLock`, removing the poisonable mutex and clarifying
/// the "set at most once" semantics.
pub(crate) struct LazyKeyMaterial(OnceLock<Zeroizing<Vec<u8>>>);

impl LazyKeyMaterial {
    /// Unloaded — material will be fetched on first access.
    pub(crate) const fn new() -> Self {
        Self(OnceLock::new())
    }

    /// Pre-populated — material is already available.
    pub(crate) fn preloaded(bytes: Zeroizing<Vec<u8>>) -> Self {
        let cell = OnceLock::new();
        // cell is freshly created, so set() always succeeds.
        drop(cell.set(bytes));
        Self(cell)
    }

    /// Return the key material, calling `fetch` exactly once if not yet loaded.
    /// Thread-safe: concurrent calls are serialised by `OnceLock`; the loser's
    /// fetched copy is dropped (and therefore zeroized) automatically.
    pub(crate) fn get_or_fetch<E, F>(&self, fetch: F) -> Result<Zeroizing<Vec<u8>>, E>
    where
        F: FnOnce() -> Result<Zeroizing<Vec<u8>>, E>,
    {
        if let Some(bytes) = self.0.get() {
            return Ok(bytes.clone());
        }
        let fetched = fetch()?;
        // Clone before calling set() so we always have a value to return,
        // regardless of whether this thread wins or loses a concurrent race.
        let to_return = fetched.clone();
        // Best-effort store: if another thread already filled the cell,
        // set() returns Err(fetched) which is explicitly dropped (and zeroed).
        drop(self.0.set(fetched));
        Ok(to_return)
    }
}

impl fmt::Debug for LazyKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LazyKeyMaterial")
            .field(&if self.0.get().is_some() {
                "loaded"
            } else {
                "unloaded"
            })
            .finish()
    }
}

/// A wrapper around a KMS KMIP object.
#[allow(dead_code)]
pub(crate) struct KmsObject {
    pub remote_id: String,
    pub object: Object,
    pub attributes: Attributes,
    pub other_tags: Vec<String>,
}

/// Load the `KmsClientConfig` from `ckms.toml` without creating a `KmsClient`.
/// Used by `C_GetFunctionList` when OIDC-pin mode is active (mode 2).
pub(crate) fn get_kms_config(conf_path: Option<PathBuf>) -> Pkcs11Result<KmsClientConfig> {
    Ok(ClientConfig::load(conf_path)?.kms_config)
}

pub(crate) fn locate_kms_objects(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<String>> {
    RUNTIME.block_on(locate_kms_objects_async(kms_rest_client, vendor_id, tags))
}

pub(crate) async fn locate_kms_objects_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<String>> {
    locate_objects(kms_rest_client, vendor_id, tags).await
}

/// Locate and export only `SecretData` objects with the given tags.
/// This is stricter than `get_kms_objects` because it adds an `ObjectType=SecretData`
/// filter to the Locate request, preventing false matches with `SymmetricKey` objects that
/// happen to carry the same tag (e.g. old TDE master keys tagged with `_sd`).
pub(crate) fn get_kms_secret_data_objects(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<KmsObject>> {
    RUNTIME.block_on(get_kms_secret_data_objects_async(
        kms_rest_client,
        vendor_id,
        tags,
    ))
}

/// Locate and export only `Certificate` objects with the given tags.
/// This adds an `ObjectType=Certificate` filter to the Locate request, preventing
/// false matches with non-certificate objects (e.g. symmetric disk-encryption keys
/// that share the same disk-encryption tag) which cannot be exported as X509 and
/// would otherwise cause the entire batch export to fail with `CKR_GENERAL_ERROR`.
pub(crate) fn get_kms_certificate_objects(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<KmsObject>> {
    RUNTIME.block_on(get_kms_certificate_objects_async(
        kms_rest_client,
        vendor_id,
        tags,
    ))
}

async fn get_kms_certificate_objects_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<KmsObject>> {
    let key_ids = locate_objects_of_type(
        kms_rest_client,
        vendor_id,
        tags,
        Some(ObjectType::Certificate),
    )
    .await?;
    if key_ids.is_empty() {
        trace!(
            "get_kms_certificate_objects_async: no Certificate objects found for tags: {:?}",
            tags
        );
        return Ok(vec![]);
    }
    let export_object_params = ExportObjectParams {
        unwrap: true,
        key_format_type: Some(KeyFormatType::X509),
        ..Default::default()
    };
    let responses = batch_export_objects(kms_rest_client, key_ids, export_object_params).await?;
    trace!(
        "get_kms_certificate_objects_async: found {} Certificate objects",
        responses.len()
    );
    let mut results = vec![];
    for (id, object, attributes) in responses {
        let other_tags = attributes
            .get_tags(vendor_id)
            .into_iter()
            .filter(|t| !t.is_empty() && !tags.contains(t) && !t.starts_with('_'))
            .collect::<Vec<String>>();
        results.push(KmsObject {
            remote_id: id.to_string(),
            object,
            attributes,
            other_tags,
        });
    }
    Ok(results)
}

async fn get_kms_secret_data_objects_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<KmsObject>> {
    let key_ids = locate_objects_of_type(
        kms_rest_client,
        vendor_id,
        tags,
        Some(ObjectType::SecretData),
    )
    .await?;
    if key_ids.is_empty() {
        trace!(
            "get_kms_secret_data_objects_async: no SecretData objects found for tags: {:?}",
            tags
        );
        return Ok(vec![]);
    }
    let export_object_params = ExportObjectParams {
        unwrap: true,
        key_format_type: Some(KeyFormatType::Raw),
        ..Default::default()
    };
    let responses = batch_export_objects(kms_rest_client, key_ids, export_object_params).await?;
    trace!(
        "get_kms_secret_data_objects_async: found {} SecretData objects",
        responses.len()
    );
    let mut results = vec![];
    for (id, object, attributes) in responses {
        let other_tags = attributes
            .get_tags(vendor_id)
            .into_iter()
            .filter(|t| !t.is_empty() && !tags.contains(t) && !t.starts_with('_'))
            .collect::<Vec<String>>();
        results.push(KmsObject {
            remote_id: id.to_string(),
            object,
            attributes,
            other_tags,
        });
    }
    Ok(results)
}

/// Locate disk-encryption symmetric keys and return them as `KmsObject`s suitable
/// for wrapping as PKCS#11 `CKO_DATA` objects.
///
/// `VeraCrypt` discovers keyfiles via `C_FindObjects` with `CKA_CLASS = CKO_DATA`.
/// This function locates `SymmetricKey` objects tagged with `disk_encryption_tag`,
/// exports them, and rewrites `remote_id` to the first user-visible tag (e.g. `"vol1"`)
/// so the label shown in the `VeraCrypt` GUI is meaningful.
pub(crate) fn get_kms_disk_encryption_data_objects(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    disk_encryption_tag: &str,
) -> Pkcs11Result<Vec<KmsObject>> {
    RUNTIME.block_on(get_kms_disk_encryption_data_objects_async(
        kms_rest_client,
        vendor_id,
        disk_encryption_tag,
    ))
}

async fn get_kms_disk_encryption_data_objects_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    disk_encryption_tag: &str,
) -> Pkcs11Result<Vec<KmsObject>> {
    let tags = [
        disk_encryption_tag.to_owned(),
        SYSTEM_TAG_SYMMETRIC_KEY.to_owned(),
    ];
    let key_ids = locate_objects_of_type(
        kms_rest_client,
        vendor_id,
        &tags,
        Some(ObjectType::SymmetricKey),
    )
    .await?;
    if key_ids.is_empty() {
        trace!(
            "get_kms_disk_encryption_data_objects_async: no SymmetricKey objects found for tag: \
             {disk_encryption_tag}",
        );
        return Ok(vec![]);
    }
    let export_object_params = ExportObjectParams {
        unwrap: true,
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        ..Default::default()
    };
    let responses = batch_export_objects(kms_rest_client, key_ids, export_object_params).await?;
    trace!(
        "get_kms_disk_encryption_data_objects_async: found {} SymmetricKey objects",
        responses.len()
    );
    let mut results = vec![];
    for (id, object, attributes) in responses {
        // Extract user-visible tags (exclude system tags and the disk-encryption tag itself).
        // Sorted so that label selection is deterministic regardless of HashSet iteration order.
        let mut other_tags: Vec<String> = attributes
            .get_tags(vendor_id)
            .into_iter()
            .filter(|t| !t.is_empty() && !t.starts_with('_') && t != disk_encryption_tag)
            .collect();
        other_tags.sort();
        // Use the first user label (sorted, e.g. "vol1") as remote_id so VeraCrypt displays it
        let label = other_tags
            .first()
            .cloned()
            .unwrap_or_else(|| id.to_string());
        results.push(KmsObject {
            remote_id: label,
            object,
            attributes,
            other_tags,
        });
    }
    Ok(results)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) async fn get_kms_objects_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
    key_format_type: Option<KeyFormatType>,
) -> Pkcs11Result<Vec<KmsObject>> {
    let key_ids = locate_objects(kms_rest_client, vendor_id, tags).await?;
    let export_object_params = ExportObjectParams {
        unwrap: true,
        key_format_type,
        ..Default::default()
    };
    if key_ids.is_empty() {
        trace!(
            "get_kms_objects_async: no objects found for tags: {:?}",
            tags
        );
        return Ok(vec![]);
    }

    let responses = batch_export_objects(kms_rest_client, key_ids, export_object_params).await?;
    trace!("Found {} objects", responses.len());

    let mut results = vec![];
    for (id, object, attributes) in responses {
        let other_tags = attributes
            .get_tags(vendor_id)
            .into_iter()
            .filter(|t| !t.is_empty() && !tags.contains(t) && !t.starts_with('_'))
            .collect::<Vec<String>>();
        results.push(KmsObject {
            remote_id: id.to_string(),
            object,
            attributes,
            other_tags,
        });
    }
    Ok(results)
}

pub(crate) fn get_kms_object(
    kms_client: &KmsClient,
    vendor_id: &str,
    object_id_or_tags: &str,
    key_format_type: KeyFormatType,
) -> Pkcs11Result<KmsObject> {
    RUNTIME.block_on(get_kms_object_async(
        kms_client,
        vendor_id,
        object_id_or_tags,
        key_format_type,
    ))
}

pub(crate) async fn get_kms_object_async(
    kms_client: &KmsClient,
    vendor_id: &str,
    object_id_or_tags: &str,
    key_format_type: KeyFormatType,
) -> Pkcs11Result<KmsObject> {
    let (id, object, _) = export_object(
        kms_client,
        object_id_or_tags,
        ExportObjectParams {
            unwrap: true,
            key_format_type: Some(key_format_type),
            ..Default::default()
        },
    )
    .await?;

    // Get request does not return attributes, try to get them form the object
    let attributes = object.attributes().cloned().unwrap_or_default();
    let other_tags = attributes
        .get_tags(vendor_id)
        .into_iter()
        .filter(|t| !t.is_empty() && !t.starts_with('_'))
        .collect::<Vec<String>>();
    Ok(KmsObject {
        remote_id: id.to_string(),
        object,
        attributes,
        other_tags,
    })
}

async fn locate_objects(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
) -> Pkcs11Result<Vec<String>> {
    locate_objects_of_type(kms_rest_client, vendor_id, tags, None).await
}

/// Locate KMS objects by tags, optionally filtering by `ObjectType`.
/// This avoids returning objects of wrong type when multiple object types share the same tag.
async fn locate_objects_of_type(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    tags: &[String],
    object_type: Option<ObjectType>,
) -> Pkcs11Result<Vec<String>> {
    let mut attributes = Attributes::default();
    attributes.set_tags(vendor_id, tags)?;
    attributes.object_type = object_type;

    let locate = Locate {
        attributes,
        ..Default::default()
    };
    let response = kms_rest_client.locate(locate).await?;
    debug!("Locate response: ids: {:?}", response.unique_identifier);
    let uniques_identifiers = response
        .unique_identifier
        .unwrap_or_default()
        .iter()
        .map(std::string::ToString::to_string)
        .filter(|id| !id.is_empty())
        .collect();
    debug!("Located objects: tags: {tags:?}, type: {object_type:?} => {uniques_identifiers:?}");
    Ok(uniques_identifiers)
}

pub(crate) fn kms_import_symmetric_key(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    algorithm: KeyAlgorithm,
    key_length: usize,
    sensitive: bool,
    label: Option<&str>,
) -> Pkcs11Result<KmsObject> {
    RUNTIME.block_on(kms_import_symmetric_key_async(
        kms_rest_client,
        vendor_id,
        algorithm,
        key_length,
        sensitive,
        label,
    ))
}

/// Creates a new KMS key.
/// At first, the key is locally created and then imported to the KMS. There are 2 reasons why:
/// - 1/ a key with `sensitive` flag cannot be extracted and then cannot be exported afterwards
/// - 2/ is that the content of the key must be kept in cache to be reused later.
pub(crate) async fn kms_import_symmetric_key_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    algorithm: KeyAlgorithm,
    key_length: usize,
    sensitive: bool,
    label: Option<&str>,
) -> Pkcs11Result<KmsObject> {
    let cryptographic_algorithm = if algorithm == KeyAlgorithm::Aes256 {
        CryptographicAlgorithm::AES
    } else {
        error!("Unsupported key algorithm: {:?}", algorithm);
        return Err(Pkcs11Error::Default(format!(
            "unsupported key algorithm: {algorithm:?}"
        )));
    };
    let tags = label.map(|l| vec![l.to_owned()]).unwrap_or_default();

    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; key_length];
    rng.fill_bytes(&mut key);

    let cryptographic_length = Some(i32::try_from(key_length * 8)?);

    let mut attributes = Attributes {
        cryptographic_algorithm: Some(cryptographic_algorithm),
        cryptographic_length,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        unique_identifier: label.map(|l| UniqueIdentifier::TextString(l.to_owned())),
        sensitive: if sensitive { Some(true) } else { None },
        ..Attributes::default()
    };
    attributes.set_tags(vendor_id, tags.clone())?;
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(cryptographic_algorithm),
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::new(key),
                },
                attributes: Some(attributes.clone()),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    });
    let is_hsm_key = label.is_some_and(|label| label.starts_with("hsm::"));
    let remote_id = if is_hsm_key {
        let request = symmetric_key_create_request(
            vendor_id,
            label.map(|label| UniqueIdentifier::TextString(label.to_owned())),
            key_length * 8,
            cryptographic_algorithm,
            &tags,
            sensitive,
            None,
        )?;
        kms_rest_client.create(request).await?.unique_identifier
    } else {
        let response = kms_rest_client
            .import(Import {
                unique_identifier: label
                    .map(|l| UniqueIdentifier::TextString(l.to_owned()))
                    .unwrap_or_default(),
                object_type: cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
                replace_existing: Some(true),
                key_wrap_type: None,
                attributes: attributes.clone(),
                object: object.clone(),
            })
            .await?;

        // Imported software keys start PreActive and must be activated before use.
        kms_rest_client
            .activate(Activate {
                unique_identifier: response.unique_identifier.clone(),
            })
            .await?;
        response.unique_identifier
    };

    let res = KmsObject {
        remote_id: remote_id.to_string(),
        object,
        attributes,
        other_tags: tags,
    };

    Ok(res)
}

pub(crate) fn kms_import_object(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    label: &str,
    data: &[u8],
) -> Pkcs11Result<KmsObject> {
    RUNTIME.block_on(kms_import_object_async(
        kms_rest_client,
        vendor_id,
        label,
        data,
    ))
}

pub(crate) async fn kms_import_object_async(
    kms_rest_client: &KmsClient,
    vendor_id: &str,
    label: &str,
    data: &[u8],
) -> Pkcs11Result<KmsObject> {
    debug!(
        "kms_import_object_async: label: {label}, data (length): {}",
        data.len()
    );
    let tags = vec![label.to_owned(), SYSTEM_TAG_SECRET_DATA.to_owned()];
    let unique_identifier = UniqueIdentifier::TextString(label.to_owned());

    let secret_data_value = data.to_vec();

    let cryptographic_length = Some(i32::try_from(secret_data_value.len() * 8)?);

    let mut attributes = Attributes::default();
    attributes.set_tags(vendor_id, tags.clone())?;

    let object = Object::SecretData(SecretData {
        secret_data_type: SecretDataType::Password,
        key_block: KeyBlock {
            cryptographic_length,
            key_format_type: KeyFormatType::Raw,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(secret_data_value)),
                attributes: Some(attributes.clone()),
            }),
            key_compression_type: None,
            cryptographic_algorithm: None,
            key_wrapping_data: None,
        },
    });

    let response = kms_rest_client
        .import(Import {
            unique_identifier,
            object_type: ObjectType::SecretData,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: attributes.clone(),
            object: object.clone(),
        })
        .await?;

    let res = KmsObject {
        remote_id: response.unique_identifier.to_string(),
        object,
        attributes,
        other_tags: tags,
    };

    Ok(res)
}

pub(crate) fn kms_revoke_object(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    RUNTIME.block_on(kms_revoke_object_async(kms_rest_client, unique_identifier))
}

pub(crate) async fn kms_revoke_object_async(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    kms_rest_client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        })
        .await?;

    Ok(())
}

pub(crate) fn kms_destroy_object(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    RUNTIME.block_on(kms_destroy_object_async(kms_rest_client, unique_identifier))
}

pub(crate) async fn kms_destroy_object_async(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    kms_rest_client
        .destroy(Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
            remove: false,
            cascade: true,
            expected_object_type: None,
        })
        .await?;

    Ok(())
}

pub(crate) fn kms_encrypt(
    kms_rest_client: &KmsClient,
    encrypt_ctx: &EncryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Vec<u8>> {
    let mut output =
        RUNTIME.block_on(kms_encrypt_async(kms_rest_client, encrypt_ctx, data, false))?;
    if matches!(encrypt_ctx.algorithm, EncryptionAlgorithm::AesGcm) {
        output.ciphertext.extend_from_slice(&output.tag);
    }
    Ok(output.ciphertext)
}

/// Encrypt one PKCS#11 v3 AES-GCM message and preserve its detached artifacts.
pub(crate) fn kms_encrypt_message(
    kms_rest_client: &KmsClient,
    encrypt_ctx: &EncryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<MessageEncryptionOutput> {
    RUNTIME.block_on(kms_encrypt_async(kms_rest_client, encrypt_ctx, data, true))
}

async fn kms_encrypt_async(
    kms_rest_client: &KmsClient,
    encrypt_ctx: &EncryptContext,
    data: Vec<u8>,
    require_generated_nonce: bool,
) -> Pkcs11Result<MessageEncryptionOutput> {
    let cryptographic_parameters = match encrypt_ctx.algorithm {
        EncryptionAlgorithm::AesCbcPad => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::PKCS5),
            ..Default::default()
        },
        EncryptionAlgorithm::AesCbc => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::None),
            ..Default::default()
        },
        EncryptionAlgorithm::AesGcm => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            ..Default::default()
        },
        EncryptionAlgorithm::RsaPkcs1v15 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            ..Default::default()
        },
        EncryptionAlgorithm::RsaOaepSha256 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
    };
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            encrypt_ctx.remote_object_id.clone(),
        )),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(Zeroizing::new(data)),
        i_v_counter_nonce: encrypt_ctx.iv.clone(),
        authenticated_encryption_additional_data: encrypt_ctx.aad.clone(),
        ..Default::default()
    };
    let response = kms_rest_client.encrypt(encryption_request).await?;
    let ciphertext = response.data.ok_or_else(|| {
        Pkcs11Error::ServerError("Encryption response does not contain data".to_owned())
    })?;
    let (iv, tag) = if matches!(encrypt_ctx.algorithm, EncryptionAlgorithm::AesGcm) {
        let iv = match response.i_v_counter_nonce {
            Some(iv) => iv,
            None if require_generated_nonce => {
                return Err(Pkcs11Error::ServerError(
                    "AES-GCM message encryption response does not contain a nonce".to_owned(),
                ));
            }
            None => Vec::new(),
        };
        let tag = response.authenticated_encryption_tag.ok_or_else(|| {
            Pkcs11Error::ServerError(
                "AES-GCM encryption response does not contain an authentication tag".to_owned(),
            )
        })?;
        (iv, tag)
    } else {
        (Vec::new(), Vec::new())
    };
    debug!(
        "kms_encrypt_async: ciphertext: {}",
        hex::encode(&ciphertext)
    );
    Ok(MessageEncryptionOutput {
        ciphertext,
        iv,
        tag,
    })
}

pub(crate) fn kms_decrypt(
    kms_rest_client: &KmsClient,
    decrypt_ctx: &DecryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Zeroizing<Vec<u8>>> {
    RUNTIME.block_on(kms_decrypt_async(kms_rest_client, decrypt_ctx, data))
}

pub(crate) async fn kms_decrypt_async(
    kms_rest_client: &KmsClient,
    decrypt_ctx: &DecryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Zeroizing<Vec<u8>>> {
    let cryptographic_parameters = match decrypt_ctx.algorithm {
        EncryptionAlgorithm::AesCbcPad => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::PKCS5),
            ..Default::default()
        },
        EncryptionAlgorithm::AesCbc => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::None),
            ..Default::default()
        },
        EncryptionAlgorithm::AesGcm => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            ..Default::default()
        },
        EncryptionAlgorithm::RsaPkcs1v15 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            ..Default::default()
        },
        EncryptionAlgorithm::RsaOaepSha256 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
    };

    // `CKM_AES_GCM` (PKCS#11 v3.0): the caller supplies a single input buffer of
    // ciphertext followed by the authentication tag ("C || T"); split it back apart
    // before sending the KMIP Decrypt request, which expects them as separate fields.
    let (ciphertext, authenticated_encryption_tag) =
        if matches!(decrypt_ctx.algorithm, EncryptionAlgorithm::AesGcm) {
            if data.len() < AES_GCM_TAG_LENGTH {
                // Too-short ciphertext is a caller/input error, not a server-side failure —
                // use the dedicated `Pkcs11` variant rather than `ServerError` so it is not
                // misclassified as a KMS backend fault.
                return Err(Pkcs11Error::Pkcs11(format!(
                    "AES-GCM ciphertext too short: {} bytes, expected at least {} (tag length)",
                    data.len(),
                    AES_GCM_TAG_LENGTH
                )));
            }
            let split_at = data.len() - AES_GCM_TAG_LENGTH;
            let mut data = data;
            let tag = data.split_off(split_at);
            (data, Some(tag))
        } else {
            (data, None)
        };

    let decryption_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            decrypt_ctx.remote_object_id.clone(),
        )),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(ciphertext),
        i_v_counter_nonce: decrypt_ctx.iv.clone(),
        authenticated_encryption_additional_data: decrypt_ctx.aad.clone(),
        authenticated_encryption_tag,
        ..Default::default()
    };
    let response = kms_rest_client.decrypt(decryption_request).await?;
    response.data.ok_or_else(|| {
        Pkcs11Error::ServerError("Decryption response does not contain data".to_owned())
    })
}

pub(crate) fn kms_sign(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
    algorithm: &SignatureAlgorithm,
    data: &[u8],
    key_algorithm: KeyAlgorithm,
) -> Pkcs11Result<Vec<u8>> {
    let runtime_block_on = profiling::phase(SignPhase::RuntimeBlockOn);
    let result = RUNTIME.block_on(kms_sign_async(
        kms_rest_client,
        unique_identifier,
        algorithm,
        data,
        key_algorithm,
    ));
    drop(runtime_block_on);
    result
}

/// Map a PKCS#11 `DigestType` to its KMIP `HashingAlgorithm` counterpart.
const fn digest_type_to_hashing_algorithm(digest: &DigestType) -> HashingAlgorithm {
    match digest {
        DigestType::Sha1 => HashingAlgorithm::SHA1,
        DigestType::Sha224 => HashingAlgorithm::SHA224,
        DigestType::Sha256 => HashingAlgorithm::SHA256,
        DigestType::Sha384 => HashingAlgorithm::SHA384,
        DigestType::Sha512 => HashingAlgorithm::SHA512,
    }
}

/// Result of mapping a `SignatureAlgorithm` to KMIP request fields: `(cryptographic_parameters,
/// data, digested_data)`. See `signature_algorithm_to_kmip_params`.
type SignatureKmipParams = (
    Option<CryptographicParameters>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// Maps a PKCS#11 `SignatureAlgorithm`/payload pair to the KMIP `CryptographicParameters` and
/// `data`/`digested_data` fields used by both the `Sign` and `SignatureVerify` KMIP operations.
///
/// Shared by `kms_sign_async` and `kms_verify_async` so the two operations can never diverge on
/// whether a given mechanism sends a raw message (`data`) or a pre-computed digest
/// (`digested_data`) — a mismatch here would make valid signatures fail verification.
fn signature_algorithm_to_kmip_params(
    algorithm: &SignatureAlgorithm,
    data: &[u8],
) -> Pkcs11Result<SignatureKmipParams> {
    Ok(match algorithm {
        SignatureAlgorithm::Ecdsa => {
            // CKM_ECDSA: caller (OpenSSH) provides a pre-computed hash
            let digital_signature_algorithm = match data.len() {
                48 => Some(DigitalSignatureAlgorithm::ECDSAWithSHA384),
                64 => Some(DigitalSignatureAlgorithm::ECDSAWithSHA512),
                _ => Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            };
            let cp = CryptographicParameters {
                digital_signature_algorithm,
                ..Default::default()
            };
            (Some(cp), None, Some(data.to_vec()))
        }
        SignatureAlgorithm::EdDsa => {
            // CKM_EDDSA: raw message, Ed25519/Ed448 handles hashing internally
            (None, Some(data.to_vec()), None)
        }
        SignatureAlgorithm::RsaRaw | SignatureAlgorithm::RsaPkcs1v15Raw => {
            // CKM_RSA_PKCS: pass raw bytes, server uses stored key attributes
            (None, Some(data.to_vec()), None)
        }
        SignatureAlgorithm::RsaPkcs1v15Sha1 => {
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA1WithRSAEncryption),
                ..Default::default()
            };
            (Some(cp), Some(data.to_vec()), None)
        }
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(
                    DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
                ),
                ..Default::default()
            };
            (Some(cp), Some(data.to_vec()), None)
        }
        SignatureAlgorithm::RsaPkcs1v15Sha384 => {
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(
                    DigitalSignatureAlgorithm::SHA384WithRSAEncryption,
                ),
                ..Default::default()
            };
            (Some(cp), Some(data.to_vec()), None)
        }
        SignatureAlgorithm::RsaPkcs1v15Sha512 => {
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(
                    DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
                ),
                ..Default::default()
            };
            (Some(cp), Some(data.to_vec()), None)
        }
        SignatureAlgorithm::RsaPss {
            digest,
            mask_generation_function,
            salt_length,
        } => {
            // CKM_RSA_PKCS_PSS is a "bare" PSS mechanism (PKCS#11 v3.1 §6.4.7): per the
            // spec, it "operate[s] only on the part of PKCS #1 that involves block
            // formatting and RSA, given a hash value; it does not compute a hash value
            // on the message to be signed." The caller (e.g. `pkcs11-tool --sign
            // --mechanism RSA-PKCS-PSS`) therefore always provides a pre-computed
            // digest, not the raw message — send it as `digested_data` (like CKM_ECDSA)
            // so the server does not hash it a second time.
            let hashing_algorithm = Some(digest_type_to_hashing_algorithm(digest));
            let mask_generator_hashing_algorithm =
                Some(digest_type_to_hashing_algorithm(mask_generation_function));
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
                hashing_algorithm,
                mask_generator: Some(MaskGenerator::MFG1),
                mask_generator_hashing_algorithm,
                salt_length: Some(i32::try_from(*salt_length)?),
                ..Default::default()
            };
            (Some(cp), None, Some(data.to_vec()))
        }
    })
}
/// Convert a DER-encoded ECDSA signature to raw PKCS#11 format (r || s).
///
/// # Arguments
/// * `der` - DER-encoded signature bytes in SEQUENCE { r INTEGER, s INTEGER } format
/// * `byte_size` - The curve's field size in bytes (e.g., 32 for P-256, 48 for P-384, 66 for P-521)
///
/// # Returns
/// Raw signature in r || s format, each component zero-padded to `byte_size`
fn ecdsa_der_to_raw(der: &[u8], byte_size: usize) -> Pkcs11Result<Vec<u8>> {
    let (tag, rest) = der
        .split_first()
        .ok_or_else(|| Pkcs11Error::Default("ECDSA DER: unexpected end of input".to_owned()))?;
    if *tag != 0x30 {
        return Err(Pkcs11Error::Default(format!(
            "ECDSA DER: expected SEQUENCE tag (0x30), found {tag:#04x}"
        )));
    }
    let (seq_len, rest) = der_parse_length(rest)?;
    let content = rest
        .get(..seq_len)
        .ok_or_else(|| Pkcs11Error::Default("ECDSA DER: truncated SEQUENCE content".to_owned()))?;
    let (r, content) = der_parse_unsigned_integer(content)?;
    let (s, _) = der_parse_unsigned_integer(content)?;

    if r.len() > byte_size || s.len() > byte_size {
        return Err(Pkcs11Error::Default(format!(
            "ECDSA DER: component larger than curve field size ({byte_size} bytes)"
        )));
    }

    let mut raw = vec![0_u8; 2 * byte_size];
    let r_start = byte_size.saturating_sub(r.len());
    raw.get_mut(r_start..byte_size)
        .ok_or_else(|| Pkcs11Error::Default("ECDSA DER: r slice out of bounds".to_owned()))?
        .copy_from_slice(r);

    let s_start = (2 * byte_size).saturating_sub(s.len());
    raw.get_mut(s_start..)
        .ok_or_else(|| Pkcs11Error::Default("ECDSA DER: s slice out of bounds".to_owned()))?
        .copy_from_slice(s);

    Ok(raw)
}

/// Convert raw PKCS#11 ECDSA signature (r || s) to DER-encoded format.
/// Each component is expected to be exactly `byte_size` bytes, zero-padded.
fn ecdsa_raw_to_der(raw: &[u8], byte_size: usize) -> Pkcs11Result<Vec<u8>> {
    if raw.len() != 2 * byte_size {
        return Err(Pkcs11Error::Default(format!(
            "ECDSA raw: expected {} bytes, got {}",
            2 * byte_size,
            raw.len()
        )));
    }

    let r = raw
        .get(0..byte_size)
        .ok_or_else(|| Pkcs11Error::Default("ECDSA raw: r component out of bounds".to_owned()))?;
    let s = raw
        .get(byte_size..2 * byte_size)
        .ok_or_else(|| Pkcs11Error::Default("ECDSA raw: s component out of bounds".to_owned()))?;

    // Strip leading zeros from r and s
    let r_trimmed = r
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect::<Vec<u8>>();
    let s_trimmed = s
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect::<Vec<u8>>();

    let r_trimmed = if r_trimmed.is_empty() {
        vec![0_u8]
    } else {
        r_trimmed
    };
    let s_trimmed = if s_trimmed.is_empty() {
        vec![0_u8]
    } else {
        s_trimmed
    };

    // Add padding byte if high bit is set
    let r_needs_padding = r_trimmed.first().is_some_and(|&b| b & 0x80 != 0);
    let s_needs_padding = s_trimmed.first().is_some_and(|&b| b & 0x80 != 0);

    let r_len = r_trimmed.len() + usize::from(r_needs_padding);
    let s_len = s_trimmed.len() + usize::from(s_needs_padding);

    // Build DER: SEQUENCE { INTEGER r, INTEGER s }
    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE tag

    let seq_len = 2 + r_len + 2 + s_len; // two INTEGER tags + lengths + data
    encode_der_length(&mut der, seq_len);

    // INTEGER r
    der.push(0x02); // INTEGER tag
    encode_der_length(&mut der, r_len);
    if r_needs_padding {
        der.push(0x00);
    }
    der.extend_from_slice(&r_trimmed);

    // INTEGER s
    der.push(0x02); // INTEGER tag
    encode_der_length(&mut der, s_len);
    if s_needs_padding {
        der.push(0x00);
    }
    der.extend_from_slice(&s_trimmed);

    Ok(der)
}

/// Encode a DER length value (supports both short and long form).
fn encode_der_length(der: &mut Vec<u8>, len: usize) {
    if len < 128 {
        der.push(u8::try_from(len).unwrap_or(127));
    } else {
        let mut len_bytes = Vec::new();
        let mut tmp = len;
        while tmp > 0 {
            len_bytes.push(u8::try_from(tmp & 0xFF).unwrap_or(0));
            tmp >>= 8;
        }
        len_bytes.reverse();
        der.push(0x80 | u8::try_from(len_bytes.len()).unwrap_or(0xFF));
        der.extend_from_slice(&len_bytes);
    }
}

/// Parse DER length encoding (supports both short form and long form).
fn der_parse_length(input: &[u8]) -> Pkcs11Result<(usize, &[u8])> {
    let (len_byte, rest) = input
        .split_first()
        .ok_or_else(|| Pkcs11Error::Default("ECDSA DER: unexpected end of input".to_owned()))?;

    if len_byte & 0x80 == 0 {
        // Short form
        Ok((usize::from(*len_byte), rest))
    } else {
        // Long form
        let len_len = usize::from(len_byte & 0x7f);
        if rest.len() < len_len {
            return Err(Pkcs11Error::Default(
                "ECDSA DER: truncated length encoding".to_owned(),
            ));
        }
        let (len_bytes, rest) = rest.split_at(len_len);
        let mut len = 0_usize;
        for byte in len_bytes {
            len = (len << 8) | usize::from(*byte);
        }
        Ok((len, rest))
    }
}

fn der_parse_unsigned_integer(input: &[u8]) -> Pkcs11Result<(&[u8], &[u8])> {
    let (tag, rest) = input
        .split_first()
        .ok_or_else(|| Pkcs11Error::Default("ECDSA DER: unexpected end of input".to_owned()))?;
    if *tag != 0x02 {
        return Err(Pkcs11Error::Default(format!(
            "ECDSA DER: expected INTEGER tag (0x02), found {tag:#04x}"
        )));
    }
    let (len, rest) = der_parse_length(rest)?;
    let (content, rest) = if rest.len() >= len {
        rest.split_at(len)
    } else {
        return Err(Pkcs11Error::Default(
            "ECDSA DER: truncated INTEGER content".to_owned(),
        ));
    };

    // Strip leading 0x00 sign-padding byte if present
    let content = if content.len() > 1
        && content.starts_with(&[0])
        && content.get(1).is_some_and(|b| b & 0x80 != 0)
    {
        content.get(1..).unwrap_or(&[])
    } else {
        content
    };

    Ok((content, rest))
}

pub(crate) async fn kms_sign_async(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
    algorithm: &SignatureAlgorithm,
    data: &[u8],
    key_algorithm: KeyAlgorithm,
) -> Pkcs11Result<Vec<u8>> {
    let request_build = profiling::phase(SignPhase::RequestBuild);
    // Map the PKCS#11 mechanism to KMIP CryptographicParameters.
    // For CKM_ECDSA (SignatureAlgorithm::Ecdsa), the data is a pre-computed hash
    // passed by OpenSSH — send it as `digested_data` to prevent double-hashing on
    // the server side.
    let (cryptographic_parameters, data_bytes, digested_data_bytes) =
        signature_algorithm_to_kmip_params(algorithm, data)?;

    let sign_request = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
        cryptographic_parameters,
        data: data_bytes.map(zeroize::Zeroizing::new),
        digested_data: digested_data_bytes,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };
    drop(request_build);

    let kms_client_sign = profiling::phase(SignPhase::KmsClientSign);
    let response = kms_rest_client.sign_bytes(sign_request).await;
    drop(kms_client_sign);
    let response = response?;
    let mut signature = response.signature_data.ok_or_else(|| {
        Pkcs11Error::ServerError("Sign response does not contain signature data".to_owned())
    })?;

    // ECDSA signatures from the KMS are DER-encoded, but PKCS#11 expects raw r||s format.
    // Convert DER to raw for EC keys.
    if matches!(algorithm, SignatureAlgorithm::Ecdsa) {
        let curve_byte_size = match key_algorithm {
            KeyAlgorithm::EccP256 | KeyAlgorithm::Secp256k1 => 32,
            KeyAlgorithm::EccP384 => 48,
            KeyAlgorithm::EccP521 => 66,
            KeyAlgorithm::Secp224k1 => 28,
            _ => {
                // Non-EC key, signature is already in correct format
                return Ok(signature);
            }
        };
        signature = ecdsa_der_to_raw(&signature, curve_byte_size)?;
    }

    Ok(signature)
}
pub(crate) fn kms_verify(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
    algorithm: &SignatureAlgorithm,
    data: &[u8],
    signature: &[u8],
    key_algorithm: KeyAlgorithm,
) -> Pkcs11Result<()> {
    RUNTIME.block_on(kms_verify_async(
        kms_rest_client,
        unique_identifier,
        algorithm,
        data,
        signature,
        key_algorithm,
    ))
}

/// Verifies `signature` over `data` for the public key `unique_identifier`, via a KMIP
/// `SignatureVerify` round trip. Reuses `signature_algorithm_to_kmip_params` — the exact same
/// mapping used by `kms_sign_async` — so a signature produced by `C_Sign` is always verified
/// with the matching raw-message/pre-hashed-digest convention.
pub(crate) async fn kms_verify_async(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
    algorithm: &SignatureAlgorithm,
    data: &[u8],
    signature: &[u8],
    key_algorithm: KeyAlgorithm,
) -> Pkcs11Result<()> {
    let (cryptographic_parameters, data_bytes, digested_data_bytes) =
        signature_algorithm_to_kmip_params(algorithm, data)?;

    // For ECDSA, convert raw r||s format to DER before sending to KMS
    let signature_data = if matches!(algorithm, SignatureAlgorithm::Ecdsa) {
        match key_algorithm {
            KeyAlgorithm::EccP256 | KeyAlgorithm::Secp256k1 => ecdsa_raw_to_der(signature, 32)?,
            KeyAlgorithm::EccP384 => ecdsa_raw_to_der(signature, 48)?,
            KeyAlgorithm::EccP521 => ecdsa_raw_to_der(signature, 66)?,
            KeyAlgorithm::Secp224k1 => ecdsa_raw_to_der(signature, 28)?,
            _ => {
                // Non-EC key or unknown curve: pass signature through unchanged
                signature.to_vec()
            }
        }
    } else {
        signature.to_vec()
    };

    let verify_request = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
        cryptographic_parameters,
        data: data_bytes,
        digested_data: digested_data_bytes,
        signature_data: Some(signature_data),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    let response = kms_rest_client.signature_verify(verify_request).await?;
    match response.validity_indicator {
        Some(ValidityIndicator::Valid) => Ok(()),
        Some(ValidityIndicator::Invalid | ValidityIndicator::Unknown) | None => {
            Err(Pkcs11Error::SignatureInvalid)
        }
    }
}

pub(crate) fn get_kms_object_attributes(
    kms_client: &KmsClient,
    object_id: &str,
) -> Pkcs11Result<Attributes> {
    RUNTIME.block_on(get_kms_object_attributes_async(kms_client, object_id))
}

pub(crate) async fn get_kms_object_attributes_async(
    kms_client: &KmsClient,
    object_id: &str,
) -> Pkcs11Result<Attributes> {
    let response = kms_client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(object_id.to_owned())),
            attribute_reference: Some(vec![
                AttributeReference::Standard(Tag::CryptographicAlgorithm),
                AttributeReference::Standard(Tag::CryptographicLength),
                AttributeReference::Standard(Tag::ObjectType),
                AttributeReference::Standard(Tag::CryptographicDomainParameters),
            ]),
        })
        .await?;
    Ok(response.attributes)
}

pub(crate) fn key_algorithm_from_attributes(attributes: &Attributes) -> Pkcs11Result<KeyAlgorithm> {
    let algorithm = match attributes.cryptographic_algorithm.ok_or_else(|| {
        Pkcs11Error::Default("missing cryptographic algorithm in attributes".to_owned())
    })? {
        CryptographicAlgorithm::AES => KeyAlgorithm::Aes256,
        CryptographicAlgorithm::RSA => KeyAlgorithm::Rsa,
        // KMIP 2.1 assigns Ed25519/Ed448 their own dedicated CryptographicAlgorithm
        // values (distinct from the generic EC/ECDH used for NIST/SECG curves) — see
        // crate/kmip/src/kmip_2_1/requests/create_key_pair.rs::build_algorithm_from_curve.
        // The curve itself is unambiguous from the algorithm alone, so no domain
        // parameters lookup is needed here (unlike the EC/ECDH branch below).
        CryptographicAlgorithm::Ed25519 => KeyAlgorithm::Ed25519,
        CryptographicAlgorithm::Ed448 => KeyAlgorithm::Ed448,
        CryptographicAlgorithm::ECDH | CryptographicAlgorithm::EC => {
            let curve = attributes
                .cryptographic_domain_parameters
                .ok_or_else(|| {
                    Pkcs11Error::Default(
                        "missing cryptographic domain parameters in attributes".to_owned(),
                    )
                })?
                .recommended_curve
                .ok_or_else(|| {
                    Pkcs11Error::Default("missing recommended curve in attributes".to_owned())
                })?;
            match curve {
                RecommendedCurve::P256 => KeyAlgorithm::EccP256,
                RecommendedCurve::P384 => KeyAlgorithm::EccP384,
                RecommendedCurve::P521 => KeyAlgorithm::EccP521,
                RecommendedCurve::CURVE448 => KeyAlgorithm::X448,
                RecommendedCurve::CURVEED448 => KeyAlgorithm::Ed448,
                RecommendedCurve::CURVE25519 => KeyAlgorithm::X25519,
                RecommendedCurve::CURVEED25519 => KeyAlgorithm::Ed25519,
                RecommendedCurve::SECP224K1 => KeyAlgorithm::Secp224k1,
                RecommendedCurve::SECP256K1 => KeyAlgorithm::Secp256k1,
                _ => {
                    return Err(Pkcs11Error::Default(format!(
                        "unsupported curve for EC key: {curve}"
                    )));
                }
            }
        }
        x => {
            error!("Unsupported cryptographic algorithm: {:?}", x);
            return Err(Pkcs11Error::Default(format!(
                "unsupported cryptographic algorithm: {x:?}"
            )));
        }
    };
    Ok(algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_der_to_raw_p256() -> Result<(), Box<dyn std::error::Error>> {
        let der_sig = vec![
            0x30, 0x44, // SEQUENCE, length 68 bytes
            0x02, 0x20, // INTEGER, length 32 bytes
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x02, 0x20, // INTEGER, length 32 bytes
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11,
        ];
        let raw = ecdsa_der_to_raw(&der_sig, 32)?;
        if raw.len() != 64 {
            return Err(format!(
                "raw signature should be 64 bytes for P-256, got {}",
                raw.len()
            )
            .into());
        }
        let r_expected = vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        if raw.get(0..32) != Some(r_expected.as_slice()) {
            return Err("r component mismatch".into());
        }
        let s_expected = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11,
        ];
        if raw.get(32..64) != Some(s_expected.as_slice()) {
            return Err("s component mismatch".into());
        }
        Ok(())
    }

    #[test]
    fn test_ecdsa_der_to_raw_with_padding() -> Result<(), Box<dyn std::error::Error>> {
        let der_sig = vec![
            0x30, 0x46, // SEQUENCE, length 70 bytes
            0x02, 0x21, // INTEGER r, length 33 bytes
            0x00, // padding byte
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc,
            0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee,
            0xdd, 0xcc, 0xbb, 0xaa, 0x02, 0x21, // INTEGER s, length 33 bytes
            0x00, // padding byte
            0x92, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        let raw = ecdsa_der_to_raw(&der_sig, 32)?;
        if raw.len() != 64 {
            return Err(format!("Expected raw signature of 64 bytes, got {}", raw.len()).into());
        }
        let r_expected = vec![
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc,
            0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee,
            0xdd, 0xcc, 0xbb, 0xaa,
        ];
        if raw.get(0..32) != Some(r_expected.as_slice()) {
            return Err("r component (padded) mismatch".into());
        }
        let s_expected = vec![
            0x92, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        if raw.get(32..64) != Some(s_expected.as_slice()) {
            return Err("s component (padded) mismatch".into());
        }
        Ok(())
    }
}

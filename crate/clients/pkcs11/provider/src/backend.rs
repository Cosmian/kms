use std::sync::Arc;

use ckms::reexport::cosmian_kms_cli_actions::reexport::{
    cosmian_kmip::kmip_2_1::{
        extra::tagging::{
            SYSTEM_TAG_CERTIFICATE, SYSTEM_TAG_COVER_CRYPT_USER_KEY, SYSTEM_TAG_PRIVATE_KEY,
            SYSTEM_TAG_PUBLIC_KEY, SYSTEM_TAG_SECRET_DATA, SYSTEM_TAG_SYMMETRIC_KEY,
        },
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_types::KeyFormatType,
    },
    cosmian_kms_client::KmsClient,
};
use cosmian_kms_logger::{debug, trace, warn};
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    core::object::Object,
    traits::{
        Backend, Certificate, DataObject, DecryptContext, EncryptContext, KeyAlgorithm, PrivateKey,
        PublicKey, SearchOptions, SignatureAlgorithm, SymmetricKey, Version,
    },
};
use zeroize::Zeroizing;

use crate::{
    kms_object::{
        get_kms_certificate_objects, get_kms_object, get_kms_object_attributes,
        get_kms_secret_data_objects, key_algorithm_from_attributes, kms_decrypt,
        kms_destroy_object, kms_encrypt, kms_import_object, kms_import_symmetric_key,
        kms_revoke_object, kms_sign, locate_kms_objects,
    },
    pkcs11_certificate::Pkcs11Certificate,
    pkcs11_data_object::Pkcs11DataObject,
    pkcs11_error,
    pkcs11_private_key::Pkcs11PrivateKey,
    pkcs11_public_key::Pkcs11PublicKey,
    pkcs11_symmetric_key::Pkcs11SymmetricKey,
};

pub(crate) const COSMIAN_PKCS11_DISK_ENCRYPTION_TAG: &str = "disk-encryption";
pub(crate) const COSMIAN_PKCS11_SSH_KEY_TAG: &str = "ssh-auth";

/// Extract the `Id` from a `SearchOptions`, returning an error if `All` was passed.
/// Centralises the "find requires an ID" check shared by four `Backend` methods.
fn require_id(query: SearchOptions, caller: &str) -> ModuleResult<String> {
    match query {
        SearchOptions::Id(id) => Ok(id),
        SearchOptions::All => Err(ModuleError::Backend(Box::new(pkcs11_error!(
            "{}: find must be made using an ID",
            caller
        )))),
    }
}

pub(crate) struct CliBackend {
    kms_rest_client: KmsClient,
}

impl CliBackend {
    /// Instantiate a new `CliBackend` using the
    pub(crate) const fn instantiate(kms_rest_client: KmsClient) -> Self {
        Self { kms_rest_client }
    }

    fn get_key_size_and_algorithm(attributes: &Attributes) -> ModuleResult<(usize, KeyAlgorithm)> {
        let key_size = usize::try_from(attributes.cryptographic_length.ok_or_else(|| {
            ModuleError::Cryptography("get_key_size_and_algorithm: missing key size".to_owned())
        })?)?;
        let algorithm = key_algorithm_from_attributes(attributes)?;
        Ok((key_size, algorithm))
    }

    /// Helper function to create a private key from an ID
    fn create_private_key_from_id(&self, id: &str) -> Option<Arc<dyn PrivateKey>> {
        let attributes = get_kms_object_attributes(&self.kms_rest_client, id).ok()?;
        // Guard: reject non-PrivateKey KMIP objects (e.g. symmetric keys that share the
        // disk-encryption tag) so they are never presented as CKO_PRIVATE_KEY handles.
        if attributes.object_type != Some(ObjectType::PrivateKey) {
            warn!(
                "create_private_key_from_id: {id} has type {:?} (expected PrivateKey), skipping",
                attributes.object_type
            );
            return None;
        }
        let (key_size, algorithm) = match Self::get_key_size_and_algorithm(&attributes) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "create_private_key_from_id: unsupported key/algorithm for PrivateKey {id}: \
                     {e}, skipping"
                );
                return None;
            }
        };
        Some(Arc::new(Pkcs11PrivateKey::new(
            id.to_owned(),
            algorithm,
            key_size,
        )))
    }

    /// Helper function to create a symmetric key from an ID
    fn create_symmetric_key_from_id(&self, id: &str) -> Option<Arc<dyn SymmetricKey>> {
        let attributes = get_kms_object_attributes(&self.kms_rest_client, id).ok()?;
        // Guard: reject non-SymmetricKey KMIP objects so they are never presented as
        // CKO_SECRET_KEY handles (e.g. private keys that accidentally share a user tag).
        if attributes.object_type != Some(ObjectType::SymmetricKey) {
            warn!(
                "create_symmetric_key_from_id: {id} has type {:?} (expected SymmetricKey), skipping",
                attributes.object_type
            );
            return None;
        }
        let (key_size, algorithm) = match Self::get_key_size_and_algorithm(&attributes) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "create_symmetric_key_from_id: unsupported key/algorithm for SymmetricKey \
                     {id}: {e}, skipping"
                );
                return None;
            }
        };
        Some(Arc::new(Pkcs11SymmetricKey::new(
            id.to_owned(),
            algorithm,
            key_size,
        )))
    }

    /// Helper function to create an object from ID and attributes
    fn create_object_from_attributes(id: &str, attributes: &Attributes) -> Option<Object> {
        let object_type = attributes.object_type?;
        match object_type {
            ObjectType::SymmetricKey => Self::create_symmetric_key_object(id, attributes),
            ObjectType::PrivateKey => Self::create_private_key_object(id, attributes),
            ObjectType::PublicKey => Self::create_public_key_object(id, attributes),
            ObjectType::SecretData => Some(Object::DataObject(Arc::new(Pkcs11DataObject::new(
                id.to_owned(),
            )))),
            other => {
                warn!(
                    "create_object_from_attributes: unsupported object type: {other}, skipping \
                     {id}"
                );
                None
            }
        }
    }

    /// Helper to create symmetric key object
    fn create_symmetric_key_object(id: &str, attributes: &Attributes) -> Option<Object> {
        let (key_size, key_algorithm) = match Self::get_key_size_and_algorithm(attributes) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "create_symmetric_key_object: unsupported key/algorithm for SymmetricKey \
                     {id}: {e}, skipping"
                );
                return None;
            }
        };
        Some(Object::SymmetricKey(Arc::new(Pkcs11SymmetricKey::new(
            id.to_owned(),
            key_algorithm,
            key_size,
        ))))
    }

    /// Helper to create private key object
    fn create_private_key_object(id: &str, attributes: &Attributes) -> Option<Object> {
        let (key_size, key_algorithm) = match Self::get_key_size_and_algorithm(attributes) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "create_private_key_object: unsupported key/algorithm for PrivateKey {id}: \
                     {e}, skipping"
                );
                return None;
            }
        };
        Some(Object::PrivateKey(Arc::new(Pkcs11PrivateKey::new(
            id.to_owned(),
            key_algorithm,
            key_size,
        ))))
    }

    /// Helper to create public key object
    fn create_public_key_object(id: &str, attributes: &Attributes) -> Option<Object> {
        let (_key_size, key_algorithm) = match Self::get_key_size_and_algorithm(attributes) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "create_public_key_object: unsupported key/algorithm for PublicKey {id}: {e}, \
                     skipping"
                );
                return None;
            }
        };
        Some(Object::PublicKey(Arc::new(Pkcs11PublicKey::new(
            id.to_owned(),
            key_algorithm,
        ))))
    }
}

impl Backend for CliBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Cosmian-KMS                     "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Cosmian                         "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"software        "
    }

    #[expect(clippy::indexing_slicing)]
    fn token_serial_number(&self) -> [u8; 16] {
        let version = env!("CARGO_PKG_VERSION").as_bytes();
        let len = version.len().min(16);
        let mut sn = [0x20; 16];
        sn[0..len].copy_from_slice(&version[..len]);
        sn
    }

    fn library_description(&self) -> [u8; 32] {
        *b"Cosmian KMS PKCS#11 provider    "
    }

    fn library_version(&self) -> Version {
        let version = env!("CARGO_PKG_VERSION");
        let mut split = version.split('.');
        let major = split.next().unwrap_or("0").parse::<u8>().unwrap_or(0);
        let minor = split.next().unwrap_or("0").parse::<u8>().unwrap_or(0);
        Version { major, minor }
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> ModuleResult<Option<Arc<dyn Certificate>>> {
        trace!("find_certificate");
        Ok(None)
    }

    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>> {
        trace!("find_all_certificates");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let kms_objects = get_kms_certificate_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, SYSTEM_TAG_CERTIFICATE.to_owned()],
        )?;
        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn Certificate> = Arc::new(Pkcs11Certificate::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn find_private_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>> {
        trace!("find_private_key: {:?}", query);
        let id = require_id(query, "find_private_key")?;
        let kms_object = get_kms_object(&self.kms_rest_client, &id, KeyFormatType::PKCS8)?;
        Ok(Arc::new(Pkcs11PrivateKey::try_from_kms_object(kms_object)?))
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        trace!("find_all_private_keys");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let ssh_key_tag = std::env::var("COSMIAN_PKCS11_SSH_KEY_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_SSH_KEY_TAG.to_owned());

        let mut seen = std::collections::HashSet::new();
        let mut private_keys = vec![];

        let disk_ids = locate_kms_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, SYSTEM_TAG_PRIVATE_KEY.to_owned()],
        )
        .unwrap_or_default();
        for id in disk_ids {
            if seen.insert(id.clone()) {
                if let Some(private_key) = self.create_private_key_from_id(&id) {
                    private_keys.push(private_key);
                }
            }
        }

        let ssh_ids = locate_kms_objects(
            &self.kms_rest_client,
            &[ssh_key_tag, SYSTEM_TAG_PRIVATE_KEY.to_owned()],
        )
        .unwrap_or_default();
        for id in ssh_ids {
            if seen.insert(id.clone()) {
                if let Some(private_key) = self.create_private_key_from_id(&id) {
                    private_keys.push(private_key);
                }
            }
        }

        Ok(private_keys)
    }

    fn find_public_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        trace!("find_public_key: {:?}", query);
        let id = require_id(query, "find_public_key")?;
        let kms_object = get_kms_object(&self.kms_rest_client, &id, KeyFormatType::PKCS8)?;
        Ok(Arc::new(Pkcs11PublicKey::try_from_kms_object(&kms_object)?))
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        trace!("find_all_public_keys");
        // Use the system tag alone so ALL public keys are visible regardless of user tags.
        // The previous query ["ssh-auth", "_pk"] used AND semantics (HAVING COUNT = 2)
        // and silently dropped any public key that did not also carry the "ssh-auth" tag.
        let ids = locate_kms_objects(&self.kms_rest_client, &[SYSTEM_TAG_PUBLIC_KEY.to_owned()])
            .unwrap_or_default();
        let mut public_keys = Vec::with_capacity(ids.len());
        for id in ids {
            let kms_object = match get_kms_object(&self.kms_rest_client, &id, KeyFormatType::PKCS8)
            {
                Ok(o) => o,
                Err(e) => {
                    warn!(
                        "find_all_public_keys: failed to export public key {id}: {e}, \
                             skipping"
                    );
                    continue;
                }
            };
            match Pkcs11PublicKey::try_from_kms_object(&kms_object) {
                Ok(pk) => {
                    let arc_pk: Arc<dyn PublicKey> = Arc::new(pk);
                    public_keys.push(arc_pk);
                }
                Err(e) => warn!(
                    "find_all_public_keys: failed to build Pkcs11PublicKey for {id}: {e}, \
                     skipping"
                ),
            }
        }
        Ok(public_keys)
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        trace!("find_all_data_objects: entering");
        // Use the _sd system tag AND ObjectType::SecretData filter to find ONLY real SecretData
        // objects. Without the type filter, Locate would also return SymmetricKeys that happen
        // to carry the _sd tag (e.g. old TDE master key objects from prior sessions), which
        // would cause batch_export_objects to fail if those objects cannot be exported as Raw.
        let kms_objects = get_kms_secret_data_objects(
            &self.kms_rest_client,
            &[SYSTEM_TAG_SECRET_DATA.to_owned()],
        )?;
        trace!("find_all_data_objects: found {} objects", kms_objects.len());

        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn DataObject> = Arc::new(Pkcs11DataObject::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn find_symmetric_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>> {
        trace!("find_symmetric_key: {:?}", query);
        let id = require_id(query, "find_symmetric_key")?;
        let kms_object = get_kms_object(
            &self.kms_rest_client,
            &id,
            KeyFormatType::TransparentSymmetricKey,
        )?;
        Ok(Arc::new(Pkcs11SymmetricKey::try_from_kms_object(
            kms_object,
        )?))
    }

    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>> {
        trace!("find_all_symmetric_keys");
        let kms_ids = locate_kms_objects(
            &self.kms_rest_client,
            &[SYSTEM_TAG_SYMMETRIC_KEY.to_owned()],
        )?;
        let mut symmetric_keys = Vec::with_capacity(kms_ids.len());

        for id in kms_ids {
            if let Some(symmetric_key) = self.create_symmetric_key_from_id(&id) {
                symmetric_keys.push(symmetric_key);
            }
        }

        Ok(symmetric_keys)
    }

    fn find_data_object(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        trace!("find_data_object: {:?}", query);
        let id = require_id(query, "find_data_object")?;
        match get_kms_object(&self.kms_rest_client, &id, KeyFormatType::Raw) {
            Ok(kms_object) => Ok(Some(Arc::new(Pkcs11DataObject::try_from_kms_object(
                kms_object,
            )?))),
            Err(_) => Ok(None),
        }
    }

    fn find_all_objects(&self) -> ModuleResult<Vec<Arc<Object>>> {
        trace!("find_all_objects: entering");
        // Use type-specific system tags to locate objects.
        // An empty-tag Locate request returns nothing with Redis-Findex because
        // that backend requires at least one tag for every lookup.
        // The KMS server always attaches system tags on import/create:
        // "_kk" to symmetric keys, "_sk" to private keys, "_pk" to public keys,
        // "_cert" to certificates, "_sd" to secret data, and "_uk" to
        // CoverCrypt user keys. Iterating over each tag with deduplication covers
        // the full object space reliably (required for Redis-Findex which needs
        // at least one tag per lookup).
        let mut seen_ids = std::collections::HashSet::new();
        let mut objects = Vec::new();
        for tag in [
            SYSTEM_TAG_SYMMETRIC_KEY,
            SYSTEM_TAG_PRIVATE_KEY,
            SYSTEM_TAG_PUBLIC_KEY,
            SYSTEM_TAG_CERTIFICATE,
            SYSTEM_TAG_SECRET_DATA,
            SYSTEM_TAG_COVER_CRYPT_USER_KEY,
        ] {
            let kms_ids =
                locate_kms_objects(&self.kms_rest_client, &[tag.to_owned()]).unwrap_or_default();
            for id in kms_ids {
                if seen_ids.insert(id.clone()) {
                    if let Ok(attributes) = get_kms_object_attributes(&self.kms_rest_client, &id) {
                        if let Some(object) = Self::create_object_from_attributes(&id, &attributes)
                        {
                            objects.push(Arc::new(object));
                        }
                    }
                }
            }
        }

        trace!("find_all_objects: found {} keys", objects.len());
        Ok(objects)
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_length: usize,
        sensitive: bool,
        label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>> {
        trace!("generate_key: {algorithm:?}-{key_length}, {label:?}");

        if algorithm != KeyAlgorithm::Aes256 {
            return Err(ModuleError::Backend(Box::new(pkcs11_error!(
                "generate_key: only support AES-256 algorithm"
            ))));
        }

        let kms_object = kms_import_symmetric_key(
            &self.kms_rest_client,
            algorithm,
            key_length,
            sensitive,
            label,
        )?;
        Ok(Arc::new(Pkcs11SymmetricKey::try_from_kms_object(
            kms_object,
        )?))
    }

    fn create_object(&self, label: &str, data: &[u8]) -> ModuleResult<Arc<dyn DataObject>> {
        trace!("create_object: {label:?}");
        let kms_object = kms_import_object(&self.kms_rest_client, label, data)?;
        Ok(Arc::new(Pkcs11DataObject::try_from_kms_object(kms_object)?))
    }

    fn revoke_object(&self, remote_id: &str) -> ModuleResult<()> {
        Ok(kms_revoke_object(&self.kms_rest_client, remote_id)?)
    }

    fn destroy_object(&self, remote_id: &str) -> ModuleResult<()> {
        Ok(kms_destroy_object(&self.kms_rest_client, remote_id)?)
    }

    fn encrypt(&self, ctx: &EncryptContext, cleartext: Vec<u8>) -> ModuleResult<Vec<u8>> {
        debug!("encrypt: ctx: {ctx:?}");
        kms_encrypt(&self.kms_rest_client, ctx, cleartext).map_err(Into::into)
    }

    fn decrypt(
        &self,
        ctx: &DecryptContext,
        ciphertext: Vec<u8>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>> {
        debug!("decrypt: decrypt_ctx: {ctx:?}");
        kms_decrypt(&self.kms_rest_client, ctx, ciphertext).map_err(Into::into)
    }

    fn remote_sign(
        &self,
        remote_id: &str,
        algorithm: &SignatureAlgorithm,
        data: &[u8],
    ) -> ModuleResult<Vec<u8>> {
        debug!("remote_sign: remote_id: {remote_id}, algorithm: {algorithm:?}");
        kms_sign(&self.kms_rest_client, remote_id, algorithm, data).map_err(Into::into)
    }
}

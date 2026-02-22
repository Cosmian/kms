use std::sync::Arc;

use ckms::reexport::cosmian_kms_cli::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::ObjectType, kmip_types::KeyFormatType,
    },
    cosmian_kms_client::KmsClient,
};
use cosmian_logger::{debug, trace, warn};
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    core::object::Object,
    traits::{
        Backend, Certificate, DataObject, DecryptContext, EncryptContext, KeyAlgorithm, PrivateKey,
        PublicKey, SearchOptions, SymmetricKey, Version,
    },
};
use zeroize::Zeroizing;

use crate::{
    kms_object::{
        get_kms_object, get_kms_object_attributes, get_kms_objects, key_algorithm_from_attributes,
        kms_decrypt, kms_destroy_object, kms_encrypt, kms_import_object, kms_import_symmetric_key,
        kms_revoke_object, locate_kms_objects,
    },
    pkcs11_certificate::Pkcs11Certificate,
    pkcs11_data_object::Pkcs11DataObject,
    pkcs11_error,
    pkcs11_private_key::Pkcs11PrivateKey,
    pkcs11_public_key::Pkcs11PublicKey,
    pkcs11_symmetric_key::Pkcs11SymmetricKey,
};

pub(crate) const COSMIAN_PKCS11_DISK_ENCRYPTION_TAG: &str = "disk-encryption";

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
        let kms_objects = get_kms_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, "_cert".to_owned()],
            Some(KeyFormatType::X509),
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
        let id = match query {
            SearchOptions::Id(id) => id,
            SearchOptions::All => {
                return Err(ModuleError::Backend(Box::new(pkcs11_error!(
                    "find_private_key: find must be made using an ID"
                ))));
            }
        };
        let id = String::from_utf8(id)?;
        let kms_object = get_kms_object(&self.kms_rest_client, &id, KeyFormatType::PKCS8)?;
        Ok(Arc::new(Pkcs11PrivateKey::try_from_kms_object(kms_object)?))
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        trace!("find_all_private_keys");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let mut private_keys = vec![];
        let ids = locate_kms_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, "_sk".to_owned()],
        )?;
        for id in ids {
            if let Some(private_key) = self.create_private_key_from_id(&id) {
                private_keys.push(private_key);
            }
        }

        Ok(private_keys)
    }

    fn find_public_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        trace!("find_public_key: {:?}", query);
        Err(ModuleError::Backend(Box::new(pkcs11_error!(
            "find_public_key: not implemented"
        ))))
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        warn!("find_all_public_keys not implemented");
        Ok(vec![])
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        trace!("find_all_data_objects: entering");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or_else(|_| COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned());
        let kms_objects = get_kms_objects(
            &self.kms_rest_client,
            &[disk_encryption_tag, "_sd".to_owned()],
            Some(KeyFormatType::Raw),
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
        let id = match query {
            SearchOptions::Id(id) => id,
            SearchOptions::All => {
                return Err(ModuleError::Backend(Box::new(pkcs11_error!(
                    "find_symmetric_key: find must be made using an ID"
                ))));
            }
        };
        let id = String::from_utf8(id)?;
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
        let kms_ids = locate_kms_objects(&self.kms_rest_client, &["_kk".to_owned()])?;
        let mut symmetric_keys = Vec::with_capacity(kms_ids.len());

        for id in kms_ids {
            if let Some(symmetric_key) = self.create_symmetric_key_from_id(&id) {
                symmetric_keys.push(symmetric_key);
            }
        }

        Ok(symmetric_keys)
    }

    fn find_data_object(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        warn!("find_data_object: {:?}, not implemented", query);
        Ok(None)
    }

    fn find_all_objects(&self) -> ModuleResult<Vec<Arc<Object>>> {
        trace!("find_all_objects: entering");
        let kms_ids = locate_kms_objects(&self.kms_rest_client, &[])?;
        let mut objects = Vec::with_capacity(kms_ids.len());
        for id in kms_ids {
            if let Ok(attributes) = get_kms_object_attributes(&self.kms_rest_client, &id) {
                if let Some(object) = Self::create_object_from_attributes(&id, &attributes) {
                    objects.push(Arc::new(object));
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
}

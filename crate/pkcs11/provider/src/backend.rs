use std::sync::Arc;

use cosmian_kms_client::KmsClient;
use pkcs11_module::traits::{
    Backend, Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey, SearchOptions,
    SignatureAlgorithm, Version,
};
use tracing::trace;

use crate::{
    error::Pkcs11Error, kms_object::get_kms_objects, pkcs11_certificate::Pkcs11Certificate,
    pkcs11_data_object::Pkcs11DataObject,
};

const COSMIAN_PKCS11_DISK_ENCRYPTION_TAG: &str = "disk-encryption";

pub struct CkmsBackend {
    kms_client: KmsClient,
}

impl CkmsBackend {
    /// Instantiate a new `CkmsBackend` using the
    pub fn instantiate(kms_client: KmsClient) -> Result<Self, Pkcs11Error> {
        Ok(CkmsBackend { kms_client })
    }
}

impl Backend for CkmsBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Cosmian-KMS                     "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Cosmian                         "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"software        "
    }

    fn token_serial_number(&self) -> [u8; 16] {
        let version = env!("CARGO_PKG_VERSION").as_bytes();
        let len = version.len().min(16);
        let mut sn = *b"                ";
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
    ) -> pkcs11_module::Result<Option<Arc<dyn Certificate>>> {
        trace!("find_all_certificates");
        Ok(None)
    }

    fn find_all_certificates(&self) -> pkcs11_module::Result<Vec<Arc<dyn Certificate>>> {
        trace!("find_all_certificates");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_string());
        let kms_objects = get_kms_objects(
            &self.kms_client,
            &[disk_encryption_tag, "_cert".to_string()],
        )?;
        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn Certificate> = Arc::new(Pkcs11Certificate::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn find_private_key(
        &self,
        _query: SearchOptions,
    ) -> pkcs11_module::Result<Option<Arc<dyn PrivateKey>>> {
        trace!("find_private_key: {:?}", _query);
        Ok(None)
    }

    fn find_public_key(
        &self,
        query: SearchOptions,
    ) -> pkcs11_module::Result<Option<Arc<dyn PublicKey>>> {
        trace!("find_public_key: {:?}", query);
        Ok(None)
    }

    fn find_all_private_keys(&self) -> pkcs11_module::Result<Vec<Arc<dyn PrivateKey>>> {
        trace!("find_all_private_keys");
        Ok(vec![])
    }

    fn find_all_public_keys(&self) -> pkcs11_module::Result<Vec<Arc<dyn PublicKey>>> {
        trace!("find_all_public_keys");
        Ok(vec![])
    }

    fn find_data_object(
        &self,
        query: SearchOptions,
    ) -> pkcs11_module::Result<Option<Arc<dyn DataObject>>> {
        trace!("find_data_object: {:?}", query);
        Ok(None)
    }

    fn find_all_data_objects(&self) -> pkcs11_module::Result<Vec<Arc<dyn DataObject>>> {
        trace!("find_all_data_objects");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_string());
        let kms_objects =
            get_kms_objects(&self.kms_client, &[disk_encryption_tag, "_kk".to_string()])?;
        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn DataObject> = Arc::new(Pkcs11DataObject::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> pkcs11_module::Result<Arc<dyn PrivateKey>> {
        trace!("generate_key: {:?}, {:?}", algorithm, label);
        Ok(Arc::new(EmptyPrivateKeyImpl {}))
    }
}

struct EmptyPrivateKeyImpl;

impl PrivateKey for EmptyPrivateKeyImpl {
    fn public_key_hash(&self) -> Vec<u8> {
        vec![]
    }

    fn label(&self) -> String {
        "PrivateKeyImpl".to_string()
    }

    fn sign(
        &self,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
    ) -> pkcs11_module::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn delete(&self) {}

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

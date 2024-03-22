use std::sync::Arc;

use cosmian_kms_client::KmsClient;
use native_pkcs11_traits::{
    Backend, Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey, SearchOptions,
    SignatureAlgorithm,
};
use tracing::trace;

use crate::{error::Pkcs11Error, pkcs_11_data_object::get_pkcs11_keys};

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
    fn name(&self) -> String {
        trace!("name");
        "Cosmian KMS".to_string()
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn Certificate>>> {
        trace!("find_all_certificates");
        Ok(None)
    }

    fn find_all_certificates(&self) -> native_pkcs11_traits::Result<Vec<Box<dyn Certificate>>> {
        trace!("find_all_certificates");
        Ok(vec![])
    }

    fn find_private_key(
        &self,
        _query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn PrivateKey>>> {
        trace!("find_private_key: {:?}", _query);
        Ok(None)
    }

    fn find_public_key(
        &self,
        query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn PublicKey>>> {
        trace!("find_public_key: {:?}", query);
        Ok(None)
    }

    fn find_all_private_keys(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn PrivateKey>>> {
        trace!("find_all_private_keys");
        Ok(vec![])
    }

    fn find_all_public_keys(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn PublicKey>>> {
        trace!("find_all_public_keys");
        Ok(vec![])
    }

    fn find_data_object(
        &self,
        query: SearchOptions,
    ) -> native_pkcs11_traits::Result<Option<Arc<dyn DataObject>>> {
        trace!("find_data_object: {:?}", query);
        Ok(None)
    }

    fn find_all_data_objects(&self) -> native_pkcs11_traits::Result<Vec<Arc<dyn DataObject>>> {
        trace!("find_all_data_objects");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or("disk-encryption".to_string());
        let keys = get_pkcs11_keys(&self.kms_client, &[disk_encryption_tag])?;
        Ok(keys
            .into_iter()
            .map(|dao| -> Arc<dyn DataObject> { Arc::new(dao) })
            .collect())
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> native_pkcs11_traits::Result<Arc<dyn PrivateKey>> {
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
    ) -> native_pkcs11_traits::Result<Vec<u8>> {
        Ok(vec![])
    }

    fn delete(&self) {}

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

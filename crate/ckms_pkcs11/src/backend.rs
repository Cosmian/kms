use native_pkcs11_traits::{
    Backend, Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey, SearchOptions,
    SignatureAlgorithm,
};
use std::sync::Arc;
use tracing::trace;

pub struct CkmsBackend {}

impl CkmsBackend {
    pub fn new() -> Self {
        CkmsBackend {}
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
        Ok(vec![
            Arc::new(TestDataObjectVol1 {}),
            Arc::new(TestDataObjectVol2 {}),
        ])
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> native_pkcs11_traits::Result<Arc<dyn PrivateKey>> {
        trace!("generate_key: {:?}, {:?}", algorithm, label);
        Ok(Arc::new(PrivateKeyImpl {}))
    }
}

struct PrivateKeyImpl {}

impl PrivateKey for PrivateKeyImpl {
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

struct TestDataObjectVol1 {}

impl DataObject for TestDataObjectVol1 {
    fn value(&self) -> Vec<u8> {
        vec![1, 2, 3, 4]
    }

    fn application(&self) -> std::ffi::CString {
        std::ffi::CString::new("TestApp").unwrap()
    }

    fn data_hash(&self) -> Vec<u8> {
        vec![5, 6, 7, 8]
    }

    fn label(&self) -> String {
        "vol1".to_string()
    }

    fn delete(&self) {}
}

struct TestDataObjectVol2 {}

impl DataObject for crate::backend::TestDataObjectVol2 {
    fn value(&self) -> Vec<u8> {
        vec![4, 5, 6, 7]
    }

    fn application(&self) -> std::ffi::CString {
        std::ffi::CString::new("TestApp").unwrap()
    }

    fn data_hash(&self) -> Vec<u8> {
        vec![7, 8, 9, 0]
    }

    fn label(&self) -> String {
        "vol2".to_string()
    }

    fn delete(&self) {}
}

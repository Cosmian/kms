use native_pkcs11_traits::{KeyAlgorithm, PrivateKey, SignatureAlgorithm};
use native_pkcs11_traits::DigestType::Sha512;
use crate::log::Logger;

pub struct TestAESPrivateKey {
    bytes: Vec<u8>,
    logger: Box<dyn Logger>,
}

impl TestAESPrivateKey {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        TestAESPrivateKey {
            bytes: include_bytes!("test_data/keyfile1").to_vec(),
            logger,
        }
    }
}

impl PrivateKey for TestAESPrivateKey {
    fn public_key_hash(&self) -> Vec<u8> {
        vec![1,2,3]
    }

    fn label(&self) -> String {
        "TestAESPrivateKey".to_string()
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> native_pkcs11_traits::Result<Vec<u8>> {
        Err(Box::new("Not implemented".to_string()))
    }

    fn delete(&self) {
        todo!()
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Aes
    }
}


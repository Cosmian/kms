use std::sync::Arc;

use cosmian_kmip::kmip::kmip_types::KeyFormatType;
use cosmian_kms_client::KmsClient;
use cosmian_pkcs11_module::{
    traits::{
        Backend, Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm, PrivateKey, PublicKey,
        RemoteObjectId, RemoteObjectType, SearchOptions, SignatureAlgorithm, Version,
    },
    MError, MResult,
};
use p256::SecretKey;
use pkcs1::RsaPrivateKey;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    error::Pkcs11Error,
    kms_object::{get_kms_object, get_kms_objects, kms_decrypt, locate_kms_objects},
    pkcs11_certificate::Pkcs11Certificate,
    pkcs11_data_object::Pkcs11DataObject,
    pkcs11_error,
    pkcs11_private_key::Pkcs11PrivateKey,
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

    fn find_certificate(&self, _query: SearchOptions) -> MResult<Option<Arc<dyn Certificate>>> {
        trace!("find_certificate");
        Ok(None)
    }

    fn find_all_certificates(&self) -> MResult<Vec<Arc<dyn Certificate>>> {
        trace!("find_all_certificates");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_string());
        let kms_objects = get_kms_objects(
            &self.kms_client,
            &[disk_encryption_tag, "_cert".to_string()],
            KeyFormatType::X509,
        )?;
        let mut result = Vec::with_capacity(kms_objects.len());
        for dao in kms_objects {
            let data_object: Arc<dyn Certificate> = Arc::new(Pkcs11Certificate::try_from(dao)?);
            result.push(data_object);
        }
        Ok(result)
    }

    fn find_private_key(&self, query: SearchOptions) -> MResult<Arc<dyn PrivateKey>> {
        trace!("find_private_key: {:?}", query);
        let id = match query {
            SearchOptions::Id(id) => {
                String::from_utf8(id).map_err(|_| pkcs11_error!("find_private_key: invalid ID"))?
            }
            _ => {
                return Err(MError::Backend(Box::new(pkcs11_error!(
                    "find_private_key: find must be made using an ID"
                ))))
            }
        };
        let kms_object = get_kms_object(&self.kms_client, &id, KeyFormatType::PKCS8)?;
        Ok(Arc::new(Pkcs11PrivateKey::try_from_kms_object(kms_object)?))
    }

    fn find_public_key(&self, query: SearchOptions) -> MResult<Arc<dyn PublicKey>> {
        trace!("find_public_key: {:?}", query);
        Err(MError::Backend(Box::new(pkcs11_error!(
            "find_public_key: not implemented"
        ))))
    }

    fn find_all_private_keys(&self) -> MResult<Vec<Arc<dyn RemoteObjectId>>> {
        trace!("find_all_private_keys");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_string());
        Ok(
            locate_kms_objects(&self.kms_client, &[disk_encryption_tag, "_sk".to_string()])?
                .into_iter()
                .map(|id| {
                    Arc::new(Pkcs11PrivateKey::new(id, RemoteObjectType::PrivateKey))
                        as Arc<dyn RemoteObjectId>
                })
                .collect(),
        )
    }

    fn find_all_public_keys(&self) -> MResult<Vec<Arc<dyn PublicKey>>> {
        trace!("find_all_public_keys");
        Ok(vec![])
    }

    fn find_data_object(&self, query: SearchOptions) -> MResult<Option<Arc<dyn DataObject>>> {
        trace!("find_data_object: {:?}", query);
        Ok(None)
    }

    fn find_all_data_objects(&self) -> MResult<Vec<Arc<dyn DataObject>>> {
        trace!("find_all_data_objects");
        let disk_encryption_tag = std::env::var("COSMIAN_PKCS11_DISK_ENCRYPTION_TAG")
            .unwrap_or(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_string());
        let kms_objects = get_kms_objects(
            &self.kms_client,
            &[disk_encryption_tag, "_kk".to_string()],
            KeyFormatType::Raw,
        )?;
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
    ) -> MResult<Arc<dyn PrivateKey>> {
        trace!("generate_key: {:?}, {:?}", algorithm, label);
        Ok(Arc::new(EmptyPrivateKeyImpl {}))
    }

    fn decrypt(
        &self,
        remote_object: Arc<dyn RemoteObjectId>,
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
    ) -> MResult<Zeroizing<Vec<u8>>> {
        debug!(
            "decrypt: {:?}, cipher text length: {}",
            remote_object,
            ciphertext.len()
        );
        kms_decrypt(
            &self.kms_client,
            remote_object.remote_id(),
            algorithm,
            ciphertext,
        )
        .map_err(Into::into)
    }
}

pub(crate) struct EmptyPrivateKeyImpl;

impl PrivateKey for EmptyPrivateKeyImpl {
    fn private_key_id(&self) -> Vec<u8> {
        vec![]
    }

    fn label(&self) -> String {
        "PrivateKeyImpl".to_string()
    }

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> MResult<Vec<u8>> {
        Ok(vec![])
    }

    fn algorithm(&self) -> MResult<KeyAlgorithm> {
        Ok(KeyAlgorithm::Rsa)
    }

    fn rsa_private_key(&self) -> MResult<RsaPrivateKey> {
        Err(MError::Todo("rsa_private_key not implemented".to_string()))
    }

    fn ec_p256_private_key(&self) -> MResult<SecretKey> {
        Err(MError::Todo(
            "`p256`_private_key not implemented".to_string(),
        ))
    }
}

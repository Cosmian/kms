use std::sync::Arc;

use cosmian_kms_common::{
    kmip::{kmip_client::KmipClient, kmip_operations::*},
    result::KResult,
};

use crate::kmip::kmip_server::{server::kmip_server::KmipServer, KMSServer};

/// A KMIP client that calls the local KMS server
pub struct Client {
    kms_server: Arc<KMSServer>,
}
impl Client {
    pub fn new(kms_server: Arc<KMSServer>) -> Client {
        Client { kms_server }
    }
}

impl KmipClient for Client {
    fn import(&self, request: Import) -> KResult<ImportResponse> {
        self.kms_server.import(request)
    }

    fn create(&self, request: &Create) -> KResult<CreateResponse> {
        self.kms_server.create(request)
    }

    fn get(&self, request: &Get) -> KResult<GetResponse> {
        self.kms_server.get(request)
    }

    fn get_attributes(&self, request: &GetAttributes) -> KResult<GetAttributesResponse> {
        self.kms_server.get_attributes(request)
    }

    fn encrypt(&self, request: &Encrypt) -> KResult<EncryptResponse> {
        self.kms_server.encrypt(request)
    }

    fn decrypt(&self, request: &Decrypt) -> KResult<DecryptResponse> {
        self.kms_server.decrypt(request)
    }

    fn create_key_pair(&self, request: &CreateKeyPair) -> KResult<CreateKeyPairResponse> {
        self.kms_server.create_key_pair(request)
    }

    fn locate(&self, request: &Locate) -> KResult<LocateResponse> {
        self.kms_server.locate(request)
    }

    fn revoke(&self, request: Revoke) -> KResult<RevokeResponse> {
        self.kms_server.revoke(request)
    }

    fn rekey_keypair(&self, request: &ReKeyKeyPair) -> KResult<ReKeyKeyPairResponse> {
        self.kms_server.rekey_keypair(request)
    }

    fn destroy(&self, request: &Destroy) -> KResult<DestroyResponse> {
        self.kms_server.destroy(request)
    }
}

use cloudproof::reexport::crypto_core::{
    Ed25519Keypair, Ed25519PrivateKey, Ed25519PublicKey, CURVE_25519_SECRET_LENGTH,
    ED25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::{kmip_operations::Get, kmip_types::LinkType};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use crate::{
    core::{certificate::get_fixed_size_key_bytes, KMS},
    error::KmsError,
    result::KResult,
};

/// The `CASigningKey` struct represents a signing key used for certificate authority
/// operations and helps retrieving from KMS the related private and public keys of this certificate authority.
///
/// Properties:
///
/// * `ca_subject_common_name`: The `ca_subject_common_name` property represents the
/// common name of the CA (Certificate Authority). It is a string that identifies
/// the CA.
/// * `private_key_uid`: The `private_key_uid` property is a unique identifier for
/// the private key associated with the CA signing key. It is used to retrieve the
/// private key from a Key Management System (KMS) when needed.
/// * `public_key_uid`: The `public_key_uid` property is a unique identifier for the
/// public key associated with the CA signing key. It is used to retrieve the
/// corresponding public key from a key management system (KMS) when needed.
#[derive(Clone, Debug, Default)]
pub(crate) struct CASigningKey {
    pub ca_subject_common_name: String,
    pub private_key_uid: String,
    pub public_key_uid: String,
}

impl CASigningKey {
    pub fn new(ca_subject_common_name: &str, private_key_uid: &str, public_key_uid: &str) -> Self {
        Self {
            ca_subject_common_name: ca_subject_common_name.to_string(),
            private_key_uid: private_key_uid.to_string(),
            public_key_uid: public_key_uid.to_string(),
        }
    }

    pub async fn from_private_key_uid(
        ca_subject_common_name: &str,
        private_key_uid: &str,
        kms: &KMS,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Self> {
        let get_response = kms.get(Get::from(private_key_uid), owner, params).await?;
        let public_key_uid = &get_response
            .object
            .attributes()?
            .get_link(LinkType::PublicKeyLink)
            .ok_or(KmsError::InvalidRequest(
                "No public key link found for the found signing key".to_string(),
            ))?;

        Ok(Self::new(
            ca_subject_common_name,
            private_key_uid,
            public_key_uid,
        ))
    }

    // For the time being, KMS PKI only supports CA certificate with ED25519 private/public key.
    pub async fn key_pair(
        &self,
        kms: &KMS,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Ed25519Keypair> {
        trace!("Get private key bytes");
        let private_key: [u8; CURVE_25519_SECRET_LENGTH] =
            get_fixed_size_key_bytes(&self.private_key_uid, kms, owner, params).await?;
        trace!("Get public key bytes");
        let public_key: [u8; ED25519_PUBLIC_KEY_LENGTH] =
            get_fixed_size_key_bytes(&self.public_key_uid, kms, owner, params).await?;

        let key_pair = Ed25519Keypair {
            private_key: Ed25519PrivateKey::try_from_bytes(private_key)?,
            public_key: Ed25519PublicKey::try_from_bytes(public_key)?,
        };
        Ok(key_pair)
    }
}

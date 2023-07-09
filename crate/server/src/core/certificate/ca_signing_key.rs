use cosmian_crypto_core::{
    Ed25519Keypair, FixedSizeCBytes, CURVE_25519_SECRET_LENGTH, ED25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::{kmip_operations::Get, kmip_types::LinkType};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use crate::{
    core::{certificate::get_key_bytes, KMS},
    error::KmsError,
    result::KResult,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct CASigningKey {
    pub ca: String,
    pub private_key_uid: String,
    pub public_key_uid: String,
}

impl CASigningKey {
    pub fn new(ca: &str, private_key_uid: &str, public_key_uid: &str) -> Self {
        Self {
            ca: ca.to_string(),
            private_key_uid: private_key_uid.to_string(),
            public_key_uid: public_key_uid.to_string(),
        }
    }

    pub async fn from_private_key_uid(
        ca: &str,
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

        Ok(Self::new(ca, private_key_uid, public_key_uid))
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
            get_key_bytes(&self.private_key_uid, kms, owner, params).await?;
        trace!("Get public key bytes");
        let public_key: [u8; ED25519_PUBLIC_KEY_LENGTH] =
            get_key_bytes(&self.public_key_uid, kms, owner, params).await?;

        let mut serialized_key_pair = [0u8; CURVE_25519_SECRET_LENGTH + ED25519_PUBLIC_KEY_LENGTH];
        serialized_key_pair[..CURVE_25519_SECRET_LENGTH].copy_from_slice(&private_key);
        serialized_key_pair[CURVE_25519_SECRET_LENGTH..].copy_from_slice(&public_key);

        let key_pair = Ed25519Keypair::try_from_bytes(serialized_key_pair).map_err(|e| {
            KmsError::ConversionError(format!("Deserialize X25519 key pair failed, Error: {e}",))
        })?;
        Ok(key_pair)
    }
}

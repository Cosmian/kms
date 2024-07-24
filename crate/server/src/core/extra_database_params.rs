use cosmian_kmip::crypto::{secret::Secret, symmetric::AES_256_GCM_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub struct ExtraDatabaseParams {
    pub group_id: u128,
    pub key: Secret<AES_256_GCM_KEY_LENGTH>,
}

impl Serialize for ExtraDatabaseParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(
            [&self.group_id.to_be_bytes(), &*self.key]
                .concat()
                .as_slice(),
        )
    }
}

impl<'de> Deserialize<'de> for ExtraDatabaseParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Zeroizing::from(<Vec<u8>>::deserialize(deserializer)?);
        let group_id_bytes: [u8; 16] = bytes[0..16]
            .try_into()
            .map_err(|_| serde::de::Error::custom("Could not deserialize ExtraDatabaseParams"))?;
        let group_id = u128::from_be_bytes(group_id_bytes);

        let mut key_bytes: [u8; AES_256_GCM_KEY_LENGTH] = bytes[16..48]
            .try_into()
            .map_err(|_| serde::de::Error::custom("Could not deserialize ExtraDatabaseParams"))?;
        let key = Secret::<AES_256_GCM_KEY_LENGTH>::from_unprotected_bytes(&mut key_bytes);
        Ok(Self { group_id, key })
    }
}

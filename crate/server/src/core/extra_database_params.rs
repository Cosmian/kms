use cosmian_kmip::crypto::{secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH};
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
        let group_id_bytes: [u8; 16] = bytes
            .get(0..16)
            .ok_or_else(|| {
                serde::de::Error::custom("Could not get the first 16 bytes.".to_owned())
            })?
            .try_into()
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "Could not deserialize ExtraDatabaseParams. Error: {e:?}"
                ))
            })?;
        let group_id = u128::from_be_bytes(group_id_bytes);

        let mut key_bytes: [u8; AES_256_GCM_KEY_LENGTH] = bytes
            .get(16..48)
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "Could not extract bytes from indices 16 to 48.".to_owned(),
                )
            })?
            .try_into()
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "Could not deserialize ExtraDatabaseParams. Error: {e:?}"
                ))
            })?;
        let key = Secret::<AES_256_GCM_KEY_LENGTH>::from_unprotected_bytes(&mut key_bytes);
        Ok(Self { group_id, key })
    }
}

use cloudproof::reexport::crypto_core::{FixedSizeCBytes, RandomFixedSizeCBytes, SymmetricKey};
use serde::{Deserialize, Serialize};

pub struct ExtraDatabaseParams {
    pub group_id: u128,
    pub key: SymmetricKey<32>,
}

impl Serialize for ExtraDatabaseParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(
            [
                self.group_id.to_be_bytes().to_vec(),
                self.key.as_bytes().to_vec(),
            ]
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
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let group_id_bytes: [u8; 16] = bytes[0..16]
            .try_into()
            .map_err(|_| serde::de::Error::custom("Could not deserialize ExtraDatabaseParams"))?;
        let group_id = u128::from_be_bytes(group_id_bytes);
        let key_bytes: [u8; 32] = bytes[16..48]
            .try_into()
            .map_err(|_| serde::de::Error::custom("Could not deserialize ExtraDatabaseParams"))?;
        let key = SymmetricKey::try_from_bytes(key_bytes)
            .map_err(|_| serde::de::Error::custom("Could not deserialize ExtraDatabaseParams"))?;
        Ok(ExtraDatabaseParams { group_id, key })
    }
}

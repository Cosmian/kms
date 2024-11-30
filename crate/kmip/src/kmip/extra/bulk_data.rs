use std::ops::Deref;

use cloudproof::reexport::crypto_core::bytes_ser_de::{Deserializer, Serializer};
use tracing::trace;
use zeroize::Zeroizing;

use crate::{
    error::{result::KmipResult, KmipError},
    kmip::kmip_operations::ErrorReason,
};

/// Bulk Data is a structure that holds a list of zeroizing byte arrays
/// i.e., a `Vec<Zeroizing<Vec<u8>>>`
/// When serialized it is prepended with the sequence 0x8787
#[derive(Debug)]
pub struct BulkData(Vec<Zeroizing<Vec<u8>>>);

impl BulkData {
    #[must_use]
    pub const fn new(data: Vec<Zeroizing<Vec<u8>>>) -> Self {
        Self(data)
    }

    /// If the data starts with the sequence 0x8787, it MAY be a `BulkData`
    #[must_use]
    #[allow(clippy::indexing_slicing, clippy::missing_asserts_for_indexing)]
    pub const fn is_bulk_data(data: &[u8]) -> bool {
        data.len() > 2 && data[0] == 0x87 && data[1] == 0x87
    }

    pub fn serialize(&self) -> KmipResult<Zeroizing<Vec<u8>>> {
        let mut se = Serializer::new();
        se.write_array(&[0x87, 0x87])?;
        se.write_leb128_u64(u64::try_from(self.0.len())?)?;
        for v in &self.0 {
            se.write_vec(v)?;
        }
        Ok(Zeroizing::new(se.finalize().to_vec()))
    }

    #[allow(clippy::indexing_slicing)]
    pub fn deserialize(serialized: &[u8]) -> Result<Self, KmipError> {
        if !Self::is_bulk_data(serialized) {
            trace!("Not a BulkData");
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Illegal_Object_Type,
                "Not a BulkData".to_owned(),
            ));
        }
        let data = &serialized[2..];
        let mut de = Deserializer::new(data);
        let v = usize::try_from(de.read_leb128_u64()?)?;
        let mut data = Vec::with_capacity(v);
        for _ in 0..v {
            data.push(Zeroizing::new(de.read_vec()?));
        }
        Ok(Self(data))
    }
}

impl Deref for BulkData {
    type Target = Vec<Zeroizing<Vec<u8>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<Zeroizing<Vec<u8>>>> for BulkData {
    fn from(value: Vec<Zeroizing<Vec<u8>>>) -> Self {
        Self(value)
    }
}

impl From<Vec<Vec<u8>>> for BulkData {
    fn from(value: Vec<Vec<u8>>) -> Self {
        Self(value.into_iter().map(Zeroizing::new).collect())
    }
}

impl From<BulkData> for Vec<Zeroizing<Vec<u8>>> {
    fn from(value: BulkData) -> Self {
        value.0
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use crate::kmip::extra::BulkData;

    #[test]
    fn test_bulk_data() {
        use zeroize::Zeroizing;
        let data = vec![
            Zeroizing::new(vec![1, 2, 3]),
            Zeroizing::new(vec![4, 5, 6]),
            Zeroizing::new(vec![7; 10]),
        ];
        let bulk_data = BulkData::new(data.clone());
        let serialized = bulk_data.serialize().unwrap();
        assert_eq!(
            serialized.to_vec(),
            vec![
                0x87, 0x87, 0x03, 0x03, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
            ]
        );
        let deserialized = BulkData::deserialize(&serialized).unwrap();
        assert_eq!(data, deserialized.0);
    }
}

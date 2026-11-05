use std::ops::Deref;

use cosmian_logger::trace;
use zeroize::Zeroizing;

use crate::{
    Deserializer, Serializer,
    error::{KmipError, result::KmipResult},
    kmip_0::kmip_types::ErrorReason,
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
    pub const fn is_bulk_data(data: &[u8]) -> bool {
        matches!(data, [0x87, 0x87, _, ..])
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

    pub fn deserialize(serialized: &[u8]) -> Result<Self, KmipError> {
        if !Self::is_bulk_data(serialized) {
            trace!("Not a BulkData");
            return Err(KmipError::InvalidKmip21Object(
                ErrorReason::Illegal_Object_Type,
                "Not a BulkData".to_owned(),
            ));
        }
        let data = serialized.get(2..).unwrap_or_default();
        let mut de = Deserializer::new(data);
        let v = usize::try_from(de.read_leb128_u64()?)?;
        // Each element requires at least 1 byte (a zero-length LEB128 prefix);
        // reject counts that exceed the remaining bytes to prevent OOM on
        // malformed or not-detected bulk data.
        let remaining = de.value().len();
        if v > remaining {
            return Err(KmipError::InvalidKmip21Object(
                ErrorReason::Illegal_Object_Type,
                format!(
                    "BulkData count {v} exceeds remaining data length {remaining}; not valid BulkData"
                ),
            ));
        }
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

#[cfg(test)]
mod tests {
    use crate::kmip_2_1::extra::BulkData;

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

#[cfg(test)]
mod characterization_tests {
    use super::BulkData;

    #[test]
    fn characterization_bulk_data_is_bulk_data_boundaries() {
        assert!(!BulkData::is_bulk_data(&[]));
        assert!(!BulkData::is_bulk_data(&[0x87]));
        assert!(!BulkData::is_bulk_data(&[0x87, 0x87]));
        assert!(BulkData::is_bulk_data(&[0x87, 0x87, 0x00]));
        assert!(BulkData::is_bulk_data(&[0x87, 0x87, 0x00, 0xFF]));
        assert!(!BulkData::is_bulk_data(&[0x87, 0x86, 0x00]));
        assert!(!BulkData::is_bulk_data(&[0x86, 0x87, 0x00]));
    }

    #[test]
    fn characterization_bulk_data_serialize_roundtrip_golden() {
        let bd = BulkData::from(vec![vec![1_u8, 2], vec![3_u8]]);
        let ser = bd.serialize().unwrap();
        assert_eq!(hex::encode(ser.as_slice()), "8787020201020103");
        let back = BulkData::deserialize(&hex::decode("8787020201020103").unwrap()).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.first().unwrap().as_slice(), [1_u8, 2]);
        assert_eq!(back.get(1).unwrap().as_slice(), [3_u8]);
    }

    #[test]
    fn characterization_bulk_data_deserialize_errors() {
        for (input, msg) in [
            (
                "",
                "Invalid KMIP 2.1 Object: Illegal_Object_Type: Not a BulkData",
            ),
            (
                "8787",
                "Invalid KMIP 2.1 Object: Illegal_Object_Type: Not a BulkData",
            ),
            (
                "000102",
                "Invalid KMIP 2.1 Object: Illegal_Object_Type: Not a BulkData",
            ),
            (
                "878705",
                "Invalid KMIP 2.1 Object: Illegal_Object_Type: BulkData count 5 exceeds remaining data length 0; not valid BulkData",
            ),
            (
                "8787010501",
                "Serialization error: when reading 5 bytes, readable buffer too small: 1 bytes",
            ),
        ] {
            let err = BulkData::deserialize(&hex::decode(input).unwrap()).unwrap_err();
            assert_eq!(err.to_string(), msg);
        }
    }
}

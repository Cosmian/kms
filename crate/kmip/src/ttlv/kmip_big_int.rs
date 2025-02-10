use serde::{Deserialize, Serialize};

use super::error::TtlvError;

/// A wrapper struct for `num_bigint_dig::BigInt` that provides KMIP-specific encoding and decoding.
///
/// This type represents a Big Integer as defined in the KMIP (Key Management Interoperability Protocol)
/// specification. It provides methods for encoding and decoding big integers according to KMIP rules.
///
/// # KMIP Specification
/// Big Integers in KMIP are encoded as a sequence of eight-bit bytes, in two's complement notation,
/// transmitted big-endian. The length of the sequence must be a multiple of eight bytes, with padding
/// applied if necessary.
///
/// # Examples
/// ```
/// use kmip::ttlv::KmipBigInt;
/// use num_bigint_dig::BigInt;
///
/// // Create from BigInt
/// let big_int = BigInt::from(42);
/// let kmip_int = KmipBigInt::from(big_int);
///
/// // Convert to bytes (KMIP-compliant encoding)
/// let bytes = kmip_int.to_bytes_be();
///
/// // Create from bytes
/// let decoded = KmipBigInt::from_bytes_be(&bytes);
/// ```
///
/// # Conversions
/// This type provides `From` implementations for conversion between `KmipBigInt` and
/// `num_bigint_dig::BigInt` in both directions.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KmipBigInt(num_bigint_dig::BigInt);

impl From<num_bigint_dig::BigInt> for KmipBigInt {
    fn from(big_int: num_bigint_dig::BigInt) -> Self {
        Self(big_int)
    }
}

impl From<KmipBigInt> for num_bigint_dig::BigInt {
    fn from(val: KmipBigInt) -> Self {
        val.0
    }
}

// FIXME: This is a temporary solution to avoid breaking changes in the API.
// The BigUints must go
impl From<num_bigint_dig::BigUint> for KmipBigInt {
    fn from(big_int: num_bigint_dig::BigUint) -> Self {
        Self(big_int.into())
    }
}

// FIXME: This is a temporary solution to avoid breaking changes in the API.
// The BigUints must go
impl From<KmipBigInt> for num_bigint_dig::BigUint {
    fn from(val: KmipBigInt) -> Self {
        val.0.to_biguint().unwrap_or_default()
    }
}

impl KmipBigInt {
    /// Encoded as a sequence of eight-bit bytes, in two's complement notation,
    /// transmitted big-endian. If the length of the sequence is not a multiple of eight bytes,
    /// then Big Integers SHALL be padded with the minimal number of leading sign-extended bytes
    /// to make the length a multiple of eight bytes.
    /// These padding bytes are part of the Item Value and SHALL be counted in the Item Length.
    #[must_use]
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut bytes = self.0.to_signed_bytes_be();
        let len = bytes.len();
        if len % 8 != 0 {
            let padding = 8 - len % 8;
            let mut padded_bytes = match self.0.sign() {
                num_bigint_dig::Sign::Minus => vec![255_u8; padding],
                num_bigint_dig::Sign::NoSign | num_bigint_dig::Sign::Plus => vec![0_u8; padding],
            };
            padded_bytes.append(&mut bytes);
            padded_bytes
        } else {
            bytes
        }
    }

    #[must_use]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(num_bigint_dig::BigInt::from_signed_bytes_be(bytes))
    }

    /// Returns the sign of the big integer.
    /// -1 if the number is negative, 0 if it is zero, and 1 if it is positive.
    /// This is used in the TTLV Deserializer to determine the sign of the big integer.
    #[must_use]
    pub fn sign(&self) -> i8 {
        match self.0.sign() {
            num_bigint_dig::Sign::Minus => -1,
            num_bigint_dig::Sign::NoSign => 0,
            num_bigint_dig::Sign::Plus => 1,
        }
    }

    /// Convert the abolute value of a `BigInt` into a `Vec<u32>`.
    /// This is used by the TTLV Serializer to construct a `BigInt`.
    ///
    /// Get the `Vec<u8>` representation from the `BigUint`,
    /// and chunk it 4-by-4 bytes to create the multiple
    /// `u32` bytes needed for `Vec<u32>` representation.
    ///
    /// This conversion is done manually, as `num-bigint-dig`
    /// doesn't provide such conversion.
    pub fn to_u32_digits(&self) -> Result<Vec<u32>, TtlvError> {
        // Since the KMS works with big-endian representation of byte arrays, casting
        // a group of 4 bytes in big-endian u32 representation needs revert iter so
        // that if you have a chunk [0, 12, 143, 239] you will do
        // B = 239 + 143*2^8 + 12*2^16 + 0*2^24 which is the correct way to do. On
        // top of that, if the number of bytes in `big_int` is not a multiple of 4,
        // it will behave as if there were leading null bytes which is technically
        // the case.
        // In this case, using this to convert a BigUint to a Vec<u32> will not lose
        // leading null bytes information which might be the case when an EC private
        // key is legally generated with leading null bytes.
        let (_sign, mut bytes_be) = self.0.to_bytes_be();
        bytes_be.reverse();

        let mut result = Vec::new();
        for group_of_4_bytes in bytes_be.chunks(4) {
            let mut acc = 0;
            for (k, elt) in group_of_4_bytes.iter().enumerate() {
                acc += u32::from(*elt) * 2_u32.pow(u32::try_from(k)? * 8);
            }
            result.push(acc);
        }
        Ok(result)
    }

    pub fn from_u32_digits(digits: &[u32], sign: i8) -> Result<Self, TtlvError> {
        let mut bytes = Vec::new();
        for digit in digits {
            let mut acc = *digit;
            for _ in 0..4 {
                #[allow(clippy::as_conversions)]
                bytes.push((acc & 0xFF) as u8);
                acc >>= 8;
            }
        }
        bytes.reverse();
        let sign = match sign {
            -1 => num_bigint_dig::Sign::Minus,
            0 => num_bigint_dig::Sign::NoSign,
            1 => num_bigint_dig::Sign::Plus,
            x => return Err(TtlvError::from(format!("InvalidSign: {x}"))),
        };
        let big_int = num_bigint_dig::BigInt::from_bytes_be(sign, &bytes);
        Ok(Self(big_int))
    }
}

impl Serialize for KmipBigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = "0x".to_owned() + &hex::encode_upper(self.to_bytes_be());
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for KmipBigInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if !s.starts_with("0x") {
            return Err(serde::de::Error::custom(
                "Invalid KMIP Big Integer string: it must start with '0x'",
            ));
        }
        // take the string from the 3rd character to the end of the string
        let hex_str = s.get(2..).ok_or_else(|| {
            serde::de::Error::custom("Invalid KMIP Big Integer string: unexpected end of string")
        })?;
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        Ok(Self::from_bytes_be(&bytes))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::panic)]
mod tests {
    use num_bigint_dig::BigInt;
    use num_traits::pow::Pow;

    use crate::ttlv::kmip_big_int::KmipBigInt;

    #[test]
    fn test_kmip_bib_int() {
        let values = [
            BigInt::from(0),
            BigInt::from(-4),
            BigInt::from(4),
            BigInt::from(-123_456_789),
            BigInt::from(123_456_789),
            BigInt::from(-1_234_567_890_123_456_i64),
            BigInt::from(1_234_567_890_123_456_i64),
            BigInt::from(-1_234_567_890_123_456_789_i64),
            BigInt::from(1_234_567_890_123_456_789_i64),
            BigInt::from(170_141_183_460_469_231_731_687_000_000_000_000_i128),
            BigInt::from(-170_141_183_460_469_231_731_687_000_000_000_000_i128),
            BigInt::from(i128::MAX),
            BigInt::from(i128::MIN),
        ];
        for value in &values {
            let big_int = KmipBigInt::from(value.clone());
            let bytes = big_int.to_bytes_be();
            assert_eq!(bytes.len() % 8, 0);
            let big_int2 = KmipBigInt::from_bytes_be(&bytes);
            assert_eq!(big_int, big_int2);
        }
    }

    #[test]
    fn test_edge_cases() {
        let values = [
            // Test very small numbers
            BigInt::from(1),
            BigInt::from(-1),
            // Test numbers near power of 2 boundaries
            BigInt::from(255),
            BigInt::from(256),
            BigInt::from(-255),
            BigInt::from(-256),
            // Test consecutive numbers
            BigInt::from(9998),
            BigInt::from(9999),
            BigInt::from(10000),
            // Test prime numbers
            BigInt::from(17),
            BigInt::from(97),
            BigInt::from(541),
            // Test near 64-bit boundaries
            BigInt::from(u64::MAX),
            BigInt::from(i64::MAX),
            BigInt::from(i64::MIN),
            // Test powers of 2
            BigInt::from(2).pow(&8_u32),
            BigInt::from(2).pow(&16_u32),
            BigInt::from(2).pow(&32_u32),
            BigInt::from(2).pow(&64_u32),
        ];

        for value in &values {
            let big_int = KmipBigInt::from(value.clone());
            let bytes = big_int.to_bytes_be();
            assert_eq!(bytes.len() % 8, 0);
            let big_int2 = KmipBigInt::from_bytes_be(&bytes);
            assert_eq!(big_int, big_int2);
        }
    }

    #[test]
    fn test_serde() {
        let tests = [
            (
                KmipBigInt::from(BigInt::from(-1_234_567_890_i128)),
                "0xFFFFFFFFB669FD2E",
            ),
            (
                KmipBigInt::from(BigInt::from(1_234_567_890_i128)),
                "0x00000000499602D2",
            ),
        ];

        for (big_int, expected) in &tests {
            let serialized = serde_json::to_string(&big_int).unwrap();
            assert_eq!(serialized, format!("\"{expected}\""));

            let deserialized: KmipBigInt = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, *big_int);
        }
    }

    #[test]
    fn test_to_u32() {
        let values = [
            BigInt::from(0),
            BigInt::from(-4),
            BigInt::from(4),
            BigInt::from(-123_456_789),
            BigInt::from(123_456_789),
            BigInt::from(-1_234_567_890_123_456_i64),
            BigInt::from(1_234_567_890_123_456_i64),
            BigInt::from(-1_234_567_890_123_456_789_i64),
            BigInt::from(1_234_567_890_123_456_789_i64),
            BigInt::from(170_141_183_460_469_231_731_687_000_000_000_000_i128),
            BigInt::from(-170_141_183_460_469_231_731_687_000_000_000_000_i128),
            BigInt::from(i128::MAX),
            BigInt::from(i128::MIN),
        ];
        for value in &values {
            let big_int = KmipBigInt::from(value.clone());
            let u32_digits = big_int.to_u32_digits().unwrap();
            let big_int2 = KmipBigInt::from_u32_digits(&u32_digits, big_int.sign()).unwrap();
            assert_eq!(big_int, big_int2);
        }
    }
}

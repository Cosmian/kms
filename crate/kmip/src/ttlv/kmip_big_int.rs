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
}

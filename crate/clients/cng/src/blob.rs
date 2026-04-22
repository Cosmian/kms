/// BCrypt/NCrypt binary blob marshaling utilities.
///
/// Windows CNG uses typed binary blobs to represent key material in public
/// `ExportKey` responses. We build these structures from KMS-returned data so
/// that callers (certificate enrollment, TLS stacks, etc.) can use the exported
/// public key in standard Windows APIs.
///
/// References:
/// - <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>
/// - <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob>
use crate::error::{KspError, KspResult};

// ─── RSA ─────────────────────────────────────────────────────────────────────

/// CNG magic numbers for RSA key blobs.
pub const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3153_4152; // "RSA1"
pub const BCRYPT_RSAPRIVATE_MAGIC: u32 = 0x3253_4152; // "RSA2"
pub const BCRYPT_RSAFULLPRIVATE_MAGIC: u32 = 0x3352_5341; // "RSA3" (little-endian "RSA3")

/// Serialises an RSA public key (modulus + public exponent) into a
/// `BCRYPT_RSAKEY_BLOB` as expected by Windows CNG `BCryptImportKeyPair`.
///
/// Layout (little-endian):
/// ```text
/// DWORD  Magic          // BCRYPT_RSAPUBLIC_MAGIC
/// DWORD  BitLength
/// DWORD  cbPublicExp    // byte length of exponent
/// DWORD  cbModulus      // byte length of modulus
/// DWORD  cbPrime1       // 0 for public blobs
/// DWORD  cbPrime2       // 0 for public blobs
/// BYTE[] PublicExponent
/// BYTE[] Modulus
/// ```
pub fn rsa_public_blob(public_exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    let bit_length = u32::try_from(modulus.len() * 8).unwrap_or(0);
    let cb_pub_exp = u32::try_from(public_exponent.len()).unwrap_or(0);
    let cb_modulus = u32::try_from(modulus.len()).unwrap_or(0);

    let mut blob = Vec::with_capacity(24 + public_exponent.len() + modulus.len());
    blob.extend_from_slice(&BCRYPT_RSAPUBLIC_MAGIC.to_le_bytes());
    blob.extend_from_slice(&bit_length.to_le_bytes());
    blob.extend_from_slice(&cb_pub_exp.to_le_bytes());
    blob.extend_from_slice(&cb_modulus.to_le_bytes());
    blob.extend_from_slice(&0_u32.to_le_bytes()); // cbPrime1 = 0
    blob.extend_from_slice(&0_u32.to_le_bytes()); // cbPrime2 = 0
    blob.extend_from_slice(public_exponent);
    blob.extend_from_slice(modulus);
    blob
}

/// Parse PKCS#1 RSA public-key DER bytes and return a `BCRYPT_RSAKEY_BLOB`.
///
/// PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
///
/// We do a minimal hand-rolled DER parse to avoid adding heavy `der`/`pkcs1`
/// dependencies to this lightweight crate.
pub fn rsa_public_blob_from_pkcs1_der(der: &[u8]) -> KspResult<Vec<u8>> {
    let (modulus, exponent) = parse_pkcs1_public_der(der)?;
    Ok(rsa_public_blob(&exponent, &modulus))
}

/// Parse a SubjectPublicKeyInfo (SPKI) DER and return a `BCRYPT_RSAKEY_BLOB`.
///
/// SPKI wraps a PKCS#1 RSAPublicKey in an AlgorithmIdentifier + BIT STRING.
pub fn rsa_public_blob_from_spki_der(spki_der: &[u8]) -> KspResult<Vec<u8>> {
    // Strip the SPKI outer SEQUENCE + AlgorithmIdentifier to reach the RSAPublicKey
    let pkcs1_der = spki_inner_key(spki_der)?;
    rsa_public_blob_from_pkcs1_der(pkcs1_der)
}

// ─── EC ──────────────────────────────────────────────────────────────────────

/// CNG magic numbers for EC key blobs.
pub const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3136_5345; // "ES61"
pub const BCRYPT_ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3336_5345; // "ES63"
pub const BCRYPT_ECDSA_PUBLIC_P521_MAGIC: u32 = 0x3536_5345; // "ES65"
pub const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345; // "ECK1"
pub const BCRYPT_ECDH_PUBLIC_P384_MAGIC: u32 = 0x334B_4345; // "ECK3"
pub const BCRYPT_ECDH_PUBLIC_P521_MAGIC: u32 = 0x354B_4345; // "ECK5"

/// Curve identifier used when choosing the EC blob magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// Return byte length of the coordinate for this curve.
    #[must_use]
    pub const fn coord_size(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// Return the ECDSA public blob magic for this curve.
    #[must_use]
    pub const fn ecdsa_public_magic(self) -> u32 {
        match self {
            Self::P256 => BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            Self::P384 => BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
            Self::P521 => BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
        }
    }

    /// Return the ECDH public blob magic for this curve.
    #[must_use]
    pub const fn ecdh_public_magic(self) -> u32 {
        match self {
            Self::P256 => BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            Self::P384 => BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            Self::P521 => BCRYPT_ECDH_PUBLIC_P521_MAGIC,
        }
    }
}

/// Build a `BCRYPT_ECCKEY_BLOB` for a public EC key.
///
/// Layout:
/// ```text
/// DWORD Magic
/// DWORD cbKey      // byte length of each coordinate (X and Y)
/// BYTE[cbKey] X
/// BYTE[cbKey] Y
/// ```
///
/// `x` and `y` must already be zero-padded to `curve.coord_size()`.
pub fn ec_public_blob(curve: EcCurve, x: &[u8], y: &[u8], ecdsa: bool) -> Vec<u8> {
    let magic = if ecdsa {
        curve.ecdsa_public_magic()
    } else {
        curve.ecdh_public_magic()
    };
    let cb_key = u32::try_from(curve.coord_size()).unwrap_or(0);

    let mut blob = Vec::with_capacity(8 + x.len() + y.len());
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&cb_key.to_le_bytes());
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);
    blob
}

/// Build an EC public `BCRYPT_ECCKEY_BLOB` from a raw uncompressed EC point
/// (`04 || X || Y`).
pub fn ec_public_blob_from_uncompressed(
    curve: EcCurve,
    point: &[u8],
    ecdsa: bool,
) -> KspResult<Vec<u8>> {
    let coord = curve.coord_size();
    // Uncompressed point: 0x04 prefix + X (coord bytes) + Y (coord bytes)
    if point.len() != 1 + 2 * coord || point[0] != 0x04 {
        return Err(KspError::InvalidParameter(
            "EC point must be uncompressed (0x04 prefix)".to_owned(),
        ));
    }
    let x = point.get(1..1 + coord).ok_or_else(|| {
        KspError::InvalidParameter("EC point too short for X coordinate".to_owned())
    })?;
    let y = point.get(1 + coord..).ok_or_else(|| {
        KspError::InvalidParameter("EC point too short for Y coordinate".to_owned())
    })?;
    Ok(ec_public_blob(curve, x, y, ecdsa))
}

/// Parse an EC SubjectPublicKeyInfo (SPKI) DER and produce a
/// `BCRYPT_ECCKEY_BLOB`.  Detects the curve from the OID.
pub fn ec_public_blob_from_spki_der(spki_der: &[u8], ecdsa: bool) -> KspResult<Vec<u8>> {
    let (curve, point) = spki_ec_inner_key(spki_der)?;
    ec_public_blob_from_uncompressed(curve, point, ecdsa)
}

// ─── Minimal DER helpers ─────────────────────────────────────────────────────

/// Skip a DER TLV and return the value slice.
fn der_read_tlv(data: &[u8]) -> KspResult<(&[u8], &[u8])> {
    if data.len() < 2 {
        return Err(KspError::InvalidParameter("DER too short".to_owned()));
    }
    let _tag = data[0];
    let (len, hdr) = if data[1] & 0x80 == 0 {
        (usize::from(data[1]), 2_usize)
    } else {
        let n = usize::from(data[1] & 0x7F);
        if data.len() < 2 + n {
            return Err(KspError::InvalidParameter("DER length truncated".to_owned()));
        }
        let mut l = 0_usize;
        for b in data.iter().skip(2).take(n) {
            l = l
                .checked_shl(8)
                .ok_or_else(|| KspError::InvalidParameter("DER length overflow".to_owned()))?
                | usize::from(*b);
        }
        (l, 2 + n)
    };
    let end = hdr + len;
    if end > data.len() {
        return Err(KspError::InvalidParameter("DER value truncated".to_owned()));
    }
    Ok((&data[hdr..end], &data[end..]))
}

/// Strip leading zero byte from a DER INTEGER value (ASN.1 sign byte).
fn strip_leading_zero(v: &[u8]) -> &[u8] {
    if v.first() == Some(&0) {
        v.get(1..).unwrap_or(v)
    } else {
        v
    }
}

/// Parse a minimal PKCS#1 RSAPublicKey DER and return (modulus, exponent).
fn parse_pkcs1_public_der(der: &[u8]) -> KspResult<(Vec<u8>, Vec<u8>)> {
    // SEQUENCE { INTEGER modulus, INTEGER exponent }
    let (seq, _) = der_read_tlv(der)?;
    if der[0] != 0x30 {
        return Err(KspError::InvalidParameter(
            "Expected SEQUENCE in RSA public key".to_owned(),
        ));
    }
    let (mod_val, rest) = der_read_tlv(seq)?;
    if seq[0] != 0x02 {
        return Err(KspError::InvalidParameter(
            "Expected INTEGER (modulus)".to_owned(),
        ));
    }
    let modulus = strip_leading_zero(mod_val).to_vec();

    let (exp_val, _) = der_read_tlv(rest)?;
    if rest[0] != 0x02 {
        return Err(KspError::InvalidParameter(
            "Expected INTEGER (exponent)".to_owned(),
        ));
    }
    let exponent = strip_leading_zero(exp_val).to_vec();

    Ok((modulus, exponent))
}

/// Strip the SPKI AlgorithmIdentifier wrapper from an RSA key and return the
/// inner PKCS#1 RSAPublicKey DER bytes.
fn spki_inner_key(spki: &[u8]) -> KspResult<&[u8]> {
    // SEQUENCE (outer SPKI)
    if spki.first() != Some(&0x30) {
        return Err(KspError::InvalidParameter("Expected SPKI SEQUENCE".to_owned()));
    }
    let (spki_body, _) = der_read_tlv(spki)?;
    // First element is AlgorithmIdentifier SEQUENCE — skip it
    let (_algo, rest) = der_read_tlv(spki_body)?;
    // Second element is BIT STRING containing the key
    if rest.first() != Some(&0x03) {
        return Err(KspError::InvalidParameter(
            "Expected BIT STRING in SPKI".to_owned(),
        ));
    }
    let (bit_string, _) = der_read_tlv(rest)?;
    // BIT STRING starts with unused-bits byte (always 0x00 for aligned keys)
    bit_string
        .get(1..)
        .ok_or_else(|| KspError::InvalidParameter("BIT STRING too short".to_owned()))
}

/// OIDs for EC named curves.
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_SECP521R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];

/// Extract the EC curve and uncompressed point from a SubjectPublicKeyInfo DER.
fn spki_ec_inner_key(spki: &[u8]) -> KspResult<(EcCurve, &[u8])> {
    if spki.first() != Some(&0x30) {
        return Err(KspError::InvalidParameter("Expected SPKI SEQUENCE".to_owned()));
    }
    let (spki_body, _) = der_read_tlv(spki)?;

    // AlgorithmIdentifier SEQUENCE
    if spki_body.first() != Some(&0x30) {
        return Err(KspError::InvalidParameter(
            "Expected AlgorithmIdentifier SEQUENCE".to_owned(),
        ));
    }
    let (algo_body, rest) = der_read_tlv(spki_body)?;

    // First OID inside algo: id-ecPublicKey (1.2.840.10045.2.1) — skip it
    if algo_body.first() != Some(&0x06) {
        return Err(KspError::InvalidParameter(
            "Expected OID in AlgorithmIdentifier".to_owned(),
        ));
    }
    let (_ec_algo_oid, curve_rest) = der_read_tlv(algo_body)?;

    // Second OID: named curve
    if curve_rest.first() != Some(&0x06) {
        return Err(KspError::InvalidParameter(
            "Expected curve OID in AlgorithmIdentifier".to_owned(),
        ));
    }
    let (curve_oid_bytes, _) = der_read_tlv(curve_rest)?;
    let curve = if curve_oid_bytes == OID_PRIME256V1 {
        EcCurve::P256
    } else if curve_oid_bytes == OID_SECP384R1 {
        EcCurve::P384
    } else if curve_oid_bytes == OID_SECP521R1 {
        EcCurve::P521
    } else {
        return Err(KspError::AlgorithmNotSupported(format!(
            "Unsupported EC curve OID: {curve_oid_bytes:02x?}"
        )));
    };

    // BIT STRING containing uncompressed point
    if rest.first() != Some(&0x03) {
        return Err(KspError::InvalidParameter(
            "Expected BIT STRING in EC SPKI".to_owned(),
        ));
    }
    let (bit_string, _) = der_read_tlv(rest)?;
    let point = bit_string
        .get(1..)
        .ok_or_else(|| KspError::InvalidParameter("BIT STRING too short".to_owned()))?;
    Ok((curve, point))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_public_blob_round_trip() {
        // Minimal sanity: check blob header fields are correct.
        let exponent = vec![0x01, 0x00, 0x01_u8]; // 65537
        let modulus = vec![0xAB_u8; 256]; // 2048-bit key
        let blob = rsa_public_blob(&exponent, &modulus);

        assert_eq!(&blob[0..4], &BCRYPT_RSAPUBLIC_MAGIC.to_le_bytes());
        let bit_len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(bit_len, 2048);
        let cb_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
        assert_eq!(cb_exp, 3);
        let cb_mod = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]);
        assert_eq!(cb_mod, 256);
    }

    #[test]
    fn ec_public_blob_p256() {
        let x = vec![0x01_u8; 32];
        let y = vec![0x02_u8; 32];
        let blob = ec_public_blob(EcCurve::P256, &x, &y, true);

        assert_eq!(&blob[0..4], &BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
        let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(cb_key, 32);
        assert_eq!(&blob[8..40], x.as_slice());
        assert_eq!(&blob[40..72], y.as_slice());
    }
}

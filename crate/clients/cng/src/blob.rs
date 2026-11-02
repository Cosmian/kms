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
///
/// These are the raw `DWORD` values from `bcrypt.h`.  When written with
/// `u32::to_le_bytes()` the four bytes read as their ASCII mnemonic:
/// - `0x3141_5352` → `[0x52, 0x53, 0x41, 0x31]` = "RSA1"
/// - `0x3241_5352` → `[0x52, 0x53, 0x41, 0x32]` = "RSA2"
/// - `0x3341_5352` → `[0x52, 0x53, 0x41, 0x33]` = "RSA3"
pub(crate) const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352; // "RSA1"
#[cfg(test)] // only referenced by the byte-level magic assertions in the tests
pub(crate) const BCRYPT_RSAPRIVATE_MAGIC: u32 = 0x3241_5352; // "RSA2"
pub(crate) const BCRYPT_RSAFULLPRIVATE_MAGIC: u32 = 0x3341_5352; // "RSA3"

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
pub(crate) fn rsa_public_blob(public_exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
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
/// PKCS#1 `RSAPublicKey` ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
///
/// We do a minimal hand-rolled DER parse to avoid adding heavy `der`/`pkcs1`
/// dependencies to this lightweight crate.
pub(crate) fn rsa_public_blob_from_pkcs1_der(der: &[u8]) -> KspResult<Vec<u8>> {
    let (modulus, exponent) = parse_pkcs1_public_der(der)?;
    Ok(rsa_public_blob(&exponent, &modulus))
}

/// Parse a `SubjectPublicKeyInfo` (SPKI) DER and return a `BCRYPT_RSAKEY_BLOB`.
///
/// SPKI wraps a PKCS#1 `RSAPublicKey` in an `AlgorithmIdentifier` + BIT STRING.
pub(crate) fn rsa_public_blob_from_spki_der(spki_der: &[u8]) -> KspResult<Vec<u8>> {
    // Strip the SPKI outer SEQUENCE + AlgorithmIdentifier to reach the RSAPublicKey
    let pkcs1_der = spki_inner_key(spki_der)?;
    rsa_public_blob_from_pkcs1_der(pkcs1_der)
}

// ─── EC ──────────────────────────────────────────────────────────────────────

/// CNG magic numbers for EC key blobs.
///
/// ECDSA public blob mnemonics (bytes in little-endian order):
/// - `0x3153_4345` → `[0x45, 0x43, 0x53, 0x31]` = "ECS1"
/// - `0x3353_4345` → `[0x45, 0x43, 0x53, 0x33]` = "ECS3"
/// - `0x3553_4345` → `[0x45, 0x43, 0x53, 0x35]` = "ECS5"
///
/// ECDH public blob mnemonics:
/// - `0x314B_4345` → `[0x45, 0x43, 0x4B, 0x31]` = "ECK1"
/// - `0x334B_4345` → `[0x45, 0x43, 0x4B, 0x33]` = "ECK3"
/// - `0x354B_4345` → `[0x45, 0x43, 0x4B, 0x35]` = "ECK5"
pub(crate) const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345; // "ECS1"
pub(crate) const BCRYPT_ECDSA_PUBLIC_P384_MAGIC: u32 = 0x3353_4345; // "ECS3"
pub(crate) const BCRYPT_ECDSA_PUBLIC_P521_MAGIC: u32 = 0x3553_4345; // "ECS5"
pub(crate) const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345; // "ECK1"
pub(crate) const BCRYPT_ECDH_PUBLIC_P384_MAGIC: u32 = 0x334B_4345; // "ECK3"
pub(crate) const BCRYPT_ECDH_PUBLIC_P521_MAGIC: u32 = 0x354B_4345; // "ECK5"

/// Curve identifier used when choosing the EC blob magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// Return byte length of the coordinate for this curve.
    #[must_use]
    pub(crate) const fn coord_size(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// Return the ECDSA public blob magic for this curve.
    #[must_use]
    pub(crate) const fn ecdsa_public_magic(self) -> u32 {
        match self {
            Self::P256 => BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            Self::P384 => BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
            Self::P521 => BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
        }
    }

    /// Return the ECDH public blob magic for this curve.
    #[must_use]
    pub(crate) const fn ecdh_public_magic(self) -> u32 {
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
pub(crate) fn ec_public_blob(curve: EcCurve, x: &[u8], y: &[u8], ecdsa: bool) -> Vec<u8> {
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
pub(crate) fn ec_public_blob_from_uncompressed(
    curve: EcCurve,
    point: &[u8],
    ecdsa: bool,
) -> KspResult<Vec<u8>> {
    let coord = curve.coord_size();
    // Uncompressed point: 0x04 prefix + X (coord bytes) + Y (coord bytes)
    if point.len() != 1 + 2 * coord || point.first() != Some(&0x04) {
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

/// Parse an EC `SubjectPublicKeyInfo` (SPKI) DER and produce a
/// `BCRYPT_ECCKEY_BLOB`.  Detects the curve from the OID.
pub(crate) fn ec_public_blob_from_spki_der(spki_der: &[u8], ecdsa: bool) -> KspResult<Vec<u8>> {
    let (curve, point) = spki_ec_inner_key(spki_der)?;
    ec_public_blob_from_uncompressed(curve, point, ecdsa)
}

// ─── Minimal DER helpers ─────────────────────────────────────────────────────

/// Skip a DER TLV and return the value slice.
fn der_read_tlv(data: &[u8]) -> KspResult<(&[u8], &[u8])> {
    let [_tag, len_byte, ..] = data else {
        return Err(KspError::InvalidParameter("DER too short".to_owned()));
    };
    let (len, hdr) = if len_byte & 0x80 == 0 {
        (usize::from(*len_byte), 2_usize)
    } else {
        let n = usize::from(len_byte & 0x7F);
        if data.len() < 2 + n {
            return Err(KspError::InvalidParameter(
                "DER length truncated".to_owned(),
            ));
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
    match (data.get(hdr..end), data.get(end..)) {
        (Some(value), Some(rest)) => Ok((value, rest)),
        _ => Err(KspError::InvalidParameter("DER value truncated".to_owned())),
    }
}

/// Strip leading zero byte from a DER INTEGER value (ASN.1 sign byte).
fn strip_leading_zero(v: &[u8]) -> &[u8] {
    if v.first() == Some(&0) {
        v.get(1..).unwrap_or(v)
    } else {
        v
    }
}

/// Parse a minimal PKCS#1 `RSAPublicKey` DER and return (modulus, exponent).
fn parse_pkcs1_public_der(der: &[u8]) -> KspResult<(Vec<u8>, Vec<u8>)> {
    // SEQUENCE { INTEGER modulus, INTEGER exponent }
    let (seq, _) = der_read_tlv(der)?;
    if der.first() != Some(&0x30) {
        return Err(KspError::InvalidParameter(
            "Expected SEQUENCE in RSA public key".to_owned(),
        ));
    }
    let (mod_val, rest) = der_read_tlv(seq)?;
    if seq.first() != Some(&0x02) {
        return Err(KspError::InvalidParameter(
            "Expected INTEGER (modulus)".to_owned(),
        ));
    }
    let modulus = strip_leading_zero(mod_val).to_vec();

    let (exp_val, _) = der_read_tlv(rest)?;
    if rest.first() != Some(&0x02) {
        return Err(KspError::InvalidParameter(
            "Expected INTEGER (exponent)".to_owned(),
        ));
    }
    let exponent = strip_leading_zero(exp_val).to_vec();

    Ok((modulus, exponent))
}

/// Strip the SPKI `AlgorithmIdentifier` wrapper from an RSA key and return the
/// inner PKCS#1 `RSAPublicKey` DER bytes.
fn spki_inner_key(spki: &[u8]) -> KspResult<&[u8]> {
    // SEQUENCE (outer SPKI)
    if spki.first() != Some(&0x30) {
        return Err(KspError::InvalidParameter(
            "Expected SPKI SEQUENCE".to_owned(),
        ));
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

/// Extract the EC curve and uncompressed point from a `SubjectPublicKeyInfo` DER.
fn spki_ec_inner_key(spki: &[u8]) -> KspResult<(EcCurve, &[u8])> {
    if spki.first() != Some(&0x30) {
        return Err(KspError::InvalidParameter(
            "Expected SPKI SEQUENCE".to_owned(),
        ));
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

// ─── RSA private key import: BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#8 DER ────────

/// RSA OID (1.2.840.113549.1.1.1) used in PKCS#8 `AlgorithmIdentifier`.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// Parse a `BCRYPT_RSAFULLPRIVATE_BLOB` and encode it as PKCS#8 DER.
///
/// The CNG blob layout:
/// ```text
/// Header (24 bytes): Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2
/// Data: e, n, p, q, dp, dq, qInv, d
/// ```
///
/// Returns PKCS#8 `PrivateKeyInfo` DER encoding.
pub(crate) fn pkcs8_from_rsa_full_private_blob(blob: &[u8]) -> KspResult<Vec<u8>> {
    if blob.len() < RSA_BLOB_HEADER_LEN {
        return Err(KspError::InvalidParameter(
            "RSA full private blob too short for header".to_owned(),
        ));
    }

    let magic = blob_u32(blob, 0)?;
    if magic != BCRYPT_RSAFULLPRIVATE_MAGIC {
        return Err(KspError::InvalidParameter(format!(
            "Expected RSA3 magic (0x{BCRYPT_RSAFULLPRIVATE_MAGIC:08X}), got 0x{magic:08X}"
        )));
    }

    let cb_pub_exp = usize_from_u32(blob_u32(blob, 8)?)?;
    let cb_modulus = usize_from_u32(blob_u32(blob, 12)?)?;
    let cb_prime1 = usize_from_u32(blob_u32(blob, 16)?)?;
    let cb_prime2 = usize_from_u32(blob_u32(blob, 20)?)?;

    let expected_len = RSA_BLOB_HEADER_LEN
        + cb_pub_exp
        + cb_modulus
        + cb_prime1
        + cb_prime2
        + cb_prime1
        + cb_prime2
        + cb_prime1
        + cb_modulus;
    if blob.len() < expected_len {
        return Err(KspError::InvalidParameter(format!(
            "RSA full private blob too short: need {expected_len}, got {}",
            blob.len()
        )));
    }

    let mut offset = RSA_BLOB_HEADER_LEN;
    let mut next_field = |len: usize| -> KspResult<&[u8]> {
        let field = blob_field(blob, offset, len)?;
        offset += len;
        Ok(field)
    };
    let public_exponent = next_field(cb_pub_exp)?;
    let modulus = next_field(cb_modulus)?;
    let prime1 = next_field(cb_prime1)?;
    let prime2 = next_field(cb_prime2)?;
    let exponent1 = next_field(cb_prime1)?;
    let exponent2 = next_field(cb_prime2)?;
    let coefficient = next_field(cb_prime1)?;
    let private_exponent = next_field(cb_modulus)?;

    // Build PKCS#1 RSAPrivateKey DER
    let pkcs1 = encode_rsa_private_key_der(&RsaPrivateKeyComponents {
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
    });
    // Wrap in PKCS#8 PrivateKeyInfo
    Ok(encode_pkcs8_rsa(&pkcs1))
}

/// Byte length of the `BCRYPT_RSAKEY_BLOB` header.
const RSA_BLOB_HEADER_LEN: usize = 24;

/// Return `len` bytes of `blob` starting at `offset`, or an error if truncated.
fn blob_field(blob: &[u8], offset: usize, len: usize) -> KspResult<&[u8]> {
    offset
        .checked_add(len)
        .and_then(|end| blob.get(offset..end))
        .ok_or_else(|| KspError::InvalidParameter("RSA full private blob truncated".to_owned()))
}

/// Read a little-endian `u32` at `offset`.
fn blob_u32(blob: &[u8], offset: usize) -> KspResult<u32> {
    let bytes = <[u8; 4]>::try_from(blob_field(blob, offset, 4)?)
        .map_err(|e| KspError::InvalidParameter(format!("RSA blob header: {e}")))?;
    Ok(u32::from_le_bytes(bytes))
}

fn usize_from_u32(value: u32) -> KspResult<usize> {
    usize::try_from(value)
        .map_err(|e| KspError::InvalidParameter(format!("RSA blob field length: {e}")))
}

/// Components of an RSA private key, as big-endian byte strings (PKCS#1 `RSAPrivateKey`).
struct RsaPrivateKeyComponents<'a> {
    modulus: &'a [u8],
    public_exponent: &'a [u8],
    private_exponent: &'a [u8],
    prime1: &'a [u8],
    prime2: &'a [u8],
    exponent1: &'a [u8],
    exponent2: &'a [u8],
    coefficient: &'a [u8],
}

/// Encode a DER INTEGER with sign padding if necessary.
fn der_encode_uint(value: &[u8]) -> Vec<u8> {
    let v = strip_leading_zero_for_encode(value);
    let needs_pad = v.first().is_some_and(|b| b & 0x80 != 0);
    let len = v.len() + usize::from(needs_pad);
    let mut out = Vec::with_capacity(2 + len + 2); // tag + length + pad + value
    out.push(0x02); // INTEGER tag
    der_encode_length(&mut out, len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(v);
    out
}

/// Strip leading zeros from CNG blob fields (which are fixed-width, big-endian).
const fn strip_leading_zero_for_encode(v: &[u8]) -> &[u8] {
    let mut s = v;
    while let [0, rest @ ..] = s {
        if rest.is_empty() {
            break;
        }
        s = rest;
    }
    s
}

/// Encode DER length (lengths of 2^24 bytes or more are not supported).
fn der_encode_length(out: &mut Vec<u8>, len: usize) {
    let [b0, b1, b2, ..] = len.to_le_bytes();
    if len < 0x80 {
        out.push(b0);
    } else if len < 0x100 {
        out.extend([0x81, b0]);
    } else if len < 0x1_0000 {
        out.extend([0x82, b1, b0]);
    } else {
        out.extend([0x83, b2, b1, b0]);
    }
}

/// Encode PKCS#1 `RSAPrivateKey` DER.
fn encode_rsa_private_key_der(key: &RsaPrivateKeyComponents<'_>) -> Vec<u8> {
    let fields = [
        der_encode_uint(&[0]), // version 0
        der_encode_uint(key.modulus),
        der_encode_uint(key.public_exponent),
        der_encode_uint(key.private_exponent),
        der_encode_uint(key.prime1),
        der_encode_uint(key.prime2),
        der_encode_uint(key.exponent1),
        der_encode_uint(key.exponent2),
        der_encode_uint(key.coefficient),
    ];
    let inner_len: usize = fields.iter().map(Vec::len).sum();

    let mut seq = Vec::with_capacity(4 + inner_len);
    seq.push(0x30); // SEQUENCE tag
    der_encode_length(&mut seq, inner_len);
    for field in &fields {
        seq.extend_from_slice(field);
    }
    seq
}

/// Wrap a PKCS#1 `RSAPrivateKey` DER in PKCS#8 `PrivateKeyInfo`.
///
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///   version INTEGER (0),
///   privateKeyAlgorithm AlgorithmIdentifier { rsaEncryption, NULL },
///   privateKey OCTET STRING (RSAPrivateKey DER)
/// }
/// ```
fn encode_pkcs8_rsa(pkcs1_der: &[u8]) -> Vec<u8> {
    // version INTEGER 0
    let version = der_encode_uint(&[0]);

    // AlgorithmIdentifier SEQUENCE { OID rsaEncryption, NULL }
    let mut algo_id = Vec::new();
    algo_id.push(0x30); // SEQUENCE
    let oid_tlv_len = 2 + OID_RSA_ENCRYPTION.len() + 2; // OID TLV + NULL TLV
    der_encode_length(&mut algo_id, oid_tlv_len);
    algo_id.push(0x06); // OID tag
    der_encode_length(&mut algo_id, OID_RSA_ENCRYPTION.len());
    algo_id.extend_from_slice(OID_RSA_ENCRYPTION);
    algo_id.push(0x05); // NULL tag
    algo_id.push(0x00); // NULL length

    // privateKey OCTET STRING
    let mut priv_key_oct = Vec::with_capacity(4 + pkcs1_der.len());
    priv_key_oct.push(0x04); // OCTET STRING tag
    der_encode_length(&mut priv_key_oct, pkcs1_der.len());
    priv_key_oct.extend_from_slice(pkcs1_der);

    // Outer SEQUENCE
    let inner_len = version.len() + algo_id.len() + priv_key_oct.len();
    let mut pkcs8 = Vec::with_capacity(4 + inner_len);
    pkcs8.push(0x30); // SEQUENCE tag
    der_encode_length(&mut pkcs8, inner_len);
    pkcs8.extend_from_slice(&version);
    pkcs8.extend_from_slice(&algo_id);
    pkcs8.extend_from_slice(&priv_key_oct);
    pkcs8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that RSA magic constants encode as their ASCII mnemonics.
    /// These byte-level assertions catch any future copy-paste error in the
    /// constant definitions — checking against the constant itself would miss
    /// a wrong value.
    #[test]
    fn rsa_magic_bytes() {
        // "RSA1" = [0x52, 0x53, 0x41, 0x31]
        assert_eq!(
            BCRYPT_RSAPUBLIC_MAGIC.to_le_bytes(),
            [0x52, 0x53, 0x41, 0x31]
        );
        // "RSA2" = [0x52, 0x53, 0x41, 0x32]
        assert_eq!(
            BCRYPT_RSAPRIVATE_MAGIC.to_le_bytes(),
            [0x52, 0x53, 0x41, 0x32]
        );
        // "RSA3" = [0x52, 0x53, 0x41, 0x33]
        assert_eq!(
            BCRYPT_RSAFULLPRIVATE_MAGIC.to_le_bytes(),
            [0x52, 0x53, 0x41, 0x33]
        );
    }

    /// Verify that EC magic constants encode as their ASCII mnemonics.
    #[test]
    fn ec_magic_bytes() {
        // ECDSA: "ECS1/3/5"
        assert_eq!(
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes(),
            [0x45, 0x43, 0x53, 0x31]
        );
        assert_eq!(
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC.to_le_bytes(),
            [0x45, 0x43, 0x53, 0x33]
        );
        assert_eq!(
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC.to_le_bytes(),
            [0x45, 0x43, 0x53, 0x35]
        );
        // ECDH: "ECK1/3/5"
        assert_eq!(
            BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes(),
            [0x45, 0x43, 0x4B, 0x31]
        );
        assert_eq!(
            BCRYPT_ECDH_PUBLIC_P384_MAGIC.to_le_bytes(),
            [0x45, 0x43, 0x4B, 0x33]
        );
        assert_eq!(
            BCRYPT_ECDH_PUBLIC_P521_MAGIC.to_le_bytes(),
            [0x45, 0x43, 0x4B, 0x35]
        );
    }

    #[test]
    fn rsa_public_blob_round_trip() {
        // Minimal sanity: check blob header fields are correct.
        let exponent = vec![0x01, 0x00, 0x01_u8]; // 65537
        let modulus = vec![0xAB_u8; 256]; // 2048-bit key
        let blob = rsa_public_blob(&exponent, &modulus);

        // Magic must be "RSA1" as raw bytes
        assert_eq!(&blob[0..4], &[0x52_u8, 0x53, 0x41, 0x31]);
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

        // Magic must be "ECS1" as raw bytes
        assert_eq!(&blob[0..4], &[0x45_u8, 0x43, 0x53, 0x31]);
        let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(cb_key, 32);
        assert_eq!(&blob[8..40], x.as_slice());
        assert_eq!(&blob[40..72], y.as_slice());
    }

    #[test]
    fn rsa_private_key_der_is_stable() {
        let der = encode_rsa_private_key_der(&RsaPrivateKeyComponents {
            modulus: &[0xC5; 8],
            public_exponent: &[0x01, 0x00, 0x01],
            private_exponent: &[0x11; 8],
            prime1: &[0x23; 4],
            prime2: &[0x29; 4],
            exponent1: &[0x31; 4],
            exponent2: &[0x37; 4],
            coefficient: &[0x3B; 4],
        });
        let expected: [u8; 61] = [
            0x30, 0x3b, 0x02, 0x01, 0x00, 0x02, 0x09, 0x00, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5, 0xc5,
            0xc5, 0xc5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x08, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x02, 0x04, 0x23, 0x23, 0x23, 0x23, 0x02, 0x04, 0x29, 0x29, 0x29,
            0x29, 0x02, 0x04, 0x31, 0x31, 0x31, 0x31, 0x02, 0x04, 0x37, 0x37, 0x37, 0x37, 0x02,
            0x04, 0x3b, 0x3b, 0x3b, 0x3b,
        ];
        assert_eq!(der, expected);
    }
}

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests pinning the BASE behavior of `blob.rs`.

    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut hex, b| {
            write!(hex, "{b:02x}").unwrap();
            hex
        })
    }

    fn head_hex(bytes: &[u8], n: usize) -> String {
        to_hex(&bytes[..n])
    }

    fn tail_hex(bytes: &[u8], n: usize) -> String {
        to_hex(&bytes[bytes.len() - n..])
    }

    /// DER TLV with short or long-form length.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let mut body = tlv(0x02, modulus);
        body.extend_from_slice(&tlv(0x02, exponent));
        tlv(0x30, &body)
    }

    const RSA_OID: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    fn rsa_spki(pkcs1: &[u8]) -> Vec<u8> {
        let mut algo_body = tlv(0x06, &RSA_OID);
        algo_body.extend_from_slice(&[0x05, 0x00]);
        let mut bit = vec![0x00];
        bit.extend_from_slice(pkcs1);
        let mut body = tlv(0x30, &algo_body);
        body.extend_from_slice(&tlv(0x03, &bit));
        tlv(0x30, &body)
    }

    const EC_PUB_OID: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const P256_OID: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    const P384_OID: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];
    const P521_OID: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x23];

    fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
        let mut algo_body = tlv(0x06, &EC_PUB_OID);
        algo_body.extend_from_slice(&tlv(0x06, curve_oid));
        let mut bit = vec![0x00];
        bit.extend_from_slice(point);
        let mut body = tlv(0x30, &algo_body);
        body.extend_from_slice(&tlv(0x03, &bit));
        tlv(0x30, &body)
    }

    fn point(coord: usize) -> Vec<u8> {
        let mut p = vec![0x04];
        p.extend((0..coord).map(|i| u8::try_from(i + 1).unwrap()));
        p.extend((0..coord).map(|i| u8::try_from(0xF0 - i).unwrap()));
        p
    }

    const RSA_PUB_PKCS1_BLOB: &str =
        "525341312000000003000000040000000000000000000000010001c0010203";

    #[test]
    fn characterization_rsa_public_blob_small() {
        let blob = rsa_public_blob(&[0x01, 0x00, 0x01], &[0xC0, 0x01, 0x02, 0x03]);
        assert_eq!(to_hex(&blob), RSA_PUB_PKCS1_BLOB);
    }

    #[test]
    fn characterization_rsa_public_blob_empty() {
        assert_eq!(
            to_hex(&rsa_public_blob(&[], &[])),
            "525341310000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn characterization_rsa_public_blob_2048() {
        let modulus: Vec<u8> = (0..256_u16).map(|i| u8::try_from(i).unwrap()).collect();
        let blob = rsa_public_blob(&[0x01, 0x00, 0x01], &modulus);
        assert_eq!(blob.len(), 24 + 3 + 256);
        assert_eq!(
            head_hex(&blob, 24),
            "525341310008000003000000000100000000000000000000"
        );
        assert_eq!(tail_hex(&blob, 4), "fcfdfeff");
    }

    #[test]
    fn characterization_rsa_public_blob_from_pkcs1_der_strips_sign_byte() {
        let der = pkcs1_der(&[0x00, 0xC0, 0x01, 0x02, 0x03], &[0x01, 0x00, 0x01]);
        assert_eq!(to_hex(&der), "300c020500c00102030203010001");
        let blob = rsa_public_blob_from_pkcs1_der(&der).unwrap();
        assert_eq!(to_hex(&blob), RSA_PUB_PKCS1_BLOB);
    }

    #[test]
    fn characterization_rsa_public_blob_from_pkcs1_der_keeps_non_sign_zero_free() {
        let der = pkcs1_der(&[0x7F, 0x01], &[0x03]);
        let blob = rsa_public_blob_from_pkcs1_der(&der).unwrap();
        assert_eq!(
            to_hex(&blob),
            "525341311000000001000000020000000000000000000000037f01"
        );
    }

    #[test]
    fn characterization_rsa_public_blob_from_pkcs1_der_errors() {
        let err = |d: &[u8]| rsa_public_blob_from_pkcs1_der(d).unwrap_err().to_string();
        assert_eq!(err(&[]), "invalid parameter: DER too short");
        assert_eq!(err(&[0x30]), "invalid parameter: DER too short");
        assert_eq!(
            err(&[0x31, 0x00]),
            "invalid parameter: Expected SEQUENCE in RSA public key"
        );
        assert_eq!(
            err(&[0x30, 0x05, 0x01]),
            "invalid parameter: DER value truncated"
        );
        assert_eq!(
            err(&[0x30, 0x81]),
            "invalid parameter: DER length truncated"
        );
        assert_eq!(
            err(&tlv(0x30, &[0x03, 0x01, 0x05, 0x02, 0x01, 0x03])),
            "invalid parameter: Expected INTEGER (modulus)"
        );
        assert_eq!(
            err(&tlv(0x30, &[0x02, 0x01, 0x05, 0x03, 0x01, 0x03])),
            "invalid parameter: Expected INTEGER (exponent)"
        );
        assert_eq!(
            err(&tlv(0x30, &[0x02, 0x01, 0x05])),
            "invalid parameter: DER too short"
        );
    }

    #[test]
    fn characterization_der_read_tlv_long_forms() {
        // 0x81 form, 0x84 form with leading zero length bytes, and trailing data returned.
        let (val, rest) = der_read_tlv(&[0x04, 0x81, 0x02, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!((val, rest), (&[0xAA, 0xBB][..], &[0xCC][..]));
        let (val, rest) = der_read_tlv(&[0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 0xAA]).unwrap();
        assert_eq!((val, rest), (&[0xAA][..], &[][..]));
        let (val, rest) = der_read_tlv(&[0x04, 0x00]).unwrap();
        assert_eq!((val, rest), (&[][..], &[][..]));
        // The tag byte is not checked.
        let (val, _) = der_read_tlv(&[0xFF, 0x01, 0x09]).unwrap();
        assert_eq!(val, &[0x09][..]);
    }

    #[test]
    fn characterization_strip_leading_zero() {
        assert_eq!(strip_leading_zero(&[0, 1, 2]), &[1, 2][..]);
        assert_eq!(strip_leading_zero(&[0, 0, 2]), &[0, 2][..]);
        let empty: &[u8] = &[];
        assert_eq!(strip_leading_zero(&[0]), empty);
        assert_eq!(strip_leading_zero(&[]), empty);
        assert_eq!(strip_leading_zero(&[5, 0]), &[5, 0][..]);
    }

    #[test]
    fn characterization_rsa_public_blob_from_spki_der() {
        let der = pkcs1_der(&[0x00, 0xC0, 0x01, 0x02, 0x03], &[0x01, 0x00, 0x01]);
        let spki = rsa_spki(&der);
        assert_eq!(
            to_hex(&spki),
            "3020300d06092a864886f70d0101010500030f00300c020500c00102030203010001"
        );
        let blob = rsa_public_blob_from_spki_der(&spki).unwrap();
        assert_eq!(to_hex(&blob), RSA_PUB_PKCS1_BLOB);
    }

    #[test]
    fn characterization_rsa_public_blob_from_spki_der_errors() {
        let err = |d: &[u8]| rsa_public_blob_from_spki_der(d).unwrap_err().to_string();
        assert_eq!(err(&[]), "invalid parameter: Expected SPKI SEQUENCE");
        assert_eq!(
            err(&[0x31, 0x00]),
            "invalid parameter: Expected SPKI SEQUENCE"
        );
        assert_eq!(err(&[0x30]), "invalid parameter: DER too short");
        // algorithm sequence only, no BIT STRING (rest is empty)
        assert_eq!(
            err(&tlv(0x30, &tlv(0x30, &[0x05, 0x00]))),
            "invalid parameter: Expected BIT STRING in SPKI"
        );
        // second element is not a BIT STRING
        let mut body = tlv(0x30, &[0x05, 0x00]);
        body.extend_from_slice(&tlv(0x04, &[0x00, 0x01]));
        assert_eq!(
            err(&tlv(0x30, &body)),
            "invalid parameter: Expected BIT STRING in SPKI"
        );
        // empty BIT STRING
        let mut body = tlv(0x30, &[0x05, 0x00]);
        body.extend_from_slice(&[0x03, 0x00]);
        assert_eq!(
            err(&tlv(0x30, &body)),
            "invalid parameter: BIT STRING too short"
        );
        // inner PKCS#1 not a sequence
        let mut body = tlv(0x30, &[0x05, 0x00]);
        body.extend_from_slice(&tlv(0x03, &[0x00, 0x31, 0x00]));
        assert_eq!(
            err(&tlv(0x30, &body)),
            "invalid parameter: Expected SEQUENCE in RSA public key"
        );
    }

    #[test]
    fn characterization_ec_curve_tables() {
        assert_eq!(EcCurve::P256.coord_size(), 32);
        assert_eq!(EcCurve::P384.coord_size(), 48);
        assert_eq!(EcCurve::P521.coord_size(), 66);
        assert_eq!(EcCurve::P256.ecdsa_public_magic(), 0x3153_4345);
        assert_eq!(EcCurve::P384.ecdsa_public_magic(), 0x3353_4345);
        assert_eq!(EcCurve::P521.ecdsa_public_magic(), 0x3553_4345);
        assert_eq!(EcCurve::P256.ecdh_public_magic(), 0x314B_4345);
        assert_eq!(EcCurve::P384.ecdh_public_magic(), 0x334B_4345);
        assert_eq!(EcCurve::P521.ecdh_public_magic(), 0x354B_4345);
    }

    #[test]
    fn characterization_ec_public_blob_all_curves() {
        for (curve, coord, ecdsa, head, tail) in [
            (EcCurve::P256, 32, true, "4543533120000000", "d4d3d2d1"),
            (EcCurve::P256, 32, false, "45434b3120000000", "d4d3d2d1"),
            (EcCurve::P384, 48, true, "4543533330000000", "c4c3c2c1"),
            (EcCurve::P384, 48, false, "45434b3330000000", "c4c3c2c1"),
            (EcCurve::P521, 66, true, "4543533542000000", "b2b1b0af"),
            (EcCurve::P521, 66, false, "45434b3542000000", "b2b1b0af"),
        ] {
            let p = point(coord);
            let x = &p[1..=coord];
            let y = &p[1 + coord..];
            {
                let blob = ec_public_blob(curve, x, y, ecdsa);
                assert_eq!(blob.len(), 8 + 2 * coord);
                assert_eq!(head_hex(&blob, 8), head);
                assert_eq!(tail_hex(&blob, 4), tail);
            }
        }
    }

    #[test]
    fn characterization_ec_public_blob_from_uncompressed_ok_and_errors() {
        let p = point(32);
        let blob = ec_public_blob_from_uncompressed(EcCurve::P256, &p, true).unwrap();
        assert_eq!(
            blob,
            ec_public_blob(EcCurve::P256, &p[1..33], &p[33..], true)
        );
        let blob = ec_public_blob_from_uncompressed(EcCurve::P256, &p, false).unwrap();
        assert_eq!(head_hex(&blob, 8), "45434b3120000000");

        let msg = "invalid parameter: EC point must be uncompressed (0x04 prefix)";
        let mut bad = p.clone();
        *bad.first_mut().unwrap() = 0x02;
        assert_eq!(
            ec_public_blob_from_uncompressed(EcCurve::P256, &bad, true)
                .unwrap_err()
                .to_string(),
            msg
        );
        assert_eq!(
            ec_public_blob_from_uncompressed(EcCurve::P256, &p[..64], true)
                .unwrap_err()
                .to_string(),
            msg
        );
        assert_eq!(
            ec_public_blob_from_uncompressed(EcCurve::P384, &p, true)
                .unwrap_err()
                .to_string(),
            msg
        );
        assert_eq!(
            ec_public_blob_from_uncompressed(EcCurve::P256, &[], true)
                .unwrap_err()
                .to_string(),
            msg
        );
    }

    #[test]
    fn characterization_ec_public_blob_from_spki_der_curves() {
        for (oid, curve, coord) in [
            (&P256_OID[..], EcCurve::P256, 32),
            (&P384_OID[..], EcCurve::P384, 48),
            (&P521_OID[..], EcCurve::P521, 66),
        ] {
            let p = point(coord);
            let spki = ec_spki(oid, &p);
            for ecdsa in [true, false] {
                assert_eq!(
                    ec_public_blob_from_spki_der(&spki, ecdsa).unwrap(),
                    ec_public_blob_from_uncompressed(curve, &p, ecdsa).unwrap()
                );
            }
        }
        let spki = ec_spki(&P256_OID, &point(32));
        assert_eq!(
            to_hex(&spki),
            "3059301306072a8648ce3d020106082a8648ce3d030107034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1"
        );
    }

    #[test]
    fn characterization_ec_public_blob_from_spki_der_errors() {
        let err = |d: &[u8]| {
            ec_public_blob_from_spki_der(d, true)
                .unwrap_err()
                .to_string()
        };
        assert_eq!(err(&[]), "invalid parameter: Expected SPKI SEQUENCE");
        assert_eq!(err(&[0x30]), "invalid parameter: DER too short");
        assert_eq!(
            err(&tlv(0x30, &tlv(0x31, &[]))),
            "invalid parameter: Expected AlgorithmIdentifier SEQUENCE"
        );
        assert_eq!(
            err(&tlv(0x30, &tlv(0x30, &tlv(0x04, &[1])))),
            "invalid parameter: Expected OID in AlgorithmIdentifier"
        );
        assert_eq!(
            err(&tlv(0x30, &tlv(0x30, &tlv(0x06, &EC_PUB_OID)))),
            "invalid parameter: Expected curve OID in AlgorithmIdentifier"
        );
        let mut algo = tlv(0x06, &EC_PUB_OID);
        algo.extend_from_slice(&tlv(0x06, &[0x2A, 0x86]));
        assert_eq!(
            err(&tlv(0x30, &tlv(0x30, &algo))),
            "algorithm not supported: Unsupported EC curve OID: [2a, 86]"
        );
        let mut algo = tlv(0x06, &EC_PUB_OID);
        algo.extend_from_slice(&tlv(0x06, &P256_OID));
        let mut body = tlv(0x30, &algo);
        assert_eq!(
            err(&tlv(0x30, &body)),
            "invalid parameter: Expected BIT STRING in EC SPKI"
        );
        body.extend_from_slice(&tlv(0x04, &[0, 1]));
        assert_eq!(
            err(&tlv(0x30, &body)),
            "invalid parameter: Expected BIT STRING in EC SPKI"
        );
        let mut body = tlv(0x30, &algo);
        body.extend_from_slice(&[0x03, 0x00]);
        assert_eq!(
            err(&tlv(0x30, &body)),
            "invalid parameter: BIT STRING too short"
        );
    }

    /// Build a `BCRYPT_RSAFULLPRIVATE_BLOB` with the given field lengths; each
    /// field is filled with a distinct byte pattern.
    fn full_private_blob(cb_e: usize, cb_n: usize, cb_p: usize, cb_q: usize) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&BCRYPT_RSAFULLPRIVATE_MAGIC.to_le_bytes());
        blob.extend_from_slice(&u32::try_from(cb_n * 8).unwrap().to_le_bytes());
        for cb in [cb_e, cb_n, cb_p, cb_q] {
            blob.extend_from_slice(&u32::try_from(cb).unwrap().to_le_bytes());
        }
        for (fill, len) in [
            (0x01_u8, cb_e),
            (0x11, cb_n),
            (0x21, cb_p),
            (0x31, cb_q),
            (0x41, cb_p),
            (0x51, cb_q),
            (0x61, cb_p),
            (0x71, cb_n),
        ] {
            blob.extend((0..len).map(|i| fill.wrapping_add(u8::try_from(i % 7).unwrap())));
        }
        blob
    }

    #[test]
    fn characterization_pkcs8_from_rsa_full_private_blob_small() {
        let blob = full_private_blob(3, 8, 2, 3);
        assert_eq!(
            to_hex(&blob),
            "52534133400000000300000008000000020000000300000001020311121314151617112122313233414251525361627172737475767771"
        );
        let der = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
        assert_eq!(
            to_hex(&der),
            "3048020100300d06092a864886f70d0101010500043430320201000208111213141516171102030102030208717273747576777102022122020331323302024142020351525302026162"
        );
    }

    #[test]
    fn characterization_pkcs8_from_rsa_full_private_blob_sign_and_zero_padding() {
        // e = 00 00 03 (leading zeros stripped), n starts with 0x80 (sign pad),
        // p = 00 00 (all zeros -> single zero), q = 0x7f.. no pad.
        let mut blob = Vec::new();
        blob.extend_from_slice(&BCRYPT_RSAFULLPRIVATE_MAGIC.to_le_bytes());
        for v in [32_u32, 3, 4, 2, 1] {
            blob.extend_from_slice(&v.to_le_bytes());
        }
        blob.extend_from_slice(&[0, 0, 3]); // e
        blob.extend_from_slice(&[0x80, 0, 0, 1]); // n
        blob.extend_from_slice(&[0, 0]); // p
        blob.extend_from_slice(&[0x7F]); // q
        blob.extend_from_slice(&[0, 0]); // dp
        blob.extend_from_slice(&[0xFF]); // dq
        blob.extend_from_slice(&[0, 0]); // qinv
        blob.extend_from_slice(&[0x80, 0, 0, 2]); // d
        // NB: the blob parser uses cb_prime1 = 2 and cb_prime2 = 1 here via header [.., 2, 1].
        let der = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
        assert_eq!(
            to_hex(&der),
            "303a020100300d06092a864886f70d010101050004263024020100020500800000010201030205008000000202010002017f020100020200ff020100"
        );
    }

    #[test]
    fn characterization_pkcs8_from_rsa_full_private_blob_trailing_bytes_ignored() {
        let mut blob = full_private_blob(3, 8, 2, 3);
        let plain = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
        blob.extend_from_slice(&[0xEE; 5]);
        assert_eq!(pkcs8_from_rsa_full_private_blob(&blob).unwrap(), plain);
    }

    #[test]
    fn characterization_pkcs8_from_rsa_full_private_blob_der_length_forms() {
        // 0x81 (modulus 200), 0x82 (modulus 300), 0x83 (modulus 70000) encodings.
        for (cb_n, len, head) in [
            (200, 474, "308201d6020100300d06092a864886f70d01010105000482"),
            (300, 676, "308202a0020100300d06092a864886f70d01010105000482"),
            (
                70_000,
                140_081,
                "308302232c020100300d06092a864886f70d010101050004",
            ),
        ] {
            let blob = full_private_blob(3, cb_n, 4, 4);
            let der = pkcs8_from_rsa_full_private_blob(&blob).unwrap();
            assert_eq!(der.len(), len);
            assert_eq!(head_hex(&der, 24), head);
            assert_eq!(tail_hex(&der, 8), "5354020461626364");
        }
    }

    #[test]
    fn characterization_pkcs8_from_rsa_full_private_blob_errors() {
        let err = |d: &[u8]| pkcs8_from_rsa_full_private_blob(d).unwrap_err().to_string();
        assert_eq!(
            err(&[]),
            "invalid parameter: RSA full private blob too short for header"
        );
        assert_eq!(
            err(&[0; 23]),
            "invalid parameter: RSA full private blob too short for header"
        );
        assert_eq!(
            err(&[0; 24]),
            "invalid parameter: Expected RSA3 magic (0x33415352), got 0x00000000"
        );
        let mut blob = rsa_public_blob(&[1], &[2]);
        assert_eq!(
            err(&blob),
            "invalid parameter: Expected RSA3 magic (0x33415352), got 0x31415352"
        );
        blob = full_private_blob(3, 8, 2, 3);
        blob.pop();
        assert_eq!(
            err(&blob),
            "invalid parameter: RSA full private blob too short: need 55, got 54"
        );
    }

    #[test]
    fn characterization_der_encode_helpers() {
        assert_eq!(der_encode_uint(&[0]), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_encode_uint(&[]), vec![0x02, 0x00]);
        assert_eq!(der_encode_uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(der_encode_uint(&[0, 0, 0x7F]), vec![0x02, 0x01, 0x7F]);
        for (len, expected) in [
            (0_usize, vec![0x00]),
            (0x7F, vec![0x7F]),
            (0x80, vec![0x81, 0x80]),
            (0xFF, vec![0x81, 0xFF]),
            (0x100, vec![0x82, 0x01, 0x00]),
            (0xFFFF, vec![0x82, 0xFF, 0xFF]),
            (0x1_0000, vec![0x83, 0x01, 0x00, 0x00]),
            (0x12_3456, vec![0x83, 0x12, 0x34, 0x56]),
        ] {
            let mut out = Vec::new();
            der_encode_length(&mut out, len);
            assert_eq!(out, expected, "len {len}");
        }
    }
}

mod algorithm;
mod models;

pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod error;
pub(crate) mod mac;
pub(crate) mod sign;
pub(crate) mod verify;

// Re-export handlers under names that callers (start_kms_server, test_utils) can use
// directly without the double-path (crypto::encrypt::encrypt).
// Re-export shared types used by handlers and algorithm module
pub(crate) use algorithm::jose_to_kmip_params;
pub(crate) use decrypt::decrypt as decrypt_handler;
pub(crate) use encrypt::encrypt as encrypt_handler;
pub(crate) use error::{CryptoApiError, CryptoResult, b64_decode, b64_encode};
pub(crate) use mac::mac as mac_handler;
pub(crate) use models::*;
pub(crate) use sign::sign as sign_handler;
pub(crate) use verify::verify as verify_handler;

/// Return the ECDSA coordinate byte-length for JOSE EC algorithms (None for non-EC algs).
///
/// Per RFC 7518 §3.4:
///   ES256 → P-256 → 32 bytes
///   ES384 → P-384 → 48 bytes
///   ES512 → P-521 → 66 bytes
pub(crate) fn ecdsa_coord_size(alg: &str) -> Option<usize> {
    match alg {
        "ES256" => Some(32),
        "ES384" => Some(48),
        "ES512" => Some(66),
        _ => None,
    }
}

/// Convert an ECDSA signature from DER/ASN.1 encoding to JOSE fixed-size r||s (IEEE P1363).
///
/// RFC 7518 §3.4 requires that the signature be the concatenation of the zero-padded
/// big-endian integer representations of `r` and `s`, each `coord_size` bytes long.
pub(crate) fn ecdsa_der_to_p1363(der: &[u8], coord_size: usize) -> Result<Vec<u8>, CryptoApiError> {
    fn bad(msg: &str) -> CryptoApiError {
        CryptoApiError::InternalError(format!("Invalid ECDSA DER signature: {msg}"))
    }

    // Minimal DER ECDSA signature: 30 len 02 rlen r 02 slen s (at least 8 bytes)
    if der.len() < 8 || der.first() != Some(&0x30) {
        return Err(bad("bad SEQUENCE tag or too short"));
    }

    // Parse outer SEQUENCE length — only definite short (1-byte) and definite long
    // 1-byte forms are needed; ECDSA signatures for P-256/P-384/P-521 are tiny.
    let b1 = *der.get(1).ok_or_else(|| bad("truncated at length byte"))?;
    let header_end: usize = if b1 & 0x80 == 0 {
        2
    } else {
        if (b1 & 0x7f) != 1 {
            return Err(bad("unsupported multi-byte length encoding"));
        }
        if der.len() < 4 {
            return Err(bad("truncated at extended length"));
        }
        3
    };

    let data = der
        .get(header_end..)
        .ok_or_else(|| bad("truncated after SEQUENCE header"))?;

    // Parse first INTEGER (r): tag 0x02, length, value
    if data.first() != Some(&0x02) {
        return Err(bad("expected INTEGER tag for r"));
    }
    let r_len = usize::from(*data.get(1).ok_or_else(|| bad("truncated at r length"))?);
    let r_full = data
        .get(2..2 + r_len)
        .ok_or_else(|| bad("r value truncated"))?;

    // Parse second INTEGER (s)
    let rest = data
        .get(2 + r_len..)
        .ok_or_else(|| bad("truncated before s"))?;
    if rest.first() != Some(&0x02) {
        return Err(bad("expected INTEGER tag for s"));
    }
    let s_len = usize::from(*rest.get(1).ok_or_else(|| bad("truncated at s length"))?);
    let s_full = rest
        .get(2..2 + s_len)
        .ok_or_else(|| bad("s value truncated"))?;

    // Strip the leading 0x00 DER inserts to keep the sign bit clear
    let r = r_full.strip_prefix(&[0x00_u8][..]).unwrap_or(r_full);
    let s = s_full.strip_prefix(&[0x00_u8][..]).unwrap_or(s_full);

    if r.len() > coord_size || s.len() > coord_size {
        return Err(bad(&format!(
            "r ({}) or s ({}) exceeds coord_size ({coord_size})",
            r.len(),
            s.len()
        )));
    }

    // Left-pad r and s to coord_size bytes and concatenate
    let mut p1363 = vec![0_u8; coord_size * 2];
    let r_start = coord_size - r.len();
    let s_start = coord_size * 2 - s.len();
    p1363
        .get_mut(r_start..coord_size)
        .ok_or_else(|| bad("r placement out of bounds"))?
        .copy_from_slice(r);
    p1363
        .get_mut(s_start..)
        .ok_or_else(|| bad("s placement out of bounds"))?
        .copy_from_slice(s);
    Ok(p1363)
}

/// Strip leading zero bytes from a DER integer value, keeping at least one byte.
fn strip_der_zeros(buf: &[u8]) -> &[u8] {
    let pos = buf.iter().position(|&b| b != 0).unwrap_or(buf.len() - 1);
    buf.get(pos..).unwrap_or(buf)
}

/// Convert an ECDSA signature from JOSE fixed-size r||s (IEEE P1363) to DER/ASN.1.
///
/// The JOSE signature is `coord_size` bytes of `r` followed by `coord_size` bytes of `s`,
/// both zero-padded to the curve's coordinate size.
pub(crate) fn ecdsa_p1363_to_der(p1363: &[u8]) -> Result<Vec<u8>, CryptoApiError> {
    if !p1363.len().is_multiple_of(2) || p1363.is_empty() {
        return Err(CryptoApiError::InternalError(
            "P1363 ECDSA signature must have even, non-zero length".to_owned(),
        ));
    }
    let coord_size = p1363.len() / 2;
    let (r_raw, s_raw) = p1363.split_at(coord_size);

    let r_stripped = strip_der_zeros(r_raw);
    let s_stripped = strip_der_zeros(s_raw);

    // If the high bit is set, DER requires a leading 0x00 to indicate a positive integer
    let r_needs_pad = r_stripped.first().is_some_and(|&b| b >= 0x80);
    let s_needs_pad = s_stripped.first().is_some_and(|&b| b >= 0x80);

    let r_encoded_len = r_stripped.len() + usize::from(r_needs_pad);
    let s_encoded_len = s_stripped.len() + usize::from(s_needs_pad);

    // SEQUENCE content: 02 r_len r 02 s_len s
    let seq_len = 2 + r_encoded_len + 2 + s_encoded_len;
    // Lengths for P-256/P-384/P-521 are well under 256, so seq_len and component
    // lengths always fit in a u8 without truncation.
    let seq_len_byte = u8::try_from(seq_len).map_err(|e| {
        CryptoApiError::InternalError(format!("ECDSA DER: sequence length overflows u8: {e}"))
    })?;
    let r_len_byte = u8::try_from(r_encoded_len).map_err(|e| {
        CryptoApiError::InternalError(format!("ECDSA DER: r length overflows u8: {e}"))
    })?;
    let s_len_byte = u8::try_from(s_encoded_len).map_err(|e| {
        CryptoApiError::InternalError(format!("ECDSA DER: s length overflows u8: {e}"))
    })?;

    // DER length encoding: short form for 0-127, long form (0x81 <len>) for 128-255.
    // P-521 SEQUENCE content is ~138 bytes so long form is required for ES512.
    let needs_long_form = seq_len >= 0x80;
    let header_len = if needs_long_form { 3 } else { 2 };
    let mut der = Vec::with_capacity(header_len + seq_len);
    der.push(0x30);
    if needs_long_form {
        der.push(0x81);
    }
    der.push(seq_len_byte);

    der.push(0x02);
    der.push(r_len_byte);
    if r_needs_pad {
        der.push(0x00);
    }
    der.extend_from_slice(r_stripped);

    der.push(0x02);
    der.push(s_len_byte);
    if s_needs_pad {
        der.push(0x00);
    }
    der.extend_from_slice(s_stripped);

    Ok(der)
}

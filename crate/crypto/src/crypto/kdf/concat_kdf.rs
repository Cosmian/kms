//! Concatenation Key Derivation Function (Concat KDF).
//!
//! Spec references:
//! - NIST SP 800-56A Rev. 3 §5.8.1.1 (the "One-Step" KDF, single-round-hash variant)
//! - RFC 7518 §4.6 / Appendix C (the JOSE `ECDH-ES` profile of Concat KDF: always uses
//!   SHA-256 as the hash function, regardless of curve or `enc` key size)
//!
//! This implementation is FIPS 140-3 available (SHA-256 is an approved hash function and
//! Concat KDF is the NIST SP 800-56A approved key-derivation construction) — not gated
//! behind `non-fips`.

use openssl::hash::{Hasher, MessageDigest};
use zeroize::Zeroizing;

use crate::{crypto_bail, error::CryptoError};

const SHA256_OUTPUT_LEN_BYTES: usize = 32;

/// Build the `OtherInfo` structure per RFC 7518 Appendix C:
///
/// `OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo`
///
/// - `AlgorithmID`, `PartyUInfo`, `PartyVInfo` are each a 4-byte big-endian length prefix
///   followed by their content (RFC 7518 §4.6: absent `apu`/`apv` encode as a zero-length
///   value, not an absent field).
/// - `SuppPubInfo` is the requested key length in bits, as a 4-byte big-endian integer.
/// - `SuppPrivInfo` is empty for the JOSE profile.
fn build_other_info(
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    key_data_len_bits: u32,
) -> Result<Vec<u8>, CryptoError> {
    let mut other_info =
        Vec::with_capacity(12 + algorithm_id.len() + party_u_info.len() + party_v_info.len() + 4);
    for part in [algorithm_id, party_u_info, party_v_info] {
        let len = u32::try_from(part.len()).map_err(|_error| {
            CryptoError::InvalidSize("Concat KDF: OtherInfo component too large".to_owned())
        })?;
        other_info.extend_from_slice(&len.to_be_bytes());
        other_info.extend_from_slice(part);
    }
    other_info.extend_from_slice(&key_data_len_bits.to_be_bytes());
    Ok(other_info)
}

/// Derive `key_data_len_bits` bits of key material from the shared secret `z` using the
/// NIST SP 800-56A Concatenation KDF (SHA-256), as profiled by RFC 7518 Appendix C for
/// `ECDH-ES`/`ECDH-ES+A128KW`/`ECDH-ES+A256KW`.
///
/// `algorithm_id` is the JOSE `alg` (bare `ECDH-ES`) or key-wrap `alg` (`A128KW`/`A256KW`)
/// value as ASCII bytes; `party_u_info`/`party_v_info` are the base64url-decoded `apu`/`apv`
/// header values (empty slices when absent).
pub fn concat_kdf(
    z: &[u8],
    key_data_len_bits: u32,
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if key_data_len_bits == 0 || !key_data_len_bits.is_multiple_of(8) {
        crypto_bail!(CryptoError::InvalidSize(
            "Concat KDF: key_data_len_bits must be a non-zero multiple of 8".to_owned()
        ));
    }
    let key_data_len_bytes = usize::try_from(key_data_len_bits / 8).map_err(|_error| {
        CryptoError::InvalidSize("Concat KDF: key_data_len_bits out of range".to_owned())
    })?;

    let other_info = build_other_info(algorithm_id, party_u_info, party_v_info, key_data_len_bits)?;

    let num_rounds = key_data_len_bytes.div_ceil(SHA256_OUTPUT_LEN_BYTES);
    let mut output = Zeroizing::new(Vec::with_capacity(num_rounds * SHA256_OUTPUT_LEN_BYTES));
    for round in 1..=num_rounds {
        let counter = u32::try_from(round).map_err(|_error| {
            CryptoError::InvalidSize(
                "Concat KDF: derived key too large (round overflow)".to_owned(),
            )
        })?;
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        hasher.update(&counter.to_be_bytes())?;
        hasher.update(z)?;
        hasher.update(&other_info)?;
        let digest = hasher.finish()?;
        output.extend_from_slice(&digest);
    }
    output.truncate(key_data_len_bytes);

    Ok(output)
}

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::concat_kdf;

    /// RFC 7518 Appendix C — "Example ECDH-ES Key Agreement Computation".
    ///
    /// Alice and Bob agree on P-256; the example gives the raw `Z` value, the
    /// `Alice`/`Bob` party info, and the expected 128-bit derived CEK for
    /// `alg=ECDH-ES` with `enc=A128GCM`.
    #[test]
    fn test_concat_kdf_rfc7518_appendix_c() {
        // Z (the ECDH shared secret) from RFC 7518 Appendix C.3.
        let z: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        // AlgorithmID = "A128GCM" (the `enc` value, since alg=ECDH-ES derives the CEK directly).
        let algorithm_id = b"A128GCM";
        // PartyUInfo = "Alice", PartyVInfo = "Bob" (ASCII, per the RFC 7518 example).
        let apu = b"Alice";
        let apv = b"Bob";

        let derived = concat_kdf(&z, 128, algorithm_id, apu, apv).unwrap();

        let expected: [u8; 16] = [
            86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26,
        ];
        assert_eq!(derived.as_slice(), &expected[..]);
    }

    #[test]
    fn test_concat_kdf_rejects_non_byte_aligned_length() {
        let z = [0_u8; 32];
        concat_kdf(&z, 12, b"A128GCM", b"", b"").unwrap_err();
        concat_kdf(&z, 0, b"A128GCM", b"", b"").unwrap_err();
    }

    #[test]
    fn test_concat_kdf_multi_round_output_length() {
        // 512-bit output requires 2 SHA-256 rounds (256 bits each).
        let z = [1_u8; 32];
        let derived = concat_kdf(&z, 512, b"A256GCM", b"", b"").unwrap();
        assert_eq!(derived.len(), 64);
    }
}

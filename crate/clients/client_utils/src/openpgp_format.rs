//! Pure `OpenPGP`< transferable-key format conversion (armored ⇄ binary packets).
//!
//! Contains no RNG and no OpenSSL dependency, so it builds for
//! `wasm32-unknown-unknown` as well as native targets. Shared by
//! `cosmian_kms_crypto` (native server/CLI) and the WASM export path in
//! `export_utils::openpgp_key_to_binary`, so there is a single
//! implementation of this conversion for every client.

use std::io::Read;

use pgp::{
    composed::{PublicOrSecret, SignedPublicKey, SignedSecretKey},
    ser::Serialize,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors raised while converting `OpenPGP` transferable keys.
#[derive(Debug, Error)]
pub enum OpenPgpFormatError {
    #[error("failed to parse OpenPGP certificate: {0}")]
    Parse(String),
    #[error("failed to parse OpenPGP certificate: no key found")]
    NoKeyFound,
    #[error("OpenPGP input contains multiple transferable keys")]
    MultipleKeys,
    #[error("failed to serialize OpenPGP secret key: {0}")]
    SerializeSecret(String),
    #[error("failed to serialize OpenPGP public key: {0}")]
    SerializePublic(String),
    #[error("failed to parse OpenPGP transferable key")]
    NotAKey,
}

/// Parse an armored or binary key into either a `SignedSecretKey` or `SignedPublicKey`.
///
/// Unprotected `EdDSA` secret keys exported by `GnuPG` whose 32-octet seed starts with `0x00`
/// (about 1 key in 256) are repaired transparently, see [`normalize_gnupg_eddsa_secret_mpi`].
///
/// # Errors
/// Returns an error if the input is not a single valid `OpenPGP` transferable key.
pub fn parse_secret_or_public(
    input: &[u8],
) -> Result<(Option<SignedSecretKey>, Option<SignedPublicKey>), OpenPgpFormatError> {
    match parse_secret_or_public_strict(input) {
        Err(error @ OpenPgpFormatError::Parse(_)) => {
            match dearmor(input).and_then(|binary| normalize_gnupg_eddsa_secret_mpi(&binary)) {
                // If the repaired key still does not parse, report the original error.
                Some(repaired) => {
                    parse_secret_or_public_strict(&repaired).map_err(|_repaired_error| error)
                }
                None => Err(error),
            }
        }
        other => other,
    }
}

fn parse_secret_or_public_strict(
    input: &[u8],
) -> Result<(Option<SignedSecretKey>, Option<SignedPublicKey>), OpenPgpFormatError> {
    let (mut keys, _) = PublicOrSecret::from_reader_many_buf(std::io::Cursor::new(input))
        .map_err(|e| OpenPgpFormatError::Parse(e.to_string()))?;
    let key = keys
        .next()
        .ok_or(OpenPgpFormatError::NoKeyFound)?
        .map_err(|e| OpenPgpFormatError::Parse(e.to_string()))?;
    if keys.next().is_some() {
        return Err(OpenPgpFormatError::MultipleKeys);
    }
    match key {
        PublicOrSecret::Secret(secret) => Ok((Some(secret), None)),
        PublicOrSecret::Public(public) => Ok((None, Some(public))),
    }
}

/// Binary packets of an armored or binary input; `None` if an armored input cannot be decoded.
fn dearmor(input: &[u8]) -> Option<Vec<u8>> {
    if !input.trim_ascii_start().starts_with(b"-----BEGIN PGP") {
        return Some(input.to_vec());
    }
    let mut binary = Vec::new();
    pgp::armor::Dearmor::new(std::io::Cursor::new(input))
        .read_to_end(&mut binary)
        .ok()?;
    Some(binary)
}

/// Number of bits of a big-endian integer, as written in an `OpenPGP` MPI header.
fn mpi_bit_len(bytes: &[u8]) -> Option<u16> {
    let first = bytes.first()?;
    let bits = bytes
        .len()
        .checked_mul(8)?
        .checked_sub(usize::try_from(first.leading_zeros()).ok()?)?;
    u16::try_from(bits).ok()
}

/// Sum of octets modulo 2^16, the checksum of an unencrypted secret key (RFC 4880 §5.5.3).
fn secret_checksum(data: &[u8]) -> u16 {
    data.iter()
        .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte)))
}

/// Parse an `OpenPGP` packet header at the start of `data`.
///
/// Returns `(tag, header_len, body_len)`, or `None` for partial/indeterminate lengths.
fn packet_header(data: &[u8]) -> Option<(u8, usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    if first & 0x40 == 0 {
        // Old format: the length type is in the two low bits of the first octet.
        let tag = (first >> 2) & 0x0f;
        return match first & 0x03 {
            0 => Some((tag, 2, usize::from(*data.get(1)?))),
            1 => Some((
                tag,
                3,
                usize::from(u16::from_be_bytes([*data.get(1)?, *data.get(2)?])),
            )),
            2 => Some((
                tag,
                5,
                usize::try_from(u32::from_be_bytes([
                    *data.get(1)?,
                    *data.get(2)?,
                    *data.get(3)?,
                    *data.get(4)?,
                ]))
                .ok()?,
            )),
            _ => None,
        };
    }
    let tag = first & 0x3f;
    match *data.get(1)? {
        len @ 0..=191 => Some((tag, 2, usize::from(len))),
        len @ 192..=223 => Some((
            tag,
            3,
            ((usize::from(len) - 192) << 8) + usize::from(*data.get(2)?) + 192,
        )),
        255 => Some((
            tag,
            6,
            usize::try_from(u32::from_be_bytes([
                *data.get(2)?,
                *data.get(3)?,
                *data.get(4)?,
                *data.get(5)?,
            ]))
            .ok()?,
        )),
        // Partial body lengths are not used by key packets.
        _ => None,
    }
}

/// Append a new-format packet (`tag`, `body`) to `out`.
fn write_packet(out: &mut Vec<u8>, tag: u8, body: &[u8]) -> Option<()> {
    out.push(0xC0 | tag);
    let len = body.len();
    if len < 192 {
        out.push(u8::try_from(len).ok()?);
    } else if len < 8384 {
        let adjusted = len.checked_sub(192)?;
        out.push(u8::try_from((adjusted >> 8) + 192).ok()?);
        out.push(u8::try_from(adjusted & 0xFF).ok()?);
    } else {
        out.push(255);
        out.extend_from_slice(&u32::try_from(len).ok()?.to_be_bytes());
    }
    out.extend_from_slice(body);
    Some(())
}

/// Skip an MPI starting at `pos` and return the offset just after it.
fn skip_mpi(body: &[u8], pos: usize) -> Option<usize> {
    let bits = usize::from(u16::from_be_bytes([
        *body.get(pos)?,
        *body.get(pos.checked_add(1)?)?,
    ]));
    pos.checked_add(2)?.checked_add(bits.div_ceil(8))
}

/// Rewrite the secret scalar of one unencrypted v4 `EdDSA`-legacy (algorithm 22) secret key
/// packet body into the minimal MPI form. `None` if nothing needs to change.
fn normalize_eddsa_secret_body(body: &[u8]) -> Option<Vec<u8>> {
    // version(1) created(4) algorithm(1) | OID len(1) OID | public MPI | s2k usage(1) | MPI | sum(2)
    if *body.first()? != 4 || *body.get(5)? != 22 {
        return None;
    }
    let oid_len = usize::from(*body.get(6)?);
    let secret_start = skip_mpi(body, 7_usize.checked_add(oid_len)?)?;
    if *body.get(secret_start)? != 0 {
        // Encrypted or checksummed with SHA-1: the plain-text checksum below does not apply.
        return None;
    }
    let mpi_start = secret_start.checked_add(1)?;
    let mpi_end = skip_mpi(body, mpi_start)?;
    let checksum_end = mpi_end.checked_add(2)?;
    if checksum_end != body.len() {
        return None;
    }
    let mpi = body.get(mpi_start..mpi_end)?;
    // Only trust the file's own checksum: never "repair" corrupted key material.
    let stored = u16::from_be_bytes([*body.get(mpi_end)?, *body.get(mpi_end.checked_add(1)?)?]);
    if stored != secret_checksum(mpi) {
        return None;
    }
    let value = mpi.get(2..)?;
    let first_non_zero = value.iter().position(|byte| *byte != 0)?;
    let minimal = value.get(first_non_zero..)?;
    let header = mpi_bit_len(minimal)?.to_be_bytes();
    if mpi.get(..2)? == header.as_slice() && minimal.len() == value.len() {
        return None;
    }
    let mut repaired = body.get(..mpi_start)?.to_vec();
    let mpi_offset = repaired.len();
    repaired.extend_from_slice(&header);
    repaired.extend_from_slice(minimal);
    let checksum = secret_checksum(repaired.get(mpi_offset..)?);
    repaired.extend_from_slice(&checksum.to_be_bytes());
    Some(repaired)
}

/// Work around `GnuPG`'s encoding of `EdDSA` secret keys, which the `pgp` crate rejects with
/// "Invalid checksum".
///
/// For an unprotected `Ed25519` key `GnuPG` writes the secret seed as a fixed 32-octet MPI whose
/// header says 256 bits even when the first octet is `0x00` (about 1 key in 256; see
/// <https://dev.gnupg.org/T4954>). The `pgp` crate verifies the secret-key checksum against its
/// own re-serialization, which strips leading zeros, so such a key is rejected although it is
/// valid. This rewrites those MPIs into the minimal form (same integer value) and recomputes
/// the checksum, only for keys whose own checksum is currently valid.
///
/// Takes and returns binary packets; `None` if the input has no secret key to repair or is not
/// a well-formed packet sequence.
fn normalize_gnupg_eddsa_secret_mpi(binary: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(binary.len());
    let mut pos = 0_usize;
    let mut changed = false;
    while pos < binary.len() {
        let rest = binary.get(pos..)?;
        let (tag, header_len, body_len) = packet_header(rest)?;
        let total = header_len.checked_add(body_len)?;
        let packet = rest.get(..total)?;
        let body = packet.get(header_len..)?;
        // 5 = secret key, 7 = secret subkey.
        match (tag, normalize_eddsa_secret_body(body)) {
            (5 | 7, Some(repaired)) => {
                write_packet(&mut out, tag, &repaired)?;
                changed = true;
            }
            _ => out.extend_from_slice(packet),
        }
        pos = pos.checked_add(total)?;
    }
    changed.then_some(out)
}

/// Serialize an armored or binary `OpenPGP` transferable key as binary packets.
///
/// # Errors
/// Returns an error if the input is not a valid transferable secret or public key
/// or if the key cannot be serialized.
pub fn openpgp_key_to_binary(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpenPgpFormatError> {
    let (secret, public) = parse_secret_or_public(input)?;
    let mut binary = Zeroizing::new(Vec::new());
    match (secret, public) {
        (Some(key), None) => key
            .to_writer(&mut *binary)
            .map_err(|e| OpenPgpFormatError::SerializeSecret(e.to_string()))?,
        (None, Some(key)) => key
            .to_writer(&mut *binary)
            .map_err(|e| OpenPgpFormatError::SerializePublic(e.to_string()))?,
        _ => return Err(OpenPgpFormatError::NotAKey),
    }
    Ok(binary)
}

#[cfg(test)]
// `.expect("reason")` in test assertions is the sanctioned exception to the workspace-wide
// `clippy::expect_used` deny.
#[expect(clippy::expect_used)]
mod tests {
    use super::{
        normalize_gnupg_eddsa_secret_mpi, openpgp_key_to_binary, packet_header,
        parse_secret_or_public, parse_secret_or_public_strict, secret_checksum, write_packet,
    };

    /// Body of an unencrypted v4 `EdDSA`-legacy secret key packet (algorithm 22, Ed25519) whose
    /// secret MPI is `header || value`, followed by its checksum, as `GnuPG` writes it.
    fn eddsa_secret_body(header: [u8; 2], value: &[u8]) -> Vec<u8> {
        let mut body = vec![4, 0, 0, 0, 1, 22, 9];
        body.extend_from_slice(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]);
        // Public point: 0x40 prefix followed by 32 octets, 263 bits.
        body.extend_from_slice(&[0x01, 0x07, 0x40]);
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0); // s2k usage: unencrypted
        let mpi_start = body.len();
        body.extend_from_slice(&header);
        body.extend_from_slice(value);
        let checksum = secret_checksum(body.get(mpi_start..).expect("mpi"));
        body.extend_from_slice(&checksum.to_be_bytes());
        body
    }

    fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_packet(&mut out, tag, body).expect("write packet");
        out
    }

    #[test]
    fn gnupg_seed_with_leading_zero_is_rewritten_to_minimal_mpi() {
        let mut seed = vec![0x00, 0x45];
        seed.extend_from_slice(&[0x77; 30]);
        // GnuPG: 256-bit header, 32 octets, leading zero kept.
        let gnupg = packet(5, &eddsa_secret_body([0x01, 0x00], &seed));
        // Same integer, minimal form: 247 bits, 31 octets.
        let minimal = packet(
            5,
            &eddsa_secret_body([0x00, 0xF7], seed.get(1..).expect("tail")),
        );

        let repaired = normalize_gnupg_eddsa_secret_mpi(&gnupg).expect("must be repaired");
        assert_eq!(repaired, minimal);
        // Idempotent: the minimal form needs no further change.
        assert_eq!(normalize_gnupg_eddsa_secret_mpi(&repaired), None);
    }

    #[test]
    fn seed_without_leading_zero_is_left_alone() {
        let seed = [0xC4; 32];
        let packets = packet(5, &eddsa_secret_body([0x01, 0x00], &seed));
        assert_eq!(normalize_gnupg_eddsa_secret_mpi(&packets), None);
    }

    #[test]
    fn corrupted_checksum_is_never_repaired() {
        let mut seed = vec![0x00];
        seed.extend_from_slice(&[0x11; 31]);
        let mut body = eddsa_secret_body([0x01, 0x00], &seed);
        let last = body.last_mut().expect("checksum");
        *last ^= 0xFF;
        assert_eq!(normalize_gnupg_eddsa_secret_mpi(&packet(7, &body)), None);
    }

    #[test]
    fn other_packets_are_preserved_and_lengths_re_encoded() {
        let mut seed = vec![0x00];
        seed.extend_from_slice(&[0x22; 31]);
        let user_id = packet(13, b"Alice <alice@example.com>");
        let mut stream = packet(5, &eddsa_secret_body([0x01, 0x00], &seed));
        stream.extend_from_slice(&user_id);

        let repaired = normalize_gnupg_eddsa_secret_mpi(&stream).expect("must be repaired");
        let (tag, header_len, body_len) = packet_header(&repaired).expect("first header");
        assert_eq!(tag, 5);
        let first_len = header_len + body_len;
        assert_eq!(repaired.get(first_len..), Some(user_id.as_slice()));
    }

    #[test]
    fn malformed_stream_yields_none() {
        assert_eq!(normalize_gnupg_eddsa_secret_mpi(&[0xC5, 0x05, 0x04]), None);
        assert_eq!(normalize_gnupg_eddsa_secret_mpi(b"not a packet"), None);
    }

    /// Throwaway unprotected key generated by `gpg --generate-key` (Ed25519 + Cv25519) whose
    /// Ed25519 secret seed starts with `0x00`; the `pgp` crate alone rejects it with
    /// "Invalid checksum" (this made `test_gpg_armored_message_decrypts` flaky on CI).
    const GNUPG_ZERO_LEADING_SEED_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEass3hRYJKwYBBAHaRw8BAQdAOtB8Rsg/AZkACuCUCiD2/xX9msbxi38ZKCwR
4s+PA+cAAQAARRKjMh25F9GYJBCoen099AwFrVlzeRS5bv6G4SzYjQ27tCBBcm1v
cmVkIE1zZyA8YXJtbXNnQGV4YW1wbGUuY29tPoiNBBMWCgA2FiEEccrzOfVMWny8
ZXiBjulhk6iSsoMFAmrLN4UCGwMECwkIBwQVCgkIBRYCAwEAAh4FAheAAAoJEI7p
YZOokrKD5akA+Pnp7lhryyFWgWJRFO0JtenblOy5QEtBM3DpQF7sSB4A/3D9I5E4
g1CjSXvQxMMnRQ0fwjhjDFLqGh2Ed5/Z6UECnF0Eass3hRIKKwYBBAGXVQEFAQEH
QLbUyk6t5Ul9xXvhKZQ5jJpArQ7Xf3XbUzNtmRVCeAxvAwEIBwAA/1sOp6ag/ww9
IoDA83ilVGh3rg1DbDRAMHvoEiWkoESQDwKIeAQYFgoAIBYhBHHK8zn1TFp8vGV4
gY7pYZOokrKDBQJqyzeFAhsMAAoJEI7pYZOokrKDypkA/1GgKGcbLqTc3vC5pfT9
M73zV2d+NOpr605ISWoRqI8HAQCr97MpnhSiZXMp+dLpexLGbf8bkXlc72gir6jv
xismDg==
=mGIF
-----END PGP PRIVATE KEY BLOCK-----
";

    #[test]
    fn gnupg_key_with_zero_leading_ed25519_seed_parses_and_round_trips() {
        // The unrepaired parse fails: this pins the premise of the workaround.
        parse_secret_or_public_strict(GNUPG_ZERO_LEADING_SEED_KEY.as_bytes())
            .expect_err("the pgp crate alone must reject this key");

        let (secret, public) =
            parse_secret_or_public(GNUPG_ZERO_LEADING_SEED_KEY.as_bytes()).expect("repaired parse");
        assert!(secret.is_some() && public.is_none());

        // The stored (re-serialized) form parses without any repair.
        let binary = openpgp_key_to_binary(GNUPG_ZERO_LEADING_SEED_KEY.as_bytes())
            .expect("armored to binary");
        parse_secret_or_public_strict(&binary).expect("re-serialized key parses without repair");
    }
}

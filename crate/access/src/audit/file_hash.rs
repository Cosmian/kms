use std::{
    fs::File,
    io::{self, Read as _},
    path::Path,
};

use sha2::{Digest, Sha256};

/// Streams `path` through SHA-256 in fixed-size chunks (no full-file load) and returns
/// `(lowercase hex digest, file size in bytes)`.
///
/// Shared by the server (sealing corrupted audit files aside) and `ckms audit verify`
/// (cross-checking sealed-evidence integrity) so the two never drift.
///
/// Reads via `Digest::update` rather than `io::copy`: `sha2`'s `impl io::Write` needs its
/// `std` feature, which the workspace deliberately disables by default (minimal surface for
/// FIPS-relevant crypto crates) — this avoids depending on a feature flag other crates
/// happen to enable elsewhere.
///
/// # Errors
/// Returns an error if the file cannot be opened or read.
pub fn sha256_file(path: &Path) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 65_536];
    let mut size = 0_u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // `Read::read` never returns more bytes than the buffer it was given, so this is
        // always `Some` — but surface a hard error rather than silently hash the wrong
        // bytes if that contract is ever violated by a future `Read` impl.
        let chunk = buf.get(..n).ok_or_else(|| {
            io::Error::other("Read::read returned more bytes than the buffer size")
        })?;
        hasher.update(chunk);
        size += u64::try_from(n).unwrap_or(u64::MAX);
    }
    Ok((hex::encode(hasher.finalize()), size))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_result_states
)]
mod tests {
    use std::io::Write as _;

    use super::sha256_file;

    #[test]
    fn hashes_and_sizes_match_known_content() {
        let path = std::env::temp_dir().join(format!(
            "kms_access_sha256_file_test_{}.bin",
            std::process::id()
        ));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"hello world")
            .unwrap();

        let (digest, size) = sha256_file(&path).unwrap();
        // echo -n "hello world" | sha256sum
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(size, 11);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_file_hashes_to_sha256_of_empty_input() {
        let path = std::env::temp_dir().join(format!(
            "kms_access_sha256_file_empty_test_{}.bin",
            std::process::id()
        ));
        std::fs::File::create(&path).unwrap();

        let (digest, size) = sha256_file(&path).unwrap();
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(size, 0);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_returns_err() {
        let path = std::env::temp_dir().join("kms_access_sha256_file_does_not_exist.bin");
        std::fs::remove_file(&path).ok();
        assert!(sha256_file(&path).is_err());
    }
}

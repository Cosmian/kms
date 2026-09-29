//! Cryptographic primitives for key splitting using XOR-based *n*-of-*n* secret sharing.
//!
//! All *n* shares are required to reconstruct the secret (no threshold — every share
//! is essential). This provides information-theoretic security: any strict subset of
//! shares reveals zero information about the secret.
//!
//! # Share encoding
//!
//! Each share is a raw byte vector of the same length as the secret.
//! `secret = share_0 XOR share_1 XOR ... XOR share_{n-1}`.

use rand_core::CryptoRng;
use zeroize::Zeroizing;

// ─── Public API ─────────────────────────────────────────────────────────────

/// Split `secret` into `total_parts` shares using XOR (*n*-of-*n* scheme).
///
/// All `total_parts` shares are required to reconstruct the secret.
/// The first `total_parts - 1` shares are uniformly random; the last share is
/// computed so that XOR-ing all shares yields the original secret.
///
/// Each share is wrapped in [`Zeroizing`] so heap memory is wiped on drop.
///
/// # Cryptographic requirement
/// `rng` must be a cryptographically-secure RNG. The `CryptoRng` bound enforces
/// this at compile time — passing `SmallRng` or any other non-CSPRNG is a
/// type error.
///
/// # Errors
/// Returns [`SplitKeyError`] if `total_parts < 2` or `secret` is empty.
pub fn xor_split(
    secret: &[u8],
    total_parts: u32,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Zeroizing<Vec<u8>>>, SplitKeyError> {
    if total_parts < 2 {
        return Err(SplitKeyError::InvalidTotalParts(
            total_parts,
            "must be >= 2".to_owned(),
        ));
    }
    if secret.is_empty() {
        return Err(SplitKeyError::EmptySecret);
    }

    let n = usize::try_from(total_parts)
        .map_err(|e| SplitKeyError::InvalidTotalParts(total_parts, e.to_string()))?;
    let m = secret.len();

    // Generate n-1 uniformly random shares.
    let mut shares: Vec<Zeroizing<Vec<u8>>> = (0..n - 1)
        .map(|_| {
            let mut s = vec![0_u8; m];
            rng.fill_bytes(&mut s);
            Zeroizing::new(s)
        })
        .collect();

    // Last share = secret XOR share_0 XOR share_1 XOR ... XOR share_{n-2}
    let mut last = vec![0_u8; m];
    last.copy_from_slice(secret);
    for share in &shares {
        for (l, s) in last.iter_mut().zip(share.iter()) {
            *l ^= s;
        }
    }
    shares.push(Zeroizing::new(last));

    Ok(shares)
}

/// Reconstruct the secret from *all* XOR shares.
///
/// `secret[i] = shares[0][i] XOR shares[1][i] XOR ... XOR shares[n-1][i]`
///
/// The returned secret is wrapped in [`Zeroizing`] for secure cleanup.
///
/// # Errors
/// Returns [`SplitKeyError`] if shares are empty or have inconsistent lengths.
pub fn xor_join(shares: &[Zeroizing<Vec<u8>>]) -> Result<Zeroizing<Vec<u8>>, SplitKeyError> {
    if shares.is_empty() {
        return Err(SplitKeyError::NoShares);
    }
    let m = shares.first().map_or(0, |s| s.len());
    if m == 0 {
        return Err(SplitKeyError::EmptySecret);
    }
    for share in shares {
        if share.len() != m {
            return Err(SplitKeyError::InconsistentShareLength);
        }
    }

    let mut secret = Zeroizing::new(vec![0_u8; m]);
    for share in shares {
        for (s, b) in secret.iter_mut().zip(share.iter()) {
            *s ^= b;
        }
    }
    Ok(secret)
}

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors returned by split-key operations.
#[derive(Debug, thiserror::Error)]
pub enum SplitKeyError {
    /// `total_parts` must be >= 2 and representable as usize.
    #[error("invalid total_parts {0}: {1}")]
    InvalidTotalParts(u32, String),

    /// Secret must not be empty.
    #[error("secret is empty")]
    EmptySecret,

    /// No shares were provided to `xor_join`.
    #[error("no shares provided for reconstruction")]
    NoShares,

    /// Shares have different lengths.
    #[error("shares have inconsistent lengths")]
    InconsistentShareLength,
}

// ─── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn deterministic_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42_u8; 32])
    }

    #[test]
    fn test_xor_roundtrip_2_of_2() {
        let secret = b"super secret key material 12345!";
        let mut rng = deterministic_rng();
        let shares = xor_split(secret, 2, &mut rng).unwrap();
        assert_eq!(shares.len(), 2);
        let rec = xor_join(&shares).unwrap();
        assert_eq!(&*rec, secret.as_slice());
    }

    #[test]
    fn test_xor_roundtrip_3_of_3() {
        let secret = b"three-way split test";
        let mut rng = deterministic_rng();
        let shares = xor_split(secret, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);
        let rec = xor_join(&shares).unwrap();
        assert_eq!(&*rec, secret.as_slice());
    }

    #[test]
    fn test_xor_roundtrip_5_of_5() {
        let secret = vec![0xAB; 32];
        let mut rng = deterministic_rng();
        let shares = xor_split(&secret, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);
        let rec = xor_join(&shares).unwrap();
        assert_eq!(&*rec, secret.as_slice());
    }

    #[test]
    fn test_xor_share_lengths() {
        let secret = b"hello";
        let mut rng = deterministic_rng();
        let shares = xor_split(secret, 4, &mut rng).unwrap();
        for share in &shares {
            assert_eq!(share.len(), secret.len());
        }
    }

    #[test]
    fn test_xor_missing_share_fails() {
        let secret = b"missing share test";
        let mut rng = deterministic_rng();
        let shares = xor_split(secret, 3, &mut rng).unwrap();
        // Only 2 of 3 shares — should produce wrong result
        let partial = xor_join(&shares[0..2]).unwrap();
        assert_ne!(&*partial, secret.as_slice());
    }

    #[test]
    fn test_xor_invalid_total_parts() {
        let mut rng = deterministic_rng();
        xor_split(b"key", 1, &mut rng).unwrap_err();
        xor_split(b"key", 0, &mut rng).unwrap_err();
    }

    #[test]
    fn test_xor_empty_secret() {
        let mut rng = deterministic_rng();
        xor_split(b"", 2, &mut rng).unwrap_err();
    }

    #[test]
    fn test_xor_join_empty() {
        xor_join(&[]).unwrap_err();
    }

    #[test]
    fn test_xor_join_length_mismatch() {
        xor_join(&[
            Zeroizing::new(vec![0_u8; 16]),
            Zeroizing::new(vec![0_u8; 15]),
        ])
        .unwrap_err();
    }
}

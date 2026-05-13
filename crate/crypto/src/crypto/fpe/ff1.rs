use core::{cmp, fmt};

use num_bigint::BigUint;
use num_traits::{ToPrimitive, identities::Zero};
use openssl::symm::{Cipher, Crypter, Mode};
use zeroize::{Zeroize, Zeroizing};

/// AES-256 block length in bytes (NIST SP 800-38G mandates a 128-bit block cipher for FF1).
const BLOCK_LEN: usize = 16;
/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Encrypt a single 128-bit block with AES-256-ECB via OpenSSL (no padding).
///
/// The key and block lengths are invariants enforced by the call sites; an
/// OpenSSL error here would indicate a programming error, so we propagate it
/// as a string rather than exposing the full `ErrorStack` type to callers.
#[allow(clippy::expect_used, clippy::indexing_slicing)]
fn aes256_ecb_block(key: &[u8; KEY_LEN], block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    // OpenSSL's Crypter::update writes at most input_len + block_len bytes.
    let mut out = [0_u8; 2 * BLOCK_LEN];
    let mut cr = Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, key, None)
        // Invariant: key is KEY_LEN bytes and AES-256-ECB is always available.
        .expect("AES-256-ECB init");
    cr.pad(false); // exact-block input — no PKCS#7 padding
    let n1 = cr.update(block, &mut out).expect("AES-256-ECB update");
    let n2 = cr.finalize(&mut out[n1..]).expect("AES-256-ECB finalize");
    debug_assert_eq!(
        n1 + n2,
        BLOCK_LEN,
        "AES-256-ECB must output exactly one block"
    );
    let mut result = [0_u8; BLOCK_LEN];
    result.copy_from_slice(&out[..BLOCK_LEN]);
    out.zeroize();
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvalidRadix(pub(crate) u32);

impl fmt::Display for InvalidRadix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The radix {} is not in the range 2..=(1 << 16)", self.0)
    }
}

impl std::error::Error for InvalidRadix {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FF1Error {
    InvalidRadix(InvalidRadix),
    /// Key length must be exactly 32 bytes (AES-256).
    InvalidKeyLength,
    InsufficientFeistelRounds,
}

impl From<InvalidRadix> for FF1Error {
    fn from(e: InvalidRadix) -> Self {
        Self::InvalidRadix(e)
    }
}

impl fmt::Display for FF1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRadix(e) => e.fmt(f),
            Self::InvalidKeyLength => {
                write!(f, "Invalid key length for AES-256-FF1: expected 32 bytes")
            }
            Self::InsufficientFeistelRounds => {
                write!(f, "FF1fr requires at least 8 Feistel rounds")
            }
        }
    }
}

impl std::error::Error for FF1Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NumeralStringError {
    InvalidForRadix(u32),
    TooLong { ns_len: usize, max_len: usize },
    TooShort { ns_len: usize, min_len: usize },
    TweakTooLong,
}

impl fmt::Display for NumeralStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidForRadix(radix) => {
                write!(f, "The given numeral string is invalid for radix {radix}")
            }
            Self::TooLong { ns_len, max_len } => write!(
                f,
                "The given numeral string is too long for FF1 ({ns_len} > {max_len})",
            ),
            Self::TooShort { ns_len, min_len } => write!(
                f,
                "The given numeral string is too short for FF1 ({ns_len} < {min_len})",
            ),
            Self::TweakTooLong => {
                write!(f, "The tweak is longer than u32::MAX bytes")
            }
        }
    }
}

impl std::error::Error for NumeralStringError {}

const MIN_NS_LEN: u32 = 2;
const MAX_NS_LEN: usize = 4_294_967_295; // u32::MAX
const MIN_RADIX_2_NS_LEN: u32 = 20;
/// Minimum domain size required by NIST SP 800-38G for FF1: `radix^min_len` >= 10^6.
const MIN_NS_DOMAIN_SIZE: u64 = 1_000_000;

#[derive(Debug, PartialEq)]
enum Radix {
    Any {
        radix: u32,
        min_len: u32,
    },
    PowerTwo {
        radix: u32,
        min_len: u32,
        log_radix: u8,
    },
}

impl Radix {
    fn from_u32(radix: u32) -> Result<Self, InvalidRadix> {
        if !(2..=(1 << 16)).contains(&radix) {
            return Err(InvalidRadix(radix));
        }

        let mut tmp = radix;
        let mut log_radix = None;
        let mut found_bit = false;

        for i in 0..17 {
            if tmp & 1 != 0 {
                if found_bit {
                    log_radix = None;
                } else {
                    log_radix = Some(i);
                    found_bit = true;
                }
            }
            tmp >>= 1;
        }
        Ok(log_radix.map_or_else(
            || {
                // Compute smallest min_len such that radix^min_len >= 10^6 (minimum domain size).
                // Pure integer arithmetic: no floats, no `as` casts.
                let mut pow: u64 = 1;
                let mut min_len: u32 = 0;
                while pow < MIN_NS_DOMAIN_SIZE {
                    pow = pow.saturating_mul(u64::from(radix));
                    min_len += 1;
                }
                Self::Any { radix, min_len }
            },
            // log_radix is already computed above in the power-of-two branch
            |log_radix| Self::PowerTwo {
                radix,
                min_len: cmp::max(
                    MIN_RADIX_2_NS_LEN.div_ceil(u32::from(log_radix)),
                    MIN_NS_LEN,
                ),
                log_radix,
            },
        ))
    }

    fn check_ns_length(&self, ns_len: usize) -> Result<(), NumeralStringError> {
        let min_len = match *self {
            Self::Any { min_len, .. } | Self::PowerTwo { min_len, .. } => {
                usize::try_from(min_len).unwrap_or(usize::MAX)
            }
        };
        let max_len = MAX_NS_LEN;

        if ns_len < min_len {
            Err(NumeralStringError::TooShort { ns_len, min_len })
        } else if ns_len > max_len {
            Err(NumeralStringError::TooLong { ns_len, max_len })
        } else {
            Ok(())
        }
    }

    fn calculate_b(&self, v: usize) -> usize {
        match *self {
            Self::Any { radix, .. } => {
                // NIST SP 800-38G §6.1 step 6: b = ⌈⌈v × log₂(radix)⌉ / 8⌉
                // Use exact floating-point log2 to match the spec precisely.
                #[allow(
                    clippy::cast_precision_loss,
                    clippy::cast_sign_loss,
                    clippy::cast_possible_truncation,
                    clippy::as_conversions
                )]
                let bit_count = (v as f64 * f64::from(radix).log2()).ceil() as usize;
                bit_count.div_ceil(8)
            }
            Self::PowerTwo { log_radix, .. } => (v * usize::from(log_radix)).div_ceil(8),
        }
    }

    const fn to_u32(&self) -> u32 {
        match *self {
            Self::Any { radix, .. } | Self::PowerTwo { radix, .. } => radix,
        }
    }
}

pub(crate) trait Numeral {
    type Bytes: AsRef<[u8]>;
    fn from_bytes(s: impl Iterator<Item = u8>) -> Self;
    fn to_bytes(&self, b: usize) -> Self::Bytes;
    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;
    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;
}

pub(crate) trait NumeralString: Sized {
    type Num: Numeral;
    fn is_valid(&self, radix: u32) -> bool;
    fn numeral_count(&self) -> usize;
    fn split(&self, u: usize) -> (Self, Self);
    fn concat(a: Self, b: Self) -> Self;
    fn num_radix(&self, radix: u32) -> Self::Num;
    fn str_radix(x: Self::Num, radix: u32, m: usize) -> Self;
}

/// CBC-MAC pseudo-random function used by FF1 (NIST SP 800-38G §4.2).
///
/// Processes arbitrary-length data aligned to 16-byte blocks and exposes the
/// last ciphertext block as output.  The zero IV required by the standard is
/// set at construction time.  Cloneable so each Feistel round can fork from
/// the common prefix computed before the loop.
#[derive(Clone)]
struct Prf {
    /// AES-256 key (zeroised on drop).
    key: [u8; KEY_LEN],
    /// Running CBC state: previous ciphertext block (starts as zero IV).
    state: [u8; BLOCK_LEN],
    /// Accumulation buffer for the next input block.
    buf: [u8; BLOCK_LEN],
    /// Bytes written to `buf` so far.
    offset: usize,
}

impl Drop for Prf {
    fn drop(&mut self) {
        self.key.zeroize();
        self.state.zeroize();
        self.buf.zeroize();
    }
}

impl Prf {
    const fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            key: *key,
            state: [0_u8; BLOCK_LEN], // zero IV per NIST SP 800-38G §4.2
            buf: [0_u8; BLOCK_LEN],
            offset: 0,
        }
    }

    #[allow(clippy::indexing_slicing)]
    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let to_read = cmp::min(BLOCK_LEN - self.offset, data.len());
            self.buf[self.offset..self.offset + to_read].copy_from_slice(&data[..to_read]);
            self.offset += to_read;
            data = &data[to_read..];

            if self.offset == BLOCK_LEN {
                // CBC: XOR plaintext block with previous ciphertext block, then ECB-encrypt.
                for (b, s) in self.buf.iter_mut().zip(self.state.iter()) {
                    *b ^= s;
                }
                self.state = aes256_ecb_block(&self.key, &self.buf);
                self.buf = [0_u8; BLOCK_LEN];
                self.offset = 0;
            }
        }
    }

    fn output(&self) -> &[u8; BLOCK_LEN] {
        debug_assert_eq!(self.offset, 0, "output() called before block boundary");
        &self.state
    }
}

/// Compute the S byte-string per NIST SP 800-38G §6.1 step 8.
///
/// S = R || `CIPH_K`(R XOR \[1\]_16) || `CIPH_K`(R XOR \[2\]_16) || ...
/// truncated to `d` bytes, where each `[j]_16` is j big-endian–encoded into
/// 16 bytes XOR'd element-wise with R.
fn generate_s(key: &[u8; KEY_LEN], r: &[u8; BLOCK_LEN], d: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(d);
    s.extend_from_slice(r);
    let num_extra = d.div_ceil(BLOCK_LEN).saturating_sub(1);
    for j in 1_u128..=u128::try_from(num_extra).unwrap_or(u128::MAX) {
        let mut block = *r;
        for (b, j_byte) in block.iter_mut().zip(j.to_be_bytes().iter()) {
            *b ^= j_byte;
        }
        let encrypted = aes256_ecb_block(key, &block);
        block.zeroize();
        s.extend_from_slice(&encrypted);
    }
    s.truncate(d);
    s
}

pub(crate) type FF1h = FF1fr<18>;

/// FF1 Format-Preserving Encryption with a fixed number of Feistel rounds and
/// AES-256 as the underlying block cipher (NIST SP 800-38G §6).
///
/// The generic constant `FEISTEL_ROUNDS` must be ≥ 8 (NIST minimum).
/// `FF1h` is the standard alias with 18 rounds.
pub(crate) struct FF1fr<const FEISTEL_ROUNDS: u8> {
    /// AES-256 key — zeroised when the struct is dropped.
    key: Zeroizing<[u8; KEY_LEN]>,
    radix: Radix,
}

impl<const FEISTEL_ROUNDS: u8> Drop for FF1fr<FEISTEL_ROUNDS> {
    fn drop(&mut self) {
        // Zeroizing<> handles the key; nothing else to explicitly wipe.
    }
}

impl<const FEISTEL_ROUNDS: u8> FF1fr<FEISTEL_ROUNDS> {
    pub(crate) fn new(key: &[u8], radix: u32) -> Result<Self, FF1Error> {
        if FEISTEL_ROUNDS < 8 {
            return Err(FF1Error::InsufficientFeistelRounds);
        }
        // FF1 mandates a 128-bit (16-byte) block cipher; AES-256 satisfies this.
        // We keep the check for parity with the original API and clear error messages.
        let key_arr: [u8; KEY_LEN] = key.try_into().map_err(|_e| FF1Error::InvalidKeyLength)?;
        let radix = Radix::from_u32(radix)?;
        Ok(Self {
            key: Zeroizing::new(key_arr),
            radix,
        })
    }
}

impl<const FEISTEL_ROUNDS: u8> FF1fr<FEISTEL_ROUNDS> {
    // Variable names (n, t, u, v, b, d, p, c, i) match NIST SP 800-38G §6 exactly
    // to allow line-by-line verification against the specification.
    #[allow(clippy::many_single_char_names)]
    pub(crate) fn encrypt<NS: NumeralString>(
        &self,
        tweak: &[u8],
        x: &NS,
    ) -> Result<NS, NumeralStringError> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(NumeralStringError::InvalidForRadix(self.radix.to_u32()));
        }
        self.radix.check_ns_length(x.numeral_count())?;

        let n = x.numeral_count();
        let t = tweak.len();

        if t > MAX_NS_LEN {
            return Err(NumeralStringError::TweakTooLong);
        }

        let u = n / 2;
        let v = n - u;

        let (mut x_a, mut x_b) = x.split(u);

        let b = self.radix.calculate_b(v);
        let d = 4 * b.div_ceil(4) + 4;

        // Low 8 bits of u (u mod 256), encoded without fallible conversion or indexing.
        let [u_byte, ..] = (u & 0xFF).to_le_bytes();
        let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
        let t_u32 = u32::try_from(t).unwrap_or(u32::MAX);
        let [_, r1, r2, r3] = self.radix.to_u32().to_be_bytes();
        let [n0, n1, n2, n3] = n_u32.to_be_bytes();
        let [t0, t1, t2, t3] = t_u32.to_be_bytes();
        let p: [u8; 16] = [
            1, 2, 1, r1, r2, r3, 10, u_byte, n0, n1, n2, n3, t0, t1, t2, t3,
        ];

        let mut prf = Prf::new(&self.key);
        prf.update(&p);
        prf.update(tweak);
        let padding = (16 - (t + b + 1) % 16) % 16;
        for _ in 0..padding {
            prf.update(&[0]);
        }
        for i in 0..FEISTEL_ROUNDS {
            let mut prf = prf.clone();
            prf.update(&[i]);
            prf.update(x_b.num_radix(self.radix.to_u32()).to_bytes(b).as_ref());
            let r = *prf.output();

            let s = generate_s(&self.key, &r, d);
            let y = NS::Num::from_bytes(s.into_iter());
            let m = if i.is_multiple_of(2) { u } else { v };

            let c = x_a
                .num_radix(self.radix.to_u32())
                .add_mod_exp(y, self.radix.to_u32(), m);

            let x_c = NS::str_radix(c, self.radix.to_u32(), m);

            x_a = x_b;
            x_b = x_c;
        }

        Ok(NS::concat(x_a, x_b))
    }

    // Variable names (n, t, u, v, b, d, p, c, i) match NIST SP 800-38G §6 exactly
    // to allow line-by-line verification against the specification.
    #[allow(clippy::many_single_char_names)]
    pub(crate) fn decrypt<NS: NumeralString>(
        &self,
        tweak: &[u8],
        x: &NS,
    ) -> Result<NS, NumeralStringError> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(NumeralStringError::InvalidForRadix(self.radix.to_u32()));
        }
        self.radix.check_ns_length(x.numeral_count())?;

        let n = x.numeral_count();
        let t = tweak.len();

        if t > MAX_NS_LEN {
            return Err(NumeralStringError::TweakTooLong);
        }

        let u = n / 2;
        let v = n - u;

        let (mut x_a, mut x_b) = x.split(u);

        let b = self.radix.calculate_b(v);
        let d = 4 * b.div_ceil(4) + 4;

        // Low 8 bits of u (u mod 256), encoded without fallible conversion or indexing.
        let [u_byte, ..] = (u & 0xFF).to_le_bytes();
        let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
        let t_u32 = u32::try_from(t).unwrap_or(u32::MAX);
        let [_, r1, r2, r3] = self.radix.to_u32().to_be_bytes();
        let [n0, n1, n2, n3] = n_u32.to_be_bytes();
        let [t0, t1, t2, t3] = t_u32.to_be_bytes();
        let p: [u8; 16] = [
            1, 2, 1, r1, r2, r3, 10, u_byte, n0, n1, n2, n3, t0, t1, t2, t3,
        ];

        let mut prf = Prf::new(&self.key);
        prf.update(&p);
        prf.update(tweak);
        let padding = (16 - (t + b + 1) % 16) % 16;
        for _ in 0..padding {
            prf.update(&[0]);
        }
        for i in 0..FEISTEL_ROUNDS {
            let i = FEISTEL_ROUNDS - 1 - i;
            let mut prf = prf.clone();
            prf.update(&[i]);
            prf.update(x_a.num_radix(self.radix.to_u32()).to_bytes(b).as_ref());
            let r = *prf.output();

            let s = generate_s(&self.key, &r, d);
            let y = NS::Num::from_bytes(s.into_iter());
            let m = if i.is_multiple_of(2) { u } else { v };

            let c = x_b
                .num_radix(self.radix.to_u32())
                .sub_mod_exp(y, self.radix.to_u32(), m);

            let x_c = NS::str_radix(c, self.radix.to_u32(), m);

            x_b = x_a;
            x_a = x_c;
        }

        Ok(NS::concat(x_a, x_b))
    }
}

fn pow(x: u32, e: usize) -> BigUint {
    num_traits::pow::pow(BigUint::from(x), e)
}

/// Returns the minimum numeral-string length required by FF1 for `radix`.
/// Mirrors the logic in `Radix::from_u32` without exposing the internal type.
pub(crate) fn radix_min_len(radix: u32) -> Result<usize, InvalidRadix> {
    Ok(match Radix::from_u32(radix)? {
        Radix::Any { min_len, .. } | Radix::PowerTwo { min_len, .. } => {
            usize::try_from(min_len).unwrap_or(usize::MAX)
        }
    })
}

impl Numeral for BigUint {
    type Bytes = Vec<u8>;

    fn from_bytes(s: impl Iterator<Item = u8>) -> Self {
        Self::from_bytes_be(&s.collect::<Vec<_>>())
    }

    fn to_bytes(&self, b: usize) -> Vec<u8> {
        if self.is_zero() {
            vec![0; b]
        } else {
            let bytes = self.to_bytes_be();
            core::iter::repeat_n(0_u8, b - bytes.len())
                .chain(bytes)
                .collect()
        }
    }

    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self {
        (self + other) % pow(radix, m)
    }

    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self {
        let modulus = pow(radix, m);
        // Avoid negative intermediates (impossible with BigUint) by adding modulus
        // before subtracting: (self + modulus - other_reduced) % modulus.
        // self is always in [0, modulus) as it comes from num_radix; after reducing
        // other the numerator is in (0, 2*modulus), so one % is sufficient.
        (self + &modulus - other % &modulus) % modulus
    }
}

#[derive(Debug)]
pub(crate) struct FlexibleNumeralString(Vec<u16>);

impl From<Vec<u16>> for FlexibleNumeralString {
    fn from(v: Vec<u16>) -> Self {
        Self(v)
    }
}

impl From<FlexibleNumeralString> for Vec<u16> {
    fn from(fns: FlexibleNumeralString) -> Self {
        fns.0
    }
}

impl NumeralString for FlexibleNumeralString {
    type Num = BigUint;

    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| u32::from(*n) < radix)
    }

    fn numeral_count(&self) -> usize {
        self.0.len()
    }

    fn split(&self, u: usize) -> (Self, Self) {
        let mut front = self.0.clone();
        let back = front.split_off(u);
        (Self(front), Self(back))
    }

    fn concat(mut a: Self, mut b: Self) -> Self {
        a.0.append(&mut b.0);
        a
    }

    fn num_radix(&self, radix: u32) -> BigUint {
        let mut res = BigUint::zero();
        for i in &self.0 {
            res *= radix;
            res += BigUint::from(*i);
        }
        res
    }

    fn str_radix(mut x: BigUint, radix: u32, m: usize) -> Self {
        let mut res = vec![0_u16; m];
        // Fill from the least-significant digit upward using rev() — no index arithmetic.
        for slot in res.iter_mut().rev() {
            // (&x % radix) < radix ≤ 65536, so to_u32() is always Some and
            // u16::try_from is always Ok. unwrap_or(0) is an unreachable fallback.
            *slot = (&x % radix)
                .to_u32()
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0);
            x /= radix;
        }
        Self(res)
    }
}

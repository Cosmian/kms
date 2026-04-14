// This code is tweaked and vendored from https://github.com/Cosmian/cosmian_fpe
use cipher::{
    Block, BlockCipher, BlockEncrypt, BlockEncryptMut, InnerIvInit, KeyInit, Unsigned,
    generic_array::GenericArray,
};
use core::{cmp, fmt};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, identities::Zero};
use zeroize::Zeroize;

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
    InvalidKeyLength,
    InsufficientFeistelRounds,
    InvalidBlockSize,
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
                write!(f, "Invalid key length for the chosen cipher")
            }
            Self::InsufficientFeistelRounds => {
                write!(f, "FF1fr requires at least 8 Feistel rounds")
            }
            Self::InvalidBlockSize => {
                write!(
                    f,
                    "FF1 requires a 128-bit (16-byte) block cipher (NIST SP 800-38G §4.3)"
                )
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

#[derive(Clone)]
struct Prf<CIPH: BlockCipher + BlockEncrypt> {
    state: cbc::Encryptor<CIPH>,
    buf: Block<CIPH>,
    offset: usize,
}

impl<CIPH: BlockCipher + BlockEncrypt> Drop for Prf<CIPH> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl<CIPH: BlockCipher + BlockEncrypt + Clone> Prf<CIPH> {
    fn new(ciph: &CIPH) -> Self {
        let ciph = ciph.clone();
        Self {
            state: cbc::Encryptor::inner_iv_init(ciph, GenericArray::from_slice(&[0; 16])),
            buf: Block::<CIPH>::default(),
            offset: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let to_read = cmp::min(self.buf.len() - self.offset, data.len());
            let (src, rest) = data.split_at(to_read);
            let (_, dst) = self.buf.split_at_mut(self.offset);
            let (dst, _) = dst.split_at_mut(to_read);
            dst.copy_from_slice(src);
            self.offset += to_read;
            data = rest;

            if self.offset == self.buf.len() {
                self.state
                    .encrypt_blocks_mut(core::slice::from_mut(&mut self.buf));
                self.offset = 0;
            }
        }
    }

    fn output(&self) -> &Block<CIPH> {
        debug_assert_eq!(self.offset, 0, "output() called before block boundary");
        &self.buf
    }
}

fn generate_s<'a, CIPH: BlockEncrypt>(
    ciph: &'a CIPH,
    r: &'a Block<CIPH>,
    d: usize,
) -> impl Iterator<Item = u8> + 'a {
    r.clone()
        .into_iter()
        .chain(
            (1_u128..u128::try_from(d.div_ceil(16)).unwrap_or(u128::MAX)).flat_map(move |j| {
                let mut block = r.clone();
                for (b, j) in block.iter_mut().zip(j.to_be_bytes().iter()) {
                    *b ^= j;
                }
                ciph.encrypt_block(&mut block);
                block.into_iter()
            }),
        )
        .take(d)
}

pub(crate) type FF1h<CIPH> = FF1fr<18, CIPH>;

pub(crate) struct FF1fr<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher> {
    ciph: CIPH,
    radix: Radix,
}

impl<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher + KeyInit> FF1fr<FEISTEL_ROUNDS, CIPH> {
    pub(crate) fn new(key: &[u8], radix: u32) -> Result<Self, FF1Error> {
        if FEISTEL_ROUNDS < 8 {
            return Err(FF1Error::InsufficientFeistelRounds);
        }
        if CIPH::BlockSize::USIZE != 16 {
            return Err(FF1Error::InvalidBlockSize);
        }
        // `new_from_slice` returns `cipher::InvalidLength` which is a unit struct
        // carrying no information beyond "wrong length" — already encoded in the variant.
        let ciph = CIPH::new_from_slice(key).ok().ok_or(FF1Error::InvalidKeyLength)?;
        let radix = Radix::from_u32(radix)?;
        Ok(Self { ciph, radix })
    }
}

impl<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher + BlockEncrypt + Clone>
    FF1fr<FEISTEL_ROUNDS, CIPH>
{
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

        // u mod 256 fits in u8; n and t are both ≤ MAX_NS_LEN (checked above) so ≤ u32::MAX.
        let u_byte = u8::try_from(u & 0xFF).unwrap_or(0);
        let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
        let t_u32 = u32::try_from(t).unwrap_or(u32::MAX);
        let [_, r1, r2, r3] = self.radix.to_u32().to_be_bytes();
        let [n0, n1, n2, n3] = n_u32.to_be_bytes();
        let [t0, t1, t2, t3] = t_u32.to_be_bytes();
        let p: [u8; 16] = [
            1, 2, 1, r1, r2, r3, 10, u_byte, n0, n1, n2, n3, t0, t1, t2, t3,
        ];

        let mut prf = Prf::new(&self.ciph);
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
            let r = prf.output();

            let s = generate_s(&self.ciph, r, d);
            let y = NS::Num::from_bytes(s);
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

        // u mod 256 fits in u8; n and t are both ≤ MAX_NS_LEN (checked above) so ≤ u32::MAX.
        let u_byte = u8::try_from(u & 0xFF).unwrap_or(0);
        let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
        let t_u32 = u32::try_from(t).unwrap_or(u32::MAX);
        let [_, r1, r2, r3] = self.radix.to_u32().to_be_bytes();
        let [n0, n1, n2, n3] = n_u32.to_be_bytes();
        let [t0, t1, t2, t3] = t_u32.to_be_bytes();
        let p: [u8; 16] = [
            1, 2, 1, r1, r2, r3, 10, u_byte, n0, n1, n2, n3, t0, t1, t2, t3,
        ];

        let mut prf = Prf::new(&self.ciph);
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
            let r = prf.output();

            let s = generate_s(&self.ciph, r, d);
            let y = NS::Num::from_bytes(s);
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

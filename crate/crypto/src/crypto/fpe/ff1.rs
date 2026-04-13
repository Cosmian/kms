// This code is tweaked and vendored from https://github.com/Cosmian/cosmian_fpe
#![allow(dead_code, unreachable_pub)]
use core::{cmp, fmt};
use cipher::{
    generic_array::GenericArray, Block, BlockCipher, BlockEncrypt, BlockEncryptMut, InnerIvInit,
    KeyInit, Unsigned,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{identities::Zero, ToPrimitive};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRadix(pub u32);

impl fmt::Display for InvalidRadix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The radix {} is not in the range 2..=(1 << 16)", self.0)
    }
}

impl std::error::Error for InvalidRadix {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FF1Error {
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
                write!(f, "FF1 requires a 128-bit (16-byte) block cipher (NIST SP 800-38G §4.3)")
            }
        }
    }
}

impl std::error::Error for FF1Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumeralStringError {
    InvalidForRadix(u32),
    TooLong { ns_len: usize, max_len: usize },
    TooShort { ns_len: usize, min_len: usize },
    TweakTooLong,
    NotByteAligned,
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
            Self::NotByteAligned => {
                write!(f, "BinaryNumeralString length is not a multiple of 8")
            }
        }
    }
}

impl std::error::Error for NumeralStringError {}

const MIN_NS_LEN: u32 = 2;
const MAX_NS_LEN: usize = 4_294_967_295; // u32::MAX
const MIN_RADIX_2_NS_LEN: u32 = 20;
const LOG_10_MIN_NS_DOMAIN_SIZE: f64 = 6.0;

#[derive(Debug, PartialEq)]
enum Radix {
    Any { radix: u32, min_len: u32 },
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
                use libm::{ceil, log10};
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::as_conversions)]
                let min_len = ceil(LOG_10_MIN_NS_DOMAIN_SIZE / log10(f64::from(radix))) as u32;
                Self::Any { radix, min_len }
            },
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
        use libm::{ceil, log2};
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            clippy::as_conversions
        )]
        match *self {
            Self::Any { radix, .. } => ceil(v as f64 * log2(f64::from(radix)) / 8_f64) as usize,
            Self::PowerTwo { log_radix, .. } => (v * usize::from(log_radix)).div_ceil(8),
        }
    }

    const fn to_u32(&self) -> u32 {
        match *self {
            Self::Any { radix, .. } | Self::PowerTwo { radix, .. } => radix,
        }
    }
}

pub trait Numeral {
    type Bytes: AsRef<[u8]>;
    fn from_bytes(s: impl Iterator<Item = u8>) -> Self;
    fn to_bytes(&self, b: usize) -> Self::Bytes;
    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;
    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;
}

pub trait NumeralString: Sized {
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
    buf: [Block<CIPH>; 1],
    offset: usize,
}

impl<CIPH: BlockCipher + BlockEncrypt> Drop for Prf<CIPH> {
    fn drop(&mut self) {
        self.buf[0].zeroize();
    }
}

impl<CIPH: BlockCipher + BlockEncrypt + Clone> Prf<CIPH> {
    fn new(ciph: &CIPH) -> Self {
        let ciph = ciph.clone();
        Self {
            state: cbc::Encryptor::inner_iv_init(ciph, GenericArray::from_slice(&[0; 16])),
            buf: [Block::<CIPH>::default()],
            offset: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        #[allow(clippy::indexing_slicing)]
        while !data.is_empty() {
            let to_read = cmp::min(self.buf[0].len() - self.offset, data.len());
            self.buf[0][self.offset..self.offset + to_read].copy_from_slice(&data[..to_read]);
            self.offset += to_read;
            data = &data[to_read..];

            if self.offset == self.buf[0].len() {
                self.state.encrypt_blocks_mut(&mut self.buf);
                self.offset = 0;
            }
        }
    }

    fn output(&self) -> &Block<CIPH> {
        debug_assert_eq!(self.offset, 0, "output() called before block boundary");
        #[allow(clippy::indexing_slicing)]
        &self.buf[0]
    }
}

fn generate_s<'a, CIPH: BlockEncrypt>(
    ciph: &'a CIPH,
    r: &'a Block<CIPH>,
    d: usize,
) -> impl Iterator<Item = u8> + 'a {
    r.clone()
        .into_iter()
        .chain((1_u128..u128::try_from(d.div_ceil(16)).unwrap_or(u128::MAX)).flat_map(move |j| {
            let mut block = r.clone();
            for (b, j) in block.iter_mut().zip(j.to_be_bytes().iter()) {
                *b ^= j;
            }
            ciph.encrypt_block(&mut block);
            block.into_iter()
        }))
        .take(d)
}

pub type FF1<CIPH> = FF1fr<10, CIPH>;
pub type FF1h<CIPH> = FF1fr<18, CIPH>;

pub struct FF1fr<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher> {
    ciph: CIPH,
    radix: Radix,
}

impl<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher + KeyInit> FF1fr<FEISTEL_ROUNDS, CIPH> {
    pub fn new(key: &[u8], radix: u32) -> Result<Self, FF1Error> {
        if FEISTEL_ROUNDS < 8 {
            return Err(FF1Error::InsufficientFeistelRounds);
        }
        if CIPH::BlockSize::USIZE != 16 {
            return Err(FF1Error::InvalidBlockSize);
        }
        #[allow(clippy::map_err_ignore)]
        let ciph = CIPH::new_from_slice(key).map_err(|_| FF1Error::InvalidKeyLength)?;
        let radix = Radix::from_u32(radix)?;
        Ok(Self { ciph, radix })
    }
}

impl<const FEISTEL_ROUNDS: u8, CIPH: BlockCipher + BlockEncrypt + Clone>
    FF1fr<FEISTEL_ROUNDS, CIPH>
{
    #[allow(clippy::many_single_char_names)]
    pub fn encrypt<NS: NumeralString>(
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

        // SAFETY: u mod 256 fits in u8; n and t are verified ≤ MAX_NS_LEN = u32::MAX
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        let mut p = [1_u8, 2, 1, 0, 0, 0, 10, u as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        #[allow(clippy::indexing_slicing, clippy::cast_possible_truncation, clippy::as_conversions)]
        {
            p[3..6].copy_from_slice(&self.radix.to_u32().to_be_bytes()[1..]);
            p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
            p[12..16].copy_from_slice(&(t as u32).to_be_bytes());
        }

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

    #[allow(clippy::many_single_char_names)]
    pub fn decrypt<NS: NumeralString>(
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

        // SAFETY: u mod 256 fits in u8; n and t are verified ≤ MAX_NS_LEN = u32::MAX
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        let mut p = [1_u8, 2, 1, 0, 0, 0, 10, u as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        #[allow(clippy::indexing_slicing, clippy::cast_possible_truncation, clippy::as_conversions)]
        {
            p[3..6].copy_from_slice(&self.radix.to_u32().to_be_bytes()[1..]);
            p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
            p[12..16].copy_from_slice(&(t as u32).to_be_bytes());
        }

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
            core::iter::repeat_n(0_u8, b - bytes.len()).chain(bytes).collect()
        }
    }

    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self {
        (self + other) % pow(radix, m)
    }

    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self {
        let modulus = BigInt::from(pow(radix, m));
        let mut c = (BigInt::from(self) - BigInt::from(other)) % &modulus;
        if c.sign() == Sign::Minus {
            c += &modulus;
            c %= modulus;
        }
        // SAFETY: c is guaranteed non-negative after the modulo correction above
        #[allow(clippy::expect_used)]
        c.to_biguint()
            .expect("value is non-negative after modulo correction")
    }
}

#[derive(Debug)]
pub struct FlexibleNumeralString(Vec<u16>);

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
        let mut res = vec![0; m];
        for i in 0..m {
            // (&x % radix) < radix ≤ 2^16, so to_u16() is always Some;
            // i < m guarantees the index is in bounds.
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            {
                res[m - 1 - i] = (&x % radix).to_u16().unwrap();
            }
            x /= radix;
        }
        Self(res)
    }
}

#[derive(Debug)]
pub struct BinaryNumeralString(Vec<u8>);

impl BinaryNumeralString {
    pub fn from_bytes_le(s: &[u8]) -> Self {
        let mut data = Vec::with_capacity(s.len() * 8);
        for n in s {
            let mut tmp = *n;
            for _ in 0..8 {
                data.push(tmp & 1);
                tmp >>= 1;
            }
        }
        Self(data)
    }

    pub fn to_bytes_le(&self) -> Result<Vec<u8>, NumeralStringError> {
        if !self.0.len().is_multiple_of(8) {
            return Err(NumeralStringError::NotByteAligned);
        }
        let mut data = Vec::with_capacity(self.0.len() / 8);
        let mut acc = 0;
        let mut shift = 0;
        for n in &self.0 {
            acc += n << shift;
            shift += 1;
            if shift == 8 {
                data.push(acc);
                acc = 0;
                shift = 0;
            }
        }
        Ok(data)
    }
}

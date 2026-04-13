use super::FPEError;
use super::KEY_LENGTH;
use super::ff1::{FF1h, FlexibleNumeralString};
use aes::Aes256;
use itertools::Itertools;
use std::{collections::HashMap, fmt::Display};

/// The recommended threshold according to NIST standards
pub(crate) const RECOMMENDED_THRESHOLD: usize = 1_000_000;

/// Minimum length of the plaintext for FPE to be secure.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::as_conversions
)]
pub(crate) fn min_plaintext_length(alphabet_len: usize) -> usize {
    ((RECOMMENDED_THRESHOLD as f64).log(alphabet_len as f64)).ceil() as usize
}

/// The `Alphabet` structure contains information about the usable characters
/// and the minimum plaintext length for FPE.
///
/// It's recommended that the alphabet contains between 8 and 2^16 characters.
/// Smaller alphabets as small as 2 characters are technically possible but can
/// be challenging to ensure security.
///
/// Pre-defined alphabets are available:
///  - `Alphabet::alpha()`
///  - `Alphabet::alpha_lower()`
///  - `Alphabet::alpha_upper()`
///  - `Alphabet::numeric()`
///  - `Alphabet::hexa_decimal()`
///  - `Alphabet::alpha_numeric()`
///  - `Alphabet::chinese()`
///  - `Alphabet::latin1sup()`
///  - `Alphabet::latin1sup_alphanum()`
///
/// To build your own, for example the hexadecimal alphabet,
/// use `Alphabet::try_from("0123456789abcdef").unwrap()`
///
/// See the `encrypt()` and `decrypt()` methods for usage
#[derive(Debug, Clone)]
pub struct Alphabet {
    pub(crate) chars: Vec<char>,
    pub(crate) min_text_length: usize,
}

impl TryFrom<&str> for Alphabet {
    type Error = FPEError;

    /// Returns an error if the alphabet contains fewer than 2 or 2^16 or more characters.
    fn try_from(alphabet: &str) -> Result<Self, Self::Error> {
        let chars = alphabet.chars().sorted().unique().collect_vec();
        if chars.len() < 2 || chars.len() >= 1 << 16 {
            return Err(FPEError::FPE(format!(
                "Alphabet must contain between 2 and 2^16 characters. This alphabet contains {} \
                 characters",
                chars.len()
            )));
        }
        Ok(Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        })
    }
}

impl TryFrom<&String> for Alphabet {
    type Error = FPEError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl Alphabet {
    pub fn instantiate(alphabet: &str) -> Result<Self, FPEError> {
        Self::try_from(alphabet)
    }

    fn extend_(&mut self, additional_characters: Vec<char>) {
        self.chars.extend(additional_characters);
        self.chars = self
            .chars
            .iter()
            .sorted()
            .unique()
            .copied()
            .collect::<Vec<_>>();
        self.min_text_length = min_plaintext_length(self.chars.len());
    }

    #[must_use]
    pub const fn minimum_plaintext_length(&self) -> usize {
        self.min_text_length
    }

    /// Extends the alphabet with additional characters, removing duplicates.
    pub fn extend_with(&mut self, additional_characters: &str) {
        self.extend_(additional_characters.chars().collect::<Vec<_>>());
    }

    #[must_use]
    pub const fn alphabet_len(&self) -> usize {
        self.chars.len()
    }

    pub(crate) fn char_to_position(&self, c: char) -> Option<u16> {
        // Safety: alphabet length is enforced to be < 2^16 in `try_from`
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        self.chars.binary_search(&c).ok().map(|pos| pos as u16)
    }

    pub(crate) fn char_from_position(&self, position: u16) -> Option<char> {
        self.chars.get(usize::from(position)).copied()
    }

    /// Maps each character in `input` to its index in the alphabet.
    /// Characters not in the alphabet are stored separately by position and
    /// reinserted verbatim by `debase`.
    fn rebase(&self, input: &str) -> (Vec<u16>, HashMap<usize, char>) {
        let mut stripped_input: Vec<u16> = vec![];
        let mut non_alphabet_chars = HashMap::<usize, char>::new();
        for (idx, c) in input.chars().enumerate() {
            if let Some(pos) = self.char_to_position(c) {
                stripped_input.push(pos);
            } else {
                non_alphabet_chars.insert(idx, c);
            }
        }
        (stripped_input, non_alphabet_chars)
    }

    /// Inverse of `rebase`: maps alphabet indices back to characters and
    /// reinserts non-alphabet characters at their original positions.
    fn debase(
        &self,
        stripped_input: &[u16],
        non_alphabet_chars: &HashMap<usize, char>,
    ) -> Result<String, FPEError> {
        let mut result = Vec::with_capacity(stripped_input.len() + non_alphabet_chars.len());
        let mut alphabet_idx = 0;
        for i in 0..stripped_input.len() + non_alphabet_chars.len() {
            result.push(if let Some(c) = non_alphabet_chars.get(&i) {
                *c
            } else {
                let position = stripped_input.get(alphabet_idx).copied().ok_or_else(|| {
                    FPEError::FPE("internal error: alphabet index out of bounds".to_owned())
                })?;
                alphabet_idx += 1;
                self.char_from_position(position).ok_or_else(|| {
                    FPEError::FPE(format!(
                        "index {} out of bounds for alphabet of size {}",
                        position,
                        self.alphabet_len()
                    ))
                })?
            });
        }
        Ok(result.into_iter().collect::<String>())
    }

    /// Encrypts the plaintext using the given `key` and `tweak` using
    /// Format-Preserving Encryption (FPE).
    ///
    /// # Examples
    ///
    /// ```
    /// use cosmian_kms_crypto::crypto::fpe::Alphabet;
    ///
    /// let alphabet = Alphabet::try_from("abcdefghijklmnopqrstuvwxyz").unwrap();
    /// let alphabet = Alphabet::alpha_lower(); //same as above
    /// let key = [0_u8; 32];
    /// let tweak = b"unique tweak";
    /// let plaintext = "plaintext";
    /// let ciphertext = alphabet.encrypt(&key, tweak, plaintext).unwrap();
    /// assert_eq!(ciphertext, "phqivnqmo");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the plaintext contains characters not in the
    /// alphabet, or if the encryption fails.
    pub fn encrypt(&self, key: &[u8], tweak: &[u8], plaintext: &str) -> Result<String, FPEError> {
        let (stripped_input, non_alphabet_chars) = self.rebase(plaintext);

        if stripped_input.len() < self.minimum_plaintext_length() {
            return Err(FPEError::FPE(format!(
                "The stripped input length of {} is too short. It should be at least {} given the \
                 alphabet length of {}.",
                stripped_input.len(),
                self.minimum_plaintext_length(),
                self.alphabet_len()
            )));
        }

        if key.len() != KEY_LENGTH {
            return Err(FPEError::KeySize(key.len(), KEY_LENGTH));
        }

        let fpe_ff = FF1h::<Aes256>::new(
            key,
            u32::try_from(self.alphabet_len())
                .map_err(|e| FPEError::ConversionError(e.to_string()))?,
        )
        .map_err(|e| FPEError::FPE(format!("failed instantiating FF1: {e}")))?;
        let ciphertext_ns = fpe_ff
            .encrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| FPEError::FPE(format!("FF1 encryption failed: {e}")))?;

        let ciphertext = Vec::<u16>::from(ciphertext_ns);

        self.debase(&ciphertext, &non_alphabet_chars)
    }

    /// Decrypts the ciphertext using the given `key` and `tweak` using
    /// Format-Preserving Encryption (FPE).
    ///
    /// # Examples
    ///
    /// ```
    /// use cosmian_kms_crypto::crypto::fpe::Alphabet;
    ///
    /// let alphabet = Alphabet::try_from("abcdefghijklmnopqrstuvwxyz").unwrap();
    /// let alphabet = Alphabet::alpha_lower(); //same as above
    /// let key = [0_u8; 32];
    /// let tweak = b"unique tweak";
    /// let ciphertext = "phqivnqmo";
    /// let cleartext = alphabet.decrypt(&key, tweak, &ciphertext).unwrap();
    /// assert_eq!(cleartext, "plaintext");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the ciphertext contains characters not in the
    /// alphabet, or if the decryption fails.
    pub fn decrypt(&self, key: &[u8], tweak: &[u8], ciphertext: &str) -> Result<String, FPEError> {
        if key.len() != KEY_LENGTH {
            return Err(FPEError::KeySize(key.len(), KEY_LENGTH));
        }
        let (stripped_input, non_alphabet_chars) = self.rebase(ciphertext);

        let fpe_ff = FF1h::<Aes256>::new(
            key,
            u32::try_from(self.alphabet_len())
                .map_err(|e| FPEError::ConversionError(e.to_string()))?,
        )
        .map_err(|e| FPEError::FPE(format!("failed instantiating FF1: {e}")))?;
        let plaintext_ns = fpe_ff
            .decrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| FPEError::FPE(format!("FF1 decryption failed: {e}")))?;

        let plaintext = Vec::<u16>::from(plaintext_ns);

        self.debase(&plaintext, &non_alphabet_chars)
    }
}

impl Display for Alphabet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.chars.iter().collect::<String>()))
    }
}

macro_rules! define_alphabet_constructors {
    ($($name:ident => $alphabet:expr),+) => {
        $(
            impl Alphabet {
                #[doc = "Creates an Alphabet with the given alphabet string: `"]
                #[doc = $alphabet]
                #[doc = "`."]
                #[must_use] pub fn $name() -> Alphabet {
                    Alphabet::try_from($alphabet).unwrap()
                }
            }
        )+
    }
}

define_alphabet_constructors! {
    numeric => "0123456789",
    hexa_decimal => "0123456789abcdef",
    alpha_lower => "abcdefghijklmnopqrstuvwxyz",
    alpha_upper => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alpha_numeric => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
}

impl Alphabet {
    /// Creates an Alphabet with the first 63489 (~2^16) Unicode characters
    pub fn utf() -> Self {
        let chars = (0..=1 << 16_u32)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the Chinese characters
    pub fn chinese() -> Self {
        let chars = (0x4E00..=0x9FFF_u32)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the latin-1 and latin1-supplement characters
    /// (supports French)
    pub fn latin1sup() -> Self {
        let chars = (0x0021..=0x007E_u32)
            .chain(0x00C0..=0x00FF)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }

    /// Creates an Alphabet with the latin-1 and latin1-supplement characters
    /// but without the non alphanumeric characters (supports French)
    pub fn latin1sup_alphanum() -> Self {
        let chars = (0x0030..=0x0039_u32)
            .chain(0x0041..=0x005A)
            .chain(0x0061..=0x007A)
            .chain(0x00C0..=0x00FF)
            .filter_map(char::from_u32)
            .collect::<Vec<char>>();
        Self {
            min_text_length: min_plaintext_length(chars.len()),
            chars,
        }
    }
}

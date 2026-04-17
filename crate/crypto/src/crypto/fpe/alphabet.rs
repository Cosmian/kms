use super::FPEError;
use super::KEY_LENGTH;
use super::ff1::{FF1h, FlexibleNumeralString};
use aes::Aes256;
use itertools::Itertools;
use std::{collections::HashMap, fmt::Display};

/// The recommended threshold according to NIST standards
pub(crate) const RECOMMENDED_THRESHOLD: usize = 1_000_000;

/// Minimum length of the plaintext for FPE to be secure.
///
/// Returns the smallest `n` such that `alphabet_len^n >= RECOMMENDED_THRESHOLD`.
pub(crate) const fn min_plaintext_length(alphabet_len: usize) -> usize {
    let (mut pow, mut n) = (1_usize, 0_usize);
    // Shorter ways to write this exist, but this compressed loop is the cleanest way to benefit from as const function while complying to KMS's linting rules.
    while pow < RECOMMENDED_THRESHOLD {
        pow = pow.saturating_mul(alphabet_len);
        n += 1;
    }
    n
}

/// Built-in alphabet presets for AES-256 FF1 Format-Preserving Encryption.
///
/// Each variant corresponds to a predefined character set. To build a custom
/// alphabet use [`Alphabet::try_from`] or [`Alphabet::from_preset_or_custom`].
//
// DEV NOTE (not shown in docs): When adding or renaming a preset, keep
// PRESET_NAMES array below (canonical name used by the CLI) in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlphabetPreset {
    /// Digits 0–9
    Numeric,
    /// Hexadecimal digits 0–9 and a–f
    Hexadecimal,
    /// Lowercase ASCII letters a–z
    AlphaLower,
    /// Uppercase ASCII letters A–Z
    AlphaUpper,
    /// All ASCII letters a–z and A–Z
    Alpha,
    /// ASCII alphanumeric: 0–9, A–Z, a–z
    AlphaNumeric,
    /// CJK Unified Ideographs (U+4E00–U+9FFF)
    Chinese,
    /// Latin-1 and Latin-1 Supplement printable characters (supports French)
    Latin1Sup,
    /// Latin-1 Supplement alphanumeric characters only (supports French)
    Latin1SupAlphanum,
    /// First ~65 000 Unicode code points
    Utf,
    /// Full printable ASCII range 0x20–0x7E (space through tilde, 95 characters)
    AsciiPrintable,
    /// Base64 alphabet A-Za-z0-9+/ (64 characters). The padding character '=' is intentionally
    /// omitted: it carries no entropy and is preserved verbatim as a non-alphabet character.
    Base64,
}

impl AlphabetPreset {
    /// Canonical name used in the HTTP API and on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Numeric => "numeric",
            Self::Hexadecimal => "hexadecimal",
            Self::AlphaLower => "alpha_lower",
            Self::AlphaUpper => "alpha_upper",
            Self::Alpha => "alpha",
            Self::AlphaNumeric => "alpha_numeric",
            Self::Chinese => "chinese",
            Self::Latin1Sup => "latin1sup",
            Self::Latin1SupAlphanum => "latin1sup_alphanum",
            Self::Utf => "utf",
            Self::AsciiPrintable => "ascii_printable",
            Self::Base64 => "base64",
        }
    }

    /// All preset names, in definition order.
    pub const PRESET_NAMES: &'static [&'static str] = &[
        "numeric",
        "hexadecimal",
        "alpha_lower",
        "alpha_upper",
        "alpha",
        "alpha_numeric",
        "chinese",
        "latin1sup",
        "latin1sup_alphanum",
        "utf",
        "ascii_printable",
        "base64",
    ];

    /// Returns the preset matching `s`, or `None` if `s` is not a known preset name.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "numeric" => Some(Self::Numeric),
            "hexadecimal" => Some(Self::Hexadecimal),
            "alpha_lower" => Some(Self::AlphaLower),
            "alpha_upper" => Some(Self::AlphaUpper),
            "alpha" => Some(Self::Alpha),
            "alpha_numeric" => Some(Self::AlphaNumeric),
            "chinese" => Some(Self::Chinese),
            "latin1sup" => Some(Self::Latin1Sup),
            "latin1sup_alphanum" => Some(Self::Latin1SupAlphanum),
            "utf" => Some(Self::Utf),
            "ascii_printable" => Some(Self::AsciiPrintable),
            "base64" => Some(Self::Base64),
            _ => None,
        }
    }
}

impl Display for AlphabetPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The `Alphabet` structure contains information about the usable characters
/// and the minimum plaintext length for FPE.
///
/// It's recommended that the alphabet contains between 8 and 2^16 characters.
/// Smaller alphabets as small as 2 characters are technically possible but can
/// be challenging to ensure security.
///
/// Pre-defined alphabets are available via [`AlphabetPreset`]; convert a preset
/// with [`Alphabet::from`] or use the convenience constructors such as
/// [`Alphabet::numeric`]. To build a custom alphabet use [`Alphabet::try_from`],
/// e.g. `Alphabet::try_from("0123456789abcdef").unwrap()`.
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
            return Err(FPEError::AlphabetError(format!(
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

    /// Resolves `s` as a preset name first, then falls back to treating `s` as
    /// a raw character set.
    ///
    /// # Errors
    ///
    /// Returns an error if `s` is neither a known preset name nor a valid
    /// character set (fewer than 2 or 2^16 or more unique characters).
    pub fn from_preset_or_custom(s: &str) -> Result<Self, FPEError> {
        AlphabetPreset::from_name(s)
            .map_or_else(|| Self::try_from(s), |preset| Ok(Self::from(preset)))
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
        // pos < self.chars.len() < 2^16 (enforced by TryFrom<&str>)
        self.chars
            .binary_search(&c)
            .ok()
            .and_then(|pos| u16::try_from(pos).ok())
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
                    FPEError::OperationFailed(
                        "internal error: alphabet index out of bounds".to_owned(),
                    )
                })?;
                alphabet_idx += 1;
                self.char_from_position(position).ok_or_else(|| {
                    FPEError::OutOfBounds(format!(
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
            return Err(FPEError::OutOfBounds(format!(
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
        .map_err(|e| FPEError::OperationFailed(format!("failed instantiating FF1: {e}")))?;
        let ciphertext_ns = fpe_ff
            .encrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| FPEError::OperationFailed(format!("FF1 encryption failed: {e}")))?;

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
        .map_err(|e| FPEError::OperationFailed(format!("failed instantiating FF1: {e}")))?;
        let plaintext_ns = fpe_ff
            .decrypt(tweak, &FlexibleNumeralString::from(stripped_input))
            .map_err(|e| FPEError::OperationFailed(format!("FF1 decryption failed: {e}")))?;

        let plaintext = Vec::<u16>::from(plaintext_ns);

        self.debase(&plaintext, &non_alphabet_chars)
    }
}

impl Display for Alphabet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.chars.iter().collect::<String>()))
    }
}

/// Builds an `Alphabet` from a preset character string.
/// Preset strings are guaranteed to produce a valid alphabet (2 ≤ chars < 2^16).
fn build_from_chars(s: &str) -> Alphabet {
    let chars = s.chars().sorted().unique().collect_vec();
    Alphabet {
        min_text_length: min_plaintext_length(chars.len()),
        chars,
    }
}

impl From<AlphabetPreset> for Alphabet {
    fn from(preset: AlphabetPreset) -> Self {
        match preset {
            AlphabetPreset::Numeric => build_from_chars("0123456789"),
            AlphabetPreset::Hexadecimal => build_from_chars("0123456789abcdef"),
            AlphabetPreset::AlphaLower => build_from_chars("abcdefghijklmnopqrstuvwxyz"),
            AlphabetPreset::AlphaUpper => build_from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            AlphabetPreset::Alpha => {
                build_from_chars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
            }
            AlphabetPreset::AlphaNumeric => {
                build_from_chars("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
            }
            AlphabetPreset::Chinese => {
                let chars = (0x4E00..=0x9FFF_u32)
                    .filter_map(char::from_u32)
                    .collect::<Vec<char>>();
                Self {
                    min_text_length: min_plaintext_length(chars.len()),
                    chars,
                }
            }
            AlphabetPreset::Latin1Sup => {
                let chars = (0x0021..=0x007E_u32)
                    .chain(0x00C0..=0x00FF)
                    .filter_map(char::from_u32)
                    .collect::<Vec<char>>();
                Self {
                    min_text_length: min_plaintext_length(chars.len()),
                    chars,
                }
            }
            AlphabetPreset::Latin1SupAlphanum => {
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
            AlphabetPreset::Utf => {
                let chars = (0..=1 << 16_u32)
                    .filter_map(char::from_u32)
                    .collect::<Vec<char>>();
                Self {
                    min_text_length: min_plaintext_length(chars.len()),
                    chars,
                }
            }
            AlphabetPreset::AsciiPrintable => {
                // 0x20 (space) through 0x7E (tilde) — 95 printable ASCII characters
                build_from_chars(
                    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                )
            }
            AlphabetPreset::Base64 => {
                // RFC 4648 alphabet without the padding character '='
                // '=' carries no entropy and is preserved verbatim via rebase/debase
                build_from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            }
        }
    }
}

impl Alphabet {
    // Thin wrappers over `From<AlphabetPreset>` kept for backward compatibility.

    #[must_use]
    pub fn numeric() -> Self {
        Self::from(AlphabetPreset::Numeric)
    }
    #[must_use]
    pub fn hexadecimal() -> Self {
        Self::from(AlphabetPreset::Hexadecimal)
    }
    #[must_use]
    pub fn alpha_lower() -> Self {
        Self::from(AlphabetPreset::AlphaLower)
    }
    #[must_use]
    pub fn alpha_upper() -> Self {
        Self::from(AlphabetPreset::AlphaUpper)
    }
    #[must_use]
    pub fn alpha() -> Self {
        Self::from(AlphabetPreset::Alpha)
    }
    #[must_use]
    pub fn alpha_numeric() -> Self {
        Self::from(AlphabetPreset::AlphaNumeric)
    }
    #[must_use]
    pub fn chinese() -> Self {
        Self::from(AlphabetPreset::Chinese)
    }
    #[must_use]
    pub fn latin1sup() -> Self {
        Self::from(AlphabetPreset::Latin1Sup)
    }
    #[must_use]
    pub fn latin1sup_alphanum() -> Self {
        Self::from(AlphabetPreset::Latin1SupAlphanum)
    }
    #[must_use]
    pub fn utf() -> Self {
        Self::from(AlphabetPreset::Utf)
    }
    #[must_use]
    pub fn ascii_printable() -> Self {
        Self::from(AlphabetPreset::AsciiPrintable)
    }
    #[must_use]
    pub fn base64() -> Self {
        Self::from(AlphabetPreset::Base64)
    }
}

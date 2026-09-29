use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{Alphabet, FPEError, Float, Integer, KEY_LENGTH};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FpeDataType {
    #[default]
    Text,
    Integer,
    Float,
}

#[derive(Debug, Default, Deserialize)]
struct FpeMetadata {
    #[serde(default, rename = "type")]
    data_type: FpeDataType,
    #[serde(default)]
    alphabet: Option<String>,
}

/// Maximum byte length of `authenticated_encryption_additional_data` accepted for JSON parsing.
/// Prevents memory/CPU exhaustion from oversized payloads sent by authenticated clients.
const MAX_ADDITIONAL_DATA_LEN: usize = 4096;

impl FpeMetadata {
    fn parse(additional_data: Option<&[u8]>) -> Result<Self, FPEError> {
        let Some(additional_data) = additional_data else {
            return Ok(Self {
                data_type: FpeDataType::Text,
                alphabet: Some("alpha_numeric".to_owned()),
            });
        };
        if additional_data.is_empty() {
            return Ok(Self {
                data_type: FpeDataType::Text,
                alphabet: Some("alpha_numeric".to_owned()),
            });
        }
        if additional_data.len() > MAX_ADDITIONAL_DATA_LEN {
            return Err(FPEError::ConversionError(format!(
                "additional_data exceeds maximum allowed length of {MAX_ADDITIONAL_DATA_LEN} bytes"
            )));
        }

        let as_text = std::str::from_utf8(additional_data).map_err(|e| {
            FPEError::ConversionError(format!(
                "failed decoding additional authenticated data as UTF-8: {e}"
            ))
        })?;
        let trimmed = as_text.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                data_type: FpeDataType::Text,
                alphabet: Some("alpha_numeric".to_owned()),
            });
        }
        if trimmed.starts_with('{') {
            let mut metadata: Self = serde_json::from_str(trimmed).map_err(|e| {
                FPEError::ConversionError(format!("failed parsing FPE metadata JSON: {e}"))
            })?;
            if matches!(metadata.data_type, FpeDataType::Text) && metadata.alphabet.is_none() {
                metadata.alphabet = Some("alpha_numeric".to_owned());
            }
            return Ok(metadata);
        }

        Ok(Self {
            data_type: FpeDataType::Text,
            alphabet: Some(trimmed.to_owned()),
        })
    }
}

fn key_to_array(key: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, FPEError> {
    if key.len() != KEY_LENGTH {
        return Err(FPEError::KeySize(key.len(), KEY_LENGTH));
    }
    let mut key_array = [0_u8; KEY_LENGTH];
    key_array.copy_from_slice(key);
    Ok(Zeroizing::new(key_array))
}

fn parse_utf8<'a>(data: &'a [u8], field: &str) -> Result<&'a str, FPEError> {
    std::str::from_utf8(data)
        .map_err(|e| FPEError::ConversionError(format!("failed decoding {field} as UTF-8: {e}")))
}

fn resolve_text_alphabet(metadata: &FpeMetadata) -> Result<Alphabet, FPEError> {
    Alphabet::from_preset_or_custom(metadata.alphabet.as_deref().unwrap_or("alpha_numeric"))
}

fn resolve_integer_alphabet(metadata: &FpeMetadata) -> Result<Alphabet, FPEError> {
    let alphabet_name = metadata.alphabet.as_deref().ok_or_else(|| {
        FPEError::AlphabetError("integer FPE requires an alphabet or radix hint".to_owned())
    })?;
    let alphabet = Alphabet::from_preset_or_custom(alphabet_name)?;
    if !(2..=16).contains(&alphabet.alphabet_len()) {
        return Err(FPEError::AlphabetError(format!(
            "integer FPE requires an alphabet with radix between 2 and 16, got {}",
            alphabet.alphabet_len()
        )));
    }
    Ok(alphabet)
}

fn integer_text_to_biguint(text: &str, alphabet: &Alphabet) -> Result<BigUint, FPEError> {
    if text.is_empty() {
        return Err(FPEError::OutOfBounds(
            "integer FPE input must not be empty".to_owned(),
        ));
    }

    let radix = u32::try_from(alphabet.alphabet_len())
        .map_err(|e| FPEError::ConversionError(e.to_string()))?;
    let mut value = BigUint::zero();
    for ch in text.chars() {
        let digit = alphabet.char_to_position(ch).ok_or_else(|| {
            FPEError::AlphabetError(format!(
                "character {ch:?} is not part of the integer alphabet"
            ))
        })?;
        value *= radix;
        value += BigUint::from(digit);
    }
    Ok(value)
}

fn biguint_to_integer_text(
    value: &BigUint,
    alphabet: &Alphabet,
    digits: usize,
) -> Result<String, FPEError> {
    if digits == 0 {
        return Err(FPEError::OutOfBounds(
            "integer FPE output must contain at least one digit".to_owned(),
        ));
    }

    let radix = u32::try_from(alphabet.alphabet_len())
        .map_err(|e| FPEError::ConversionError(e.to_string()))?;
    let radix_big = BigUint::from(radix);
    let mut remainder = value.clone();
    let mut encoded = Vec::with_capacity(digits);

    for _ in 0..digits {
        let digit = (&remainder % &radix_big).to_u16().ok_or_else(|| {
            FPEError::ConversionError(
                "failed converting encrypted integer digit to alphabet index".to_owned(),
            )
        })?;
        let ch = alphabet.char_from_position(digit).ok_or_else(|| {
            FPEError::OutOfBounds(format!(
                "digit position {digit} is outside the integer alphabet"
            ))
        })?;
        encoded.push(ch);
        remainder /= &radix_big;
    }

    if !remainder.is_zero() {
        return Err(FPEError::OutOfBounds(
            "encrypted integer no longer fits in the configured digit count".to_owned(),
        ));
    }

    encoded.reverse();
    Ok(encoded.into_iter().collect())
}

pub fn encrypt_fpe(
    key: &[u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    tweak: Option<&[u8]>,
) -> Result<Vec<u8>, FPEError> {
    let key = key_to_array(key)?;
    let metadata = FpeMetadata::parse(additional_data)?;
    let tweak = tweak.unwrap_or_default();

    match metadata.data_type {
        FpeDataType::Text => {
            let alphabet = resolve_text_alphabet(&metadata)?;
            let plaintext = parse_utf8(data, "FPE plaintext")?;
            Ok(alphabet.encrypt(&*key, tweak, plaintext)?.into_bytes())
        }
        FpeDataType::Integer => {
            let alphabet = resolve_integer_alphabet(&metadata)?;
            let plaintext = parse_utf8(data, "FPE integer plaintext")?;
            let digits = plaintext.chars().count();
            let radix = u32::try_from(alphabet.alphabet_len())
                .map_err(|e| FPEError::ConversionError(e.to_string()))?;
            let integer = Integer::instantiate(radix, digits)?;
            let plaintext_value = integer_text_to_biguint(plaintext, &alphabet)?;
            let ciphertext_value = integer.encrypt_big(&key, tweak, &plaintext_value)?;
            Ok(biguint_to_integer_text(&ciphertext_value, &alphabet, digits)?.into_bytes())
        }
        FpeDataType::Float => {
            let plaintext = parse_utf8(data, "FPE float plaintext")?;
            let float_value = plaintext.parse::<f64>().map_err(|e| {
                FPEError::ConversionError(format!("failed parsing FPE float plaintext: {e}"))
            })?;
            let float = Float::instantiate()?;
            // Encode as 16 lowercase hex digits (the raw IEEE-754 bit pattern) to
            // preserve all bit patterns — including NaN and ±Inf payloads — without
            // floating-point canonicalization on the decrypt path.
            let ciphertext_bits = float.encrypt(&key, tweak, float_value)?.to_bits();
            Ok(format!("{ciphertext_bits:016x}").into_bytes())
        }
    }
}

pub fn decrypt_fpe(
    key: &[u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    tweak: Option<&[u8]>,
) -> Result<Vec<u8>, FPEError> {
    let key = key_to_array(key)?;
    let metadata = FpeMetadata::parse(additional_data)?;
    let tweak = tweak.unwrap_or_default();

    match metadata.data_type {
        FpeDataType::Text => {
            let alphabet = resolve_text_alphabet(&metadata)?;
            let ciphertext = parse_utf8(data, "FPE ciphertext")?;
            Ok(alphabet
                .decrypt(key.as_ref(), tweak, ciphertext)?
                .into_bytes())
        }
        FpeDataType::Integer => {
            let alphabet = resolve_integer_alphabet(&metadata)?;
            let ciphertext = parse_utf8(data, "FPE integer ciphertext")?;
            let digits = ciphertext.chars().count();
            let radix = u32::try_from(alphabet.alphabet_len())
                .map_err(|e| FPEError::ConversionError(e.to_string()))?;
            let integer = Integer::instantiate(radix, digits)?;
            let ciphertext_value = integer_text_to_biguint(ciphertext, &alphabet)?;
            let plaintext_value = integer.decrypt_big(&key, tweak, &ciphertext_value)?;
            Ok(biguint_to_integer_text(&plaintext_value, &alphabet, digits)?.into_bytes())
        }
        FpeDataType::Float => {
            let ciphertext_str = parse_utf8(data, "FPE float ciphertext")?;
            // Decode from the 16-hex-digit bit-pattern representation produced by
            // encrypt_fpe, preserving exact IEEE-754 semantics without NaN canonicalization.
            let bits = u64::from_str_radix(ciphertext_str.trim(), 16).map_err(|e| {
                FPEError::ConversionError(format!("failed decoding FPE float ciphertext: {e}"))
            })?;
            let float_value = f64::from_bits(bits);
            let float = Float::instantiate()?;
            Ok(float
                .decrypt(&key, tweak, float_value)?
                .to_string()
                .into_bytes())
        }
    }
}

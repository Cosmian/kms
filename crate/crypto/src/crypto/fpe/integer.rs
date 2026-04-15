use num_bigint::BigUint;
use num_traits::{Num, One, ToPrimitive};

use super::{Alphabet, FPEError};

pub struct Integer {
    pub(crate) radix: u32,
    pub(crate) digits: usize,
    pub(crate) max_value: BigUint,
    pub(crate) numeric_alphabet: Alphabet,
}

impl Integer {
    /// Creates a new instance of the `Integer` representation with the given
    /// `radix` and `digits`. The `max_value` is calculated as the number of
    /// `digits` raised to the power of `radix`.
    ///
    /// # Example
    ///
    /// ```
    /// use cloudproof_fpe::core::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let number = Integer::instantiate(8, 7).unwrap();
    /// assert_eq!(number.digits(), 7);
    /// assert_eq!(number.max_value(), BigUint::from(2097151_u64));
    /// ```
    ///
    /// # Arguments
    ///
    /// * `radix` - The base of the number representation. Must be between 2 and
    ///   16 inclusive.
    /// * `digits` - The number of digits in the representation.
    ///
    /// # Returns
    ///
    /// A new instance of the `Integer` representation.
    ///
    /// # Errors
    ///
    /// Returns an error if `radix` is not between 2 and 16 inclusive or if
    /// the calculation of the maximum value fails.
    pub fn instantiate(radix: u32, digits: usize) -> Result<Self, FPEError> {
        if !(2..=16).contains(&radix) {
            return Err(FPEError::AlphabetError(format!(
                "Radix must be between 2 and 16 inclusive, got {radix}"
            )));
        }

        // Derive the minimum digit count from the FF1 algorithm's own constraint,
        // keeping a single source of truth instead of a duplicated lookup table.
        let min_digits = super::ff1::radix_min_len(radix)
            .map_err(|e| FPEError::OperationFailed(e.to_string()))?;

        if digits < min_digits {
            return Err(FPEError::OutOfBounds(format!(
                "Integer of digits must be at least {min_digits}, got {digits}"
            )));
        }

        let max_value = BigUint::from(radix)
            .pow(u32::try_from(digits).map_err(|e| FPEError::ConversionError(e.to_string()))?)
            - BigUint::one();
        let alphabet = &"0123456789abcdef"
            [0..usize::try_from(radix).map_err(|e| FPEError::ConversionError(e.to_string()))?];

        Ok(Self {
            radix,
            digits,
            max_value,
            numeric_alphabet: Alphabet::try_from(alphabet)?,
        })
    }

    /// Encrypts the given `value` using the FPE method. The value must be less
    /// than or equal to the `max_value` of the `Integer` representation.
    ///
    /// # Example
    ///
    /// ```
    /// use cloudproof_fpe::core::Integer;
    ///
    /// let integer = Integer::instantiate(10, 8).unwrap();
    /// let key = [0u8; 32];
    /// let tweak = b"tweak";
    ///
    /// let encrypted = integer.encrypt(&key, tweak, 100).unwrap();
    /// assert_ne!(100, encrypted);
    ///
    /// let decrypted = integer.decrypt(&key, tweak, encrypted).unwrap();
    /// assert_eq!(100, decrypted);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `value` - The big integer number to encrypt.
    /// * `key` - The key used for encryption.
    /// * `tweak` - The tweak used for encryption.
    ///
    /// # Returns
    ///
    /// The encrypted big integer number.
    pub fn encrypt(&self, key: &[u8; 32], tweak: &[u8], value: u64) -> Result<u64, FPEError> {
        let ciphertext = self.encrypt_big(key, tweak, &BigUint::from(value))?;
        ciphertext.to_u64().ok_or_else(|| {
            FPEError::ConversionError(format!(
                "failed converting the ciphertext value: {ciphertext}, to an u64"
            ))
        })
    }

    /// Encrypts the given `value` using the FPE method. The value must be less
    /// than or equal to the `max_value` of the `Integer` representation.
    ///
    /// # Example
    ///
    /// ```
    /// use cloudproof_fpe::core::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let integer = Integer::instantiate(16, 8).unwrap();
    /// let key = [0u8; 32];
    /// let tweak = b"tweak";
    ///
    /// let encrypted = integer.encrypt_big(&key, tweak, &BigUint::from(0xa1_u64)).unwrap();
    /// assert_ne!(BigUint::from(0xa1_u64), encrypted);
    ///
    /// let decrypted = integer.decrypt_big(&key, tweak, &encrypted).unwrap();
    /// assert_eq!(BigUint::from(0xa1_u64), decrypted);
    /// ```
    ///
    /// # Arguments
    ///
    /// * `value` - The big integer number to encrypt.
    /// * `key` - The key used for encryption.
    /// * `tweak` - The tweak used for encryption.
    ///
    /// # Returns
    ///
    /// The encrypted big integer number.
    pub fn encrypt_big(
        &self,
        key: &[u8; 32],
        tweak: &[u8],
        big_value: &BigUint,
    ) -> Result<BigUint, FPEError> {
        if big_value > &self.max_value {
            return Err(FPEError::OutOfBounds(format!(
                "the value: {} must be lower or equal to {}",
                big_value, self.max_value
            )));
        }

        let digits = self.digits;
        let str_value = format!("{:0>digits$}", big_value.to_str_radix(self.radix));

        //encrypt
        let ciphertext = self.numeric_alphabet.encrypt(key, tweak, &str_value)?;
        let big_ciphertext = BigUint::from_str_radix(&ciphertext, self.radix).map_err(|e| {
            FPEError::OperationFailed(format!("failed generating the ciphertext value {e}"))
        })?;
        Ok(big_ciphertext)
    }

    /// Decrypts the ciphertext using the specified key and tweak and returns
    /// the plaintext as a `u64`.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - A `u64` representing the encrypted value.
    /// * `key` - A `[u8; 32]` representing the encryption key.
    /// * `tweak` - A slice `[u8]` representing the tweak value.
    ///
    /// # Returns
    ///
    /// Returns the plaintext as a `u64` on success, or an error if the
    /// decryption was not successful.
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    /// * If the `ciphertext` is greater than the maximum value set for the
    ///   `Integer` struct.
    /// * If the plaintext could not be generated from the `ciphertext`.
    /// * If the plaintext value could not be converted to a `u64`.
    pub fn decrypt(&self, key: &[u8; 32], tweak: &[u8], ciphertext: u64) -> Result<u64, FPEError> {
        let plaintext = self.decrypt_big(key, tweak, &BigUint::from(ciphertext))?;
        plaintext.to_u64().ok_or_else(|| {
            FPEError::ConversionError(format!(
                "failed converting the plaintext value: {plaintext}, to an u64"
            ))
        })
    }

    /// Decrypts the ciphertext using the specified key and tweak and returns
    /// the plaintext as a `BigUint`.
    ///
    /// # Parameters
    ///
    /// - `ciphertext`: A `BigUint` representing the encrypted value.
    /// - `key`: A `&[u8; 32]` representing the encryption key.
    /// - `tweak`: A `&[u8]` representing the tweak value.
    ///
    /// # Returns
    ///
    /// Returns the plaintext as a `BigUint` on success, or an error if the
    /// decryption was not successful.
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    ///
    /// - If the ciphertext is greater than the maximum value set for the
    ///   `Integer` struct.
    /// - If the plaintext could not be generated from the ciphertext.
    /// - If the plaintext value could not be converted to a `BigUint`.
    ///
    /// # Example
    ///
    /// ```
    /// use cloudproof_fpe::core::Integer;
    /// use num_bigint::BigUint;
    ///
    /// let key = [0; 32];
    /// let tweak = [0];
    /// let number_radix = Integer::instantiate(10, 8).unwrap();
    /// let ciphertext = number_radix.encrypt_big(&key, &tweak, &BigUint::from(123456_u64)).unwrap();
    /// let plaintext = number_radix.decrypt_big(&key, &tweak, &ciphertext).unwrap();
    ///
    /// assert_eq!(BigUint::from(123456_u64), plaintext);
    /// ```
    pub fn decrypt_big(
        &self,
        key: &[u8; 32],
        tweak: &[u8],
        big_ciphertext: &BigUint,
    ) -> Result<BigUint, FPEError> {
        if big_ciphertext > &self.max_value {
            return Err(FPEError::OutOfBounds(format!(
                "the ciphertext value: {} must be lower or equal to {}",
                big_ciphertext, self.max_value
            )));
        }

        let digits = self.digits;
        let str_value = format!("{:0>digits$}", big_ciphertext.to_str_radix(self.radix));
        let plaintext = self.numeric_alphabet.decrypt(key, tweak, &str_value)?;

        BigUint::from_str_radix(&plaintext, self.radix).map_err(|e| {
            FPEError::OperationFailed(format!("failed generating the plaintext value {e}"))
        })
    }

    /// The maximum value supported by this Integer
    #[must_use]
    pub fn max_value(&self) -> BigUint {
        self.max_value.clone()
    }

    /// The number of digits of the max value
    /// that is the same as the `radix^digits - 1`
    #[must_use]
    pub const fn digits(&self) -> usize {
        self.digits
    }
}

//! Generic redacting wrapper for secret values.
//!
//! `Debug` and `Display` of a [`Sensitive`] never print the content, only its size, so a secret
//! cannot leak through a derived `Debug`/`Display` of a containing struct.

use std::{
    fmt::{self, Debug, Display, Formatter},
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// A value whose size can be shown but whose content must never be printed.
pub trait SensitiveSize {
    /// Human readable size, e.g. `<12 bytes>`.
    fn sensitive_size(&self) -> String;
}

impl SensitiveSize for Vec<u8> {
    fn sensitive_size(&self) -> String {
        format!("<{} bytes>", self.len())
    }
}

impl SensitiveSize for String {
    fn sensitive_size(&self) -> String {
        format!("<{} bytes>", self.len())
    }
}

/// Secret value: zeroized on drop; `Debug` and `Display` print only its size.
/// Wire format is identical to the wrapped `T` (`#[serde(transparent)]`).
///
/// Use [`SensitiveBytes`] / [`SensitiveString`] for the common cases, or any
/// `T: Zeroize + SensitiveSize` for other secret structs.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sensitive<T: Zeroize>(Zeroizing<T>);

/// Secret bytes (keys, IVs, passwords, PINs, plaintext).
pub type SensitiveBytes = Sensitive<Vec<u8>>;
/// Secret string (passwords).
pub type SensitiveString = Sensitive<String>;

impl<T: Zeroize> Sensitive<T> {
    /// Wraps a secret.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Moves the secret out as a plain `Zeroizing`, without copying.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<T> {
        self.0
    }
}

impl<T: Zeroize + Clone> Sensitive<T> {
    /// Copy of the secret in a plain `Zeroizing` for APIs that expect it.
    #[must_use]
    pub fn to_zeroizing(&self) -> Zeroizing<T> {
        self.0.clone()
    }
}

impl<T: Zeroize + SensitiveSize> Debug for Sensitive<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.sensitive_size())
    }
}

impl<T: Zeroize + SensitiveSize> Display for Sensitive<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.sensitive_size())
    }
}

impl<T: Zeroize> Deref for Sensitive<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Sensitive<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Constant-time comparison (length is not secret); XOR-folds every byte.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && std::hint::black_box(a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

impl<T: Zeroize + AsRef<[u8]>> PartialEq for Sensitive<T> {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Sensitive<T> {}

/// Constant-time comparison with the plain value.
impl<T: Zeroize + AsRef<[u8]>> PartialEq<T> for Sensitive<T> {
    fn eq(&self, other: &T) -> bool {
        ct_eq(self.0.as_ref(), other.as_ref())
    }
}

impl<T: Zeroize> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> From<Zeroizing<T>> for Sensitive<T> {
    fn from(value: Zeroizing<T>) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> From<Sensitive<T>> for Zeroizing<T> {
    fn from(value: Sensitive<T>) -> Self {
        value.0
    }
}

impl From<&[u8]> for SensitiveBytes {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

impl From<&str> for SensitiveString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_print_only_the_size() {
        let marker = b"SECRET-MARKER";
        let b = SensitiveBytes::from(marker.to_vec());
        let s = SensitiveString::from("SECRET-MARKER");
        let list = format!("{:?}", marker.to_vec());
        for out in [
            format!("{b:?}"),
            format!("{b}"),
            format!("{s:?}"),
            format!("{s}"),
        ] {
            assert!(!out.contains("SECRET-MARKER"));
            assert!(!out.contains(&list[1..list.len() - 1]));
            assert!(!out.contains("U0VDUkVULU1BUktFUg"));
            assert_eq!(out, "<13 bytes>");
        }
    }

    #[test]
    fn equality_handles_equal_unequal_and_different_lengths() {
        let a = SensitiveBytes::from(vec![1, 2, 3]);
        assert_eq!(a, SensitiveBytes::from(vec![1, 2, 3]));
        assert_ne!(a, SensitiveBytes::from(vec![1, 2, 4]));
        assert_ne!(a, SensitiveBytes::from(vec![1, 2]));
        assert_eq!(a, vec![1_u8, 2, 3]);
    }

    #[test]
    fn serde_is_transparent() {
        let b = SensitiveBytes::from(vec![1, 2, 3]);
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, serde_json::to_string(&vec![1_u8, 2, 3]).unwrap());
        assert_eq!(serde_json::from_str::<SensitiveBytes>(&json).unwrap(), b);
    }
}

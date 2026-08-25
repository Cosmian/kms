//! Copyright 2026 Cosmian Tech SAS
//!
//! A typed wrapper for user/owner identity strings that prevents accidental
//! mixing of user IDs with object UIDs in function signatures.

use std::{
    fmt::{self, Display, Formatter},
    ops::Deref,
};

use serde::{Deserialize, Serialize};

/// A typed user/owner identity (typically an e-mail address or certificate CN).
///
/// Wraps a `String` so that user identity strings are distinct from object UIDs
/// at the type level, preventing parameter transposition and making function
/// signatures self-documenting.
///
/// `UserId` implements `Deref<Target = str>` so a `&UserId` coerces to `&str`
/// automatically wherever a plain string slice is required (e.g. SQL query
/// parameters, tracing spans), keeping call-site boilerplate minimal.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserId(String);

impl UserId {
    /// Try to wrap a string as a `UserId`, rejecting empty strings.
    ///
    /// Use this whenever the string originates from user input or any
    /// untrusted source. For string literals in tests, `UserId::from("…")`
    /// is sufficient — the `From` impl checks for emptiness in debug builds.
    ///
    /// # Errors
    /// Returns an error if the string is empty.
    pub fn try_new(s: impl Into<String>) -> Result<Self, String> {
        let s = s.into();
        if s.is_empty() {
            return Err("UserId must not be empty".to_owned());
        }
        Ok(Self(s))
    }

    /// Return a borrowed `&str` view of the user ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the inner `String`.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Deref for UserId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        debug_assert!(!s.is_empty(), "UserId must not be empty");
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        debug_assert!(!s.is_empty(), "UserId must not be empty");
        Self(s.to_owned())
    }
}

impl From<UserId> for String {
    fn from(u: UserId) -> Self {
        u.0
    }
}

// Cross-type comparisons so that `&UserId == &str` and `&str == &UserId` work
// without boilerplate at call sites.  Rust's blanket impl
// `impl<A, B> PartialEq<&B> for &A where A: PartialEq<B>` derives
// `PartialEq<&str> for &UserId` from `PartialEq<str> for UserId`.

impl PartialEq<str> for UserId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<UserId> for str {
    fn eq(&self, other: &UserId) -> bool {
        self == other.0.as_str()
    }
}

impl PartialEq<String> for UserId {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl PartialEq<UserId> for String {
    fn eq(&self, other: &UserId) -> bool {
        self.as_str() == other.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref_coerces_to_str() {
        let uid = UserId::from("alice@example.com");
        let s: &str = &uid;
        assert_eq!(s, "alice@example.com");
    }

    #[test]
    fn round_trip_string() {
        let uid = UserId::from("bob@example.com");
        assert_eq!(uid.as_str(), "bob@example.com");
        assert_eq!(String::from(uid), "bob@example.com");
    }

    #[test]
    fn equality_and_hash() {
        use std::collections::HashSet;
        let a = UserId::from("a@b.com");
        let b = UserId::from("a@b.com");
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }
}

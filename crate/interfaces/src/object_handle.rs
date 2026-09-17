//! Copyright 2026 Cosmian Tech SAS
//!
//! [`ObjectHandle`] — a parsed representation of a KMIP object identifier, shared by the
//! KMS server and its object stores so that identifier classification (tags, HSM prefixes,
//! plain UIDs) lives in a single place accessible across crate boundaries.

use cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;

use crate::error::{InterfaceError, InterfaceResult};

/// A parsed representation of a KMIP object identifier.
///
/// Eliminates ad-hoc string dispatch (`starts_with('[')`, `starts_with("hsm::")`)
/// by centralising all identifier classification in one place.
///
/// Use `ObjectHandle::from(&str)` (or `.into()`) to convert a raw `&str` into a typed variant.
/// The variant then drives `match` exhaustiveness — the compiler catches missing branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectHandle<'a> {
    /// A JSON tag-array literal: `["tag1", "tag2"]`.
    Tags(&'a str),
    /// An HSM-managed key with its routing `prefix` (e.g. `"hsm"` or `"hsm::softhsm2"`)
    /// and the full original `uid` string.
    Hsm {
        /// The routing prefix used to select the HSM object store.
        prefix: &'a str,
        /// The full original UID string.
        uid: &'a str,
    },
    /// A plain object identifier (UUID, user-chosen name, or keyset reference).
    Uid(&'a str),
}

impl<'a> ObjectHandle<'a> {
    /// Returns `true` if this handle refers to an HSM-managed key.
    #[must_use]
    pub const fn is_hsm(self) -> bool {
        matches!(self, Self::Hsm { .. })
    }

    /// Returns the HSM routing prefix if this handle refers to an HSM-managed key.
    #[must_use]
    pub const fn hsm_prefix(self) -> Option<&'a str> {
        if let Self::Hsm { prefix, .. } = self {
            Some(prefix)
        } else {
            None
        }
    }

    /// Returns the raw identifier string regardless of variant.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        match self {
            Self::Tags(s) | Self::Uid(s) => s,
            Self::Hsm { uid, .. } => uid,
        }
    }

    /// Parse the components of an HSM key UID (`{prefix}::{slot}::{base_id}[@N]`).
    ///
    /// This is the single source of truth for HSM UID parsing; callers that need the
    /// slot id, base id, or generation should go through here instead of re-implementing
    /// the `strip_prefix` / `split_once` / `rsplit_once('@')` dance.
    ///
    /// # Errors
    /// - [`InterfaceError::InvalidRequest`] — if this handle is not an HSM UID or is malformed.
    pub fn hsm_parts(self) -> InterfaceResult<HsmUidParts> {
        let uid = self.as_str();
        let prefix = self
            .hsm_prefix()
            .ok_or_else(|| {
                InterfaceError::InvalidRequest(format!("UID '{uid}' is not an HSM UID"))
            })?
            .to_owned();
        let rest = uid.strip_prefix(&format!("{prefix}::")).ok_or_else(|| {
            InterfaceError::InvalidRequest("HSM UID has unexpected format".to_owned())
        })?;
        let (slot_str, key_id) = rest.split_once("::").ok_or_else(|| {
            InterfaceError::InvalidRequest(format!(
                "HSM UID '{uid}' must have format '{prefix}::<slot>::<key_id>'"
            ))
        })?;
        let slot_id: usize = slot_str.parse().map_err(|e| {
            InterfaceError::InvalidRequest(format!("HSM slot_id '{slot_str}' is not valid: {e}"))
        })?;
        let (base_id, generation, has_explicit_gen) = key_id
            .rsplit_once('@')
            .and_then(|(base, suffix)| suffix.parse::<i32>().ok().map(|n| (base, n, true)))
            .unwrap_or((key_id, 0, false));
        Ok(HsmUidParts {
            prefix,
            slot_id,
            base_id: base_id.to_owned(),
            generation,
            has_explicit_gen,
        })
    }
}

impl<'a> From<&'a str> for ObjectHandle<'a> {
    /// Classify a raw identifier string into an `ObjectHandle` (infallible).
    ///
    /// Classification rules (in order):
    /// 1. Starts with `[` → [`ObjectHandle::Tags`]
    /// 2. Matches the HSM UID format (`hsm::` prefix with a second `::` separator) → [`ObjectHandle::Hsm`]
    /// 3. Anything else → [`ObjectHandle::Uid`]
    ///
    /// HSM UID formats supported:
    /// - Old: `hsm::<slot_id>::<key_id>` → `prefix = "hsm"`
    /// - New: `hsm::<model>::<slot_id>::<key_id>` → `prefix = "hsm::<model>"`
    ///
    /// Unrecognized or malformed identifiers fall through to [`ObjectHandle::Uid`].
    fn from(s: &'a str) -> Self {
        if s.starts_with('[') {
            return Self::Tags(s);
        }
        if let Some(rest) = s.strip_prefix("hsm::") {
            if let Some(pos) = rest.find("::") {
                let first_segment = &rest[..pos];
                let prefix = if first_segment.parse::<usize>().is_ok() {
                    "hsm" // Old format: hsm::<slot_id>::<key_id>
                } else {
                    &s[..5 + pos] // New format: hsm::<model>::... → prefix = "hsm::<model>"
                };
                return Self::Hsm { prefix, uid: s };
            }
        }
        Self::Uid(s)
    }
}

/// Delegates to [`ObjectHandle::from`] so `&String` identifiers convert ergonomically.
impl<'a> From<&'a String> for ObjectHandle<'a> {
    fn from(s: &'a String) -> Self {
        Self::from(s.as_str())
    }
}

impl<'a> TryFrom<&'a UniqueIdentifier> for ObjectHandle<'a> {
    type Error = InterfaceError;

    /// Classify a `UniqueIdentifier` request field into an `ObjectHandle`.
    ///
    /// # Errors
    /// - [`InterfaceError::InvalidRequest`] — if the identifier is not a `TextString`.
    fn try_from(uid: &'a UniqueIdentifier) -> Result<Self, Self::Error> {
        let s = uid.as_str().ok_or_else(|| {
            InterfaceError::InvalidRequest("the unique identifier must be a string".to_owned())
        })?;
        Ok(Self::from(s))
    }
}

impl std::fmt::Display for ObjectHandle<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Components extracted from an HSM key UID (`{prefix}::{slot}::{base_id}[@N]`).
///
/// Produced by [`ObjectHandle::hsm_parts`] — the single source of truth for HSM UID parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsmUidParts {
    /// The routing prefix (e.g. `"hsm"` or `"hsm::softhsm2"`).
    pub prefix: String,
    /// The PKCS#11 slot id.
    pub slot_id: usize,
    /// The base key id, with any `@N` generation suffix stripped.
    pub base_id: String,
    /// The generation number (`0` when no explicit `@N` suffix is present).
    pub generation: i32,
    /// `true` when the original UID carried an explicit `@N` generation suffix.
    pub has_explicit_gen: bool,
}

impl HsmUidParts {
    /// Returns the stable base UID (`{prefix}::{slot}::{base_id}`, no generation suffix).
    ///
    /// This is the canonical `rotate_name` for HSM-resident keys.
    #[must_use]
    pub fn full_base_uid(&self) -> String {
        format!("{}::{}::{}", self.prefix, self.slot_id, self.base_id)
    }

    /// Returns the key id segment, re-appending the `@N` generation suffix when the
    /// original UID carried one.
    #[must_use]
    pub fn key_id(&self) -> String {
        if self.has_explicit_gen {
            format!("{}@{}", self.base_id, self.generation)
        } else {
            self.base_id.clone()
        }
    }
}

#[cfg(test)]
// Test-only: `expect()` and `assert!` on result states are idiomatic in unit tests.
#[allow(clippy::expect_used, clippy::assertions_on_result_states)]
mod handle_tests {
    use super::*;

    #[test]
    fn test_parse_tags() {
        let h = ObjectHandle::from("[\"tag1\", \"tag2\"]");
        assert!(matches!(h, ObjectHandle::Tags(_)));
        assert!(!h.is_hsm());
        assert!(h.hsm_prefix().is_none());
    }

    #[test]
    fn test_parse_hsm_old_format() {
        // hsm::<slot_id>::<key_id> → prefix == "hsm"
        let h = ObjectHandle::from("hsm::0::my-key");
        assert_eq!(h.hsm_prefix(), Some("hsm"));
        assert!(h.is_hsm());
    }

    #[test]
    fn test_parse_hsm_new_format() {
        // hsm::<model>::<slot_id>::<key_id> → prefix == "hsm::<model>"
        let h = ObjectHandle::from("hsm::softhsm2::0::my-key");
        assert_eq!(h.hsm_prefix(), Some("hsm::softhsm2"));
        assert!(h.is_hsm());
    }

    #[test]
    fn test_parse_hsm_preserves_uid() {
        let uid = "hsm::softhsm2::0::my-key";
        let h = ObjectHandle::from(uid);
        assert!(
            matches!(h, ObjectHandle::Hsm { .. }),
            "expected ObjectHandle::Hsm"
        );
        if let ObjectHandle::Hsm { uid: stored, .. } = h {
            assert_eq!(stored, uid);
        }
    }

    #[test]
    fn test_parse_plain_uuid() {
        let h = ObjectHandle::from("550e8400-e29b-41d4-a716-446655440000");
        assert!(!h.is_hsm());
        assert!(matches!(h, ObjectHandle::Uid(_)));
    }

    #[test]
    fn test_parse_user_named_uid() {
        let h = ObjectHandle::from("my-production-key");
        assert!(!h.is_hsm());
        assert!(matches!(h, ObjectHandle::Uid(_)));
    }

    #[test]
    fn test_parse_hsm_without_second_separator_is_uid() {
        // "hsm::incomplete" (no second ::) → treated as plain UID, not an HSM key
        let h = ObjectHandle::from("hsm::incomplete");
        assert!(!h.is_hsm());
        assert!(matches!(h, ObjectHandle::Uid(_)));
    }

    #[test]
    fn test_hsm_parts_new_format() {
        let parts = ObjectHandle::from("hsm::softhsm2::0::my-key")
            .hsm_parts()
            .expect("should parse HSM parts");
        assert_eq!(parts.prefix, "hsm::softhsm2");
        assert_eq!(parts.slot_id, 0);
        assert_eq!(parts.base_id, "my-key");
        assert_eq!(parts.generation, 0);
        assert!(!parts.has_explicit_gen);
        assert_eq!(parts.full_base_uid(), "hsm::softhsm2::0::my-key");
        assert_eq!(parts.key_id(), "my-key");
    }

    #[test]
    fn test_hsm_parts_with_generation() {
        let parts = ObjectHandle::from("hsm::softhsm2::0::my-key@3")
            .hsm_parts()
            .expect("should parse HSM parts");
        assert_eq!(parts.base_id, "my-key");
        assert_eq!(parts.generation, 3);
        assert!(parts.has_explicit_gen);
        assert_eq!(parts.key_id(), "my-key@3");
        assert_eq!(parts.full_base_uid(), "hsm::softhsm2::0::my-key");
    }

    #[test]
    fn test_hsm_parts_rejects_non_hsm() {
        assert!(ObjectHandle::from("my-production-key").hsm_parts().is_err());
    }
}

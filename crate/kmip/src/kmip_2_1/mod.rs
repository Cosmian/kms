use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use strum::{EnumCount, FromRepr};

pub mod extra;
pub mod kmip_attributes;
pub mod kmip_data_structures;
pub mod kmip_messages;
pub mod kmip_objects;
pub mod kmip_operations;
pub mod kmip_types;
pub mod requests;

/// Operation types that can get or create objects
/// These operations use `retrieve` or `get` methods.
#[derive(
    Eq, PartialEq, Serialize, Deserialize, Copy, Clone, Hash, PartialOrd, Ord, FromRepr, EnumCount,
)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum KmipOperation {
    Create = 0,
    Certify = 1,
    Decrypt = 2,
    DeriveKey = 3,
    Destroy = 4,
    Encrypt = 5,
    Export = 6,
    Get = 7,
    GetAttributes = 8,
    Hash = 9,
    Import = 10,
    Locate = 11,
    MAC = 12,
    Revoke = 13,
    Rekey = 14,
    Sign = 15,
    SignatureVerify = 16,
    Validate = 17,
    SetAttribute = 18,
    ModifyAttribute = 19,
    AddAttribute = 20,
    DeleteAttribute = 21,
    Activate = 22,
    // This enum gets serialized, so new variants must be added at the end
    // If it's imperative to change their order, consider a migration for Redis's DB
}

impl From<KmipOperation> for u8 {
    #[allow(clippy::as_conversions)] // the discriminants are defined as u8
    fn from(op: KmipOperation) -> Self {
        op as Self
    }
}

impl fmt::Debug for KmipOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for KmipOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            Self::Create => "create",
            Self::Certify => "certify",
            Self::Decrypt => "decrypt",
            Self::DeriveKey => "derive_key",
            Self::Destroy => "destroy",
            Self::Encrypt => "encrypt",
            Self::Export => "export",
            Self::Get => "get",
            Self::GetAttributes => "get_attributes",
            Self::Hash => "hash",
            Self::Import => "import",
            Self::Locate => "locate",
            Self::MAC => "mac",
            Self::Revoke => "revoke",
            Self::Rekey => "rekey",
            Self::Sign => "sign",
            Self::SignatureVerify => "signature_verify",
            Self::Validate => "validate",
            Self::SetAttribute => "set_attribute",
            Self::ModifyAttribute => "modify_attribute",
            Self::AddAttribute => "add_attribute",
            Self::DeleteAttribute => "delete_attribute",
            Self::Activate => "activate",
        };
        write!(f, "{str}")
    }
}

// any error type implementing Display is acceptable.
type ParseError = &'static str;

impl FromStr for KmipOperation {
    type Err = ParseError;

    fn from_str(op: &str) -> Result<Self, Self::Err> {
        match op {
            "create" => Ok(Self::Create),
            "certify" => Ok(Self::Certify),
            "decrypt" => Ok(Self::Decrypt),
            "derive_key" => Ok(Self::DeriveKey),
            "destroy" => Ok(Self::Destroy),
            "encrypt" => Ok(Self::Encrypt),
            "get_attributes" => Ok(Self::GetAttributes),
            "export" => Ok(Self::Export),
            "get" => Ok(Self::Get),
            "hash" => Ok(Self::Hash),
            "import" => Ok(Self::Import),
            "locate" => Ok(Self::Locate),
            "mac" => Ok(Self::MAC),
            "rekey" => Ok(Self::Rekey),
            "revoke" => Ok(Self::Revoke),
            "sign" => Ok(Self::Sign),
            "signature_verify" => Ok(Self::SignatureVerify),
            "validate" => Ok(Self::Validate),
            "set_attribute" => Ok(Self::SetAttribute),
            "modify_attribute" => Ok(Self::ModifyAttribute),
            "add_attribute" => Ok(Self::AddAttribute),
            "delete_attribute" => Ok(Self::DeleteAttribute),
            "activate" => Ok(Self::Activate),
            _ => Err("Could not parse an operation"),
        }
    }
}

impl KmipOperation {
    /// Map a TTLV operation tag name (`PascalCase`, as it appears on the wire) to the
    /// corresponding [`KmipOperation`] variant used for role-based access control.
    ///
    /// Returns `None` for operations that exist in TTLV dispatch but have no
    /// `KmipOperation` variant — specifically `CreateKeyPair`, `Register`,
    /// `ReKeyKeyPair`, `CreateSplitKey`, and `JoinSplitKey`. Those are handled by
    /// [`KmipOperation::is_restricted_lifecycle_tag`] and
    /// [`KmipOperation::is_ceremony_prerequisite_tag`].
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "Activate" => Some(Self::Activate),
            "AddAttribute" => Some(Self::AddAttribute),
            "Certify" => Some(Self::Certify),
            "Create" => Some(Self::Create),
            "Decrypt" => Some(Self::Decrypt),
            "DeleteAttribute" => Some(Self::DeleteAttribute),
            "DeriveKey" => Some(Self::DeriveKey),
            "Destroy" => Some(Self::Destroy),
            "Encrypt" => Some(Self::Encrypt),
            "Export" => Some(Self::Export),
            "Get" => Some(Self::Get),
            "GetAttributes" => Some(Self::GetAttributes),
            "Hash" => Some(Self::Hash),
            "Import" => Some(Self::Import),
            "Locate" => Some(Self::Locate),
            "Mac" | "MAC" => Some(Self::MAC),
            "ModifyAttribute" => Some(Self::ModifyAttribute),
            "ReKey" => Some(Self::Rekey),
            "Revoke" => Some(Self::Revoke),
            "SetAttribute" => Some(Self::SetAttribute),
            "Sign" => Some(Self::Sign),
            "SignatureVerify" => Some(Self::SignatureVerify),
            "Validate" => Some(Self::Validate),
            _ => None,
        }
    }

    /// Returns `true` if `tag` is a lifecycle operation that:
    ///
    /// - Has no [`KmipOperation`] variant (and therefore returns `None` from
    ///   [`KmipOperation::from_tag`])
    /// - Creates or replaces Managed Objects
    /// - Must be restricted to `CryptoOfficer` (or an explicit `Create` grant)
    ///
    /// Covers `CreateKeyPair`, `Register`, `ReKeyKeyPair`, and `CreateSplitKey`.
    ///
    /// `JoinSplitKey` is **intentionally excluded** — CO *candidates* need it to
    /// complete the split-key ceremony before holding an active Crypto Officer role.
    #[must_use]
    pub fn is_restricted_lifecycle_tag(tag: &str) -> bool {
        matches!(
            tag,
            "CreateKeyPair" | "Register" | "ReKeyKeyPair" | "CreateSplitKey"
        )
    }

    /// Returns `true` if `tag` is a ceremony-prerequisite operation that Crypto Officer
    /// *candidates* (users in `crypto_officer_users` with `require_ceremony = true`) must
    /// be allowed to call before holding an active Crypto Officer role.
    ///
    /// Covers `Create`, `Import`, `CreateSplitKey`, and `JoinSplitKey`:
    /// candidates need `Create`/`Import` to create the master key and `CreateSplitKey`/
    /// `JoinSplitKey` to split it and complete the ceremony.
    #[must_use]
    pub fn is_ceremony_prerequisite_tag(tag: &str) -> bool {
        matches!(tag, "Create" | "Import" | "CreateSplitKey" | "JoinSplitKey")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── from_tag ────────────────────────────────────────────────────────────

    #[test]
    fn from_tag_maps_every_kmip_operation_variant() {
        // Every KmipOperation variant must be reachable from its TTLV tag name.
        assert_eq!(
            KmipOperation::from_tag("Activate"),
            Some(KmipOperation::Activate)
        );
        assert_eq!(
            KmipOperation::from_tag("AddAttribute"),
            Some(KmipOperation::AddAttribute)
        );
        assert_eq!(
            KmipOperation::from_tag("Certify"),
            Some(KmipOperation::Certify)
        );
        assert_eq!(
            KmipOperation::from_tag("Create"),
            Some(KmipOperation::Create)
        );
        assert_eq!(
            KmipOperation::from_tag("Decrypt"),
            Some(KmipOperation::Decrypt)
        );
        assert_eq!(
            KmipOperation::from_tag("DeleteAttribute"),
            Some(KmipOperation::DeleteAttribute)
        );
        assert_eq!(
            KmipOperation::from_tag("DeriveKey"),
            Some(KmipOperation::DeriveKey)
        );
        assert_eq!(
            KmipOperation::from_tag("Destroy"),
            Some(KmipOperation::Destroy)
        );
        assert_eq!(
            KmipOperation::from_tag("Encrypt"),
            Some(KmipOperation::Encrypt)
        );
        assert_eq!(
            KmipOperation::from_tag("Export"),
            Some(KmipOperation::Export)
        );
        assert_eq!(KmipOperation::from_tag("Get"), Some(KmipOperation::Get));
        assert_eq!(
            KmipOperation::from_tag("GetAttributes"),
            Some(KmipOperation::GetAttributes)
        );
        assert_eq!(KmipOperation::from_tag("Hash"), Some(KmipOperation::Hash));
        assert_eq!(
            KmipOperation::from_tag("Import"),
            Some(KmipOperation::Import)
        );
        assert_eq!(
            KmipOperation::from_tag("Locate"),
            Some(KmipOperation::Locate)
        );
        assert_eq!(KmipOperation::from_tag("Mac"), Some(KmipOperation::MAC));
        assert_eq!(KmipOperation::from_tag("MAC"), Some(KmipOperation::MAC));
        assert_eq!(
            KmipOperation::from_tag("ModifyAttribute"),
            Some(KmipOperation::ModifyAttribute)
        );
        assert_eq!(KmipOperation::from_tag("ReKey"), Some(KmipOperation::Rekey));
        assert_eq!(
            KmipOperation::from_tag("Revoke"),
            Some(KmipOperation::Revoke)
        );
        assert_eq!(
            KmipOperation::from_tag("SetAttribute"),
            Some(KmipOperation::SetAttribute)
        );
        assert_eq!(KmipOperation::from_tag("Sign"), Some(KmipOperation::Sign));
        assert_eq!(
            KmipOperation::from_tag("SignatureVerify"),
            Some(KmipOperation::SignatureVerify)
        );
        assert_eq!(
            KmipOperation::from_tag("Validate"),
            Some(KmipOperation::Validate)
        );
    }

    #[test]
    fn from_tag_returns_none_for_unmapped_lifecycle_ops() {
        // These have no KmipOperation variant and must return None.
        for tag in &[
            "CreateKeyPair",
            "Register",
            "ReKeyKeyPair",
            "CreateSplitKey",
            "JoinSplitKey",
        ] {
            assert_eq!(
                KmipOperation::from_tag(tag),
                None,
                "{tag} should return None from from_tag — it is gated via is_restricted_lifecycle_tag",
            );
        }
    }

    #[test]
    fn from_tag_returns_none_for_unknown_and_empty() {
        assert_eq!(KmipOperation::from_tag(""), None);
        assert_eq!(KmipOperation::from_tag("Unknown"), None);
        assert_eq!(
            KmipOperation::from_tag("create"),
            None,
            "from_tag is case-sensitive (PascalCase only)"
        );
        assert_eq!(
            KmipOperation::from_tag("GET"),
            None,
            "from_tag is case-sensitive"
        );
    }

    // ─── is_restricted_lifecycle_tag ─────────────────────────────────────────

    #[test]
    fn is_restricted_lifecycle_tag_accepts_exactly_the_four_restricted_ops() {
        assert!(KmipOperation::is_restricted_lifecycle_tag("CreateKeyPair"));
        assert!(KmipOperation::is_restricted_lifecycle_tag("Register"));
        assert!(KmipOperation::is_restricted_lifecycle_tag("ReKeyKeyPair"));
        assert!(KmipOperation::is_restricted_lifecycle_tag("CreateSplitKey"));
    }

    #[test]
    fn is_restricted_lifecycle_tag_excludes_join_split_key() {
        // JoinSplitKey is intentionally excluded: CO candidates need it pre-ceremony.
        assert!(!KmipOperation::is_restricted_lifecycle_tag("JoinSplitKey"));
    }

    #[test]
    fn is_restricted_lifecycle_tag_rejects_mappable_ops() {
        // Operations that have a KmipOperation variant are not in the restricted list.
        assert!(!KmipOperation::is_restricted_lifecycle_tag("Create"));
        assert!(!KmipOperation::is_restricted_lifecycle_tag("Import"));
        assert!(!KmipOperation::is_restricted_lifecycle_tag("Get"));
        assert!(!KmipOperation::is_restricted_lifecycle_tag(""));
        assert!(!KmipOperation::is_restricted_lifecycle_tag("Unknown"));
    }

    // ─── is_ceremony_prerequisite_tag ────────────────────────────────────────

    #[test]
    fn is_ceremony_prerequisite_tag_accepts_all_four_prereqs() {
        assert!(KmipOperation::is_ceremony_prerequisite_tag("Create"));
        assert!(KmipOperation::is_ceremony_prerequisite_tag("Import"));
        assert!(KmipOperation::is_ceremony_prerequisite_tag(
            "CreateSplitKey"
        ));
        assert!(KmipOperation::is_ceremony_prerequisite_tag("JoinSplitKey"));
    }

    #[test]
    fn is_ceremony_prerequisite_tag_rejects_non_prereqs() {
        assert!(!KmipOperation::is_ceremony_prerequisite_tag("Get"));
        assert!(!KmipOperation::is_ceremony_prerequisite_tag("Export"));
        assert!(!KmipOperation::is_ceremony_prerequisite_tag("Destroy"));
        assert!(!KmipOperation::is_ceremony_prerequisite_tag(
            "CreateKeyPair"
        ));
        assert!(!KmipOperation::is_ceremony_prerequisite_tag(""));
    }

    // ─── coverage invariant: from_tag + restricted + prerequisite are disjoint ─

    /// Every tag in `is_restricted_lifecycle_tag` must return `None` from `from_tag`.
    /// If this fails, a tag was added to both tables — which would create a security
    /// inconsistency in `check_role_permission`.
    #[test]
    fn restricted_lifecycle_tags_are_not_in_from_tag() {
        for tag in &[
            "CreateKeyPair",
            "Register",
            "ReKeyKeyPair",
            "CreateSplitKey",
        ] {
            assert!(
                KmipOperation::from_tag(tag).is_none(),
                "Tag `{tag}` is in is_restricted_lifecycle_tag but also maps via from_tag — \
                 this creates a security inconsistency in check_role_permission",
            );
        }
    }
}

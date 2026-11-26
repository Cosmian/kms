/// KMS protection attributes of a secret or private key, mirrored into the PKCS#11
/// `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_NEVER_EXTRACTABLE` and `CKA_ALWAYS_SENSITIVE`
/// attributes. `None` means the KMS did not report the attribute; the accessors apply the
/// KMS defaults (not sensitive, extractable).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyProtection {
    pub sensitive: Option<bool>,
    pub extractable: Option<bool>,
    pub never_extractable: Option<bool>,
    pub always_sensitive: Option<bool>,
}

impl KeyProtection {
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        self.sensitive.unwrap_or(false)
    }

    #[must_use]
    pub fn is_extractable(&self) -> bool {
        self.extractable.unwrap_or(true)
    }

    #[must_use]
    pub fn is_never_extractable(&self) -> bool {
        self.never_extractable.unwrap_or(false)
    }

    #[must_use]
    pub fn is_always_sensitive(&self) -> bool {
        self.always_sensitive.unwrap_or(false)
    }

    /// Whether `CKA_VALUE` may be returned (PKCS#11 v2.40 §4.9: sensitive or non-extractable
    /// keys must answer `CKR_ATTRIBUTE_SENSITIVE`).
    #[must_use]
    pub fn value_readable(&self) -> bool {
        !self.is_sensitive() && self.is_extractable() && !self.is_never_extractable()
    }
}

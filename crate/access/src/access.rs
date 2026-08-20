use std::{
    collections::{BTreeSet, HashSet},
    fmt,
};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_types::UniqueIdentifier},
};
use serde::{Deserialize, Serialize};

/// KMS server-level roles as defined by:
/// - **ISO/IEC 19790:2012 §7.4** (adopted by FIPS 140-3): mandates `CryptoOfficer` and `User`
///   as the two required module roles. "Key output" is a Crypto Officer service (§7.4.3);
///   the User role is limited to "use of approved security functions."
/// - **NIST SP 800-57 Part 2 Rev 1**: §4.6 (dual control / split knowledge for key
///   distribution), §4.8 (access control).
///
/// Roles are optional and server-configured as lists of user email addresses.
/// A user not listed in any role is subject to the standard per-object capability check.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// ISO/IEC 19790 §7.4 "User" / PKCS#11 `CKU_USER`.
    ///
    /// May use approved security functions server-side (encrypt, decrypt, sign, verify, MAC,
    /// hash) and observe KMS state (`GetAttributes`, `Locate`, `Validate`).
    /// **Cannot** access raw key material (`Get`, `Export`) — "key output" is a Crypto Officer
    /// service per ISO/IEC 19790 §7.4.
    /// Cannot perform key lifecycle operations (create, import, certify, revoke, destroy, etc.).
    Operator,
    /// ISO/IEC 19790 §7.4 "Crypto Officer" / PKCS#11 `CKU_SO`.
    ///
    /// May manage key lifecycle (create, certify, import, rekey, activate, revoke, destroy),
    /// access raw key material (`Get`, `Export` — "key output" per ISO/IEC 19790 §7.4),
    /// modify object attributes, **and** use approved security functions
    /// (encrypt, decrypt, sign, verify, MAC, hash).
    ///
    /// Normative basis: ISO/IEC 19790 §7.4 requires each role's services to be clearly
    /// defined and enforced, but does NOT prohibit the CO from also holding cryptographic-use
    /// services. NIST SP 800-57 Part 2 Rev 1 confirms that a crypto officer "can perform
    /// encryption, decryption, and other operations to the extent defined by policy."
    /// Concretely: a dormant CO candidate is treated as Operator and CAN perform crypto
    /// operations; denying those same operations upon CO activation would reduce privileges
    /// on promotion — contrary to least-privilege and operational necessity (a CO must be
    /// able to test keys they manage).
    ///
    /// When activated (config-only or via split-key ceremony), also gains **ownership bypass**:
    /// can access any Managed Object regardless of ownership (NIST SP 800-57 Part 2 Rev 1 §4.6).
    CryptoOfficer,
}

impl Role {
    /// Returns the set of [`KmipOperation`]s this role is permitted to invoke.
    ///
    /// The returned set depends on the variant; privileged roles include every known
    /// operation, so callers may short-circuit without inspecting the set.
    #[must_use]
    pub fn allowed_operations(self) -> HashSet<KmipOperation> {
        match self {
            Self::Operator => [
                // Use of approved security functions (ISO/IEC 19790 §7.4 "User" services)
                KmipOperation::Encrypt,
                KmipOperation::Decrypt,
                KmipOperation::Sign,
                KmipOperation::SignatureVerify,
                KmipOperation::MAC,
                KmipOperation::Hash,
                // Status/observation output
                KmipOperation::GetAttributes,
                KmipOperation::Locate,
                KmipOperation::Validate,
            ]
            .into(),
            Self::CryptoOfficer => [
                // Key generation (ISO/IEC 19790 §7.4 "Crypto Officer" services)
                KmipOperation::Create,
                KmipOperation::Certify,
                KmipOperation::Import,
                // Key output (ISO/IEC 19790 §7.4 "key output")
                KmipOperation::Get,
                KmipOperation::Export,
                // Rotation / re-key
                KmipOperation::Rekey,
                KmipOperation::DeriveKey,
                // Lifecycle transitions
                KmipOperation::Activate,
                KmipOperation::Revoke,
                KmipOperation::Destroy,
                // Attribute management
                KmipOperation::SetAttribute,
                KmipOperation::ModifyAttribute,
                KmipOperation::AddAttribute,
                KmipOperation::DeleteAttribute,
                // Observation (needed to locate objects to manage)
                KmipOperation::GetAttributes,
                KmipOperation::Locate,
                // Approved security functions — CO inherits all User services.
                // ISO/IEC 19790 §7.4 does not forbid the CO from also using crypto;
                // NIST SP 800-57 Part 2 Rev 1 explicitly allows it when defined by policy.
                // A dormant CO candidate already holds Operator privileges (including crypto
                // use), so active CO must retain those to avoid privilege regression.
                KmipOperation::Encrypt,
                KmipOperation::Decrypt,
                KmipOperation::Sign,
                KmipOperation::SignatureVerify,
                KmipOperation::MAC,
                KmipOperation::Hash,
                KmipOperation::Validate,
            ]
            .into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Access {
    /// Determines the object being requested. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// User identifier, beneficiary of the access
    pub user_id: String,
    /// Operation types for the access
    pub operation_types: Vec<KmipOperation>,
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.user_id,
            self.unique_identifier
                .as_ref()
                .map_or_else(|| "[N/A]".to_owned(), std::string::ToString::to_string),
            self.operation_types
        )
    }
}

/// Crypto Officer role configuration.
///
/// Implements ISO/IEC 19790:2012 §7.4.3 "Crypto Officer" services with optional ceremony-based
/// activation following NIST SP 800-57 Part 2 Rev 1 §4.6 (dual control / split knowledge).
///
/// The Crypto Officer role provides:
/// - **Key lifecycle management**: Create, Import, Certify, Rekey, Activate, Revoke, Destroy
/// - **Key output**: Get, Export (ISO/IEC 19790 §7.4 "key output")
/// - **Attribute management**: Set/Modify/Add/Delete Attribute
/// - **Ownership bypass**: can access any Managed Object regardless of ownership (non-HSM)
/// - **Cryptographic use**: Encrypt, Decrypt, Sign, `SignatureVerify`, MAC, Hash — a CO
///   candidate is already an Operator with full crypto-use rights on their own objects, and
///   promotion to active CO does not reduce those rights. Note: the ownership bypass
///   (`user_can_perform_operation`) applies to **KMIP key-lifecycle operations** only.
///   Crypto operations (Encrypt/Decrypt/Sign/…) use a separate authorization path
///   (`is_owm_authorized_with_get_wildcard`) that checks ownership or explicit per-object
///   grants and does **not** include a CO bypass — an active CO can only encrypt/sign with
///   keys they own or have been explicitly granted access to.
///
/// When `require_ceremony` is `true`, Crypto Officer privileges are inactive until a quorum
/// of custodians completes a `JoinSplitKey` ceremony with CO-tagged shares.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CryptoOfficerConfig {
    /// Users that hold (or are candidates for) Crypto Officer privileges.
    ///
    /// When `require_ceremony` is `false`, these users are Crypto Officers immediately.
    /// When `require_ceremony` is `true`, they are candidates until a ceremony activates them.
    #[serde(default)]
    pub users: Vec<String>,

    /// When `true`, the Crypto Officer role is inactive until a split-key ceremony
    /// completes. The ceremony requires all shares (XOR n-of-n) tagged
    /// `x-cosmian-crypto-officer-ceremony`, created via `CreateSplitKey`.
    #[serde(default)]
    pub require_ceremony: bool,
}

impl CryptoOfficerConfig {
    /// Determine the [`Role`] held by `user`, if any.
    ///
    /// Returns `None` when the user is not listed — callers must treat `None` as
    /// [`Role::Operator`] (fail-secure default) when role enforcement is active.
    ///
    /// **Note**: when `require_ceremony = true`, users in `users` are candidates but
    /// are NOT returned as `CryptoOfficer` here — they default to [`Role::Operator`]
    /// until the DB-backed activation check confirms ceremony completion.
    #[must_use]
    pub fn role_for(&self, user: &str) -> Option<Role> {
        // Only grant CryptoOfficer at dispatch level when ceremony is NOT required.
        if !self.require_ceremony && self.users.iter().any(|x| x == user) {
            return Some(Role::CryptoOfficer);
        }
        None
    }

    /// Returns `true` if a Crypto Officer list is configured (role enforcement is active).
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        !self.users.is_empty()
    }

    /// Validate role configuration.
    ///
    /// Enforces NIST SP 800-57 Part 2 Rev 1 §4.6 split-knowledge minimum:
    /// `require_ceremony = true` requires at least 3 CO users. With XOR n-of-n
    /// and only n = 2, the key creator can derive S2 = K ⊕ S1 trivially, so
    /// genuine dual-control requires n ≥ 3.
    ///
    /// # Errors
    /// Returns an error string when `require_ceremony = true` and `users.len() < 3`.
    pub fn validate(&self) -> Result<(), String> {
        if self.require_ceremony && self.users.len() < 3 {
            return Err(format!(
                "crypto_officer_require_ceremony = true requires at least 3 \
                 crypto_officer_users (got {}). \
                 With XOR n-of-n split keys, the key creator knows the master key K \
                 and their own share S1, so they can derive any other share (S_i = K ⊕ S1 ⊕ … \
                 for n=2: S2 = K ⊕ S1) — bypassing dual control entirely. \
                 With n ≥ 3, the creator knows K and S1 but can only derive S2 ⊕ S3 ⊕ … \
                 without knowing individual shares, preserving split knowledge.",
                self.users.len()
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)] // Debug is required by ok_json()
pub struct UserAccessResponse {
    pub user_id: String,
    /// A `BTreeSet` is used to keep results sorted
    pub operations: BTreeSet<KmipOperation>,
}
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Debug)]
pub struct ObjectOwnedResponse {
    pub object_id: UniqueIdentifier,
    pub state: State,
    pub attributes: Attributes,
}
impl fmt::Display for ObjectOwnedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] {} - {}",
            self.state,
            self.object_id,
            self.attributes
                .key_format_type
                .map_or_else(String::new, |format| format.to_string())
        )
    }
}
impl From<(String, State, Attributes)> for ObjectOwnedResponse {
    fn from(e: (String, State, Attributes)) -> Self {
        Self {
            object_id: UniqueIdentifier::TextString(e.0),
            state: e.1,
            attributes: e.2,
        }
    }
}
#[derive(Deserialize, Serialize, Clone)]
pub struct AccessRightsObtainedResponse {
    pub object_id: UniqueIdentifier,
    pub owner_id: String,
    pub state: State,
    pub operations: HashSet<KmipOperation>,
}
impl fmt::Display for AccessRightsObtainedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}][{}]{} {:?} - comments",
            self.state, self.owner_id, self.object_id, self.operations
        )
    }
}
impl From<(String, (String, State, HashSet<KmipOperation>))> for AccessRightsObtainedResponse {
    fn from(e: (String, (String, State, HashSet<KmipOperation>))) -> Self {
        Self {
            object_id: UniqueIdentifier::TextString(e.0),
            owner_id: e.1.0,
            state: e.1.1,
            operations: e.1.2,
        }
    }
}
// Response for success
#[derive(Deserialize, Serialize, Debug)] // Debug is required by ok_json()
pub struct SuccessResponse {
    pub success: String,
}

#[derive(Serialize)]
pub struct CreatePermissionResponse {
    pub has_create_permission: bool,
}

#[derive(Serialize)]
pub struct PrivilegedAccessResponse {
    pub has_privileged_access: bool,
}

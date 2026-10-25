use std::{
    collections::{BTreeSet, HashSet},
    fmt,
};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_types::{OperationEnumeration, UniqueIdentifier},
    },
};
use serde::{Deserialize, Serialize};

/// Error type for [`CryptoOfficerConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoOfficerConfigError {
    /// `require_ceremony = true` requires at least 3 CO users.
    ///
    /// With XOR n-of-n and only n = 2, the key creator knows K and S1 and can
    /// trivially derive S2 = K ⊕ S1, defeating dual control. n ≥ 3 is required
    /// for genuine split knowledge (NIST SP 800-57 Part 2 Rev 1 §4.6).
    InsufficientCandidates {
        /// Number of configured CO users.
        count: usize,
        /// Minimum required (3).
        minimum: usize,
    },
}

impl fmt::Display for CryptoOfficerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientCandidates { count, minimum } => write!(
                f,
                "crypto_officer_require_ceremony = true requires at least {minimum} \
                 crypto_officer_users (got {count}). \
                 With XOR n-of-n split keys, the key creator knows the master key K \
                 and their own share S1, so they can derive any other share (S_i = K ⊕ S1 ⊕ … \
                 for n=2: S2 = K ⊕ S1) — bypassing dual control entirely. \
                 With n ≥ {minimum}, the creator knows K and S1 but can only derive \
                 S2 ⊕ S3 ⊕ … without knowing individual shares, preserving split knowledge."
            ),
        }
    }
}

impl std::error::Error for CryptoOfficerConfigError {}

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
    /// Reaches per-object services (`Get`, `Export`, lifecycle, attribute changes) only through
    /// handler ownership/grant checks; object creation additionally requires the Create right,
    /// and `RNGSeed` is refused (see [`Role::decide`]).
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

/// Outcome of the dispatch-level role check for one KMIP operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RoleDecision {
    /// Dispatched; the handler still enforces object ownership or an explicit grant.
    Allow,
    /// Dispatched only if the caller also holds the Create right
    /// (Crypto Officer listed, `default_username`, or an explicit `Create` grant).
    RequireCreatePermission,
    /// Refused before dispatch.
    Deny,
}

impl Role {
    /// Dispatch-level decision for `operation` once roles are configured.
    ///
    /// Exhaustive over every KMIP operation: a new variant cannot be allowed by omission.
    ///
    /// An `Operator` may use approved security functions, observe server state, call the
    /// stateless server services, and retrieve (`Get`) or `Export` an object it owns or was
    /// granted, and manage the lifecycle and attributes of such objects. It cannot reach
    /// server-wide administration (`PKCS11`, `SetConstraints`, `RNGSeed`). Creating objects
    /// needs the Create right.
    #[must_use]
    pub const fn decide(self, operation: OperationEnumeration) -> RoleDecision {
        use OperationEnumeration as Op;
        match operation {
            // Cryptographic use, key output, attribute reads, discovery, random output, server
            // services: every role; the handler still requires ownership or a grant on the
            // objects used (a Crypto Officer may grant `Get`/`Export` to an Operator).
            Op::Encrypt
            | Op::Decrypt
            | Op::Sign
            | Op::SignatureVerify
            | Op::MAC
            | Op::MACVerify
            | Op::Hash
            | Op::GetAttributes
            | Op::GetAttributeList
            | Op::Locate
            | Op::Check
            | Op::Validate
            | Op::Query
            | Op::DiscoverVersions
            | Op::RNGRetrieve
            | Op::Log
            | Op::Interop
            | Op::Login
            | Op::Logout
            | Op::Ping
            | Op::GetConstraints
            | Op::Get
            | Op::Export
            | Op::Certify
            | Op::ReCertify
            | Op::ReKey
            | Op::DeriveKey
            | Op::Activate
            | Op::Revoke
            | Op::Destroy
            | Op::SetAttribute
            | Op::ModifyAttribute
            | Op::AddAttribute
            | Op::DeleteAttribute
            | Op::JoinSplitKey => RoleDecision::Allow,
            // Server-wide administration: Crypto Officer only.
            Op::PKCS11 | Op::RNGSeed | Op::SetConstraints => match self {
                Self::Operator => RoleDecision::Deny,
                Self::CryptoOfficer => RoleDecision::Allow,
            },
            // Operations that create Managed Objects.
            Op::Create
            | Op::Import
            | Op::CreateKeyPair
            | Op::Register
            | Op::ReKeyKeyPair
            | Op::CreateSplitKey => match self {
                Self::Operator => RoleDecision::RequireCreatePermission,
                Self::CryptoOfficer => RoleDecision::Allow,
            },
            // Not served by this KMS: refused until their implementation decides a policy.
            Op::ObtainLease
            | Op::GetUsageAllocation
            | Op::Archive
            | Op::Recover
            | Op::Cancel
            | Op::Poll
            | Op::Notify
            | Op::Put
            | Op::DelegatedLogin
            | Op::AdjustAttribute
            | Op::SetEndpointRole
            | Op::ReProvision
            | Op::SetDefaults
            | Op::QueryAsynchronousRequests
            | Op::Process => RoleDecision::Deny,
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

    /// UID of a KMS symmetric key used to AES-KW (RFC 5649) wrap each split-key share
    /// before it is written to the database.
    ///
    /// When set, `CreateSplitKey` wraps every share's raw bytes with this key, and
    /// `JoinSplitKey` unwraps them before XOR reconstruction.  The wrapping key must be
    /// an AES-128, AES-192, or AES-256 symmetric key already present in the KMS object
    /// store.  The UID is stamped as the `x-cosmian-share-wrapping-key` vendor attribute
    /// on every share object so `JoinSplitKey` can locate the correct key on reassembly.
    ///
    /// When the KMS itself is HSM-backed, this key can be an HSM-resident object, giving
    /// the same hardware boundary protection as purpose-built HSM split-key solutions.
    ///
    /// Security note: the wrapping key must be created and made available **before**
    /// the first `CreateSplitKey` call.  Rotate it by creating a new key, updating this
    /// field, and re-running the ceremony (existing wrapped shares cannot be unwrapped
    /// with a new key; re-ceremony is required on rotation).
    #[serde(default)]
    pub ceremony_wrapping_key_id: Option<String>,
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

    /// Operations a Crypto Officer *candidate* may call before the ceremony activates them:
    /// create or import the ceremony key, mark it as a ceremony key, then split and re-join it.
    #[must_use]
    pub const fn is_ceremony_prerequisite(operation: OperationEnumeration) -> bool {
        matches!(
            operation,
            OperationEnumeration::Create
                | OperationEnumeration::Import
                | OperationEnumeration::SetAttribute
                | OperationEnumeration::CreateSplitKey
                | OperationEnumeration::JoinSplitKey
        )
    }

    /// Validate role configuration.
    ///
    /// Enforces NIST SP 800-57 Part 2 Rev 1 §4.6 split-knowledge minimum:
    /// `require_ceremony = true` requires at least 3 CO users. With XOR n-of-n
    /// and only n = 2, the key creator can derive S2 = K ⊕ S1 trivially, so
    /// genuine dual-control requires n ≥ 3.
    ///
    /// # Errors
    /// Returns [`CryptoOfficerConfigError::InsufficientCandidates`] when
    /// `require_ceremony = true` and `users.len() < 3`.
    pub const fn validate(&self) -> Result<(), CryptoOfficerConfigError> {
        const MINIMUM_CEREMONY_CANDIDATES: usize = 3;
        if self.require_ceremony && self.users.len() < MINIMUM_CEREMONY_CANDIDATES {
            return Err(CryptoOfficerConfigError::InsufficientCandidates {
                count: self.users.len(),
                minimum: MINIMUM_CEREMONY_CANDIDATES,
            });
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

#[cfg(test)]
mod tests {
    use OperationEnumeration as Op;
    use RoleDecision::{Allow, Deny, RequireCreatePermission};

    use super::*;

    #[test]
    fn role_decisions() {
        for (role, op, expected) in [
            (Role::Operator, Op::RNGSeed, Deny),
            (Role::CryptoOfficer, Op::RNGSeed, Allow),
            (Role::Operator, Op::Ping, Allow),
            (Role::CryptoOfficer, Op::Ping, Allow),
            (Role::Operator, Op::Get, Allow),
            (Role::Operator, Op::Export, Allow),
            (Role::CryptoOfficer, Op::Get, Allow),
            (Role::Operator, Op::JoinSplitKey, Allow),
            (Role::Operator, Op::Revoke, Allow),
            (Role::Operator, Op::Destroy, Allow),
            (Role::Operator, Op::PKCS11, Deny),
            (Role::Operator, Op::ReCertify, Allow),
            (Role::Operator, Op::SetConstraints, Deny),
            (Role::CryptoOfficer, Op::SetConstraints, Allow),
            (Role::Operator, Op::GetConstraints, Allow),
            (Role::Operator, Op::Login, Allow),
            (Role::Operator, Op::RNGRetrieve, Allow),
            (Role::Operator, Op::Encrypt, Allow),
            (Role::Operator, Op::Poll, Deny),
        ] {
            assert_eq!(role.decide(op), expected, "{role:?} / {op}");
        }
        for op in [
            Op::Create,
            Op::Import,
            Op::CreateKeyPair,
            Op::Register,
            Op::ReKeyKeyPair,
            Op::CreateSplitKey,
        ] {
            assert_eq!(Role::Operator.decide(op), RequireCreatePermission, "{op}");
            assert_eq!(Role::CryptoOfficer.decide(op), Allow, "{op}");
        }
    }
}

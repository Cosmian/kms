use serde::{Deserialize, Serialize};

/// RBAC input following NIST SP 800-162 ABAC attribute categories.
///
/// This structure is serialized to JSON and passed as `input` to the
/// Rego policy engine (either embedded regorus or external OPA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacInput {
    /// Subject attributes (the authenticated user)
    pub subject: SubjectAttrs,
    /// Action attributes (the requested KMIP operation)
    pub action: ActionAttrs,
    /// Resource attributes (the target object, if any)
    pub resource: ResourceAttrs,
    /// Environment attributes (contextual)
    pub environment: EnvironmentAttrs,
}

/// Subject (user) attributes per NIST SP 800-162 §4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectAttrs {
    /// Authenticated user identifier
    pub user_id: String,
    /// Roles assigned to the user (from the `role_assignments` store)
    pub roles: Vec<String>,
    /// Whether the user owns the target object
    pub is_owner: bool,
    /// Whether the user is in the `privileged_users` list
    pub is_privileged: bool,
}

/// Action attributes per NIST SP 800-162 §4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAttrs {
    /// The KMIP operation being requested (lowercase, e.g. "encrypt")
    pub operation: String,
}

/// Resource (object) attributes per NIST SP 800-162 §4.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceAttrs {
    /// Object unique identifier (empty for Create operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    /// KMIP object type (e.g. `SymmetricKey`, `PrivateKey`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    /// Object lifecycle state (e.g. `Active`, `PreActive`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Object owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Whether the key is marked as sensitive
    #[serde(default)]
    pub sensitive: bool,
    /// Whether the key is extractable
    #[serde(default)]
    pub extractable: bool,
}

/// Environment attributes per NIST SP 800-162 §4.
///
/// Currently a placeholder; can be extended with time-of-day,
/// source IP, etc. for more advanced policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentAttrs {
    /// Reserved for future attributes (time-of-day, source IP, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
}

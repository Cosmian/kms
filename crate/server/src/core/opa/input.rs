//! OPA input document for the KMS RBAC policy.

use serde::Serialize;

/// The input document sent to OPA for evaluation.
///
/// Evaluated at: `POST {opa_url}/v1/data/kms/allow`
///
/// See `test_data/opa/kms.rego` for the Rego policy that consumes this input.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct OpaInput {
    /// Authenticated identity (JWT `sub`, TLS CN, or API-token id).
    pub user: String,
    /// Domain from the `as_domain` JWT private claim; `""` for non-JWT auth.
    pub user_domain: String,
    /// Roles from the JWT `roles` claim (RFC 9068); `[]` for non-JWT auth (fail-closed).
    pub roles: Vec<String>,
    /// KMIP operation name as returned by `KmipOperation::to_string()` (lowercase `snake_case`,
    /// e.g. `"create"`, `"decrypt"`, `"get_attributes"`).
    pub operation: String,
    /// UID of the target KMIP object; `"*"` for object-less operations.
    pub object_uid: String,
    /// Domain the target object belongs to.
    /// For object-less operations (e.g. `Create`, `Locate`) this is set to `user_domain` so
    /// that the `same_domain` Rego rule passes for the caller's own domain.
    /// For operations on existing objects this is the `domain` column value stored with the object.
    pub object_domain: String,
    /// Whether the caller is the owner of the target object.
    pub is_owner: bool,
}

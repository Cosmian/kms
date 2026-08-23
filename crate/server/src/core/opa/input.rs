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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_input(is_owner: bool) -> OpaInput {
        OpaInput {
            user: "alice@acme.com".to_owned(),
            user_domain: "acme".to_owned(),
            roles: vec!["CryptoOfficer".to_owned()],
            operation: "get".to_owned(),
            object_uid: "uid-001".to_owned(),
            object_domain: "acme".to_owned(),
            is_owner,
        }
    }

    /// All seven OPA input fields serialize with the exact `snake_case` names the
    /// Rego policy expects.  A mismatch silently breaks policy evaluation.
    #[test]
    fn test_opa_input_serializes_all_expected_field_names() {
        let input = sample_input(true);
        let json = serde_json::to_string(&input).expect("OpaInput must serialize");
        for field in &[
            "user",
            "user_domain",
            "roles",
            "operation",
            "object_uid",
            "object_domain",
            "is_owner",
        ] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "serialized JSON must contain field '{field}', got: {json}"
            );
        }
    }

    /// `is_owner: true` serializes as JSON `true` (not `"true"` or `1`).
    #[test]
    fn test_opa_input_is_owner_true_serializes_as_json_boolean() {
        let input = sample_input(true);
        let json = serde_json::to_string(&input).expect("serialize");
        assert!(
            json.contains("\"is_owner\":true"),
            "is_owner must be JSON true, got: {json}"
        );
    }

    /// `is_owner: false` serializes as JSON `false`.
    #[test]
    fn test_opa_input_is_owner_false_serializes_as_json_boolean() {
        let input = sample_input(false);
        let json = serde_json::to_string(&input).expect("serialize");
        assert!(
            json.contains("\"is_owner\":false"),
            "is_owner must be JSON false, got: {json}"
        );
    }

    /// `roles` serializes as a JSON array (not a comma-separated string).
    #[test]
    fn test_opa_input_roles_serializes_as_json_array() {
        let mut input = sample_input(false);
        input.roles = vec!["CryptoOfficer".to_owned(), "Auditor".to_owned()];
        let json = serde_json::to_string(&input).expect("serialize");
        assert!(
            json.contains("\"roles\":["),
            "roles must be a JSON array, got: {json}"
        );
        assert!(json.contains("\"CryptoOfficer\""));
        assert!(json.contains("\"Auditor\""));
    }

    /// An object-less input has `object_uid = "*"` and `is_owner = false`.
    #[test]
    fn test_opa_input_objectless_wildcard_uid() {
        let input = OpaInput {
            user: "alice@acme.com".to_owned(),
            user_domain: "acme".to_owned(),
            roles: vec![],
            operation: "create".to_owned(),
            object_uid: "*".to_owned(),
            object_domain: "acme".to_owned(),
            is_owner: false,
        };
        let json = serde_json::to_string(&input).expect("serialize");
        assert!(
            json.contains("\"object_uid\":\"*\""),
            "object-less op must use '*', got: {json}"
        );
        assert!(json.contains("\"is_owner\":false"));
    }
}

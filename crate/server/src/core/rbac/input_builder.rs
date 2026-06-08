//! Policy Input Builder
//!
//! Constructs the OPA input document (`PolicyInput`) from KMIP request context,
//! JWT claims, object metadata, and ACL state. This input is passed to the Regorus
//! evaluator for every authorization decision.

use regorus::Value;
use serde::Serialize;

/// Complete OPA input document matching the stable API contract in `CONTEXT.md`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyInput {
    pub subject: Subject,
    pub request: RequestContext,
    pub operation: OperationContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl: Option<AclContext>,
}

/// The authenticated subject (user) making the request.
#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub user_id: String,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub is_privileged: bool,
}

/// HTTP request context (environment signals for policy decisions).
#[derive(Debug, Clone, Serialize)]
pub struct RequestContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

/// The KMIP operation being performed.
#[derive(Debug, Clone, Serialize)]
pub struct OperationContext {
    pub kmip_op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    /// For Grant/Revoke access-management operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    /// For Grant operations: which ops are being granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_ops: Option<Vec<String>>,
}

/// Resource (object) context for object-targeting operations.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceContext {
    pub id: String,
    pub owner: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub state: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// ACL context for object-targeting operations.
#[derive(Debug, Clone, Serialize)]
pub struct AclContext {
    pub is_owner: bool,
    pub granted_ops: Vec<String>,
}

impl PolicyInput {
    /// Convert to a Regorus `Value` for policy evaluation.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails (should not happen for well-formed inputs).
    pub fn to_regorus_value(&self) -> Result<Value, String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        Value::from_json_str(&json).map_err(|e| e.to_string())
    }

    /// Build a policy input for a non-object operation (Create, `CreateKeyPair`, etc.).
    ///
    /// `resource` and `acl` are `None` since no existing object is involved.
    pub const fn for_non_object_operation(
        subject: Subject,
        request: RequestContext,
        operation: OperationContext,
    ) -> Self {
        Self {
            subject,
            request,
            operation,
            resource: None,
            acl: None,
        }
    }

    /// Build a policy input for an object-targeting operation (Get, Encrypt, Destroy, etc.).
    pub const fn for_object_operation(
        subject: Subject,
        request: RequestContext,
        operation: OperationContext,
        resource: ResourceContext,
        acl: AclContext,
    ) -> Self {
        Self {
            subject,
            request,
            operation,
            resource: Some(resource),
            acl: Some(acl),
        }
    }

    /// Build a policy input for an access-management endpoint (Grant, Revoke).
    pub const fn for_access_management(
        subject: Subject,
        request: RequestContext,
        operation: OperationContext,
    ) -> Self {
        Self {
            subject,
            request,
            operation,
            resource: None,
            acl: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_input_serialization_non_object() {
        let input = PolicyInput::for_non_object_operation(
            Subject {
                user_id: "alice@example.com".to_owned(),
                roles: vec!["operator".to_owned()],
                tenant_id: Some("acme-corp".to_owned()),
                is_privileged: false,
            },
            RequestContext {
                ip: Some("192.168.1.1".to_owned()),
                tls_subject: None,
                user_agent: Some("ckms/1.0".to_owned()),
            },
            OperationContext {
                kmip_op: "Create".to_owned(),
                algorithm: Some("AES".to_owned()),
                mode: None,
                padding: None,
                target_user: None,
                grant_ops: None,
            },
        );

        let value = input.to_regorus_value().unwrap();
        let json = serde_json::to_value(&input).unwrap();

        // Verify structure
        assert_eq!(json["subject"]["user_id"], "alice@example.com");
        assert_eq!(json["subject"]["roles"][0], "operator");
        assert_eq!(json["operation"]["kmip_op"], "Create");
        assert_eq!(json["operation"]["algorithm"], "AES");
        assert!(json.get("resource").is_none());
        assert!(json.get("acl").is_none());

        // Verify Regorus value is valid
        assert!(!format!("{value:?}").is_empty());
    }

    #[test]
    fn test_policy_input_serialization_object_op() {
        let input = PolicyInput::for_object_operation(
            Subject {
                user_id: "bob@example.com".to_owned(),
                roles: vec!["admin".to_owned()],
                tenant_id: Some("acme-corp".to_owned()),
                is_privileged: true,
            },
            RequestContext {
                ip: None,
                tls_subject: Some("CN=bob,O=Acme".to_owned()),
                user_agent: None,
            },
            OperationContext {
                kmip_op: "Decrypt".to_owned(),
                algorithm: Some("RSA".to_owned()),
                mode: None,
                padding: Some("OAEP".to_owned()),
                target_user: None,
                grant_ops: None,
            },
            ResourceContext {
                id: "key-123".to_owned(),
                owner: "alice@example.com".to_owned(),
                object_type: "PrivateKey".to_owned(),
                state: "Active".to_owned(),
                tags: vec!["env:prod".to_owned()],
                tenant_id: Some("acme-corp".to_owned()),
            },
            AclContext {
                is_owner: false,
                granted_ops: vec!["Decrypt".to_owned(), "Get".to_owned()],
            },
        );

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["resource"]["id"], "key-123");
        assert_eq!(json["acl"]["is_owner"], false);
        assert_eq!(json["acl"]["granted_ops"][0], "Decrypt");
        assert_eq!(json["subject"]["is_privileged"], true);
    }

    #[test]
    fn test_policy_input_access_management() {
        let input = PolicyInput::for_access_management(
            Subject {
                user_id: "alice@example.com".to_owned(),
                roles: vec!["operator".to_owned()],
                tenant_id: Some("acme-corp".to_owned()),
                is_privileged: false,
            },
            RequestContext {
                ip: None,
                tls_subject: None,
                user_agent: None,
            },
            OperationContext {
                kmip_op: "Grant".to_owned(),
                algorithm: None,
                mode: None,
                padding: None,
                target_user: Some("bob@example.com".to_owned()),
                grant_ops: Some(vec!["Encrypt".to_owned(), "Decrypt".to_owned()]),
            },
        );

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["operation"]["target_user"], "bob@example.com");
        assert_eq!(json["operation"]["grant_ops"][0], "Encrypt");
    }
}

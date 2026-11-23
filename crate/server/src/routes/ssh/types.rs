use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigureCaRequest {
    pub(crate) ca_key_uid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PutRoleRequest {
    pub(crate) allowed_principals: Vec<String>,
    pub(crate) default_ttl: String,
    pub(crate) max_ttl: String,
    /// Users (as authenticated by the KMS) allowed to request certificates with this role.
    /// Active Crypto Officers may always use every role.
    #[serde(default)]
    pub(crate) allowed_users: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignRequest {
    pub(crate) public_key: String,
    pub(crate) valid_principals: Vec<String>,
    pub(crate) ttl: Option<String>,
}

/// The password endpoint's request body: exactly the empty JSON object `{}`.
pub(crate) struct PasswordRequest;

impl<'de> Deserialize<'de> for PasswordRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // A map rejects `null`, arrays and scalars; only the empty object is accepted.
        let fields = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        if fields.is_empty() {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "password request accepts no field",
            ))
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SignedKeyData {
    pub(crate) signed_key: String,
    pub(crate) serial_number: String,
}

/// No `Debug`: the generated password must not end up in logs.
#[derive(Serialize)]
pub(crate) struct PasswordData {
    #[serde(serialize_with = "serialize_zeroizing_str")]
    pub(crate) password: Zeroizing<String>,
}

fn serialize_zeroizing_str<S: Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[derive(Debug, Serialize)]
pub(crate) struct DataWrapper<T> {
    pub(crate) data: T,
}

pub(crate) fn validate_principals(principals: &[String]) -> Result<(), String> {
    if principals.is_empty() || principals.len() > 64 {
        return Err("principal list must contain between 1 and 64 entries".to_owned());
    }

    let mut seen = HashSet::with_capacity(principals.len());
    for principal in principals {
        if principal.is_empty()
            || principal.len() > 128
            || !principal
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte))
        {
            return Err("principal contains unsupported characters or length".to_owned());
        }
        if !seen.insert(principal) {
            return Err("principal list contains a duplicate".to_owned());
        }
    }
    Ok(())
}

/// Users allowed to request certificates with a role. An empty list is valid: only active
/// Crypto Officers can then use the role.
pub(crate) fn validate_allowed_users(users: &[String]) -> Result<(), String> {
    if users.len() > 256 {
        return Err("allowed_users must contain at most 256 entries".to_owned());
    }
    let mut seen = HashSet::with_capacity(users.len());
    for user in users {
        if user.trim().is_empty() || user.len() > 256 || user.chars().any(char::is_control) {
            return Err(
                "allowed_users entry is empty, too long or has control characters".to_owned(),
            );
        }
        if user == "*" {
            return Err("allowed_users does not support wildcards".to_owned());
        }
        if !seen.insert(user) {
            return Err("allowed_users contains a duplicate".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_request_is_exactly_the_empty_object() {
        assert!(matches!(
            serde_json::from_str::<PasswordRequest>("{}"),
            Ok(PasswordRequest)
        ));
        let error = |body: &str| {
            serde_json::from_str::<PasswordRequest>(body)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        };
        assert!(error(r#"{"length":64}"#).contains("accepts no field"));
        for rejected in ["null", "[]", "1", r#""""#] {
            assert!(error(rejected).contains("invalid type"), "{rejected}");
        }
    }

    #[test]
    fn validates_principals_without_wildcards_or_duplicates() {
        assert_eq!(
            validate_principals(&["alice".to_owned(), "svc-db.example".to_owned()]),
            Ok(())
        );
        assert_eq!(
            validate_principals(&[]),
            Err("principal list must contain between 1 and 64 entries".to_owned())
        );
        assert_eq!(
            validate_principals(&["*".to_owned()]),
            Err("principal contains unsupported characters or length".to_owned())
        );
        assert_eq!(
            validate_principals(&["alice".to_owned(), "alice".to_owned()]),
            Err("principal list contains a duplicate".to_owned())
        );
    }

    #[test]
    fn validates_allowed_users() {
        assert_eq!(validate_allowed_users(&[]), Ok(()));
        assert_eq!(
            validate_allowed_users(&["alice@example.com".to_owned(), "CN=svc".to_owned()]),
            Ok(())
        );
        assert!(validate_allowed_users(&["*".to_owned()]).is_err());
        assert!(validate_allowed_users(&[String::new()]).is_err());
        assert!(validate_allowed_users(&["a\nb".to_owned()]).is_err());
        assert!(validate_allowed_users(&["bob".to_owned(), "bob".to_owned()]).is_err());
        assert!(validate_allowed_users(&["u".repeat(257)]).is_err());
    }
}

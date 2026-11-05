use std::collections::HashSet;

use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignRequest {
    pub(crate) public_key: String,
    pub(crate) valid_principals: Vec<String>,
    pub(crate) ttl: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::empty_structs_with_brackets)] // `{}` is the endpoint's empty JSON request shape.
pub(crate) struct PasswordRequest {}

#[derive(Debug, Serialize)]
pub(crate) struct SignedKeyData {
    pub(crate) signed_key: String,
    pub(crate) serial_number: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PasswordData {
    pub(crate) password: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct DataWrapper<T> {
    pub(crate) data: T,
}

pub(crate) fn parse_duration_secs(raw: &str) -> Option<u64> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }

    let split = value.len().checked_sub(1)?;
    let (number, unit) = value.split_at(split);
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return None,
    };
    let amount = if number.is_empty() {
        value.parse::<u64>().ok()?
    } else {
        number.parse::<u64>().ok()?.checked_mul(multiplier)?
    };
    (amount > 0).then_some(amount)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_durations() {
        assert_eq!(parse_duration_secs("15m"), Some(900));
        assert_eq!(parse_duration_secs("1h"), Some(3_600));
        assert_eq!(parse_duration_secs("2d"), Some(172_800));
        assert_eq!(parse_duration_secs("45s"), Some(45));
    }

    #[test]
    fn rejects_invalid_or_overflowing_durations() {
        assert_eq!(parse_duration_secs("0s"), None);
        assert_eq!(parse_duration_secs("-1m"), None);
        assert_eq!(parse_duration_secs("5w"), None);
        assert_eq!(parse_duration_secs("999999999999999999999h"), None);
        assert_eq!(parse_duration_secs("45"), None);
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
}

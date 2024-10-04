use regex::{Regex, RegexBuilder};

/// Extract the `key_uid` (prefixed by a pattern) from a text
pub(crate) fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
    let formatted = format!(r"^\s*{pattern}: (?P<uid>.+?)[\s\.]*?$");
    let uid_regex: Regex = RegexBuilder::new(formatted.as_str())
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Extract the private key from a test.
pub(crate) fn extract_private_key(text: &str) -> Option<&str> {
    extract_uid(text, "Private key unique identifier")
}

/// Extract the public key from a test.
pub(crate) fn extract_public_key(text: &str) -> Option<&str> {
    extract_uid(text, "Public key unique identifier")
}

/// Extract the imported key id
pub(crate) fn extract_unique_identifier(text: &str) -> Option<&str> {
    extract_uid(text, "Unique identifier")
}

/// Extract the decryption user key from a test.
pub(crate) fn extract_user_key(text: &str) -> Option<&str> {
    extract_uid(text, "Unique identifier")
}

/// Extract the database secret from a test
pub(crate) fn extract_database_secret(text: &str) -> Option<&str> {
    let formatted = r"entry of your KMS_CLI_CONF\):\s*?(?P<uid>[a-zA-Z0-9=]+)$";
    let uid_regex = RegexBuilder::new(formatted)
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Extract the `key_uid` (prefixed by a pattern) from a text
pub(crate) fn extract_locate_uids(text: &str) -> Option<Vec<String>> {
    let formatted = r"^\.*?List of unique identifiers:\s*(?P<uids>.+)$";
    let uid_regex: Regex = RegexBuilder::new(formatted)
        .multi_line(true)
        .dot_matches_new_line(true)
        .build()
        .unwrap();
    let uids = uid_regex.captures(text).and_then(|cap| {
        cap.name("uids").map(|uid| {
            let uids = uid.as_str();
            uids.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(std::borrow::ToOwned::to_owned)
                .collect::<Vec<String>>()
        })
    });
    uids
}

/// Extract the wrapping key from a test.
#[cfg(not(feature = "fips"))]
pub(crate) fn extract_wrapping_key(text: &str) -> Option<&str> {
    let formatted = r"Wrapping key:\s*(?P<uid>[a-zA-Z0-9+/=]+)";
    let uid_regex = RegexBuilder::new(formatted)
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

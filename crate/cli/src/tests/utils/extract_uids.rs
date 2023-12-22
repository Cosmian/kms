use regex::{Regex, RegexBuilder};

/// Extract the `key_uid` (prefixed by a pattern) from a text
pub fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
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
pub fn extract_private_key(text: &str) -> Option<&str> {
    extract_uid(text, "Private key unique identifier")
}

/// Extract the public key from a test.
pub fn extract_public_key(text: &str) -> Option<&str> {
    extract_uid(text, "Public key unique identifier ")
}

/// Extract the imported key id
pub fn extract_imported_key_id(text: &str) -> Option<&str> {
    extract_uid(text, ".*? was imported with id")
}

/// Extract the decryption user key from a test.
pub fn extract_user_key(text: &str) -> Option<&str> {
    extract_uid(text, "Created the user decryption key with ID")
}

/// Extract the database secret from a test
pub fn extract_database_secret(text: &str) -> Option<&str> {
    let formatted = r"entry of your KMS_CLI_CONF\):\s*?(?P<uid>[a-zA-Z0-9=]+)$";
    let uid_regex = RegexBuilder::new(formatted)
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Extract the wrapping key from a test.
pub fn extract_wrapping_key(text: &str) -> Option<&str> {
    extract_uid(text, "Wrapping key")
}

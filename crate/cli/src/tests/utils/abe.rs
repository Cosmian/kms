use regex::{Regex, RegexBuilder};

/// Extract the key_uid (prefixed by a pattern) from a text
fn extract_uid<'a>(text: &'a str, pattern: &'a str) -> Option<&'a str> {
    let formatted = format!(r"^  {}: (?P<uid>[a-z0-9-]+)$", pattern);
    let uid_regex: Regex = RegexBuilder::new(formatted.as_str())
        .multi_line(true)
        .build()
        .unwrap();
    uid_regex
        .captures(text)
        .and_then(|cap| cap.name("uid").map(|uid| uid.as_str()))
}

/// Extract the private key from a text.
pub fn extract_private_key(text: &str) -> Option<&str> {
    extract_uid(text, "Private key unique identifier")
}

/// Extract the public key from a text.
pub fn extract_public_key(text: &str) -> Option<&str> {
    extract_uid(text, "Public key unique identifier")
}

/// Extract the decryption user key from a text.
pub fn extract_user_key(text: &str) -> Option<&str> {
    extract_uid(text, "Decryption user key unique identifier")
}

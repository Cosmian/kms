//! Characterization of `validate_kacls_url` at BASE.

use super::validate_kacls_url;

const INTERNAL: &str = "Invalid Request: original_kacls_url must not target internal hostnames";
const PRIVATE: &str =
    "Invalid Request: original_kacls_url must not target private or loopback addresses";

fn outcome(url: &str) -> String {
    match validate_kacls_url(url) {
        Ok(()) => "ok".to_owned(),
        Err(e) => e.to_string(),
    }
}

#[test]
fn characterization_validate_kacls_url_accepted_hosts() {
    for url in [
        "https://kacls.example.com/v1",
        "https://local",
        "https://foo.localhost",
        "https://[::1]",
        "https://internal",
        "https://x.internal.example.com",
        "https://local.example.com",
        "https://foo.local.",
    ] {
        assert_eq!(outcome(url), "ok", "{url}");
    }
}

#[test]
fn characterization_validate_kacls_url_rejected_internal_hostnames() {
    for url in [
        "https://foo.local",
        "https://foo.LOCAL",
        "https://a.b.internal",
        "https://metadata.google.internal",
        "https://localhost",
    ] {
        assert_eq!(outcome(url), INTERNAL, "{url}");
    }
}

#[test]
fn characterization_validate_kacls_url_rejected_addresses() {
    for url in [
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://169.254.1.1",
        "https://0.0.0.0",
    ] {
        assert_eq!(outcome(url), PRIVATE, "{url}");
    }
}

#[test]
fn characterization_validate_kacls_url_rejected_scheme_and_syntax() {
    assert_eq!(
        outcome("http://kacls.example.com"),
        "Invalid Request: original_kacls_url must use HTTPS scheme"
    );
    assert_eq!(
        outcome("not a url"),
        "Invalid Request: Invalid original_kacls_url: relative URL without a base"
    );
}

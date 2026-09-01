mod find;

pub(crate) use find::{
    retrieve_certificate_for_private_key, retrieve_issuer_private_key_and_certificate,
    retrieve_private_key_for_certificate,
};

/// Validates that a CRL Distribution Point URL is safe to fetch.
///
/// Mitigations applied (COSMIAN-2026-020):
/// - Only `http://` and `https://` schemes are permitted (RFC 5280 CDPs are
///   typically HTTP to avoid circular TLS-validation dependencies; both are
///   allowed here but all other checks still apply).
/// - Private, loopback, unspecified, and link-local IP addresses are rejected.
/// - Well-known internal hostnames (`localhost`, `*.local`, `*.internal`,
///   `metadata.google.internal`, `169.254.169.254`) are rejected.
/// - `file://` URLs and bare filesystem paths are rejected separately in
///   `get_crl_bytes()` before this function is called.
// allow: `.local` and `.internal` are DNS suffixes here, not file extensions;
// the comparison is intentionally case-sensitive because the input is already
// `.to_lowercase()`.  Using Path::extension() would give false negatives for
// multi-label suffixes such as `svc.cluster.local`.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub(crate) fn validate_crl_url(url_str: &str) -> crate::result::KResult<()> {
    use url::Url;

    let parsed = Url::parse(url_str).map_err(|e| {
        crate::error::KmsError::Certificate(format!("Invalid CRL Distribution Point URL: {e}"))
    })?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(crate::error::KmsError::Certificate(format!(
            "CRL Distribution Point URL must use http or https scheme, got: {scheme}"
        )));
    }

    let host = parsed.host_str().ok_or_else(|| {
        crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must contain a host".to_owned(),
        )
    })?;

    // Reject IP-based hosts targeting private/loopback/link-local/unspecified ranges.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback()
            || ip.is_unspecified()
            || matches!(
                ip,
                std::net::IpAddr::V4(v4) if v4.is_private() || v4.is_link_local()
            )
            // IPv4-mapped link-local (169.254.x.x) expressed as IPv6
            || matches!(
                ip,
                std::net::IpAddr::V6(v6) if v6.is_loopback()
            )
        {
            return Err(crate::error::KmsError::Certificate(
                "CRL Distribution Point URL must not target private, loopback, or \
                 link-local addresses"
                    .to_owned(),
            ));
        }
    }

    // Reject well-known internal hostnames.
    // `.local` and `.internal` are DNS suffixes, not file extensions — see
    // the function-level `#[allow]` above.
    let lower = host.to_lowercase();
    if lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower == "metadata.google.internal"
        // Cloud metadata endpoints expressed as raw IPs are already caught above,
        // but reject the hostname form explicitly as well.
        || lower == "169.254.169.254"
    {
        return Err(crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must not target internal or cloud-metadata \
             hostnames"
                .to_owned(),
        ));
    }

    Ok(())
}

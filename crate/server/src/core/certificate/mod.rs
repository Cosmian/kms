mod find;
pub(crate) mod oracle_signing;

pub(crate) use find::{
    find_ca_issued_certificates, linked_id_str, retrieve_certificate_for_private_key,
    retrieve_issuer_private_key_and_certificate, retrieve_private_key_for_certificate,
};

/// Returns `true` if `v4` is a private (RFC 1918), loopback, link-local, or
/// unspecified IPv4 address — the set of IPv4 ranges that must never be
/// reachable via a CRL Distribution Point fetch.
const fn is_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_private() || v4.is_link_local() || v4.is_loopback() || v4.is_unspecified()
}

/// Returns `true` if `ip` must never be reached by a server-side fetch: the IPv4 ranges of
/// [`is_blocked_ipv4`], IPv6 loopback, unspecified, unique-local (`fc00::/7`) and
/// link-local (`fe80::/10`), and IPv4-mapped IPv6 addresses of blocked IPv4 ranges.
pub(crate) fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some_and(is_blocked_ipv4)
        }
    }
}

/// Is `host` a well-known internal DNS name (`localhost`, `*.local`, `*.internal`, which also
/// covers `metadata.google.internal`)? IP literals are rejected separately by [`is_blocked_ip`].
///
/// `.local` and `.internal` are DNS suffixes, not file extensions; the comparison is done on
/// ASCII-case-insensitive bytes, so it covers multi-label names such as `svc.cluster.local`.
/// A single trailing dot (fully-qualified form, e.g. `localhost.`) resolves identically, so it
/// is ignored.
pub(crate) fn is_blocked_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let ends_with = |suffix: &str| {
        host.len()
            .checked_sub(suffix.len())
            .and_then(|start| host.as_bytes().get(start..))
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix.as_bytes()))
    };
    host.eq_ignore_ascii_case("localhost") || ends_with(".local") || ends_with(".internal")
}

/// Validates that a CRL Distribution Point URL is safe to fetch.
///
/// Mitigations applied (COSMIAN-2026-021):
/// - Only `http://` and `https://` schemes are permitted (RFC 5280 CDPs are
///   typically HTTP to avoid circular TLS-validation dependencies; both are
///   allowed here but all other checks still apply).
/// - IPv4 private (RFC 1918), loopback, unspecified, and link-local
///   addresses are rejected.
/// - IPv6 loopback (`::1`), unspecified (`::`), unique-local (`fc00::/7`,
///   RFC 4193 — the IPv6 equivalent of RFC 1918 private space), and
///   link-local (`fe80::/10`) addresses are rejected. IPv4-mapped IPv6
///   addresses (`::ffff:0:0/96`, RFC 4291) are unwrapped and the embedded
///   IPv4 address is checked against the same IPv4 ranges above, so
///   `http://[::ffff:169.254.169.254]/` cannot be used to reach cloud
///   metadata endpoints. See RFC 6890 for the full special-purpose address
///   registry these ranges are drawn from.
/// - Well-known internal hostnames (see [`is_blocked_hostname`]) are rejected; the cloud
///   metadata address `169.254.169.254` is an IPv4 literal, covered by the IP checks.
/// - `file://` URLs and bare filesystem paths are rejected separately in
///   `get_crl_bytes()` before this function is called.
///
/// The host is obtained via [`url::Url::host()`] rather than
/// [`url::Url::host_str()`]: `host_str()` returns IPv6 hosts wrapped in
/// brackets (e.g. `"[::1]"`), which fails to parse as `std::net::IpAddr` and
/// would silently skip every IP-literal check below for IPv6 URLs.
pub(crate) fn validate_crl_url(url_str: &str) -> crate::result::KResult<()> {
    use url::{Host, Url};

    let parsed = Url::parse(url_str).map_err(|e| {
        crate::error::KmsError::Certificate(format!("Invalid CRL Distribution Point URL: {e}"))
    })?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(crate::error::KmsError::Certificate(format!(
            "CRL Distribution Point URL must use http or https scheme, got: {scheme}"
        )));
    }

    let host = parsed.host().ok_or_else(|| {
        crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must contain a host".to_owned(),
        )
    })?;

    // Reject IP-based hosts targeting private/loopback/link-local/unspecified ranges.
    let blocked = match host {
        Host::Ipv4(v4) => is_blocked_ip(v4.into()),
        Host::Ipv6(v6) => is_blocked_ip(v6.into()),
        Host::Domain(_) => false,
    };
    if blocked {
        return Err(crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must not target private, loopback, or \
             link-local addresses"
                .to_owned(),
        ));
    }

    // Reject well-known internal hostnames.
    if parsed.host_str().is_some_and(is_blocked_hostname) {
        return Err(crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must not target internal or cloud-metadata \
             hostnames"
                .to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_blocked_hostname;

    #[test]
    fn blocked_hostnames_match_whole_dns_suffixes_case_insensitively() {
        for host in [
            "localhost",
            "LocalHost",
            "localhost.",
            "metadata.google.internal",
            "metadata.google.internal.",
            "svc.cluster.LOCAL",
            "foo.local.",
            "a.internal",
        ] {
            assert!(is_blocked_hostname(host), "{host}");
        }
        // Only the exact names and the ".local" / ".internal" suffixes are blocked.
        for host in [
            "",
            "local",
            "internal",
            "example.com",
            "notlocalhost",
            "kms.localhost.com",
        ] {
            assert!(!is_blocked_hostname(host), "{host}");
        }
    }
}

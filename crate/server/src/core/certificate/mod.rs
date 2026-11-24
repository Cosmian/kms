mod find;
pub(crate) mod oracle_signing;

pub(crate) use find::{
    CertificateRecord, find_ca_issued_certificates, linked_id_str,
    retrieve_certificate_for_private_key, retrieve_issuer_private_key_and_certificate,
    retrieve_private_key_for_certificate,
};

/// Returns `true` if `v4` belongs to an IPv4 range that must never be reachable via a CRL
/// Distribution Point fetch: private (RFC 1918), loopback, link-local, unspecified and
/// "this network" (`0.0.0.0/8`), CGNAT (`100.64.0.0/10`), IETF protocol assignments
/// (`192.0.0.0/24`), documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
/// benchmarking (`198.18.0.0/15`), multicast, and reserved/broadcast (`240.0.0.0/4`).
const fn is_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    v4.is_private()
        || v4.is_link_local()
        || v4.is_loopback()
        || v4.is_multicast()
        || a == 0
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a == 198 && (b & 0xfe) == 18)
        || a >= 240
}

/// Returns `true` if the IPv6 address `v6` must never be reached by a server-side fetch.
const fn is_blocked_ipv6(v6: std::net::Ipv6Addr) -> bool {
    let [s0, s1, s2, s3, s4, s5, _, _] = v6.segments();
    let [.., a, b, c, d] = v6.octets();
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || v6.is_multicast()
        // Documentation prefix 2001:db8::/32.
        || (s0 == 0x2001 && s1 == 0x0db8)
        // NAT64 well-known prefix 64:ff9b::/96 embedding a blocked IPv4 address.
        || (s0 == 0x64
            && s1 == 0xff9b
            && s2 == 0
            && s3 == 0
            && s4 == 0
            && s5 == 0
            && is_blocked_ipv4(std::net::Ipv4Addr::new(a, b, c, d)))
}

/// Returns `true` if `ip` must never be reached by a server-side fetch: the IPv4 ranges of
/// [`is_blocked_ipv4`], the IPv6 ranges of [`is_blocked_ipv6`] (loopback, unspecified,
/// unique-local `fc00::/7`, link-local `fe80::/10`, multicast, documentation, NAT64), and
/// IPv4-mapped IPv6 addresses of blocked IPv4 ranges.
pub(crate) fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            is_blocked_ipv6(v6) || v6.to_ipv4_mapped().is_some_and(is_blocked_ipv4)
        }
    }
}

/// Rejects a DNS resolution result that is empty or contains any blocked address.
///
/// A public-looking CRL Distribution Point host name can resolve to an internal address
/// (DNS rebinding / attacker-controlled records); every resolved address is checked, and the
/// caller then pins the connection to exactly these addresses.
///
/// # Errors
/// [`crate::error::KmsError::Certificate`] when `addrs` is empty or any address is blocked.
pub(crate) fn validate_resolved_addrs(
    addrs: &[std::net::SocketAddr],
) -> crate::result::KResult<()> {
    if addrs.is_empty() || addrs.iter().any(|a| is_blocked_ip(a.ip())) {
        return Err(crate::error::KmsError::Certificate(
            "CRL Distribution Point resolves to a forbidden address".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves the host of a CRL Distribution Point URL to socket addresses.
///
/// IP literals are returned directly without any DNS query; domain names are resolved with
/// the system resolver.
///
/// # Errors
/// [`crate::error::KmsError::ClientConnectionError`] when the name cannot be resolved (treated
/// as an unreachable distribution point by `verify_crls`), and
/// [`crate::error::KmsError::Certificate`] when the URL has no host or port.
pub(crate) async fn resolve_crl_host(
    url: &url::Url,
) -> crate::result::KResult<Vec<std::net::SocketAddr>> {
    use std::net::SocketAddr;

    use url::Host;

    let port = url.port_or_known_default().ok_or_else(|| {
        crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must have a port or a known default port".to_owned(),
        )
    })?;
    match url.host() {
        Some(Host::Ipv4(v4)) => Ok(vec![SocketAddr::new(v4.into(), port)]),
        Some(Host::Ipv6(v6)) => Ok(vec![SocketAddr::new(v6.into(), port)]),
        Some(Host::Domain(domain)) => Ok(tokio::net::lookup_host((domain, port))
            .await
            .map_err(|e| {
                crate::error::KmsError::ClientConnectionError(format!(
                    "CRL Distribution Point host '{domain}' cannot be resolved: {e}"
                ))
            })?
            .collect()),
        None => Err(crate::error::KmsError::Certificate(
            "CRL Distribution Point URL must contain a host".to_owned(),
        )),
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
    use std::net::{IpAddr, SocketAddr};

    use super::{is_blocked_hostname, resolve_crl_host, validate_resolved_addrs};

    fn sock(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse::<IpAddr>().unwrap(), port)
    }

    #[test]
    fn resolved_addrs_in_internal_ranges_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "0.1.2.3",
            "192.0.0.8",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.19.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::a00:1",
            "::ffff:169.254.169.254",
        ] {
            let err = validate_resolved_addrs(&[sock(ip, 80)]).unwrap_err();
            assert_eq!(
                err.to_string(),
                "Certificate error: CRL Distribution Point resolves to a forbidden address",
                "{ip}"
            );
        }
        // One blocked address among public ones is enough to reject the whole answer.
        validate_resolved_addrs(&[sock("93.184.216.34", 80), sock("10.0.0.1", 80)]).unwrap_err();
        // An empty resolution result is rejected.
        validate_resolved_addrs(&[]).unwrap_err();
    }

    #[test]
    fn resolved_public_addrs_are_accepted() {
        validate_resolved_addrs(&[
            sock("93.184.216.34", 80),
            sock("2606:2800::1", 80),
            sock("64:ff9b::5db8:d822", 80),
        ])
        .unwrap();
    }

    #[tokio::test]
    async fn resolve_crl_host_returns_ip_literals_without_dns() {
        let url = url::Url::parse("http://93.184.216.34:8080/crl").unwrap();
        assert_eq!(
            resolve_crl_host(&url).await.unwrap(),
            vec![sock("93.184.216.34", 8080)]
        );
        let url = url::Url::parse("https://[2606:2800::1]/crl").unwrap();
        assert_eq!(
            resolve_crl_host(&url).await.unwrap(),
            vec![sock("2606:2800::1", 443)]
        );
    }

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

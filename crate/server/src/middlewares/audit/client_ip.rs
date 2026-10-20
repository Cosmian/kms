//! Client-IP and operation-name extraction from an incoming request.

use std::net::IpAddr;

use actix_web::dev::ServiceRequest;
use ipnet::IpNet;

/// Derives an operation name from the HTTP path by taking the first path segment.
///
/// For KMIP requests the route handler injects a `KmipOperationName` extension with
/// the exact operation name — this function only provides the fallback used when no
/// extension is present (non-KMIP paths, or failures before dispatch).
pub(super) fn extract_operation(path: &str) -> &str {
    let segment = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if segment.is_empty() {
        "unknown"
    } else {
        segment
    }
}

/// Extracts the client IP address.
///
/// The `X-Forwarded-For` header is only trusted when the direct TCP peer address
/// falls within one of the `trusted_proxies` CIDR ranges.  If the peer is not a
/// trusted proxy, or if `trusted_proxies` is empty, the peer address is used
/// directly — preventing clients from spoofing their apparent IP.  Behind a trusted proxy
/// the address is the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy:
/// each proxy appends the address it received the request from, so the leftmost entries are
/// whatever the client chose to send.
pub(super) fn extract_client_ip(req: &ServiceRequest, trusted_proxies: &[IpNet]) -> Option<String> {
    resolve_client_ip(
        req.peer_addr().map(|a| a.ip()),
        forwarded_for(req.headers()).as_deref(),
        trusted_proxies,
    )
    .map(|ip| ip.to_string())
}

/// Every `X-Forwarded-For` line of a request as one comma-separated list. A proxy may append
/// its own line instead of extending the client's, so reading only the first line would read
/// what the client sent.
pub(crate) fn forwarded_for(headers: &actix_web::http::header::HeaderMap) -> Option<String> {
    let lines: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!lines.is_empty()).then(|| lines.join(","))
}

/// Same rule as [`extract_client_ip`] on already extracted values, for handlers that sit
/// outside the audit middleware (EST / SCEP).
pub(crate) fn resolve_client_ip(
    peer_ip: Option<IpAddr>,
    x_forwarded_for: Option<&str>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let peer_is_trusted = peer_ip
        .as_ref()
        .is_some_and(|ip| trusted_proxies.iter().any(|cidr| cidr.contains(ip)));

    if peer_is_trusted {
        for entry in x_forwarded_for.into_iter().flat_map(|v| v.rsplit(',')) {
            // Only trust syntactically valid IPs; on garbage fall back to the peer address
            // so a forged header never reaches the audit log or the enrollment lockout.
            let Ok(parsed) = entry.trim().parse::<IpAddr>() else {
                break;
            };
            if !trusted_proxies.iter().any(|cidr| cidr.contains(&parsed)) {
                return Some(parsed);
            }
        }
    }

    peer_ip
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn operation_extraction_from_paths() {
        assert_eq!(extract_operation("/kmip/2_1"), "kmip");
        assert_eq!(extract_operation("/google_cse/digest"), "google_cse");
        assert_eq!(extract_operation("/ms_dke/version"), "ms_dke");
        assert_eq!(extract_operation("/azure_ekm/keys"), "azure_ekm");
        assert_eq!(extract_operation("/aws_xks/healthcheck"), "aws_xks");
        assert_eq!(extract_operation("/health"), "health");
        assert_eq!(extract_operation("/v1/crypto/encrypt"), "v1");
        assert_eq!(extract_operation("/"), "unknown");
        assert_eq!(extract_operation(""), "unknown");
    }

    /// Helper: build a minimal `ServiceRequest` with a given peer address and
    /// optional `X-Forwarded-For` header.  Uses `actix_web::test::TestRequest`.
    fn make_request(peer: &str, xff: Option<&str>) -> actix_web::test::TestRequest {
        let mut req = actix_web::test::TestRequest::default().peer_addr(peer.parse().unwrap());
        if let Some(v) = xff {
            req = req.insert_header(("x-forwarded-for", v));
        }
        req
    }

    #[test]
    fn xff_ignored_when_no_trusted_proxies() {
        let req = make_request("1.2.3.4:9000", Some("10.0.0.1")).to_srv_request();
        let ip = extract_client_ip(&req, &[]);
        assert_eq!(ip.as_deref(), Some("1.2.3.4"), "peer IP used, XFF ignored");
    }

    #[test]
    fn xff_ignored_when_peer_not_in_trusted_cidr() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("1.2.3.4:9000", Some("192.168.1.1")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("1.2.3.4"),
            "peer is not in CIDR, XFF ignored"
        );
    }

    #[test]
    fn xff_used_when_peer_in_trusted_cidr() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.1:9000", Some("203.0.113.5")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("203.0.113.5"),
            "peer in CIDR, XFF first IP used"
        );
    }

    #[test]
    fn xff_rightmost_untrusted_entry_is_taken_from_comma_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.2:9000", Some("203.0.113.5, 10.0.0.1")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(ip.as_deref(), Some("203.0.113.5"), "trusted hop skipped");
    }

    /// A proxy may add its own `X-Forwarded-For` line instead of extending the client's: the
    /// client's line must not be the one that is read.
    #[test]
    fn xff_lines_are_read_as_one_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.2:9000", Some("198.51.100.99"))
            .append_header(("x-forwarded-for", "203.0.113.5"))
            .to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(ip.as_deref(), Some("203.0.113.5"), "last line, last entry");
    }

    /// The client controls the left of the header: it can neither pick its own address nor
    /// aim the enrollment lockout at someone else's.
    #[test]
    fn xff_entries_forged_by_the_client_are_ignored() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req =
            make_request("10.0.0.2:9000", Some("198.51.100.99, 203.0.113.5")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("203.0.113.5"),
            "added by the trusted proxy"
        );
        let req = make_request("10.0.0.2:9000", Some("203.0.113.5, not-an-ip")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("10.0.0.2"),
            "garbage falls back to the peer"
        );
    }

    #[test]
    fn xff_absent_with_trusted_proxy_falls_back_to_peer() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.1:9000", None).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("10.0.0.1"),
            "no XFF header, peer IP used"
        );
    }
}

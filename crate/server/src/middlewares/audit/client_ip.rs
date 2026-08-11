//! Client-IP and operation-name extraction from an incoming request.

use std::net::IpAddr;

use actix_web::dev::ServiceRequest;
use ipnet::IpNet;

/// Derives an operation name from the HTTP path by taking the first path segment.
///
/// For KMIP requests the route handler injects a `KmipOperationName` extension with
/// the exact operation name — this function only provides the fallback used when no
/// extension is present (non-KMIP paths, or failures before dispatch).
pub(super) fn extract_operation(path: &str) -> String {
    let segment = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if segment.is_empty() {
        "unknown".to_owned()
    } else {
        segment.to_owned()
    }
}

/// Extracts the client IP address.
///
/// The `X-Forwarded-For` header is only trusted when the direct TCP peer address
/// falls within one of the `trusted_proxies` CIDR ranges.  If the peer is not a
/// trusted proxy, or if `trusted_proxies` is empty, the peer address is used
/// directly — preventing clients from spoofing their apparent IP.
pub(super) fn extract_client_ip(req: &ServiceRequest, trusted_proxies: &[IpNet]) -> Option<String> {
    let peer_ip = req.peer_addr().map(|a| a.ip());

    let peer_is_trusted = peer_ip
        .as_ref()
        .is_some_and(|ip| trusted_proxies.iter().any(|cidr| cidr.contains(ip)));

    if peer_is_trusted {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(val) = xff.to_str() {
                if let Some(ip) = val.split(',').next() {
                    // Only trust a syntactically valid IP; otherwise fall back to the
                    // peer address so garbage headers never reach the audit log.
                    if let Ok(parsed) = ip.trim().parse::<IpAddr>() {
                        return Some(parsed.to_string());
                    }
                }
            }
        }
    }

    peer_ip.map(|ip| ip.to_string())
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
    fn xff_first_ip_taken_from_comma_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.2:9000", Some("203.0.113.5, 10.0.0.1")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(ip.as_deref(), Some("203.0.113.5"), "first XFF entry used");
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

    #[test]
    fn xff_malformed_ip_falls_back_to_peer() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.1:9000", Some("not-an-ip")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("10.0.0.1"),
            "malformed XFF, peer IP used"
        );
    }
}

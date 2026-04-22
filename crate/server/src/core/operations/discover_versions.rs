use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::{
    kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
    kmip_types::ProtocolVersion,
};
use cosmian_logger::trace;

/// This request is used by the client to determine a list of protocol versions
/// that is supported by the server.
/// The request payload contains an optional list of protocol versions
/// that is supported by the client. The protocol versions SHALL be ranked
/// in order of preference (highest preference first).
// The response payload contains a list of protocol versions that is supported by the server.
// The protocol versions are ranked in order of preference (highest preference first).
// If the client provides the server with a list of supported protocol versions
// in the request payload, the server SHALL return only the protocol versions
// that are supported by both the client and server.
// The server SHOULD list all the protocol versions supported by both client and server.
// If the protocol version specified in the request header is not specified in the request
// payload and the server does not support any protocol version specified in the request payload,
// the server SHALL return an empty list in the response payload.
// If no protocol versions are specified in the request payload,
// the server SHOULD simply return all the protocol versions that are supported by the server.
pub(crate) async fn discover_versions(request: DiscoverVersions) -> DiscoverVersionsResponse {
    trace!(
        "Discover versions: {}",
        serde_json::to_string(&request).unwrap_or_else(|_| "[N/A]".to_owned())
    );

    let supported = vec![
        ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: 1,
        },
        ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: 0,
        },
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 4,
        },
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 3,
        },
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 2,
        },
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        },
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 0,
        },
    ];

    if let Some(requested_versions) = request.protocol_version {
        // build intersection of supported versions
        let mut response = Vec::new();
        for version in requested_versions {
            if supported.contains(&version) {
                response.push(version);
            }
        }
        return DiscoverVersionsResponse {
            protocol_version: if response.is_empty() {
                None
            } else {
                Some(response)
            },
        };
    }

    // no requested versions, return all supported versions
    DiscoverVersionsResponse {
        protocol_version: Some(supported),
    }
}

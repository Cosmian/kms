//! Audit-context extraction for KMIP route handlers.
//!
//! These functions peek at the raw TTLV *before* full deserialization and inject
//! `KmipOperationName`, `KmipObjectUid`, and `KmipAlgorithm` into the Actix
//! request extensions so the audit middleware can record them after dispatch.
//!

// Note: Infallibility
//
// All functions in this module are infallible: no `unwrap`, no `expect`, no `?`.
// Missing or unexpected TTLV structure always yields `None` or a fallback string —
// never a panic. A failure here affects only the audit record, not the KMIP response.

use actix_web::{HttpMessage, HttpRequest};
use cosmian_kms_server_database::reexport::cosmian_kmip::ttlv::{TTLV, TTLValue};

use crate::middlewares::{KmipAlgorithm, KmipObjectUid, KmipOperationName};

/// Extracts the specific KMIP operation name from a TTLV for audit purposes.
///
/// * Single-operation requests (e.g. `"Encrypt"`, `"Create"`): returns `ttlv.tag`.
/// * `RequestMessage` (batch): returns all `BatchItem` operation names joined with `+`
///   (e.g. `"Create+Encrypt+Destroy"`), or `"Message"` if none can be found.
pub(super) fn extract_kmip_op_from_ttlv(ttlv: &TTLV) -> String {
    if ttlv.tag != "RequestMessage" {
        return ttlv.tag.clone();
    }
    if let TTLValue::Structure(items) = &ttlv.value {
        let ops: Vec<String> = items
            .iter()
            .filter(|item| item.tag == "BatchItem")
            .filter_map(|item| {
                if let TTLValue::Structure(fields) = &item.value {
                    fields.iter().find(|f| f.tag == "Operation").and_then(|f| {
                        if let TTLValue::Enumeration(ev) = &f.value {
                            Some(ev.name.clone())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
            .collect();
        if !ops.is_empty() {
            return ops.join("+"); // TODO: this is not standard, but it will be worked on in the future
        }
    }
    "Message".to_owned()
}

/// Depth-first search for the first `TTLV` node with the given tag.
/// Used for response-side extraction where the layout is well-defined.
fn find_ttlv_recursive<'a>(ttlv: &'a TTLV, tag: &str) -> Option<&'a TTLV> {
    if ttlv.tag == tag {
        return Some(ttlv);
    }
    if let TTLValue::Structure(children) = &ttlv.value {
        for child in children {
            if let Some(found) = find_ttlv_recursive(child, tag) {
                return Some(found);
            }
        }
    }
    None
}

/// Extracts the `UniqueIdentifier` for audit purposes from a single-operation TTLV.
///
/// * `is_response = false` — looks for `UniqueIdentifier` as a **direct child** of
///   the operation node (avoids picking up nested UIDs from `Link` structures).
/// * `is_response = true` — used for Create/CreateKeyPair where the server-generated
///   UID only appears in the response TTLV; performs a recursive search.
///
/// Returns `None` for batch (`RequestMessage`) TTLVs; the caller must not pass those.
fn extract_object_uid(ttlv: &TTLV, op_name: &str, is_response: bool) -> Option<String> {
    let text_string = |t: &TTLV| {
        if let TTLValue::TextString(s) = &t.value {
            Some(s.clone())
        } else {
            None
        }
    };
    match op_name {
        op if op.contains('+') => None,
        "Create" | "CreateKeyPair" if is_response => {
            find_ttlv_recursive(ttlv, "UniqueIdentifier").and_then(text_string)
        }
        "Create" | "CreateKeyPair" => None,
        _ => {
            if let TTLValue::Structure(children) = &ttlv.value {
                children
                    .iter()
                    .find(|c| c.tag == "UniqueIdentifier")
                    .and_then(text_string)
            } else {
                None
            }
        }
    }
}

/// Extracts the `CryptographicAlgorithm` for audit purposes from a single-operation TTLV.
///
/// * Create / `CreateKeyPair` / Register: algorithm is in `Attributes → CryptographicAlgorithm`.
/// * Encrypt / Decrypt / MAC / Sign / Verify / `SignatureVerify`: algorithm is in
///   `CryptographicParameters → CryptographicAlgorithm`.
///
/// Returns `None` for operations that carry no algorithm information or for batch TTLVs.
fn extract_algorithm(ttlv: &TTLV, op_name: &str) -> Option<String> {
    let enum_name = |t: &TTLV| {
        if let TTLValue::Enumeration(ev) = &t.value {
            Some(ev.name.clone())
        } else {
            None
        }
    };
    let child_algo = |parent: &TTLV| -> Option<String> {
        if let TTLValue::Structure(c) = &parent.value {
            c.iter()
                .find(|t| t.tag == "CryptographicAlgorithm")
                .and_then(enum_name)
        } else {
            None
        }
    };

    match op_name {
        op if op.contains('+') => None,
        "Create" | "CreateKeyPair" | "Register" => {
            if let TTLValue::Structure(children) = &ttlv.value {
                children
                    .iter()
                    .find(|c| c.tag == "Attributes")
                    .and_then(child_algo)
            } else {
                None
            }
        }
        "Encrypt" | "Decrypt" | "MAC" | "Sign" | "Verify" | "SignatureVerify" => {
            if let TTLValue::Structure(children) = &ttlv.value {
                children
                    .iter()
                    .find(|c| c.tag == "CryptographicParameters")
                    .and_then(child_algo)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Injects `KmipOperationName`, `KmipObjectUid`, and `KmipAlgorithm` into the
/// request extensions for the audit middleware. Returns the operation name.
/// `RefMut` is dropped on return — safe to call before `.await`.
pub(super) fn inject_audit_request(req: &HttpRequest, ttlv: &TTLV) -> String {
    let op_name = extract_kmip_op_from_ttlv(ttlv);
    let mut ext = req.extensions_mut();
    ext.insert(KmipOperationName(op_name.clone()));
    if let Some(uid) = extract_object_uid(ttlv, &op_name, false) {
        ext.insert(KmipObjectUid(uid));
    }
    if let Some(algo) = extract_algorithm(ttlv, &op_name) {
        ext.insert(KmipAlgorithm(algo));
    }
    op_name
}

/// Backfills `KmipObjectUid` from the response TTLV for `Create` / `CreateKeyPair`,
/// where the UID is server-generated and absent from the request.
pub(super) fn inject_response_uid(req: &HttpRequest, response_ttlv: &TTLV, op_name: &str) {
    if !op_name.contains('+')
        && (op_name == "Create" || op_name == "CreateKeyPair")
        && req.extensions().get::<KmipObjectUid>().is_none()
    {
        if let Some(uid) = extract_object_uid(response_ttlv, op_name, true) {
            req.extensions_mut().insert(KmipObjectUid(uid));
        }
    }
}

#[cfg(test)]
mod extraction_tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::ttlv::{
        KmipEnumerationVariant, TTLV, TTLValue,
    };

    use super::{extract_algorithm, extract_object_uid, find_ttlv_recursive};

    fn text(tag: &str, value: &str) -> TTLV {
        TTLV {
            tag: tag.to_owned(),
            value: TTLValue::TextString(value.to_owned()),
        }
    }

    fn enumv(tag: &str, name: &str) -> TTLV {
        TTLV {
            tag: tag.to_owned(),
            value: TTLValue::Enumeration(KmipEnumerationVariant {
                value: 0,
                name: name.to_owned(),
            }),
        }
    }

    fn structure(tag: &str, children: Vec<TTLV>) -> TTLV {
        TTLV {
            tag: tag.to_owned(),
            value: TTLValue::Structure(children),
        }
    }

    /// Create request: no UID in request, algorithm extracted from Attributes.
    #[test]
    fn create_request_no_uid_has_algorithm() {
        let ttlv = structure(
            "Create",
            vec![
                enumv("ObjectType", "SymmetricKey"),
                structure("Attributes", vec![enumv("CryptographicAlgorithm", "AES")]),
            ],
        );
        assert_eq!(extract_object_uid(&ttlv, "Create", false), None);
        assert_eq!(extract_algorithm(&ttlv, "Create").as_deref(), Some("AES"));
    }

    /// Encrypt request: UID from direct child, algorithm from `CryptographicParameters`.
    #[test]
    fn encrypt_request_extracts_uid_and_algorithm() {
        let ttlv = structure(
            "Encrypt",
            vec![
                text("UniqueIdentifier", "my-key-id"),
                structure(
                    "CryptographicParameters",
                    vec![enumv("CryptographicAlgorithm", "AES")],
                ),
            ],
        );
        assert_eq!(
            extract_object_uid(&ttlv, "Encrypt", false).as_deref(),
            Some("my-key-id")
        );
        assert_eq!(extract_algorithm(&ttlv, "Encrypt").as_deref(), Some("AES"));
    }

    /// Get request: UID from direct child, no algorithm.
    #[test]
    fn get_request_extracts_uid_no_algorithm() {
        let ttlv = structure("Get", vec![text("UniqueIdentifier", "key-abc")]);
        assert_eq!(
            extract_object_uid(&ttlv, "Get", false).as_deref(),
            Some("key-abc")
        );
        assert_eq!(extract_algorithm(&ttlv, "Get"), None);
    }

    /// Create response: recursive search finds the server-generated UID.
    #[test]
    fn create_response_extracts_uid_recursively() {
        let ttlv = structure(
            "CreateResponse",
            vec![
                text("UniqueIdentifier", "server-gen-uid"),
                enumv("ObjectType", "SymmetricKey"),
            ],
        );
        assert_eq!(
            extract_object_uid(&ttlv, "Create", true).as_deref(),
            Some("server-gen-uid")
        );
    }

    /// Batch op names ('+'-joined): both extractors return None.
    #[test]
    fn batch_op_name_returns_none() {
        let ttlv = structure("RequestMessage", vec![text("UniqueIdentifier", "some-id")]);
        assert_eq!(extract_object_uid(&ttlv, "Create+Encrypt", false), None);
        assert_eq!(extract_algorithm(&ttlv, "Create+Encrypt"), None);
    }

    /// Regression: a UID nested inside a Link structure must NOT be returned
    /// for a direct-child-only search (e.g. on a Get response containing a link).
    #[test]
    fn nested_link_uid_not_leaked() {
        let ttlv = structure(
            "GetResponse",
            vec![structure(
                "Attributes",
                vec![structure(
                    "Link",
                    vec![text("UniqueIdentifier", "linked-key-id")],
                )],
            )],
        );
        assert_eq!(extract_object_uid(&ttlv, "GetResponse", false), None);
    }

    /// `find_ttlv_recursive`: basic depth-first traversal.
    #[test]
    fn recursive_find_traverses_deeply() {
        let ttlv = structure(
            "Root",
            vec![structure(
                "Level1",
                vec![structure("Level2", vec![text("Target", "found")])],
            )],
        );
        let found = find_ttlv_recursive(&ttlv, "Target");
        assert!(matches!(found, Some(node) if node.tag == "Target"));
    }
}

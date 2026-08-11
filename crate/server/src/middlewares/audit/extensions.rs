//! Request-extension marker types used to pass KMIP-specific audit context from route handlers
//! (`routes/kmip/audit.rs`) to the audit middleware (`super::mod`).

use cosmian_kms_access::audit::AuditResult;

/// KMIP-specific operation name injected by the KMIP route handlers so the audit middleware
/// records the exact operation ("Encrypt", "Create", …) instead of the coarse path-derived
/// grouping ("KMIP").
#[derive(Debug, Clone)]
pub(crate) struct KmipOperationName(pub String);

/// KMIP object UID injected by the KMIP route handler for audit purposes.
/// For Create/CreateKeyPair this is the server-generated UID from the response TTLV.
/// For object-bearing ops (Encrypt, Decrypt, Get, Destroy, …) it is the
/// `UniqueIdentifier` from the request TTLV.
#[derive(Debug, Clone)]
pub(crate) struct KmipObjectUid(pub String);

/// KMIP cryptographic algorithm (e.g. `"AES"`, `"RSA"`) injected by the KMIP
/// route handler for audit purposes.
#[derive(Debug, Clone)]
pub(crate) struct KmipAlgorithm(pub String);

/// Per-`BatchItem` audit context extracted from a `RequestMessage` TTLV.
/// Injected by the KMIP route handler for batch requests.
#[derive(Debug, Clone)]
pub(crate) struct BatchItemAuditContext {
    pub operation: String,
    pub object_uid: Option<String>,
    pub algorithm: Option<String>,
    /// Per-item result backfilled from the `ResponseMessage` after dispatch.
    pub result: Option<AuditResult>,
}

/// Container for per-`BatchItem` audit contexts extracted from a `RequestMessage`.
/// Injected into request extensions by `inject_audit_request`; consumed by the
/// audit middleware to fan out one `AuditEventDraft` per item.
#[derive(Debug, Clone)]
pub(crate) struct KmipBatchOperations(pub Vec<BatchItemAuditContext>);

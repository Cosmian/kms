// Centralized set of KMIP tags that represent byte-like fields.
// Used by normalization to collapse runs or wrappers into ByteString values.
// Keep this list conservative and informed by protocol fields and observed encodings.
pub(crate) const BYTE_LIKE_TAGS: &[&str] = &[
    // Generic
    "ByteString",
    "Key",
    // KMIP 2.1 messages/types + common vector fields
    "UniqueBatchItemID",
    "AsynchronousCorrelationValue",
    // Derivation parameters (both canonical and serde-derived lowercase)
    "Salt",
    "DerivationData",
    "InitializationVector",
    "salt",
    "derivation_data",
    "initialization_vector",
    // Other byte-like fields encountered across requests/responses
    "VendorExtension",
    "CertificateValue",
    "OpaqueDataValue",
    "DigestValue",
    "IVCounterNonce",
    "CorrelationValue",
    "AuthenticatedEncryptionAdditionalData",
    "AuthenticatedEncryptionTag",
    "SignatureData",
    "DigestedData",
    "CertificateRequestValue",
    "IssuerDistinguishedName",
    "CertificateSerialNumber",
    "TicketValue",
    "Data",
    "AttestationMeasurement",
    "AttestationAssertion",
    "ServerHashedPassword",
    // Accept both official and commonly cased forms
    "MACData",
    "MacData",
    "ClientCorrelationValue",
    "ServerCorrelationValue",
    // Wrapping/MAC signatures
    "MACSignature",
    // EC public key octet string
    "QString",
    // KMIP 0 Nonce variants
    "NonceID",
    "NonceId",
    "NonceValue",
];

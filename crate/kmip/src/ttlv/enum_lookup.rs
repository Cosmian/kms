/// Look up the numeric KMIP code for a textual enumeration variant name.
///
/// Returns `(code, canonical_name)` if the name is known, or `None` otherwise.
/// This table covers all enumeration values used by the KMIP 1.4 and 2.1 specs
/// that appear in test vectors and integration payloads.
///
/// This function is shared between the XML deserializer and the
/// `TTLV::resolve_enumeration_values()` method so that JSON-originated TTLV
/// trees can be reliably serialized to binary TTLV.
#[expect(clippy::too_many_lines)]
#[must_use]
pub fn lookup_enum_code(name: &str) -> Option<(u32, &'static str)> {
    let key = name.replace('-', "_");
    match key.as_str() {
        // ── OperationEnumeration ──────────────────────────────────────
        "Create" => Some((0x0000_0001, "Create")),
        "CreateKeyPair" => Some((0x0000_0002, "CreateKeyPair")),
        "Register" => Some((0x0000_0003, "Register")),
        "ReKey" => Some((0x0000_0004, "ReKey")),
        "DeriveKey" => Some((0x0000_0005, "DeriveKey")),
        "Certify" => Some((0x0000_0006, "Certify")),
        "ReCertify" => Some((0x0000_0007, "ReCertify")),
        "Locate" => Some((0x0000_0008, "Locate")),
        "Check" => Some((0x0000_0009, "Check")),
        "Get" => Some((0x0000_000A, "Get")),
        "GetAttributes" => Some((0x0000_000B, "GetAttributes")),
        "GetAttributeList" => Some((0x0000_000C, "GetAttributeList")),
        "AddAttribute" => Some((0x0000_000D, "AddAttribute")),
        "ModifyAttribute" => Some((0x0000_000E, "ModifyAttribute")),
        "DeleteAttribute" => Some((0x0000_000F, "DeleteAttribute")),
        "ObtainLease" => Some((0x0000_0010, "ObtainLease")),
        "GetUsageAllocation" => Some((0x0000_0011, "GetUsageAllocation")),
        "Activate" => Some((0x0000_0012, "Activate")),
        "Revoke" => Some((0x0000_0013, "Revoke")),
        "Destroy" => Some((0x0000_0014, "Destroy")),
        "Archive" => Some((0x0000_0015, "Archive")),
        "Recover" => Some((0x0000_0016, "Recover")),
        "Validate" => Some((0x0000_0017, "Validate")),
        "Query" => Some((0x0000_0018, "Query")),
        "Cancel" => Some((0x0000_0019, "Cancel")),
        "Poll" => Some((0x0000_001A, "Poll")),
        "Notify" => Some((0x0000_001B, "Notify")),
        "Put" => Some((0x0000_001C, "Put")),
        "ReKeyKeyPair" => Some((0x0000_001D, "ReKeyKeyPair")),
        "DiscoverVersions" => Some((0x0000_001E, "DiscoverVersions")),
        "Encrypt" => Some((0x0000_001F, "Encrypt")),
        "Decrypt" => Some((0x0000_0020, "Decrypt")),
        "Sign" => Some((0x0000_0021, "Sign")),
        "SignatureVerify" => Some((0x0000_0022, "SignatureVerify")),
        "MAC" => Some((0x0000_0023, "MAC")),
        "MACVerify" => Some((0x0000_0024, "MACVerify")),
        "RNGRetrieve" => Some((0x0000_0025, "RNGRetrieve")),
        "RNGSeed" => Some((0x0000_0026, "RNGSeed")),
        "Hash" => Some((0x0000_0027, "Hash")),
        "CreateSplitKey" => Some((0x0000_0028, "CreateSplitKey")),
        "JoinSplitKey" => Some((0x0000_0029, "JoinSplitKey")),
        "Import" => Some((0x0000_002A, "Import")),
        "Export" => Some((0x0000_002B, "Export")),
        "Log" => Some((0x0000_002C, "Log")),
        "Login" => Some((0x0000_002D, "Login")),
        "Logout" => Some((0x0000_002E, "Logout")),
        "DelegatedLogin" => Some((0x0000_002F, "DelegatedLogin")),
        "AdjustAttribute" => Some((0x0000_0030, "AdjustAttribute")),
        "SetAttribute" => Some((0x0000_0031, "SetAttribute")),
        "SetEndpointRole" => Some((0x0000_0032, "SetEndpointRole")),
        "PKCS_11" | "PKCS11" => Some((0x0000_0033, "PKCS11")),
        "Interop" => Some((0x0000_0034, "Interop")),
        "ReProvision" => Some((0x0000_0035, "ReProvision")),
        "SetDefaults" => Some((0x0000_0036, "SetDefaults")),
        "SetConstraints" => Some((0x0000_0037, "SetConstraints")),
        "GetConstraints" => Some((0x0000_0038, "GetConstraints")),
        "QueryAsynchronousRequests" => Some((0x0000_0039, "QueryAsynchronousRequests")),
        "Process" => Some((0x0000_003A, "Process")),
        "Ping" => Some((0x0000_003B, "Ping")),

        // ── QueryFunction ─────────────────────────────────────────────
        "QueryOperations" => Some((0x0000_0001, "QueryOperations")),
        "QueryObjects" => Some((0x0000_0002, "QueryObjects")),
        "QueryServerInformation" => Some((0x0000_0003, "QueryServerInformation")),
        "QueryApplicationNamespaces" => Some((0x0000_0004, "QueryApplicationNamespaces")),
        "QueryExtensionList" => Some((0x0000_0005, "QueryExtensionList")),
        "QueryExtensionMap" => Some((0x0000_0006, "QueryExtensionMap")),
        "QueryAttestationTypes" => Some((0x0000_0007, "QueryAttestationTypes")),
        "QueryRNGs" => Some((0x0000_0008, "QueryRNGs")),
        "QueryValidations" => Some((0x0000_0009, "QueryValidations")),
        "QueryProfiles" => Some((0x0000_000A, "QueryProfiles")),
        "QueryCapabilities" => Some((0x0000_000B, "QueryCapabilities")),
        "QueryClientRegistrationMethods" => Some((0x0000_000C, "QueryClientRegistrationMethods")),
        "QueryDefaultsInformation" => Some((0x0000_000D, "QueryDefaultsInformation")),
        "QueryStorageProtectionMasks" => Some((0x0000_000E, "QueryStorageProtectionMasks")),

        // ── ResultStatusEnumeration ───────────────────────────────────
        "Success" => Some((0x0000_0000, "Success")),
        "OperationFailed" => Some((0x0000_0001, "OperationFailed")),
        "OperationPending" | "Pending" => Some((0x0000_0002, "OperationPending")),
        "OperationUndone" => Some((0x0000_0003, "OperationUndone")),
        "Undo" => Some((0x0000_0003, "Undo")),

        // ── ObjectType ────────────────────────────────────────────────
        "Certificate" => Some((0x0000_0001, "Certificate")),
        "SymmetricKey" => Some((0x0000_0002, "SymmetricKey")),
        "PublicKey" => Some((0x0000_0003, "PublicKey")),
        "PrivateKey" => Some((0x0000_0004, "PrivateKey")),
        "SecretData" => Some((0x0000_0007, "SecretData")),
        "SplitKey" => Some((0x0000_0005, "SplitKey")),
        "Template" => Some((0x0000_0006, "Template")),
        "OpaqueObject" => Some((0x0000_0008, "OpaqueObject")),
        "PGPKey" => Some((0x0000_0009, "PGPKey")),
        "CertificateRequest" => Some((0x0000_000A, "CertificateRequest")),

        // ── NameType ──────────────────────────────────────────────────
        "UninterpretedTextString" => Some((0x1, "UninterpretedTextString")),
        "URI" => Some((0x2, "URI")),

        // ── SecretDataType ────────────────────────────────────────────
        "Password" => Some((0x0000_0001, "Password")),
        "Seed" => Some((0x0000_0002, "Seed")),

        // ── State ─────────────────────────────────────────────────────
        "PreActive" => Some((0x0000_0001, "PreActive")),
        "Active" => Some((0x0000_0002, "Active")),
        "Deactivated" => Some((0x0000_0003, "Deactivated")),
        "Compromised" => Some((0x0000_0004, "Compromised")),
        "Destroyed" => Some((0x0000_0005, "Destroyed")),
        "DestroyedCompromised" => Some((0x0000_0006, "DestroyedCompromised")),

        // ── KeyFormatType ─────────────────────────────────────────────
        "Raw" => Some((0x01, "Raw")),
        "Opaque" => Some((0x02, "Opaque")),
        "PKCS1" | "PKCS_1" => Some((0x03, "PKCS1")),
        "PKCS8" | "PKCS_8" => Some((0x04, "PKCS8")),
        "X509" | "X_509" => Some((0x05, "X509")),
        "TransparentRSAPublicKey" => Some((0x0000_0006, "TransparentRSAPublicKey")),
        "TransparentRSAPrivateKey" => Some((0x0000_0007, "TransparentRSAPrivateKey")),
        "TransparentSymmetricKey" => Some((0x0000_0007, "TransparentSymmetricKey")),
        "TransparentDSAPublicKey" => Some((0x0000_0008, "TransparentDSAPublicKey")),
        "TransparentDSAPrivateKey" => Some((0x0000_0009, "TransparentDSAPrivateKey")),
        "TransparentDHPublicKey" => Some((0x0000_000A, "TransparentDHPublicKey")),
        "TransparentDHPrivateKey" => Some((0x0000_000B, "TransparentDHPrivateKey")),
        "TransparentECDSAPublicKey" => Some((0x0000_000C, "TransparentECDSAPublicKey")),
        "TransparentECDSAPrivateKey" => Some((0x0000_000D, "TransparentECDSAPrivateKey")),
        "TransparentECDHPublicKey" => Some((0x0000_000E, "TransparentECDHPublicKey")),
        "TransparentECDHPrivateKey" => Some((0x0000_000F, "TransparentECDHPrivateKey")),
        "TransparentECMQVPrivateKey" => Some((0x0000_0010, "TransparentECMQVPrivateKey")),
        "ECPrivateKey" => Some((0x0000_0011, "ECPrivateKey")),

        // ── CryptographicAlgorithm ────────────────────────────────────
        "DES" => Some((0x0000_0001, "DES")),
        "THREE_DES" | "3DES" | "DES3" => Some((0x0000_0002, "")),
        "AES" => Some((0x0000_0003, "AES")),
        "RSA" => Some((0x0000_0004, "RSA")),
        "DSA" => Some((0x0000_0005, "DSA")),
        "ECDSA" => Some((0x0000_0006, "ECDSA")),
        "HMAC_SHA1" => Some((0x0000_0007, "HMACSHA1")),
        "HMAC_SHA224" => Some((0x0000_0008, "HMACSHA224")),
        "HMAC_SHA256" => Some((0x0000_0009, "HMACSHA256")),
        "HMAC_SHA384" => Some((0x0000_000A, "HMACSHA384")),
        "HMAC_SHA512" => Some((0x0000_000B, "HMACSHA512")),
        "ChaCha20" => Some((0x0000_001C, "ChaCha20")),
        "ChaCha20Poly1305" => Some((0x0000_001E, "ChaCha20Poly1305")),
        "SKIPJACK" => Some((0x0000_0018, "SKIPJACK")),

        // ── HashingAlgorithm ──────────────────────────────────────────
        "SHA1" | "SHA_1" => Some((0x0000_0004, "SHA1")),
        "SHA224" | "SHA_224" => Some((0x0000_0005, "SHA224")),
        "SHA256" | "SHA_256" => Some((0x0000_0006, "SHA256")),
        "SHA384" | "SHA_384" => Some((0x0000_0007, "SHA384")),
        "SHA512" | "SHA_512" => Some((0x0000_0008, "SHA512")),

        // ── RevocationReasonCode ──────────────────────────────────────
        "Unspecified" | "UNSPECIFIED_RNG" | "RNG_Unspecified" => Some((0x0000_0001, "Unspecified")),
        "KeyCompromise" => Some((0x0000_0002, "KeyCompromise")),
        "CACompromise" => Some((0x0000_0003, "CACompromise")),
        "AffiliationChanged" => Some((0x0000_0004, "AffiliationChanged")),
        "Superseded" => Some((0x0000_0005, "Superseded")),
        "CessationOfOperation" => Some((0x0000_0006, "CessationOfOperation")),
        "PrivilegeWithdrawn" => Some((0x0000_0007, "PrivilegeWithdrawn")),

        // ── ResultReason ──────────────────────────────────────────────
        "ItemNotFound" => Some((0x0000_0001, "Item_Not_Found")),
        "ResponseTooLarge" => Some((0x0000_0002, "Response_Too_Large")),
        "AuthenticationNotSuccessful" => Some((0x0000_0003, "Authentication_Not_Successful")),
        "InvalidMessage" => Some((0x0000_0004, "Invalid_Message")),
        "OperationNotSupported" => Some((0x0000_0005, "Operation_Not_Supported")),
        "MissingData" => Some((0x0000_0006, "Missing_Data")),
        "InvalidField" => Some((0x0000_0007, "Invalid_Field")),
        "FeatureNotSupported" => Some((0x0000_0008, "Feature_Not_Supported")),
        "OperationCanceledByRequester" => Some((0x0000_0009, "Operation_Canceled_By_Requester")),
        "CryptographicFailure" => Some((0x0000_000A, "Cryptographic_Failure")),
        "PermissionDenied" => Some((0x0000_000C, "Permission_Denied")),
        "ObjectArchived" => Some((0x0000_000D, "Object_Archived")),
        "ApplicationNamespaceNotSupported" => {
            Some((0x0000_000F, "Application_Namespace_Not_Supported"))
        }
        "KeyFormatTypeNotSupported" => Some((0x0000_0010, "Key_Format_Type_Not_Supported")),
        "KeyCompressionTypeNotSupported" => {
            Some((0x0000_0011, "Key_Compression_Type_Not_Supported"))
        }
        "EncodingOptionError" => Some((0x0000_0012, "Encoding_Option_Error")),
        "KeyValueNotPresent" => Some((0x0000_0013, "Key_Value_Not_Present")),
        "AttestationRequired" => Some((0x0000_0014, "Attestation_Required")),
        "AttestationFailed" => Some((0x0000_0015, "Attestation_Failed")),
        "Sensitive" => Some((0x0000_0016, "Sensitive")),
        "NotExtractable" => Some((0x0000_0017, "Not_Extractable")),
        "ObjectAlreadyExists" => Some((0x0000_0018, "Object_Already_Exists")),
        "InvalidTicket" => Some((0x0000_0019, "Invalid_Ticket")),
        "UsageLimitExceeded" => Some((0x0000_001A, "Usage_Limit_Exceeded")),
        "NumericRange" => Some((0x0000_001B, "Numeric_Range")),
        "InvalidDataType" => Some((0x0000_001C, "Invalid_Data_Type")),
        "ReadOnlyAttribute" => Some((0x0000_001D, "Read_Only_Attribute")),
        "MultiValuedAttribute" => Some((0x0000_001E, "Multi_Valued_Attribute")),
        "UnsupportedAttribute" => Some((0x0000_001F, "Unsupported_Attribute")),
        "AttributeInstanceNotFound" => Some((0x0000_0020, "Attribute_Instance_Not_Found")),
        "AttributeNotFound" => Some((0x0000_0021, "Attribute_Not_Found")),
        "AttributeReadOnly" => Some((0x0000_0022, "Attribute_Read_Only")),
        "AttributeSingleValued" => Some((0x0000_0023, "Attribute_Single_Valued")),
        "BadCryptographicParameters" => Some((0x0000_0024, "Bad_Cryptographic_Parameters")),
        "BadPassword" => Some((0x0000_0025, "Bad_Password")),
        "CodecError" => Some((0x0000_0026, "Codec_Error")),
        "IllegalObjectType" => Some((0x0000_0028, "Illegal_Object_Type")),
        "IncompatibleCryptographicUsageMask" => {
            Some((0x0000_0029, "Incompatible_Cryptographic_Usage_Mask"))
        }
        "InternalServerError" => Some((0x0000_002A, "Internal_Server_Error")),
        "InvalidAsynchronousCorrelationValue" => {
            Some((0x0000_002B, "Invalid_Asynchronous_Correlation_Value"))
        }
        "InvalidAttribute" => Some((0x0000_002C, "Invalid_Attribute")),
        "InvalidAttributeValue" => Some((0x0000_002D, "Invalid_Attribute_Value")),
        "InvalidCorrelationValue" => Some((0x0000_002E, "Invalid_Correlation_Value")),
        "InvalidCSR" => Some((0x0000_002F, "Invalid_CSR")),
        "InvalidObjectType" => Some((0x0000_0030, "Invalid_Object_Type")),
        "KeyWrapTypeNotSupported" => Some((0x0000_0032, "Key_Wrap_Type_Not_Supported")),
        "MissingInitializationVector" => Some((0x0000_0034, "Missing_Initialization_Vector")),
        "NonUniqueNameAttribute" => Some((0x0000_0035, "Non_Unique_Name_Attribute")),
        "ObjectDestroyed" => Some((0x0000_0036, "Object_Destroyed")),
        "ObjectNotFound" => Some((0x0000_0037, "Object_Not_Found")),
        "NotAuthorised" => Some((0x0000_0039, "Not_Authorised")),
        "ServerLimitExceeded" => Some((0x0000_003A, "Server_Limit_Exceeded")),
        "UnknownEnumeration" => Some((0x0000_003B, "Unknown_Enumeration")),
        "UnknownMessageExtension" => Some((0x0000_003C, "Unknown_Message_Extension")),
        "UnknownTag" => Some((0x0000_003D, "Unknown_Tag")),
        "UnsupportedCryptographicParameters" => {
            Some((0x0000_003E, "Unsupported_Cryptographic_Parameters"))
        }
        "UnsupportedProtocolVersion" => Some((0x0000_003F, "Unsupported_Protocol_Version")),
        "WrappingObjectArchived" => Some((0x0000_0040, "Wrapping_Object_Archived")),
        "WrappingObjectDestroyed" => Some((0x0000_0041, "Wrapping_Object_Destroyed")),
        "WrappingObjectNotFound" => Some((0x0000_0042, "Wrapping_Object_Not_Found")),
        "WrongKeyLifecycleState" => Some((0x0000_0043, "Wrong_Key_Lifecycle_State")),
        "ProtectionStorageUnavailable" => Some((0x0000_0044, "Protection_Storage_Unavailable")),
        "PKCS11CodecError" => Some((0x0000_0045, "PKCS_11_Codec_Error")),
        "PKCS11InvalidFunction" => Some((0x0000_0046, "PKCS_11_Invalid_Function")),
        "PKCS11InvalidInterface" => Some((0x0000_0047, "PKCS_11_Invalid_Interface")),
        "PrivateProtectionStorageUnavailable" => {
            Some((0x0000_0048, "Private_Protection_Storage_Unavailable"))
        }
        "PublicProtectionStorageUnavailable" => {
            Some((0x0000_0049, "Public_Protection_Storage_Unavailable"))
        }
        "UnknownObjectGroup" => Some((0x0000_004A, "Unknown_Object_Group")),
        "ConstraintViolation" => Some((0x0000_004B, "Constraint_Violation")),
        "DuplicateProcessRequest" => Some((0x0000_004C, "Duplicate_Process_Request")),
        "GeneralFailure" => Some((0x0000_0100, "General_Failure")),

        // ── ValidityIndicator ─────────────────────────────────────────
        "Valid" => Some((0x0000_0001, "Valid")),
        "Invalid" => Some((0x0000_0002, "Invalid")),
        "Fresh" => Some((0x0000_0003, "Fresh")),

        // ── BlockCipherMode ───────────────────────────────────────────
        "GCM" => Some((0x0000_0009, "GCM")),
        "CBC" => Some((0x0000_0001, "CBC")),
        "ECB" => Some((0x0000_0002, "ECB")),
        "XTS" => Some((0x0000_000B, "XTS")),
        "CTR" => Some((0x0000_0006, "CTR")),
        "CFB" => Some((0x0000_0004, "CFB")),
        "OFB" => Some((0x0000_0005, "OFB")),
        "PCBC" => Some((0x0000_0003, "PCBC")),
        "CCM" => Some((0x0000_0008, "CCM")),
        "CMAC" => Some((0x0000_0007, "CMAC")),
        "AEAD" => Some((0x0000_0012, "AEAD")),
        "AESKeyWrapPadding" => Some((0x0000_000C, "AESKeyWrapPadding")),
        "NISTKeyWrap" => Some((0x0000_000D, "NISTKeyWrap")),

        // ── PaddingMethod ─────────────────────────────────────────────
        "None" => Some((0x1, "None")),
        "OAEP" => Some((0x2, "OAEP")),
        "PKCS5" => Some((0x0000_0008, "PKCS5")),
        "PKCS7" => Some((0x0000_0009, "PKCS7")),
        "PSS" => Some((0x0000_000A, "PSS")),

        // ── RNGAlgorithm ──────────────────────────────────────────────
        "ANSI_X931" | "ANSIX9_31" | "ANSI_X9_31" => Some((0x5, "ANSI_X931")),
        "FIPS186_2" | "FIPS_186_2" => Some((0x2, "FIPS186_2")),
        "DRBG" => Some((0x3, "DRBG")),
        "NRBG" => Some((0x4, "NRBG")),
        "ANSI_X962" | "ANSI_X9_62" => Some((0x6, "ANSI_X962")),

        // ── UsageLimitsUnit ───────────────────────────────────────────
        "Byte" => Some((0x0000_0001, "Byte")),
        "Block" => Some((0x0000_0002, "Block")),
        "Object" => Some((0x0000_0003, "Object")),
        "Operation" => Some((0x0000_0004, "Operation")),

        // ── CredentialType ────────────────────────────────────────────
        "UsernameAndPassword" => Some((0x0000_0001, "UsernameAndPassword")),
        "Device" => Some((0x0000_0002, "Device")),
        "Attestation" => Some((0x0000_0003, "Attestation")),

        // ── BatchErrorContinuationOption ──────────────────────────────
        "Continue" => Some((0x0000_0001, "Continue")),
        "Stop" => Some((0x0000_0002, "Stop")),

        // ── MaskGenerator ─────────────────────────────────────────────
        "MGF1" => Some((0x0000_0001, "MFG1")),

        // ── InteropFunction ───────────────────────────────────────────
        "Begin" => Some((0x0000_0001, "Begin")),
        "End" => Some((0x0000_0002, "End")),

        // ── PKCS#11 Functions ─────────────────────────────────────────
        "C_Initialize" => Some((0x0000_0001, "C_Initialize")),
        "C_GetInfo" => Some((0x0000_0002, "C_GetInfo")),
        "C_Finalize" => Some((0x0000_0003, "C_Finalize")),
        "OK" => Some((0x0000_0000, "OK")),

        // ── LinkType ──────────────────────────────────────────────────
        "CertificateLink" => Some((0x0000_0101, "CertificateLink")),
        "PublicKeyLink" => Some((0x0000_0102, "PublicKeyLink")),
        "PrivateKeyLink" => Some((0x0000_0103, "PrivateKeyLink")),
        "DerivationBaseObjectLink" => Some((0x0000_0104, "DerivationBaseObjectLink")),
        "DerivedKeyLink" => Some((0x0000_0105, "DerivedKeyLink")),
        "ReplacementObjectLink" => Some((0x0000_0106, "ReplacementObjectLink")),
        "ReplacedObjectLink" => Some((0x0000_0107, "ReplacedObjectLink")),
        "ParentLink" => Some((0x0000_0108, "ParentLink")),
        "ChildLink" => Some((0x0000_0109, "ChildLink")),
        "PreviousLink" => Some((0x0000_010A, "PreviousLink")),
        "NextLink" => Some((0x0000_010B, "NextLink")),
        "PKCS12CertificateLink" => Some((0x0000_010C, "PKCS12CertificateLink")),
        "PKCS12PasswordLink" => Some((0x0000_010D, "PKCS12PasswordLink")),
        "WrappingKeyLink" => Some((0x0000_010E, "WrappingKeyLink")),

        // ── ProtectionLevel ──────────────────────────────────────────
        "Low" => Some((0x0000_0001, "Low")),
        "Medium" => Some((0x0000_0002, "Medium")),
        "High" => Some((0x0000_0003, "High")),

        _ => Option::None,
    }
}

/// Reverse look up: given a numeric KMIP enumeration code, return the
/// canonical textual name if known.
///
/// The function walks the *same* table as [`lookup_enum_code`] but keyed by
/// `u32`.  Because different KMIP enumerations may share the same numeric
/// code (e.g. `Create` and `Certificate` are both `0x01` in different
/// contexts), the caller should use this only when a unique resolution is
/// acceptable (response display / test assertions).
#[must_use]
pub fn lookup_enum_name(code: u32) -> Option<&'static str> {
    REVERSE_TABLE.get(&code).copied()
}

use std::{collections::HashMap, sync::LazyLock};

/// Reverse mapping from numeric code → canonical name.
///
/// Built once from the forward table in [`lookup_enum_code`].
/// When two names share the same code, the *last* entry wins — the table is
/// ordered so that the most commonly expected name for a shared code appears
/// last in each group.
static REVERSE_TABLE: LazyLock<HashMap<u32, &'static str>> = LazyLock::new(|| {
    // All (name, code, canonical) triples — derived from the match arms above.
    let entries: &[(&str, u32)] = &[
        // ── OperationEnumeration ──
        ("Create", 0x0000_0001),
        ("CreateKeyPair", 0x0000_0002),
        ("Register", 0x0000_0003),
        ("ReKey", 0x0000_0004),
        ("DeriveKey", 0x0000_0005),
        ("Certify", 0x0000_0006),
        ("ReCertify", 0x0000_0007),
        ("Locate", 0x0000_0008),
        ("Check", 0x0000_0009),
        ("Get", 0x0000_000A),
        ("GetAttributes", 0x0000_000B),
        ("GetAttributeList", 0x0000_000C),
        ("AddAttribute", 0x0000_000D),
        ("ModifyAttribute", 0x0000_000E),
        ("DeleteAttribute", 0x0000_000F),
        ("ObtainLease", 0x0000_0010),
        ("GetUsageAllocation", 0x0000_0011),
        ("Activate", 0x0000_0012),
        ("Revoke", 0x0000_0013),
        ("Destroy", 0x0000_0014),
        ("Archive", 0x0000_0015),
        ("Recover", 0x0000_0016),
        ("Validate", 0x0000_0017),
        ("Query", 0x0000_0018),
        ("Cancel", 0x0000_0019),
        ("Poll", 0x0000_001A),
        ("Notify", 0x0000_001B),
        ("Put", 0x0000_001C),
        ("ReKeyKeyPair", 0x0000_001D),
        ("DiscoverVersions", 0x0000_001E),
        ("Encrypt", 0x0000_001F),
        ("Decrypt", 0x0000_0020),
        ("Sign", 0x0000_0021),
        ("SignatureVerify", 0x0000_0022),
        ("MAC", 0x0000_0023),
        ("MACVerify", 0x0000_0024),
        ("RNGRetrieve", 0x0000_0025),
        ("RNGSeed", 0x0000_0026),
        ("Hash", 0x0000_0027),
        ("CreateSplitKey", 0x0000_0028),
        ("JoinSplitKey", 0x0000_0029),
        ("Import", 0x0000_002A),
        ("Export", 0x0000_002B),
        ("Log", 0x0000_002C),
        ("Login", 0x0000_002D),
        ("Logout", 0x0000_002E),
        ("DelegatedLogin", 0x0000_002F),
        ("AdjustAttribute", 0x0000_0030),
        ("SetAttribute", 0x0000_0031),
        ("SetEndpointRole", 0x0000_0032),
        ("PKCS11", 0x0000_0033),
        ("Interop", 0x0000_0034),
        ("ReProvision", 0x0000_0035),
        ("SetDefaults", 0x0000_0036),
        ("SetConstraints", 0x0000_0037),
        ("GetConstraints", 0x0000_0038),
        // ── QueryFunction ──
        ("QueryOperations", 0x0000_0001),
        ("QueryObjects", 0x0000_0002),
        ("QueryServerInformation", 0x0000_0003),
        ("QueryApplicationNamespaces", 0x0000_0004),
        // ── ResultStatus ──
        ("Success", 0x0000_0000),
        ("OperationFailed", 0x0000_0001),
        ("OperationPending", 0x0000_0002),
        ("OperationUndone", 0x0000_0003),
        // ── ObjectType ──
        ("Certificate", 0x0000_0001),
        ("SymmetricKey", 0x0000_0002),
        ("PublicKey", 0x0000_0003),
        ("PrivateKey", 0x0000_0004),
        ("SplitKey", 0x0000_0005),
        ("SecretData", 0x0000_0007),
        ("OpaqueData", 0x0000_0008),
        ("PGPKey", 0x0000_0009),
        ("CertificateRequest", 0x0000_000A),
        // ── NameType ──
        ("UninterpretedTextString", 0x0000_0001),
        ("URI", 0x0000_0002),
        // ── SecretDataType ──
        ("Password", 0x0000_0001),
        ("Seed", 0x0000_0002),
        // ── State ──
        ("PreActive", 0x0000_0001),
        ("Active", 0x0000_0002),
        ("Deactivated", 0x0000_0003),
        ("Compromised", 0x0000_0004),
        ("Destroyed", 0x0000_0005),
        ("DestroyedCompromised", 0x0000_0006),
        // ── KeyFormatType ──
        ("Raw", 0x0000_0001),
        ("Opaque", 0x0000_0002),
        ("PKCS1", 0x0000_0003),
        ("PKCS8", 0x0000_0004),
        ("TransparentSymmetricKey", 0x0000_0005),
        ("TransparentDSAPrivateKey", 0x0000_0006),
        ("TransparentDSAPublicKey", 0x0000_0007),
        ("TransparentRSAPrivateKey", 0x0000_0008),
        ("TransparentRSAPublicKey", 0x0000_0009),
        ("TransparentDHPrivateKey", 0x0000_000A),
        ("TransparentDHPublicKey", 0x0000_000B),
        ("TransparentECPrivateKey", 0x0000_0014),
        ("TransparentECPublicKey", 0x0000_0015),
        ("PKCS12", 0x0000_0016),
        ("PKCS10", 0x0000_0017),
        // ── CryptographicAlgorithm ──
        ("DES", 0x0000_0001),
        ("THREEDES", 0x0000_0002),
        ("AES", 0x0000_0003),
        ("RSA", 0x0000_0004),
        ("DSA", 0x0000_0005),
        ("ECDSA", 0x0000_0006),
        ("HMACSHA1", 0x0000_0007),
        ("HMACSHA224", 0x0000_0008),
        ("HMACSHA256", 0x0000_0009),
        ("HMACSHA384", 0x0000_000A),
        ("HMACSHA512", 0x0000_000B),
        ("HMACMD5", 0x0000_000C),
        ("DH", 0x0000_000D),
        ("ECDH", 0x0000_000E),
        ("ECMQV", 0x0000_000F),
        ("Blowfish", 0x0000_0010),
        ("Camellia", 0x0000_0011),
        ("CAST5", 0x0000_0012),
        ("IDEA", 0x0000_0013),
        ("MARS", 0x0000_0014),
        ("RC2", 0x0000_0015),
        ("RC4", 0x0000_0016),
        ("RC5", 0x0000_0017),
        ("SKIPJACK", 0x0000_0018),
        ("Twofish", 0x0000_0019),
        ("EC", 0x0000_001A),
        ("Ed25519", 0x0000_001B),
        ("Ed448", 0x0000_001C),
        ("HKDF", 0x0000_002B),
        ("SHAKE256", 0x0000_002E),
        ("SHA3224", 0x0000_002F),
        ("SHA3256", 0x0000_0030),
        ("SHA3384", 0x0000_0031),
        ("SHA3512", 0x0000_0032),
        // ── HashingAlgorithm ──
        ("MD2", 0x0000_0001),
        ("MD4", 0x0000_0002),
        ("MD5", 0x0000_0003),
        ("SHA_1", 0x0000_0004),
        ("SHA_224", 0x0000_0005),
        ("SHA_256", 0x0000_0006),
        ("SHA_384", 0x0000_0007),
        ("SHA_512", 0x0000_0008),
        ("SHA_512_224", 0x0000_0009),
        ("SHA_512_256", 0x0000_000A),
        ("SHA3_224", 0x0000_000B),
        ("SHA3_256", 0x0000_000C),
        ("SHA3_384", 0x0000_000D),
        ("SHA3_512", 0x0000_000E),
        // ── RevocationReasonCode ──
        ("Unspecified", 0x0000_0001),
        ("KeyCompromise", 0x0000_0002),
        ("CACompromise", 0x0000_0003),
        ("AffiliationChanged", 0x0000_0004),
        ("Superseded", 0x0000_0005),
        ("CessationOfOperation", 0x0000_0006),
        ("PrivilegeWithdrawn", 0x0000_0007),
        // ── ResultReason ──
        ("ItemNotFound", 0x0000_0001),
        ("ResponseTooLarge", 0x0000_0002),
        ("AuthenticationNotSuccessful", 0x0000_0003),
        ("InvalidMessage", 0x0000_0004),
        ("OperationNotSupported", 0x0000_0005),
        ("MissingData", 0x0000_0006),
        ("InvalidField", 0x0000_0007),
        ("FeatureNotSupported", 0x0000_0008),
        ("OperationCanceledByRequester", 0x0000_0009),
        ("CryptographicFailure", 0x0000_000A),
        ("PermissionDenied", 0x0000_0011),
        ("ObjectArchived", 0x0000_0012),
        ("ApplicationNamespaceNotSupported", 0x0000_0014),
        ("KeyFormatTypeNotSupported", 0x0000_0015),
        ("KeyCompressionTypeNotSupported", 0x0000_0016),
        ("EncodingOptionError", 0x0000_0017),
        ("KeyValueNotPresent", 0x0000_0018),
        ("AttestationRequired", 0x0000_0019),
        ("AttestationFailed", 0x0000_001A),
        ("Sensitive", 0x0000_001B),
        ("NotExtractable", 0x0000_001C),
        ("ObjectAlreadyExists", 0x0000_001D),
        ("InvalidTicket", 0x0000_001E),
        ("UsageLimitExceeded", 0x0000_001F),
        ("NumericRange", 0x0000_0020),
        ("InvalidDataType", 0x0000_0021),
        ("ReadOnlyAttribute", 0x0000_0022),
        ("MultiValuedAttribute", 0x0000_0023),
        ("UnsupportedAttribute", 0x0000_0024),
        ("AttributeInstanceNotFound", 0x0000_0025),
        ("AttributeNotFound", 0x0000_0026),
        ("ItemNotFoundBest", 0x0000_0027),
        ("GeneralFailure", 0x0000_0100),
        // ── ValidityIndicator ──
        ("Valid", 0x0000_0000),
        ("Invalid", 0x0000_0001),
        ("Unknown", 0x0000_0002),
        // ── BlockCipherMode ──
        ("CBC", 0x0000_0001),
        ("ECB", 0x0000_0002),
        ("PCBC", 0x0000_0003),
        ("CFB", 0x0000_0004),
        ("OFB", 0x0000_0005),
        ("CTR", 0x0000_0006),
        ("CMAC", 0x0000_0007),
        ("CCM", 0x0000_0008),
        ("GCM", 0x0000_0009),
        ("CBCMAC", 0x0000_000A),
        ("XTS", 0x0000_000B),
        ("X9_102_AESKW", 0x0000_000E),
        ("X9_102_TDKW", 0x0000_000F),
        ("X9_102_AKW1", 0x0000_0010),
        ("X9_102_AKW2", 0x0000_0011),
        ("AEAD", 0x0000_0012),
        // ── PaddingMethod ──
        ("None", 0x0000_0001),
        ("OAEP", 0x0000_0002),
        ("PKCS5", 0x0000_0003),
        ("SSL3", 0x0000_0004),
        ("Zeros", 0x0000_0005),
        ("ANSIX9_23", 0x0000_0006),
        ("PSS", 0x0000_0007),
        ("PKCS1v1_5", 0x0000_0008),
        // ── DerivationMethod ──
        ("PBKDF2", 0x0000_0001),
        ("HASH", 0x0000_0002),
        ("HMAC", 0x0000_0003),
        ("ENCRYPT", 0x0000_0004),
        ("NIST800_108_C", 0x0000_0005),
        ("NIST800_108_F", 0x0000_0006),
        ("NIST800_108_DPI", 0x0000_0007),
        ("AsymmetricKey", 0x0000_0008),
        ("AWS_SIG_V4", 0x0000_0009),
        ("HKDF", 0x0000_000A),
        // ── KeyRoleType ──
        ("BDK", 0x0000_0001),
        ("CVK", 0x0000_0002),
        ("DEK", 0x0000_0003),
        ("MKAC", 0x0000_0004),
        ("MKSMC", 0x0000_0005),
        ("MKSMI", 0x0000_0006),
        ("MKDAC", 0x0000_0007),
        ("MKDN", 0x0000_0008),
        ("MKCP", 0x0000_0009),
        ("MKOTH", 0x0000_000A),
        ("KEK", 0x0000_000B),
        ("MAC16609", 0x0000_000C),
        ("MAC97971", 0x0000_000D),
        ("MAC97972", 0x0000_000E),
        ("MAC97973", 0x0000_000F),
        ("MAC97974", 0x0000_0010),
        ("MAC97975", 0x0000_0011),
        ("ZPK", 0x0000_0012),
        ("PVKIBM", 0x0000_0013),
        ("PVKPVV", 0x0000_0014),
        ("PVKOTH", 0x0000_0015),
        ("DUKPT", 0x0000_0016),
        ("IV", 0x0000_0017),
        ("TRKBK", 0x0000_0018),
        // ── RecommendedCurve ──
        ("P_192", 0x0000_0001),
        ("K_163", 0x0000_0002),
        ("B_163", 0x0000_0003),
        ("P_224", 0x0000_0004),
        ("K_233", 0x0000_0005),
        ("B_233", 0x0000_0006),
        ("P_256", 0x0000_0007),
        ("K_283", 0x0000_0008),
        ("B_283", 0x0000_0009),
        ("P_384", 0x0000_000A),
        ("K_409", 0x0000_000B),
        ("B_409", 0x0000_000C),
        ("P_521", 0x0000_000D),
        ("K_571", 0x0000_000E),
        ("B_571", 0x0000_000F),
        ("CURVEED25519", 0x0000_0018),
        ("CURVEED448", 0x0000_0019),
        ("CURVE25519", 0x0000_001A),
        ("CURVE448", 0x0000_001B),
        // ── CertificateType ──
        ("X_509", 0x0000_0001),
        ("PGP", 0x0000_0002),
        // ── WrappingMethod ──
        ("EncryptOnly", 0x0000_0001),
        ("MACSign", 0x0000_0002),
        ("EncryptThenMAC", 0x0000_0003),
        ("MACThenEncrypt", 0x0000_0004),
        ("TR31", 0x0000_0005),
        // ── EncodingOption ──
        ("NoEncoding", 0x0000_0001),
        ("TTLVEncoding", 0x0000_0002),
        // ── PKCS11Function ──
        ("C_Initialize", 0x0000_0001),
        ("C_GetInfo", 0x0000_0002),
        ("C_Finalize", 0x0000_0003),
        ("OK", 0x0000_0000),
        // ── LinkType ──
        ("CertificateLink", 0x0000_0101),
        ("PublicKeyLink", 0x0000_0102),
        ("PrivateKeyLink", 0x0000_0103),
        ("DerivationBaseObjectLink", 0x0000_0104),
        ("DerivedKeyLink", 0x0000_0105),
        ("ReplacementObjectLink", 0x0000_0106),
        ("ReplacedObjectLink", 0x0000_0107),
        ("ParentLink", 0x0000_0108),
        ("ChildLink", 0x0000_0109),
        ("PreviousLink", 0x0000_010A),
        ("NextLink", 0x0000_010B),
        ("PKCS12CertificateLink", 0x0000_010C),
        ("PKCS12PasswordLink", 0x0000_010D),
        ("WrappingKeyLink", 0x0000_010E),
        // ── ProtectionLevel ──
        ("Low", 0x0000_0001),
        ("Medium", 0x0000_0002),
        ("High", 0x0000_0003),
    ];
    let mut map = HashMap::with_capacity(entries.len());
    for &(name, code) in entries {
        map.insert(code, name);
    }
    map
});

# Error Codes Reference

## Contents

- [HTTP status code mapping](#http-status-code-mapping)
- [KMIP ResultReason codes](#kmip-resultreason-codes)
- [Enterprise endpoint error formats](#enterprise-endpoint-error-formats)

---

## HTTP status code mapping

Defined in `crate/server/src/routes/mod.rs` (`impl ResponseError for KmsError`, plain-text `text/plain; charset=utf-8` body unless overridden by a scoped JSON handler):

| KMS Error Type | HTTP Status | Typical cause |
| -------------- | ----------- | ------------- |
| `Unauthorized` | 401 | Authentication or authorization failed |
| `RouteNotFound` | 404 | Endpoint or KMIP operation doesn't exist |
| `Conflict` | 409 | Optimistic-lock check failed (concurrent modification) |
| `ItemNotFound`, `InvalidRequest`, `NotSupported`, `UnsupportedAlgorithm`, `InconsistentOperation`, `Kmip21Error`, `Kmip14Error`, `UnsupportedProtectionMasks`, `UnsupportedPlaceholder`, `ClientConnectionError`, `UrlError` | 422 | Client/KMIP error |
| `Database` (message contains `"already exist"`), `ServerError` (message contains `"not supported"` / `"Not Supported"`) | 422 | Client-facing duplicate key or unsupported feature |
| `Database` (other), `ServerError` (other), `ConversionError`, `CryptographicError`, `Certificate`, `Tls`, `Default`, `Redis`, `Findex` | 500 | Server-side error |

---

## KMIP ResultReason codes

Defined in `crate/kmip/src/kmip_0/kmip_types.rs` (`pub enum ErrorReason`) and mapped in `crate/server/src/core/operations/message.rs`:

| Code | Reason | Common trigger |
| ---- | ------ | -------------- |
| `0x00000001` | `Item_Not_Found` | Key/object doesn't exist (`KmsError::ItemNotFound`) |
| `0x00000002` | `Response_Too_Large` | Response exceeds maximum size |
| `0x00000003` | `Authentication_Not_Successful` | KMIP credential authentication failed |
| `0x00000004` | `Invalid_Message` | Malformed message or missing ID placeholder (`UnsupportedPlaceholder`) |
| `0x00000005` | `Operation_Not_Supported` | Unknown or unimplemented KMIP operation (`RouteNotFound`) |
| `0x00000006` | `Missing_Data` | Required field or data missing |
| `0x00000007` | `Invalid_Field` | Invalid request field or inconsistent operation (`InvalidRequest`, `InconsistentOperation`) |
| `0x00000008` | `Feature_Not_Supported` | Unsupported feature, algorithm, or protection mask (`NotSupported`, `UnsupportedAlgorithm`, `UnsupportedProtectionMasks`) |
| `0x0000000A` | `Cryptographic_Failure` | GCM tag mismatch, invalid IV/size, or OpenSSL error (`CryptographicError`) |
| `0x0000000C` | `Permission_Denied` | User lacks access (`Unauthorized`) |
| `0x00000016` | `Sensitive` | Attempt to export sensitive key material |
| `0x00000017` | `Not_Extractable` | Attempt to export non-extractable key |
| `0x00000018` | `Object_Already_Exists` | Object with same UID already exists |
| `0x00000021` | `Attribute_Not_Found` | Requested attribute not present on object |
| `0x00000024` | `Bad_Cryptographic_Parameters` | Invalid cryptographic parameters |
| `0x00000026` | `Codec_Error` | TTLV serialization/deserialization or conversion error (`ConversionError`, `TtlvError`) |
| `0x00000029` | `Incompatible_Cryptographic_Usage_Mask` | Key usage mask forbids the requested operation |
| `0x00000030` | `Invalid_Object_Type` | Wrong KMIP object type for the operation |
| `0x00000036` | `Object_Destroyed` | Operation attempted on a destroyed object |
| `0x0000003E` | `Unsupported_Cryptographic_Parameters` | Valid KMIP crypto parameters not supported by server (`CryptoError::NotSupported`) |
| `0x00000043` | `Wrong_Key_Lifecycle_State` | Key state (`PreActive`, `Deactivated`, `Compromised`, …) forbids operation |
| `0x0000004B` | `Constraint_Violation` | Server constraint violated |
| `0x00000100` | `General_Failure` | Default fallback for unmapped internal errors |

---

## Enterprise endpoint error formats

- **AWS XKS**: `{"errorName":"...","errorMessage":"..."}` (e.g. `"ValidationException"`, `"InvalidStateException"`, `"KeyNotFoundException"`, `"UnsupportedOperationException"`)
- **Azure EKM**: `{"code":"...","message":"..."}` (e.g. `"InvalidRequest"`, `"UnsupportedApiVersion"`, `"KeyNotFound"`, `"Forbidden"`, `"InternalError"`)
- **Google CSE**: `{"code":422,"message":"A CSE request to the Cosmian KMS failed","details":"..."}`
- **MS DKE**: Plain-text `KmsError` body (`text/plain; charset=utf-8`) with the mapped HTTP status code above (no JSON wrapper)
- **JOSE REST (`/v1/crypto/*`)**: `{"error":"<snake_case_code>","description":"..."}`
- **Tokenize**: `{"code":422,"message":"..."}`

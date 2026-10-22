# Error Codes Reference

## Contents

- [HTTP status code mapping](#http-status-code-mapping)
- [KMIP ResultReason codes](#kmip-resultreason-codes)
- [Enterprise endpoint error formats](#enterprise-endpoint-error-formats)

---

## HTTP status code mapping

| KMS Error Type | HTTP Status | Typical cause |
| -------------- | ----------- | ------------- |
| `RouteNotFound` | 404 | Endpoint doesn't exist |
| `Unauthorized` | 401 | Authentication failed |
| `ItemNotFound`, `InvalidRequest`, `NotSupported`, `UnsupportedAlgorithm`, `InconsistentOperation`, `Kmip21Error`, `Kmip14Error`, `UnsupportedProtectionMasks`, `UnsupportedPlaceholder` | 422 | Client request issue |
| `Database`, `CryptographicError`, `Certificate`, `TLS`, `ServerError`, `Default`, `Redis`, `Findex` | 500 | Server-side error |

---

## KMIP ResultReason codes

| Code | Reason | Common trigger |
| ---- | ------ | -------------- |
| `0x00000001` | OperationFailed | General failure |
| `0x00000004` | Invalid_Message | Malformed TTLV |
| `0x00000009` | Item_Not_Found | Key/object doesn't exist |
| `0x0000000C` | Unsupported_Operation | Operation not implemented |
| `0x0000000E` | Unsupported_Cryptographic_Algorithm | Algorithm not available (e.g., ChaCha20 in FIPS) |
| `0x00000010` | Permission_Denied | User lacks access |
| `0x00000011` | Duplicate_Item | Object already exists |
| `0x00000017` | Incompatible_Cryptographic_Parameters | Bad crypto params |

---

## Enterprise endpoint error formats

- **AWS XKS**: `{"errorCode":"...","message":"..."}`
- **Azure EKM**: `{"code":"...","message":"...","details":{...}}`
- **Google CSE**: `{"error":"...","error_description":"..."}`
- **MS DKE**: `{"error":"...","error_description":"..."}`
- **Tokenize**: `{"code":422,"message":"..."}`

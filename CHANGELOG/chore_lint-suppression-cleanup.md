## Bug Fixes

### Crypto

- Free the OCSP basic response after successful response encoding instead of leaking it on each request.
- Return an error if allocating the requested OCSP signer certificate stack fails instead of silently omitting it.

### HSM

- Serialize PKCS#11 `C_GetInfo` fields without reading uninitialized structure padding; preserve the native layout and zero padding bytes.

## Refactor

### Crypto

- Use existing safe OpenSSL APIs for CRL Number extensions, SCEP CMS construction and attribute OIDs, and OCSP request parsing, digest lookup, certificate stacks, and response serialization.

## Testing

- Isolate XML draft and registration vector servers by owner on the `KMS_TEST_DB` backend so unfiltered Locate requests cannot select objects created by unrelated tests.

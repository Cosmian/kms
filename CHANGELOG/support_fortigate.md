## Bug Fixes

### FortiGate 40F / KMIP 1.0–1.1 interoperability

- Fix missing `Authentication` wrapper in KMIP 1.4 `RequestMessageHeader`: the TTLV deserializer previously looked for `CredentialType` as a direct child of `Authentication`, skipping the `Credential` wrapper and failing with `missing field 'CredentialType'` when a FortiGate 40F (FortiOS 7.6) client connects ([#824](https://github.com/Cosmian/kms/issues/824))
- Fix `Locate` name filter silently dropped for KMIP 1.0/1.1 clients (e.g. FortiGate): FortiGate wraps filter `Attribute` items inside a `TemplateAttribute` structure in the `RequestPayload`; without the new `template_attribute` field on `kmip_1_4::Locate`, the TTLV deserializer discarded the wrapper, causing every Locate to match all objects and `MaximumItems=1` to always return the same first key regardless of the requested name ([#824](https://github.com/Cosmian/kms/issues/824))

### HSM — sensitive (non-extractable) keys

- Fix `ModifyAttribute` failing with "This key is sensitive and cannot be exported from the HSM" for non-extractable HSM-backed keys: `HsmStore::retrieve` now catches the sensitive-key export error and falls back to `get_key_metadata()` (no key material access) to build a metadata-only stub that satisfies attribute-only KMIP operations (e.g. `ModifyAttribute(Name)`, `GetAttributes`); `HsmStore::update_object` was also changed to return `Ok(())` for attribute updates instead of an error ([#933](https://github.com/Cosmian/kms/issues/933))

### Web UI

- Fix flaky Windows E2E tests: reduce `PLAYWRIGHT_WORKERS` from 10 to 4 on Windows CI to prevent the debug-build KMS server from being overwhelmed by concurrent crypto operations (which saturates the tokio reactor and causes actix-web to return HTTP 408 before reading request bodies); also add retry with exponential backoff to the `createHmacKey` test helper for transient 408/network errors ([#827](https://github.com/Cosmian/kms/pull/827))

Closes #824
Closes #933

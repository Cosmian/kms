## Bug Fixes

### FortiGate 40F / KMIP 1.0–1.1 interoperability

- Fix missing `Authentication` wrapper in KMIP 1.4 `RequestMessageHeader`: the TTLV deserializer previously looked for `CredentialType` as a direct child of `Authentication`, skipping the `Credential` wrapper and failing with `missing field 'CredentialType'` when a FortiGate 40F (FortiOS 7.6) client connects ([#824](https://github.com/Cosmian/kms/issues/824))
- Fix `Locate` name filter silently dropped for KMIP 1.0/1.1 clients (e.g. FortiGate): FortiGate wraps filter `Attribute` items inside a `TemplateAttribute` structure in the `RequestPayload`; without the new `template_attribute` field on `kmip_1_4::Locate`, the TTLV deserializer discarded the wrapper, causing every Locate to match all objects and `MaximumItems=1` to always return the same first key regardless of the requested name ([#824](https://github.com/Cosmian/kms/issues/824))

Closes #824

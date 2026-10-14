## Breaking Changes

### KMIP

- `SetAttribute` now returns `Attribute_Read_Only` (HTTP 422) for `UniqueIdentifier`, `ObjectType`, `CryptographicLength`, `CertificateLength`, `Digest`, `InitialDate`, `LastChangeDate`, `OriginalCreationDate` and `Fresh`. Previously these server-managed attributes were accepted and persisted. Clients that set them through `SetAttribute` must stop doing so; `AddAttribute` is unchanged ([#1004](https://github.com/Cosmian/kms/issues/1004))

## Security

- Enforce read-only attribute rules for client updates (COSMIAN-2026-030, see `SECURITY.md`)

## Refactor

### KMIP

- Decide per attribute and per operation whether an edit is allowed, needs a grant, or is server-managed with one policy table (`Tag::edit_policy`), shared by `AddAttribute`, `SetAttribute`, `ModifyAttribute` and `DeleteAttribute`

## Documentation

- Document the read-only attributes of `SetAttribute`, `ModifyAttribute` and `DeleteAttribute`, and remove the `ModifyAttribute` example that set `CryptographicLength`

---

Closes #1004

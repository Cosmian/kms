---
name: 'Rust KMIP Protocol'
description: 'KMIP 2.1 protocol type definitions and serialization rules'
applyTo: 'crate/kmip/**/*.rs'
---

# KMIP protocol rules

## Source of truth

- The KMIP 2.1 specification HTML files in the repo-root `kmip/` submodule (`kmip/v2.1/kmip-spec-v2.1-os.html`; run `git submodule update --init kmip` if empty) are the authoritative reference.
- Tag names, enum values, and field types **must match the spec exactly**.
- When in doubt, verify against the spec HTML — do not rely on training-data recall.

## TTLV serialization

- TTLV (Tag-Type-Length-Value) serialization goes through `serde` (`crate/kmip/src/ttlv/`) plus `kmip-derive` enum macros and the 3-byte hex tag table in `crate/kmip/src/ttlv/wire/kmip_tag.rs`.
- Custom `Serialize`/`Deserialize` impls are only needed for protocol edge cases (such as `Attribute` / `Object` dispatch); document why with a comment.
- Tag values are 3-byte hex constants (`0x42XXXX`) mapped in `kmip_tag.rs`.

## Type conventions

- KMIP enumerations → Rust `#[repr(u32)] pub enum` annotated with `#[kmip_enum]` and `#[derive(KmipEnumSerialize, KmipEnumDeserialize, ...)]` (`crate/kmip-derive`).
- KMIP structures → Rust `pub struct` with `#[derive(Serialize, Deserialize, ...)]` and `#[serde(rename_all = "PascalCase")]` (plus `#[serde(rename = "...")]` when the KMIP tag name contains acronyms like `PKCS11` or `IVCounterNonce`).
- Optional fields → `Option<T>` with `#[serde(skip_serializing_if = "Option::is_none")]`.
- KMIP `TextString` → `String`, `ByteString` → `Vec<u8>` or `Zeroizing<Vec<u8>>` for secrets.

## Backward compatibility

- KMIP 1.4 operations are supported alongside 2.1 via dedicated types in `crate/kmip/src/kmip_1_4/` with `From` / `TryFrom` conversions to and from KMIP 2.1 types (and `#[serde(alias = "...")]` when wire tag spellings vary).

## Testing

```bash
cargo test -p cosmian_kmip
cargo test -p cosmian_kmip --features non-fips
```

> For compliance verification of KMIP operations, run `/kmip-compliance`.
> Run `/kmip-compliance` when an operation or protocol behavior changes; schema-only changes unrelated to operation semantics may use a confirmed scoped skip.

---
name: 'Rust KMIP Protocol'
description: 'KMIP 2.1 protocol type definitions and serialization rules'
applyTo: 'crate/kmip/**/*.rs'
---

# KMIP protocol rules

## Source of truth

- The KMIP 2.1 specification HTML files in `crate/kmip/src/` are the authoritative reference.
- Tag names, enum values, and field types **must match the spec exactly**.
- When in doubt, verify against the spec HTML — do not rely on training-data recall.

## TTLV serialization

- Use `kmip-derive` proc macros for automatic TTLV (Tag-Type-Length-Value) serialization.
- Custom serialization is only needed for protocol edge cases; document why with a comment.
- Tag values are hex constants defined in the spec.

## Type conventions

- KMIP enumerations → Rust `enum` with `#[derive(KmipEnum)]`.
- KMIP structures → Rust `struct` with `#[derive(KmipStruct)]`.
- Optional fields → `Option<T>`.
- KMIP `TextString` → `String`, `ByteString` → `Vec<u8>` or `Zeroizing<Vec<u8>>` for secrets.

## Backward compatibility

- KMIP 1.4 operations are supported alongside 2.1.
- Use `#[kmip(tag = 0x...)]` to override tag values when they differ between versions.

## Testing

```bash
cargo test -p cosmian_kmip
cargo test -p cosmian_kmip --features non-fips
```

> For compliance verification of KMIP operations, run `/kmip-compliance`.

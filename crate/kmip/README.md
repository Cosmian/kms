# Cosmian KMIP

The `cosmian_kmip` library implements the KMIP standard versions 1.4 and 2.1.
It also implements the TTLV serialization format to JSON and bytes.

With the feature `openssl`, the library provides conversions from KMIP objects to OpenSSL objects.

For specific Cosmian crypto-systems, you can use the [cosmian_kmip](https://github.com/Cosmian/kms/tree/main/crate/kmip) to generate KMIP data with an abstraction level.

## Enumerations

Enumerations are used for two different purposes:

- to hold the variant names and values of `Attributes` such as those described in chapter 4 of the KMIP 2.1 standard
- to offer alternative representations of the same value

### Enumerations holding KMIP variant names and values

A typical example is the `CryptographicAlgorithm` enumeration:

```rust
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(
    KmipEnumSerialize,
    Deserialize,
    Copy,
    Clone,
    Debug,
    Display,
    Eq,
    PartialEq,
    EnumIter,
    strum::IntoStaticStr,
)]
pub enum CryptographicAlgorithm {
    DES = 0x0000_0001,
    THREE_DES = 0x0000_0002,
    AES = 0x0000_0003,
    RSA = 0x0000_0004,
    DSA = 0x0000_0005,
    ECDSA = 0x0000_0006,
    ...
}
```

To be correctly serialized, the enumeration must implement the `KmipEnumSerialize` trait, as well as `Copy` and the `strum::IntoStaticStr`. They must also be annotated with `#[repr(u32)]` and `#[allow(non_camel_case_types)]`.

For details, see the `kmip-derive` crate and the `KmipEnumSerialize` trait.

### Enumerations offering alternative representations of the same value

A typical example is the `LinkedObjectIdentifier` enumeration:

```rust
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum LinkedObjectIdentifier {
    /// Unique Identifier of a Managed Object.
    TextString(String),
    /// Unique Identifier Enumeration
    Enumeration(UniqueIdentifierEnumeration),
    /// Zero based nth Unique Identifier in the response. If
    /// negative the count is backwards from the beginning
    /// of the current operation's batch item.
    Index(i64),
}
```

This enumeration offers alternative representations of the identifier of a linked Object.
Only one of this alternative is serialized to TTLV, depending on the value of the identifier.
In this case, when using the default `Serialize` trait, the enumeration must be marked as `#[serde(untagged)]`.

Please note that when deserializing an `untagged` enum, the deserializer will try each variant in order, and the first one that successfully deserializes will be used. This means that the order of the variants is important and that when 2 variants hold the same type, post-fixing the deserialization to select the right variant is necessary. This is typically the case for the `Object` enumeration in KMIP 2.1.

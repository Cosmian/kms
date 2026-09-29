#![allow(clippy::as_conversions)] // All enums are #[repr(u32)]; casts are intentional.

use std::{collections::HashMap, sync::LazyLock};

use strum::IntoEnumIterator;

use crate::{
    kmip_0::kmip_types as k0,
    kmip_1_4::kmip_types as k14,
    kmip_2_1::{kmip_objects as k21_obj, kmip_operations as k21_ops, kmip_types as k21},
};

/// Look up the numeric KMIP code for a textual enumeration variant name.
///
/// Returns `(code, canonical_name)` if the name is known, or `None` otherwise.
/// This table covers all enumeration values used by the KMIP 1.4 and 2.1 specs
/// that appear in test vectors and integration payloads.
///
/// This function is shared between the XML deserializer and the
/// `TTLV::resolve_enumeration_values()` method so that JSON-originated TTLV
/// trees can be reliably serialized to binary TTLV.
#[must_use]
pub fn lookup_enum_code(name: &str) -> Option<(u32, &'static str)> {
    let key = name.replace('-', "_");
    FORWARD_TABLE.get(key.as_str()).copied()
}

/// Tag-aware enum code lookup. When a TTLV tag is known (e.g.
/// `"HashingAlgorithm"`), this function intercepts the small set of variant
/// names that collide across enums before falling through to the global table.
///
/// The only actual collision is the SHA3 family (`SHA3224`/`SHA3256`/`SHA3384`/
/// `SHA3512`): these names appear in both `HashingAlgorithm` and
/// `CryptographicAlgorithm` with **different** numeric codes. The global
/// [`FORWARD_TABLE`] resolves them to `CryptographicAlgorithm` codes (inserted
/// first); when the TTLV tag is `HashingAlgorithm` or
/// `MaskGeneratorHashingAlgorithm` the correct `HashingAlgorithm` codes are
/// returned directly without touching the global table.
#[must_use]
pub fn lookup_enum_code_for_tag(name: &str, tag: &str) -> Option<(u32, &'static str)> {
    if matches!(tag, "HashingAlgorithm" | "MaskGeneratorHashingAlgorithm") {
        let resolved = match name {
            "SHA3224" => Some((k0::HashingAlgorithm::SHA3224 as u32, "SHA3224")),
            "SHA3256" => Some((k0::HashingAlgorithm::SHA3256 as u32, "SHA3256")),
            "SHA3384" => Some((k0::HashingAlgorithm::SHA3384 as u32, "SHA3384")),
            "SHA3512" => Some((k0::HashingAlgorithm::SHA3512 as u32, "SHA3512")),
            _ => None,
        };
        if resolved.is_some() {
            return resolved;
        }
    }
    lookup_enum_code(name)
}

/// Reverse look up: given a numeric KMIP enumeration code, return the
/// canonical textual name if known.
///
/// Because different KMIP enumerations may share the same numeric
/// code (e.g. `Create` and `Certificate` are both `0x01` in different
/// contexts), the caller should use this only when a unique resolution is
/// acceptable (response display / test assertions).
#[must_use]
pub fn lookup_enum_name(code: u32) -> Option<&'static str> {
    REVERSE_TABLE.get(&code).copied()
}

// ─── Table construction macros ───────────────────────────────────────────────

/// Insert all variants of one or more enums into the forward table.
/// Uses `or_insert` so the first-inserted entry wins for duplicate names.
macro_rules! insert_forward {
    ($map:expr, $($enum_type:ty),+ $(,)?) => {
        $(
            for variant in <$enum_type>::iter() {
                let name: &'static str = variant.into();
                let code = variant as u32;
                $map.entry(name).or_insert((code, name));
            }
        )+
    };
}

/// Insert all variants of one or more enums into the reverse table.
/// Uses plain `insert` so the last-inserted entry wins for duplicate codes.
macro_rules! insert_reverse {
    ($map:expr, $($enum_type:ty),+ $(,)?) => {
        $(
            for variant in <$enum_type>::iter() {
                let name: &'static str = variant.into();
                let code = variant as u32;
                $map.insert(code, name);
            }
        )+
    };
}

// ─── Forward table ───────────────────────────────────────────────────────────

/// Forward mapping: textual name → (numeric code, canonical name).
///
/// Built once by iterating all KMIP enum variants (via strum `IntoEnumIterator`)
/// in priority order: KMIP 2.1 → 1.4 → 0. First insertion wins for shared names.
/// Additional aliases for alternative name forms (e.g. `PKCS_1` → `PKCS1`) are
/// appended after the canonical entries.
static FORWARD_TABLE: LazyLock<HashMap<&'static str, (u32, &'static str)>> = LazyLock::new(|| {
    let mut map: HashMap<&'static str, (u32, &'static str)> = HashMap::with_capacity(512);

    // ── KMIP 2.1 types (highest priority) ────────────────────────────────
    insert_forward!(
        map,
        k21::OperationEnumeration,
        k21_obj::ObjectType,
        k21::KeyFormatType,
        k21::CryptographicAlgorithm,
        k21::DigitalSignatureAlgorithm,
        k21::RecommendedCurve,
        k21::QueryFunction,
        k21::ValidityIndicator,
        k21::ProtectionLevel,
        k21::LinkType,
        k21::NameType,
        k21::BatchErrorContinuationOption,
        k21::UsageLimitsUnit,
        k21::DerivationMethod,
        k21::WrappingMethod,
        k21::EncodingOption,
        k21_ops::PKCS11Function,
        k21_ops::PKCS11ReturnCode,
        k21::Tag,
    );

    #[cfg(feature = "interop")]
    insert_forward!(map, k21_ops::InteropFunction);

    // ── KMIP 1.4 types ───────────────────────────────────────────────────
    // ResultReason maps PascalCase names → ErrorReason underscore canonical names.
    // This is needed because downstream deserialization expects ErrorReason format.
    for variant in k14::ResultReason::iter() {
        let pascal_name: &'static str = variant.into();
        let code = variant as u32;
        // Find the matching ErrorReason variant by code to get the underscore name
        if let Some(er_variant) = k0::ErrorReason::from_repr(code) {
            let er_name: &'static str = er_variant.into();
            map.entry(pascal_name).or_insert((code, er_name));
        } else {
            map.entry(pascal_name).or_insert((code, pascal_name));
        }
    }
    insert_forward!(
        map,
        k14::KeyFormatType,
        k14::WrappingMethod,
        k14::EncodingOption,
        k14::RecommendedCurve,
        k14::ObjectType,
        k14::CryptographicAlgorithm,
    );

    // ── KMIP 0 (base) types ──────────────────────────────────────────────
    insert_forward!(
        map,
        k0::ResultStatusEnumeration,
        k0::BlockCipherMode,
        k0::PaddingMethod,
        k0::HashingAlgorithm,
        k0::RevocationReasonCode,
        k0::State,
        k0::SecretDataType,
        k0::CredentialType,
        k0::KeyRoleType,
        k0::CertificateType,
        k0::MaskGenerator,
        k0::RNGAlgorithm,
    );

    // ErrorReason: insert underscore canonical names AND PascalCase aliases.
    // XML test vectors use PascalCase (e.g. "WrongKeyLifecycleState") while
    // the Rust variants use underscores (e.g. "Wrong_Key_Lifecycle_State").
    for variant in k0::ErrorReason::iter() {
        let name: &'static str = variant.into();
        let code = variant as u32;
        map.entry(name).or_insert((code, name));
        // Generate PascalCase form by removing underscores
        let pascal: String = name.replace('_', "");
        if pascal != name {
            let pascal_static: &'static str = Box::leak(pascal.into_boxed_str());
            map.entry(pascal_static).or_insert((code, name));
        }
    }

    // ── Aliases ──────────────────────────────────────────────────────────
    // Alternative name forms used in test vectors and XML payloads.
    // Each (alias, canonical) maps the alias to the same (code, name) entry.
    let aliases: &[(&str, &str)] = &[
        // KeyFormatType
        ("PKCS_1", "PKCS1"),
        ("PKCS_8", "PKCS8"),
        ("X_509", "X509"),
        // CryptographicAlgorithm
        ("3DES", "THREE_DES"),
        ("DES3", "THREE_DES"),
        ("HMAC_SHA1", "HMACSHA1"),
        ("HMAC_SHA224", "HMACSHA224"),
        ("HMAC_SHA256", "HMACSHA256"),
        ("HMAC_SHA384", "HMACSHA384"),
        ("HMAC_SHA512", "HMACSHA512"),
        // OperationEnumeration
        ("PKCS_11", "PKCS11"),
        // HashingAlgorithm
        ("SHA_1", "SHA1"),
        ("SHA_224", "SHA224"),
        ("SHA_256", "SHA256"),
        ("SHA_384", "SHA384"),
        ("SHA_512", "SHA512"),
        // ResultStatusEnumeration
        ("Pending", "OperationPending"),
        ("Undo", "OperationUndone"),
        // RNGAlgorithm
        ("ANSIX9_31", "ANSI_X931"),
        ("ANSI_X9_31", "ANSI_X931"),
        ("FIPS_186_2", "FIPS186_2"),
        ("ANSI_X9_62", "ANSI_X962"),
        // RevocationReasonCode / RNGAlgorithm (shared "Unspecified" name)
        ("UNSPECIFIED_RNG", "Unspecified"),
        ("RNG_Unspecified", "Unspecified"),
        // MaskGenerator
        ("MGF1", "MFG1"),
        // RecommendedCurve (underscore-separated forms)
        ("P_192", "P192"),
        ("K_163", "K163"),
        ("B_163", "B163"),
        ("P_224", "P224"),
        ("K_233", "K233"),
        ("B_233", "B233"),
        ("P_256", "P256"),
        ("K_283", "K283"),
        ("B_283", "B283"),
        ("P_384", "P384"),
        ("K_409", "K409"),
        ("B_409", "B409"),
        ("P_521", "P521"),
        ("K_571", "K571"),
        ("B_571", "B571"),
        // BlockCipherMode
        ("X9_102_AESKW", "X9102AESKW"),
        ("X9_102_TDKW", "X9102TDKW"),
        ("X9_102_AKW1", "X9102AKW1"),
        ("X9_102_AKW2", "X9102AKW2"),
        // PaddingMethod
        ("ANSIX9_23", "ANSI_X923"),
        ("PKCS1v1_5", "PKCS1v15"),
        // CertificateType
        ("X_509", "X509"),
        // CertificateAttributes fields: PascalCase serde renames produce
        // lowercase second letter for two-letter abbreviations (e.g. "Cn"),
        // but the Tag enum uses all-caps ("CN"). Add aliases so the
        // binary TTLV serializer's write_tag fallback can resolve them.
        ("CertificateSubjectCn", "CertificateSubjectCN"),
        ("CertificateSubjectOu", "CertificateSubjectOU"),
        ("CertificateSubjectSt", "CertificateSubjectST"),
        ("CertificateSubjectDc", "CertificateSubjectDC"),
        ("CertificateSubjectUid", "CertificateSubjectUID"),
        (
            "CertificateSubjectDnQualifier",
            "CertificateSubjectDNQualifier",
        ),
        ("CertificateIssuerCn", "CertificateIssuerCN"),
        ("CertificateIssuerOu", "CertificateIssuerOU"),
        ("CertificateIssuerSt", "CertificateIssuerST"),
        ("CertificateIssuerDc", "CertificateIssuerDC"),
        ("CertificateIssuerUid", "CertificateIssuerUID"),
        (
            "CertificateIssuerDnQualifier",
            "CertificateIssuerDNQualifier",
        ),
    ];
    for &(alias, canonical) in aliases {
        if let Some(&entry) = map.get(canonical) {
            map.entry(alias).or_insert(entry);
        }
    }

    map
});

// ─── Reverse table ───────────────────────────────────────────────────────────

/// Reverse mapping: numeric code → canonical name.
///
/// Built once by iterating all KMIP enum variants. Because different enumerations
/// share codes (e.g. `Create` and `Certificate` are both `0x01`), last-write-wins
/// determines which name is returned. The insertion order is chosen so that the
/// most commonly expected name for display appears last (`kmip_2_1` > `kmip_1_4` > `kmip_0`).
static REVERSE_TABLE: LazyLock<HashMap<u32, &'static str>> = LazyLock::new(|| {
    let mut map: HashMap<u32, &'static str> = HashMap::with_capacity(512);

    // Insert in ascending priority — last write wins.
    // kmip_0 first (lowest priority for shared codes).
    insert_reverse!(
        map,
        k0::ResultStatusEnumeration,
        k0::ErrorReason,
        k0::BlockCipherMode,
        k0::PaddingMethod,
        k0::HashingAlgorithm,
        k0::RevocationReasonCode,
        k0::State,
        k0::SecretDataType,
        k0::CredentialType,
        k0::KeyRoleType,
        k0::CertificateType,
        k0::MaskGenerator,
        k0::RNGAlgorithm,
    );

    // kmip_1_4 (medium priority).
    insert_reverse!(
        map,
        k14::ResultReason,
        k14::KeyFormatType,
        k14::WrappingMethod,
        k14::EncodingOption,
        k14::RecommendedCurve,
    );

    // kmip_2_1 (highest priority — preferred display names).
    insert_reverse!(
        map,
        k21::OperationEnumeration,
        k21_obj::ObjectType,
        k21::KeyFormatType,
        k21::CryptographicAlgorithm,
        k21::DigitalSignatureAlgorithm,
        k21::RecommendedCurve,
        k21::QueryFunction,
        k21::ValidityIndicator,
        k21::ProtectionLevel,
        k21::LinkType,
        k21::NameType,
        k21::BatchErrorContinuationOption,
        k21::UsageLimitsUnit,
        k21::DerivationMethod,
        k21::WrappingMethod,
        k21::EncodingOption,
        k21_ops::PKCS11Function,
        k21_ops::PKCS11ReturnCode,
    );

    #[cfg(feature = "interop")]
    insert_reverse!(map, k21_ops::InteropFunction);

    map
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_table_aliases() {
        // Canonical entries
        assert!(FORWARD_TABLE.get("ANSI_X931").is_some());
        assert!(FORWARD_TABLE.get("FIPS186_2").is_some());
        assert!(FORWARD_TABLE.get("Unspecified").is_some());
        assert!(FORWARD_TABLE.get("MFG1").is_some());

        // PascalCase ErrorReason aliases
        assert!(FORWARD_TABLE.get("WrongKeyLifecycleState").is_some());
        assert!(FORWARD_TABLE.get("ItemNotFound").is_some());

        // Dash/underscore aliases
        assert!(FORWARD_TABLE.get("PKCS_1").is_some());
        assert!(FORWARD_TABLE.get("THREE_DES").is_some());
        assert!(FORWARD_TABLE.get("3DES").is_some());

        // k14 cross-version compat
        assert!(lookup_enum_code("THREE_DES").is_some());
        assert!(lookup_enum_code("Template").is_some());
    }

    #[test]
    fn test_reverse_table() {
        // Known codes resolve to names
        assert!(REVERSE_TABLE.get(&0x01).is_some());
        assert!(REVERSE_TABLE.get(&0x1F).is_some());

        // ValidityIndicator spec codes
        assert_eq!(lookup_enum_code("Valid"), Some((0x01, "Valid")));
        assert_eq!(lookup_enum_code("Invalid"), Some((0x02, "Invalid")));
        assert_eq!(lookup_enum_code("Unknown"), Some((0x03, "Unknown")));
    }

    #[test]
    fn test_binary_ttlv_enum_coverage() {
        let mut failures = Vec::new();

        // DigitalSignatureAlgorithm — must be in forward table
        let dsa_names = [
            ("ECDSAWithSHA256", 0x0E_u32),
            ("ECDSAWithSHA384", 0x0F),
            ("ECDSAWithSHA512", 0x10),
            ("SHA256WithRSAEncryption", 0x05),
            ("RSASSAPSS", 0x08),
        ];
        for (name, expected) in dsa_names {
            match lookup_enum_code(name) {
                Some((code, _)) => {
                    if code != expected {
                        failures.push(format!(
                            "{name}: global lookup code={code:#06X}, expected {expected:#06X}"
                        ));
                    }
                }
                None => failures.push(format!("{name} NOT in forward table")),
            }
            // Also verify tag-aware lookup
            match lookup_enum_code_for_tag(name, "DigitalSignatureAlgorithm") {
                Some((code, _)) => {
                    if code != expected {
                        failures.push(format!(
                            "{name}: tag-aware code={code:#06X}, expected {expected:#06X}"
                        ));
                    }
                }
                None => failures.push(format!("{name} NOT in tag override table")),
            }
        }

        // DerivationMethod — HKDF must resolve
        match lookup_enum_code("HKDF") {
            Some((code, _)) => {
                assert_eq!(code, 0x0A, "HKDF should be 0x0A");
            }
            None => failures.push("HKDF NOT in forward table".to_owned()),
        }

        // HashingAlgorithm — SHA3 variants: tag-aware lookup must return
        // HashingAlgorithm codes (0x0E-0x11), NOT CryptographicAlgorithm codes
        let sha3_hashing = [
            ("SHA3224", 0x0E_u32),
            ("SHA3256", 0x0F),
            ("SHA3384", 0x10),
            ("SHA3512", 0x11),
        ];
        for (name, expected) in sha3_hashing {
            match lookup_enum_code_for_tag(name, "HashingAlgorithm") {
                Some((code, _)) => {
                    if code != expected {
                        failures.push(format!(
                            "{name} (HashingAlgorithm tag): code={code:#06X}, expected {expected:#06X}"
                        ));
                    }
                }
                None => failures.push(format!("{name} NOT in tag override for HashingAlgorithm")),
            }
        }

        assert!(
            failures.is_empty(),
            "Enum lookup failures:\n{}",
            failures.join("\n")
        );
    }
}

# KMIP 1.0 XML Specifications – Test Vectors

This directory contains the KMIP 1.0 conformance test vectors (XML) organized per profile:

- `XML/mandatory/` – Mandatory profile test cases (57 files: 19 unique × 3 KMIP minor-version variants -10/-11/-12)
- `XML/optional/` – Optional profile test cases (27 files: 9 unique × 3 KMIP minor-version variants -10/-11/-12)

They originate from the OASIS KMIP Profiles v1.0 repository of test cases. The test harness parses
each XML file into structured KMIP requests/responses through the TTLV pipeline and validates that
the round-trip parse completes without errors.

> **Note**: These are *parse-only* non-regression tests. They validate that the XML → TTLV
> deserializer can correctly decode every KMIP 1.0 test vector, including all enumeration tokens
> and message structures defined in the KMIP 1.0 specification.

## Test coverage

The Rust tests live in `crate/kmip/src/ttlv/xml/tests/`:

| Test file | Coverage |
| --- | --- |
| `kmip_1_0_xml_mandatory_test_vectors.rs` | All 57 mandatory XML files (sweep + per-group) |
| `kmip_1_0_xml_optional_test_vectors.rs` | All 27 optional XML files (sweep + per-group) |

Run with:

```bash
cargo test-non-fips
```

## Test case groups

### Mandatory profile (57 files)

| Group | Files | Operations |
| --- | --- | --- |
| SKLC-M-1..3 | 9 | Create, GetAttributes, Destroy |
| SKFF-M-1..12 | 36 | Create, Destroy |
| AKLC-M-1..3 | 9 | CreateKeyPair, GetAttributes, [Activate, Revoke,] Destroy |
| OMOS-M-1 | 3 | Register, Destroy |

The SKLC (Symmetric Key Lifecycle) and SKFF (Symmetric Key Foundry/Factory) groups cover the
core AES key lifecycle operations. AKLC (Asymmetric Key Lifecycle) covers RSA key pair
management. OMOS (Opaque Managed Object Store) covers opaque object registration.

### Optional profile (27 files)

| Group | Files | Operations | Notes |
| --- | --- | --- | --- |
| SKLC-O-1 | 3 | Create, Locate, GetAttributes, Destroy | Locate operation |
| SKFF-O-1..3 | 9 | Create, Destroy | SKIPJACK algorithm |
| SKFF-O-4..6 | 9 | Create, Destroy | AES variants |
| AKLC-O-1 | 3 | CreateKeyPair, GetAttributes, Destroy | |
| OMOS-O-1 | 3 | Register, GetAttributes, Destroy | |

`SKFF-O-1` through `SKFF-O-3` use the `SKIPJACK` cryptographic algorithm (KMIP enumeration
code `0x0000_0018`), which was mandated by certain KMIP 1.0 profiles and is supported by
the XML deserializer for backwards compatibility.

## File naming convention

Each XML file is named `<GROUP>-<VARIANT>-<MINOR>.xml` where:

- `<GROUP>` identifies the test group (e.g. `SKLC-M-1`, `SKFF-O-3`)
- `<MINOR>` is the protocol minor-version variant: `10` = 1.0, `11` = 1.1, `12` = 1.2

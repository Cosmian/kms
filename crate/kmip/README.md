# Cosmian KMIP

Complete implementation of KMIP 1.0–2.1 protocol with TTLV binary and JSON serialization. Defines all KMIP objects, operations, attributes, and enumerations as Rust types.

KMIP operation handlers in `cosmian_kms_server` deserialize requests from this crate and route them to operation implementations. See the repo-root `kmip/` submodule (for example `kmip/v2.1/kmip-spec-v2.1-os.html`; run `git submodule update --init kmip` if empty) for the full KMIP HTML spec reference.

## XML test vector parsing

The XML → TTLV helper used in tests enforces strict KMIP enumeration and usage
mask validation by default. Unknown enumeration tokens, unknown
`CryptographicUsageMask` textual values, or unknown `AttributeReference` names
produce errors. The only tolerated deviation (for interoperability with some
public test vectors) is that a missing `type="Structure"` attribute on a
container element is still accepted and treated as a Structure.

If your custom vectors fail, ensure all textual enumeration and usage mask
tokens are valid per the KMIP specification.

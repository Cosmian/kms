# KMIP support by Cosmian KMS (v4.23 → v5.11.0)

This page summarizes the KMIP coverage in Cosmian KMS, using the OVHcloud guide as a layout
reference. Columns are KMS server versions grouped by identical support. Operation support is
derived from the presence of a dedicated implementation in
`crate/server/src/core/operations` for each version tag.

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated (not used here)
- 🚧 Partially supported (not used here)
- N/A Not applicable

Version columns (merged where identical):

- 4.23.0 – 4.24.0
- 5.0.0 – 5.4.1
- 5.5.0 – 5.5.1
- 5.6.0 – 5.7.1
- 5.8.0 – 5.10.0
- 5.11.0

Notes:

- The Operations table below is computed from the server source tree at each version tag.
- Prior to 5.10.0, some KMIP documents used "Modify Attribute" to refer to the server's
  Set Attribute handler. From 5.10.0, a dedicated Modify Attribute operation is implemented.
- "Discover" here refers to the KMIP Discover Versions operation.

## KMIP coverage

### Messages

| Message          | 4.23–4.24 | 5.0–5.11 |
| ---------------- | --------: | -------: |
| Request Message  |         ✅ |        ✅ |
| Response Message |         ✅ |        ✅ |

### Operations

| Operation              | 4.23–4.24 | 5.0–5.4.1 | 5.5–5.5.1 | 5.6–5.7.1 | 5.8–5.10 | 5.11.0 |
| ---------------------- | --------: | --------: | --------: | --------: | -------: | -----: |
| Create                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Create Key Pair        |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Register               |         ❌ |         ❌ |         ✅ |         ✅ |        ✅ |      ✅ |
| Re-key                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Re-key Key Pair        |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| DeriveKey              |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Certify                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Re-certify             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Locate                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Check                  |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Get                    |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Get Attributes         |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Get Attribute List     |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Add Attribute          |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Set Attribute (Modify) |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Modify Attribute       |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Delete Attribute       |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Obtain Lease           |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Get Usage Allocation   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Activate               |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Revoke                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Destroy                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Archive                |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Recover                |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Validate               |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Query                  |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cancel                 |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Poll                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Notify                 |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Put                    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Discover Versions      |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Encrypt                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Decrypt                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Sign                   |         ❌ |         ❌ |         ❌ |         ❌ |        ✅ |      ✅ |
| Signature Verify       |         ❌ |         ❌ |         ❌ |         ❌ |        ✅ |      ✅ |
| MAC                    |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| MAC Verify             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| RNG Retrieve           |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| RNG Seed               |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Hash                   |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Create Split Key       |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Join Split Key         |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Export                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Import                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |

### Methodology

- Operations shown as ✅ are backed by a Rust implementation file under `crate/server/src/core/operations` at the corresponding version tag.
- If no implementation file exists at a tag for an operation, it is marked ❌ for that version range.
- Version ranges were merged when the set of supported operations did not change across the range:

    - 4.23.0–4.24.0
    - 5.0.0–5.4.1 (adds AddAttribute, Discover Versions, Query)
    - 5.5.0–5.5.1 (adds Register)
    - 5.6.0–5.7.1 (adds Activate, Digest internal support)
    - 5.8.0–5.10.0 (adds Sign, Signature Verify at 5.8)
    - 5.11.0 (adds DeriveKey, Check, Get Attribute List, RNG Retrieve, RNG Seed, MAC Verify, and a dedicated Modify Attribute)

If you spot a mismatch or want to extend coverage, please open an issue or PR.

### Managed Objects

| Managed Object | 4.23–4.24 | 5.0–5.11 |
| -------------- | --------: | -------: |
| Certificate    |         ✅ |        ✅ |
| Symmetric Key  |         ✅ |        ✅ |
| Public Key     |         ✅ |        ✅ |
| Private Key    |         ✅ |        ✅ |
| Split Key      |         ❌ |        ❌ |
| Template       |         🚫 |        🚫 |
| Secret Data    |         ✅ |        ✅ |
| Opaque Object  |         ❌ |        ✅ |
| PGP Key        |         ❌ |        ❌ |

Notes:

- Opaque Object import support is present from 5.0.0 (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.

### Base Objects

| Base Object                              | 4.23–4.24 | 5.0–5.10 | 5.11.0 |
| ---------------------------------------- | --------: | -------: | -----: |
| Attribute                                |         ✅ |        ✅ |      ✅ |
| Credential                               |         ✅ |        ✅ |      ✅ |
| Key Block                                |         ✅ |        ✅ |      ✅ |
| Key Value                                |         ✅ |        ✅ |      ✅ |
| Key Wrapping Data                        |         ✅ |        ✅ |      ✅ |
| Key Wrapping Specification               |         ✅ |        ✅ |      ✅ |
| Transparent Key Structures               |         ✅ |        ✅ |      ✅ |
| Template-Attribute Structures            |         ✅ |        ✅ |      ✅ |
| Extension Information                    |         ✅ |        ✅ |      ✅ |
| Data                                     |         ❌ |        ❌ |      ❌ |
| Data Length                              |         ❌ |        ❌ |      ❌ |
| Signature Data                           |         ❌ |        ❌ |      ✅ |
| MAC Data                                 |         ❌ |        ❌ |      ✅ |
| Nonce                                    |         ✅ |        ✅ |      ✅ |
| Correlation Value                        |         ❌ |        ❌ |      ✅ |
| Init Indicator                           |         ❌ |        ❌ |      ✅ |
| Final Indicator                          |         ❌ |        ❌ |      ✅ |
| RNG Parameter                            |         ✅ |        ✅ |      ✅ |
| Profile Information                      |         ✅ |        ✅ |      ✅ |
| Validation Information                   |         ✅ |        ✅ |      ✅ |
| Capability Information                   |         ✅ |        ✅ |      ✅ |
| Authenticated Encryption Additional Data |         ✅ |        ✅ |      ✅ |
| Authenticated Encryption Tag             |         ✅ |        ✅ |      ✅ |

Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.

### Transparent Key Structures

| Structure                | 4.23–4.24 | 5.0–5.11 |
| ------------------------ | --------: | -------: |
| Symmetric Key            |         ✅ |        ✅ |
| DSA Private/Public Key   |         ❌ |        ❌ |
| RSA Private/Public Key   |         ✅ |        ✅ |
| DH Private/Public Key    |         ❌ |        ❌ |
| ECDSA Private/Public Key |         ✅ |        ✅ |
| ECDH Private/Public Key  |         ❌ |        ❌ |
| ECMQV Private/Public     |         ❌ |        ❌ |
| EC Private/Public        |         ✅ |        ✅ |

Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

### Attributes

| Attribute                           | 4.23–4.24 | 5.0–5.4.1 | 5.5–5.5.1 | 5.6–5.7.1 | 5.8–5.10 | 5.11.0 |
| ----------------------------------- | --------: | --------: | --------: | --------: | -------: | -----: |
| Unique Identifier                   |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Name                                |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Object Type                         |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Algorithm             |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Length                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Parameters            |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Domain Parameters     |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Certificate Type                    |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Certificate Identifier              |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Certificate Subject                 |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Certificate Issuer                  |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Digest                              |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Operation Policy Name               |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Cryptographic Usage Mask            |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Lease Time                          |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Usage Limits                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| State                               |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Initial Date                        |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Activation Date                     |         ✅ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Process Start Date                  |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Protect Stop Date                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Deactivation Date                   |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Destroy Date                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Compromise Occurrence Date          |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Compromise Date                     |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Revocation Reason                   |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Archive Date                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Object Group                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Link                                |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Application Specific Information    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Contact Information                 |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Last Change Date                    |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Custom Attribute (Vendor Attribute) |         ✅ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Certificate Length                  |         ✅ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| X.509 Certificate Identifier        |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| X.509 Certificate Subject           |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| X.509 Certificate Issuer            |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Digital Signature Algorithm         |         ❌ |         ❌ |         ❌ |         ❌ |        ✅ |      ✅ |
| Fresh                               |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Alternative Name                    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Key Value Present                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Key Value Location                  |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Original Creation Date              |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Random Number Generator             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| PKCS#12 Friendly Name               |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Description                         |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Comment                             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Sensitive                           |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Always Sensitive                    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Extractable                         |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Never Extractable                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |

Notes:

- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- For the 5.x columns above, a ✅ indicates the attribute is used or updated by at least one KMIP operation implementation in `crate/server/src/core/operations`, explicitly excluding the attribute-only handlers (Add/Delete/Get/Set Attribute).

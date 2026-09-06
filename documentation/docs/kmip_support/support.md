# KMIP support by Eviden KMS

This page summarizes the KMIP coverage in Eviden KMS. The support status is
derived from the actual implementation in `crate/server/src/core/operations`.

**Eviden KMS Server supports KMIP versions:** 2.1, 2.0, 1.4, 1.3, 1.2, 1.1, 1.0

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated
- N/A Not applicable (operation/attribute not defined in that KMIP version)

## KMIP Baseline Profile Compliance

**Baseline Server:** ✅ Compliant (all 9 required + 18/18 optional)

The Baseline Server profile (defined in KMIP Profiles v2.1 Section 4.1) requires:

- **Required operations:** Discover Versions, Query, Create, Register, Get, Destroy, Locate, Activate, Revoke
- **Optional operations:** Many additional operations for extended functionality

## KMIP Coverage

### Messages

| Message          | Support |
| ---------------- | ------: |
| Request Message  |      ✅ |
| Response Message |      ✅ |

### Operations by KMIP Version

The following table shows operation support across all KMIP versions.

| Operation | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Activate               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Add Attribute          |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Archive                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Cancel                 |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Certify                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Check                  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create Key Pair        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create Split Key       |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Decrypt                |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Delete Attribute       |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DeriveKey              |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Destroy                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Discover Versions      |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Encrypt                |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Export                 |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Get                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Attribute List     |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Attributes         |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Usage Allocation   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Hash                   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Import                 |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Join Split Key         |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Locate                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC                    |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC Verify             |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Notify                 |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |
| Obtain Lease           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Poll                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Put                    |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |
| Query                  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Retrieve           |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Seed               |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Re-certify             |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Re-key                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Re-key Key Pair        |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Recover                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Register               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Revoke                 |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Set Attribute (Modify) |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |
| Sign                   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Signature Verify       |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Validate               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |

### Methodology

- Operations marked ✅ are backed by a Rust implementation file under `crate/server/src/core/operations`.
- Operations marked ❌ are defined in the KMIP specification but not implemented in Eviden KMS.
- Operations marked N/A do not exist in that particular KMIP version.
- This documentation is auto-generated by analyzing source code and KMIP specifications.

If you spot a mismatch or want to extend coverage, please open an issue or PR.

### Managed Objects

The following table shows managed object support across all KMIP versions.

| Managed Object | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| -------------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Certificate    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Symmetric Key  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Public Key     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Private Key    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Split Key      |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Template       |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |   N/A   |   N/A   |
| Secret Data    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Opaque Data    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| PGP Key        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |

Notes:

- Opaque Object import support is present (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.
- Template objects are deprecated in newer KMIP versions.

### Base Objects

The following table shows base object support across all KMIP versions.

| Base Object | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| ----------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Attribute                                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Credential                               |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Key Block                                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Value                                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Key Wrapping Data                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Wrapping Specification               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Transparent Key Structures               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| Template-Attribute Structures            |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| Server Information                       |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Extension Information                    |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Data                                     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Data Length                              |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Signature Data                           |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC Data                                 |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Nonce                                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Correlation Value                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Init Indicator                           |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| Final Indicator                          |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Parameters                           |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Profile Information                      |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Validation Information                   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Capability Information                   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |
| Authenticated Encryption Additional Data |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Authenticated Encryption Tag             |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |

Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.
- Base objects are fundamental structures present across all KMIP versions.

### Transparent Key Structures

The following table shows transparent key structure support across all KMIP versions.

| Structure | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Symmetric Key            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DSA Private Key          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DSA Public Key           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| RSA Private Key          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RSA Public Key           |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DH Private Key           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| DH Public Key            |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| EC Private Key           |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| EC Public Key            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| ECDSA Private Key        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| ECDSA Public Key         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| ECDH Private Key         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECDH Public Key          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECMQV Private Key        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECMQV Public Key         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |

Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

### Attributes

| Attribute                                |  1.0  |  1.1  |  1.2  |  1.3  |  1.4  |  2.0  |  2.1  |
| ---------------------------------------- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Activation Date                          |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Alternative Name                         |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Always Sensitive                         |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Application Specific Information         |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Archive Date                             |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Attribute Index                          |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |
| Certificate Attributes                   |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Certificate Length                       |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Certificate Type                         |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Comment                                  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Compromise Date                          |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Compromise Occurrence Date               |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Contact Information                      |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Critical                                 |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |
| Cryptographic Algorithm                  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Cryptographic Domain Parameters          |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Cryptographic Length                     |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Cryptographic Parameters                 |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Cryptographic Usage Mask                 |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Deactivation Date                        |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Description                              |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Destroy Date                             |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Digest                                   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Digital Signature Algorithm              |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Extractable                              |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Fresh                                    |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Initial Date                             |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Key Format Type                          |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Key Value Location                       |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Key Value Present                        |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Last Change Date                         |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Lease Time                               |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Link                                     |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Name                                     |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Never Extractable                        |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Nist Key Type                            |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Object Group                             |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Object Group Member                      |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |   🔧   |
| Object Type                              |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Opaque Data Type                         |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Original Creation Date                   |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| PKCS#12 Friendly Name                    |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Process Start Date                       |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Protect Stop Date                        |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Protection Level                         |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Protection Period                        |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Protection Storage Masks                 |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Quantum Safe                             |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| Random Number Generator                  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |
| Revocation Reason                        |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Rotate Automatic                         |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Rotate Date                              |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Rotate Generation                        |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Rotate Interval                          |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Rotate Latest                            |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Rotate Name                              |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Rotate Offset                            |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |
| Sensitive                                |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |   ✅   |
| Short Unique Identifier                  |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| State                                    |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Unique Identifier                        |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Usage Limits                             |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| Vendor Attribute                         |  N/A  |  N/A  |  N/A  |  N/A  |  N/A  |   ✅   |   ✅   |
| X.509 Certificate Identifier             |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| X.509 Certificate Issuer                 |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |
| X.509 Certificate Subject                |  N/A  |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |   ✅   |

Notes:

- ✅ = attribute defined in that KMIP version **and** implemented by this server.
- ❌ = attribute defined in that KMIP version but **not yet implemented**.
- N/A = attribute was **not defined** in that KMIP version (protocol gap, not a server limitation).
- 🔧 = **Cosmian-specific extension** — attribute is absent from all standard KMIP versions.
- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- `AlwaysSensitive`, `NeverExtractable`, `Extractable`, and `Sensitive` were introduced in **KMIP 1.4**
  and must not appear in responses to KMIP 1.0–1.3 clients (the server enforces this automatically).
- `Rotate*` attributes were introduced in **KMIP 2.1**.

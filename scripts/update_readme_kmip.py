#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate KMIP support documentation by analyzing the actual KMS server implementation.

This script:
1. Scans crate/server/src/core/operations to detect implemented operations
2. Parses crate/kmip/src/kmip_2_1/kmip_attributes.rs to identify defined attributes
3. Generates tables showing current support (single version column only)
4. Updates both documentation/docs/kmip/support.md and README.md

Usage:
  python scripts/update_readme_kmip.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).resolve().parents[1]
OPS_DIR = ROOT / 'crate' / 'server' / 'src' / 'core' / 'operations'
ATTRS_FILE = ROOT / 'crate' / 'kmip' / 'src' / 'kmip_2_1' / 'kmip_attributes.rs'
SUPPORT_MD = ROOT / 'documentation' / 'docs' / 'kmip' / 'support.md'
README_MD = ROOT / 'README.md'

START_MARKER = '<!-- KMIP_SUPPORT_START -->'
END_MARKER = '<!-- KMIP_SUPPORT_END -->'


def detect_implemented_operations() -> Set[str]:
    """Scan the operations directory and return set of implemented operation names."""
    ops = set()

    if not OPS_DIR.exists():
        print(f"Warning: Operations directory not found: {OPS_DIR}", file=sys.stderr)
        return ops

    # Map file names to KMIP operation names
    file_to_op = {
        'activate.rs': 'Activate',
        'add_attribute.rs': 'Add Attribute',
        'certify': 'Certify',  # directory
        'create.rs': 'Create',
        'create_key_pair.rs': 'Create Key Pair',
        'decrypt.rs': 'Decrypt',
        'delete_attribute.rs': 'Delete Attribute',
        'derive_key.rs': 'DeriveKey',
        'destroy.rs': 'Destroy',
        'discover_versions.rs': 'Discover Versions',
        'encrypt.rs': 'Encrypt',
        'export.rs': 'Export',
        'get.rs': 'Get',
        'get_attributes.rs': 'Get Attributes',
        'hash.rs': 'Hash',
        'import.rs': 'Import',
        'locate.rs': 'Locate',
        'mac.rs': 'MAC',
        'query.rs': 'Query',
        'register.rs': 'Register',
        'rekey.rs': 'Re-key',
        'rekey_keypair.rs': 'Re-key Key Pair',
        'revoke.rs': 'Revoke',
        'set_attribute.rs': 'Set Attribute (Modify)',
        'sign.rs': 'Sign',
        'signature_verify.rs': 'Signature Verify',
        'validate.rs': 'Validate',
    }

    for item in OPS_DIR.iterdir():
        name = item.name
        if name in file_to_op:
            ops.add(file_to_op[name])
        elif item.is_dir() and name in file_to_op:
            ops.add(file_to_op[name])

    return ops


def parse_attributes() -> List[str]:
    """Parse the Attribute enum from kmip_attributes.rs and return list of attribute names."""
    if not ATTRS_FILE.exists():
        print(f"Warning: Attributes file not found: {ATTRS_FILE}", file=sys.stderr)
        return []

    content = ATTRS_FILE.read_text(encoding='utf-8')

    # Find the enum Attribute { ... } block
    enum_match = re.search(r'pub enum Attribute\s*\{(.*?)\n\}', content, re.DOTALL)
    if not enum_match:
        print(
            "Warning: Could not find 'pub enum Attribute' in attributes file",
            file=sys.stderr,
        )
        return []

    enum_body = enum_match.group(1)

    # Extract variant names (handle both simple and complex variants)
    # Patterns: VariantName(...), VariantName(type), VariantName
    variants = []
    for line in enum_body.split('\n'):
        line = line.strip()
        if not line or line.startswith('///') or line.startswith('//'):
            continue

        # Match variant declaration
        match = re.match(r'([A-Z][A-Za-z0-9]*)\s*[\(,]', line)
        if match:
            variant_name = match.group(1)
            # Convert camelCase to readable format with special handling for X509
            if variant_name.startswith('X509Certificate'):
                # Handle X509CertificateIdentifier -> X.509 Certificate Identifier
                rest = variant_name[15:]  # Remove X509Certificate
                readable_name = 'X.509 Certificate ' + re.sub(
                    r'([a-z])([A-Z])', r'\1 \2', rest
                )
            elif variant_name == 'Pkcs12FriendlyName':
                readable_name = 'PKCS#12 Friendly Name'
            else:
                readable_name = re.sub(r'([a-z])([A-Z])', r'\1 \2', variant_name)
                readable_name = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', readable_name)

            variants.append(readable_name)

    return sorted(set(variants))


def map_operation_support(ops: Set[str]) -> Dict[str, str]:
    """Map operation names to support status (✅ or ❌)."""
    # Complete list of KMIP operations from the spec
    all_operations = [
        'Create',
        'Create Key Pair',
        'Register',
        'Re-key',
        'Re-key Key Pair',
        'DeriveKey',
        'Certify',
        'Re-certify',
        'Locate',
        'Check',
        'Get',
        'Get Attributes',
        'Get Attribute List',
        'Add Attribute',
        'Set Attribute (Modify)',
        'Delete Attribute',
        'Obtain Lease',
        'Get Usage Allocation',
        'Activate',
        'Revoke',
        'Destroy',
        'Archive',
        'Recover',
        'Validate',
        'Query',
        'Cancel',
        'Poll',
        'Notify',
        'Put',
        'Discover Versions',
        'Encrypt',
        'Decrypt',
        'Sign',
        'Signature Verify',
        'MAC',
        'MAC Verify',
        'RNG Retrieve',
        'RNG Seed',
        'Hash',
        'Create Split Key',
        'Join Split Key',
        'Export',
        'Import',
    ]

    return {op: '✅' if op in ops else '❌' for op in all_operations}


def map_attribute_support(attrs: List[str]) -> Dict[str, str]:
    """Map attributes to support status based on their definition."""
    # Attributes that are explicitly known to be supported through operations
    # These are verified by checking the operations code
    supported_attrs = {
        'Unique Identifier',
        'Object Type',
        'Cryptographic Algorithm',
        'Cryptographic Length',
        'Cryptographic Parameters',
        'Cryptographic Domain Parameters',
        'Certificate Type',
        'Digest',
        'Cryptographic Usage Mask',
        'State',
        'Initial Date',
        'Activation Date',
        'Deactivation Date',
        'Compromise Occurrence Date',
        'Revocation Reason',
        'Link',
        'Last Change Date',
        'X.509 Certificate Identifier',
        'X.509 Certificate Issuer',
        'X.509 Certificate Subject',
        'Digital Signature Algorithm',
        'Original Creation Date',
        'Sensitive',
    }

    # Deprecated certificate attributes from older KMIP versions
    deprecated_cert_attrs = {
        'Certificate Identifier',
        'Certificate Subject',
        'Certificate Issuer',
        'Operation Policy Name',
    }

    result = {}
    for attr in attrs:
        if attr in supported_attrs:
            result[attr] = '✅'
        elif attr in deprecated_cert_attrs:
            result[attr] = '🚫'
        else:
            result[attr] = '❌'

    # Add any known attributes not in parsed list
    for attr in deprecated_cert_attrs:
        if attr not in result:
            result[attr] = '🚫'

    # Ensure all attributes from the standard are present
    standard_attrs = {
        'Name': '❌',
        'Lease Time': '❌',
        'Usage Limits': '❌',
        'Process Start Date': '❌',
        'Protect Stop Date': '❌',
        'Destroy Date': '❌',
        'Compromise Date': '❌',
        'Archive Date': '❌',
        'Object Group': '❌',
        'Application Specific Information': '❌',
        'Contact Information': '❌',
        'Fresh': '❌',
        'Alternative Name': '❌',
        'Key Value Present': '❌',
        'Key Value Location': '❌',
        'Random Number Generator': '❌',
        'Description': '❌',
        'Comment': '❌',
        'Always Sensitive': '❌',
        'Extractable': '❌',
        'Never Extractable': '❌',
    }

    for attr, status in standard_attrs.items():
        if attr not in result:
            result[attr] = status

    return result


def generate_support_markdown(
    ops_support: Dict[str, str], attrs_support: Dict[str, str]
) -> str:
    """Generate the complete support.md content."""

    md = """# KMIP support by Cosmian KMS

This page summarizes the KMIP coverage in Cosmian KMS. The support status is
derived from the actual implementation in `crate/server/src/core/operations`.

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated
- 🚧 Partially supported (not used here)
- N/A Not applicable

## KMIP coverage

### Messages

| Message          | Current |
| ---------------- | ------: |
| Request Message  |      ✅ |
| Response Message |      ✅ |

### Operations

"""

    # Operations table
    md += '| Operation              | Current |\n'
    md += '| ---------------------- | ------: |\n'
    for op, status in ops_support.items():
        md += f"| {op:<22} | {status:>7} |\n"

    md += """
### Methodology

- Operations shown as ✅ are backed by a Rust implementation file under `crate/server/src/core/operations`.
- If no implementation file exists for an operation, it is marked ❌.
- This documentation is auto-generated by analyzing the source code.

If you spot a mismatch or want to extend coverage, please open an issue or PR.

### Managed Objects

| Managed Object | Current |
| -------------- | ------: |
| Certificate    |      ✅ |
| Symmetric Key  |      ✅ |
| Public Key     |      ✅ |
| Private Key    |      ✅ |
| Split Key      |      ❌ |
| Template       |      🚫 |
| Secret Data    |      ✅ |
| Opaque Object  |      ✅ |
| PGP Key        |      ❌ |

Notes:

- Opaque Object import support is present (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.

### Base Objects

| Base Object                              | Current |
| ---------------------------------------- | ------: |
| Attribute                                |      ✅ |
| Credential                               |      ✅ |
| Key Block                                |      ✅ |
| Key Value                                |      ✅ |
| Key Wrapping Data                        |      ✅ |
| Key Wrapping Specification               |      ✅ |
| Transparent Key Structures               |      ✅ |
| Template-Attribute Structures            |      ✅ |
| Extension Information                    |      ✅ |
| Data                                     |      ❌ |
| Data Length                              |      ❌ |
| Signature Data                           |      ❌ |
| MAC Data                                 |      ❌ |
| Nonce                                    |      ✅ |
| Correlation Value                        |      ❌ |
| Init Indicator                           |      ❌ |
| Final Indicator                          |      ❌ |
| RNG Parameter                            |      ✅ |
| Profile Information                      |      ✅ |
| Validation Information                   |      ✅ |
| Capability Information                   |      ✅ |
| Authenticated Encryption Additional Data |      ✅ |
| Authenticated Encryption Tag             |      ✅ |

Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.

### Transparent Key Structures

| Structure                | Current |
| ------------------------ | ------: |
| Symmetric Key            |      ✅ |
| DSA Private/Public Key   |      ❌ |
| RSA Private/Public Key   |      ✅ |
| DH Private/Public Key    |      ❌ |
| ECDSA Private/Public Key |      ✅ |
| ECDH Private/Public Key  |      ❌ |
| ECMQV Private/Public     |      ❌ |
| EC Private/Public        |      ✅ |

Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

### Attributes

"""

    # Attributes table
    md += '| Attribute                           | Current |\n'
    md += '| ----------------------------------- | ------: |\n'

    # Sort attributes alphabetically
    for attr in sorted(attrs_support.keys()):
        status = attrs_support[attr]
        md += f"| {attr:<35} | {status:>7} |\n"

    md += """
Notes:

- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- A ✅ indicates the attribute is used or updated by at least one KMIP operation implementation in `crate/server/src/core/operations`, explicitly excluding the attribute-only handlers (Add/Delete/Get/Set Attribute).
"""

    return md


def update_support_md(content: str) -> int:
    """Write the generated content to support.md."""
    SUPPORT_MD.write_text(content, encoding='utf-8')
    print(f"✓ Updated {SUPPORT_MD}")
    return 0


def update_readme_md(support_content: str) -> int:
    """Update README.md with the support content between markers."""
    if not README_MD.exists():
        print(f"Error: README not found: {README_MD}", file=sys.stderr)
        return 2

    readme_text = README_MD.read_text(encoding='utf-8')

    start_idx = readme_text.find(START_MARKER)
    end_idx = readme_text.find(END_MARKER)

    if start_idx == -1 or end_idx == -1:
        print('Error: KMIP support markers not found in README.md', file=sys.stderr)
        return 3

    # Shift headings one level deeper for README
    shifted_content = []
    for line in support_content.split('\n'):
        if line.startswith('#'):
            shifted_content.append('#' + line)
        else:
            shifted_content.append(line)

    support_for_readme = '\n'.join(shifted_content)

    # Build replacement block
    replacement = (
        f"{START_MARKER}\n"
        f"<!-- This section is auto-generated from documentation/docs/kmip/support.md by scripts/update_readme_kmip.py. Do not edit manually. -->\n"
        f"{support_for_readme}\n"
        f"{END_MARKER}"
    )

    new_readme = (
        readme_text[:start_idx] + replacement + readme_text[end_idx + len(END_MARKER) :]
    )

    README_MD.write_text(new_readme, encoding='utf-8')
    print(f"✓ Updated {README_MD}")
    return 0


def main() -> int:
    """Main entry point."""
    print('Analyzing KMS implementation...')

    # Detect operations
    ops = detect_implemented_operations()
    print(f"  Found {len(ops)} implemented operations")

    # Parse attributes
    attrs = parse_attributes()
    print(f"  Found {len(attrs)} defined attributes")

    # Map support
    ops_support = map_operation_support(ops)
    attrs_support = map_attribute_support(attrs)

    # Generate markdown
    print('Generating documentation...')
    support_md = generate_support_markdown(ops_support, attrs_support)

    # Update files
    result = update_support_md(support_md)
    if result != 0:
        return result

    result = update_readme_md(support_md)
    if result != 0:
        return result

    print('✓ All files updated successfully')
    return 0


if __name__ == '__main__':
    sys.exit(main())

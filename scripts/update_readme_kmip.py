#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate KMIP support documentation by analyzing the actual KMS server implementation.

This script:
1. Scans crate/server/src/core/operations to detect implemented operations
2. Parses crate/kmip/src/kmip_2_1/kmip_attributes.rs to identify defined attributes
3. Parses OASIS KMIP specification HTML files to determine exact version support
4. Determines baseline profile compliance
5. Generates comprehensive tables showing support across KMIP versions
6. Updates both documentation/docs/kmip/support.md and README.md

Usage:
  python scripts/update_readme_kmip.py

Requirements:
  pip install beautifulsoup4 lxml
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

try:
    from bs4 import BeautifulSoup

    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print(
        'Warning: beautifulsoup4 not found. Install with: pip install beautifulsoup4 lxml',
        file=sys.stderr,
    )

ROOT = Path(__file__).resolve().parents[1]
OPS_DIR = ROOT / 'crate' / 'server' / 'src' / 'core' / 'operations'
ATTRS_FILE = ROOT / 'crate' / 'kmip' / 'src' / 'kmip_2_1' / 'kmip_attributes.rs'
SUPPORT_MD = ROOT / 'documentation' / 'docs' / 'kmip' / 'support.md'
README_MD = ROOT / 'README.md'
OASIS_DIR = ROOT / 'crate' / 'kmip' / 'src' / 'oasis'


START_MARKER = '<!-- KMIP_SUPPORT_START -->'
END_MARKER = '<!-- KMIP_SUPPORT_END -->'

# Map version to HTML file
SPEC_FILES = {
    '1.0': 'kmip-spec-1.0-os.html',
    '1.1': 'kmip-spec-v1.1-os.html',
    '1.2': 'kmip-spec-v1.2-os.html',
    '1.3': 'kmip-spec-v1.3-os.html',
    '1.4': 'kmip-spec-v1.4-os.html',
    '2.0': 'kmip-spec-v2.0-os.html',
    '2.1': 'kmip-spec-v2.1-os.html',
}


def normalize_operation_name(op_name: str) -> str:
    """
    Normalize operation names from KMIP specs to match our implementation naming.
    The specs use variations like "Derive Key", "Re-key", "Rekey Key Pair", etc.
    We normalize these to match the canonical names used in the code.

    Key normalizations:
    - "Derive Key" (KMIP 2.x) -> "DeriveKey" (matches 1.x and implementation)
    - "Rekey" variants -> "Re-key" with hyphen
    - "Set Attribute" -> "Set Attribute (Modify)"
    """
    # Map of spec variations to canonical names
    normalization_map = {
        'Derive Key': 'DeriveKey',  # KMIP 2.x uses "Derive Key", 1.x uses "DeriveKey"
        'Re key': 'Re-key',
        'Re key Key Pair': 'Re-key Key Pair',
        'Rekey': 'Re-key',  # KMIP 2.x "Rekey" -> "Re-key"
        'Rekey Key Pair': 'Re-key Key Pair',  # KMIP 2.x "Rekey Key Pair" -> "Re-key Key Pair"
        'Re certify': 'Re-certify',
        'Recertify': 'Re-certify',  # KMIP 2.x "Recertify" -> "Re-certify"
        'Set Attribute': 'Set Attribute (Modify)',
    }

    # Direct mapping
    if op_name in normalization_map:
        return normalization_map[op_name]

    # Return as-is if no normalization needed
    return op_name


def parse_kmip_spec_with_bs4(version: str) -> Dict[str, Set[str]]:
    """
    Parse KMIP specification HTML file using BeautifulSoup4 for accurate extraction.
    Extracts operations, attributes, managed objects, and key structures.
    """
    spec_file = OASIS_DIR / SPEC_FILES.get(version, '')

    if not spec_file.exists():
        print(
            f"  Warning: Spec file not found for version {version}: {spec_file}",
            file=sys.stderr,
        )
        return get_fallback_version_data(version)

    if not HAS_BS4:
        print(
            f"  Warning: BeautifulSoup4 not available, using fallback data",
            file=sys.stderr,
        )
        return get_fallback_version_data(version)

    try:
        content = spec_file.read_text(encoding='utf-8', errors='ignore')
        soup = BeautifulSoup(content, 'html.parser')

        operations = set()
        attributes = set()
        managed_objects = set()
        key_structures = set()

        # Extract operations from section headings
        # In KMIP 1.x specs, operations are in section 4.x
        # In KMIP 2.x specs, operations are in section 6.x
        # Note: Some specs have no space between section number and name (e.g., "4.5Derive Key")

        # Determine which section contains operations based on version
        major_version = version.split('.')[0]
        operation_section = '6' if major_version == '2' else '4'

        for heading in soup.find_all(['h2']):  # Operations are typically in h2 headings
            text = heading.get_text(strip=True)

            # Only look at the operations section
            section_pattern = f'^{operation_section}\\.\\d+'
            if not re.match(section_pattern, text):
                continue

            # Match patterns like "4.1 Create" or "4.1Create" (with or without space, without "Operation" suffix)
            # Known operations from KMIP spec
            # NOTE: Order matters! More specific operations (longer names) must come before shorter ones
            # to avoid partial matches (e.g., "Create Key Pair" must come before "Create")
            known_ops = [
                'Create Key Pair',
                'Create Split Key',
                'Join Split Key',
                'Rekey Key Pair',
                'Re-key Key Pair',
                'Get Attribute List',
                'Get Attributes',
                'Get Usage Allocation',
                'Add Attribute',
                'Modify Attribute',
                'Set Attribute',
                'Delete Attribute',
                'Signature Verify',
                'MAC Verify',
                'RNG Retrieve',
                'RNG Seed',
                'Discover Versions',
                'Obtain Lease',
                'Derive Key',
                'Recertify',
                'Re-certify',
                'Create',
                'Register',
                'Rekey',
                'Re-key',
                'Certify',
                'Locate',
                'Check',
                'Get',
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
                'Encrypt',
                'Decrypt',
                'Sign',
                'MAC',
                'Hash',
                'Export',
                'Import',
            ]

            # Check if this heading contains any known operation name
            for known_op in known_ops:
                if known_op.lower() in text.lower():
                    op_name = normalize_operation_name(known_op)
                    operations.add(op_name)
                    break

        # Extract attributes from tables
        # Look for attribute definition tables
        for table in soup.find_all('table'):
            table_text = table.get_text()
            if 'Attribute' in table_text or 'Tag' in table_text:
                for row in table.find_all('tr'):
                    cells = row.find_all(['td', 'th'])
                    for cell in cells:
                        cell_text = cell.get_text(strip=True)
                        # Look for attribute names (typically start with capital, contain spaces/specific words)
                        if re.match(r'^[A-Z]', cell_text) and any(
                            word in cell_text
                            for word in [
                                'Date',
                                'Name',
                                'Type',
                                'Mask',
                                'Length',
                                'Algorithm',
                                'State',
                                'Identifier',
                                'Subject',
                                'Issuer',
                                'Usage',
                                'Link',
                            ]
                        ):
                            if 3 < len(cell_text) < 50:
                                attributes.add(cell_text)

        # Extract managed object types from the specification
        object_patterns = [
            'Certificate',
            'Symmetric Key',
            'Public Key',
            'Private Key',
            'Split Key',
            'Template',
            'Secret Data',
            'Opaque Data',
            'PGP Key',
        ]
        full_text = soup.get_text()
        for obj in object_patterns:
            if obj in full_text:
                managed_objects.add(obj)

        # Extract key structures
        structure_patterns = [
            'Symmetric Key',
            'DSA Private Key',
            'DSA Public Key',
            'RSA Private Key',
            'RSA Public Key',
            'DH Private Key',
            'DH Public Key',
            'ECDSA Private Key',
            'ECDSA Public Key',
            'ECDH Private Key',
            'ECDH Public Key',
            'ECMQV Private Key',
            'ECMQV Public Key',
            'EC Private Key',
            'EC Public Key',
        ]
        for struct in structure_patterns:
            if struct in full_text:
                key_structures.add(struct)

        # Combine with fallback data to ensure we don't miss anything
        fallback = get_fallback_version_data(version)

        # Prefer parsed operations if we found any, otherwise use fallback
        final_operations = operations if operations else fallback['operations']

        return {
            'operations': final_operations,
            'attributes': attributes if attributes else fallback['attributes'],
            'managed_objects': (
                managed_objects if managed_objects else fallback['managed_objects']
            ),
            'base_objects': fallback['base_objects'],
            'key_structures': (
                key_structures if key_structures else fallback['key_structures']
            ),
        }
    except Exception as e:
        print(f"  Error parsing spec file {spec_file}: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return get_fallback_version_data(version)


def parse_kmip_spec(version: str) -> Dict[str, Set[str]]:
    """Parse KMIP specification HTML file for a specific version."""
    return parse_kmip_spec_with_bs4(version)


def get_fallback_version_data(version: str) -> Dict[str, Set[str]]:
    """
    Provide fallback data for KMIP version support based on known specification evolution.
    This is used when spec parsing fails or as a baseline.
    All operation names use normalized forms to match implementation.
    """
    # KMIP 1.0 baseline operations (using normalized names)
    ops_v1_0 = {
        'Create',
        'Create Key Pair',
        'Register',
        'Re-key',
        'DeriveKey',  # Normalized: DeriveKey
        'Certify',
        'Re-certify',
        'Locate',
        'Check',
        'Get',
        'Get Attributes',  # Normalized: Re-certify
        'Get Attribute List',
        'Add Attribute',
        'Modify Attribute',
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
    }

    # KMIP 1.1 added cryptographic operations
    ops_v1_1 = ops_v1_0 | {
        'Encrypt',
        'Decrypt',
        'Sign',
        'Signature Verify',
        'MAC',
        'MAC Verify',
        'RNG Retrieve',
        'RNG Seed',
        'Hash',
    }

    # KMIP 1.2 added Set Attribute and Re-key Key Pair (normalized)
    ops_v1_2 = ops_v1_1 | {'Set Attribute (Modify)', 'Re-key Key Pair'}  # Normalized

    # KMIP 1.3 added Split Key operations
    ops_v1_3 = ops_v1_2 | {'Create Split Key', 'Join Split Key'}

    # KMIP 1.4 added Import and Export
    ops_v1_4 = ops_v1_3 | {'Import', 'Export'}

    # KMIP 2.0 (same as 1.4)
    ops_v2_0 = ops_v1_4.copy()

    # KMIP 2.1 (same as 2.0)
    ops_v2_1 = ops_v2_0.copy()

    ops_by_version = {
        '1.0': ops_v1_0,
        '1.1': ops_v1_1,
        '1.2': ops_v1_2,
        '1.3': ops_v1_3,
        '1.4': ops_v1_4,
        '2.0': ops_v2_0,
        '2.1': ops_v2_1,
    }

    # Managed objects (all versions support these core types)
    managed_objects = {
        'Certificate',
        'Symmetric Key',
        'Public Key',
        'Private Key',
        'Split Key',
        'Template',
        'Secret Data',
        'Opaque Data',
    }

    # Key structures (all versions)
    key_structures = {
        'Symmetric Key',
        'DSA Private Key',
        'DSA Public Key',
        'RSA Private Key',
        'RSA Public Key',
        'EC Private Key',
        'EC Public Key',
    }

    return {
        'operations': ops_by_version.get(version, ops_v2_1),
        'attributes': set(),  # Attributes are harder to track by version
        'managed_objects': managed_objects,
        'base_objects': set(),
        'key_structures': key_structures,
    }


def get_supported_versions() -> List[Tuple[int, int]]:
    """Extract supported KMIP versions from discover_versions.rs."""
    discover_file = OPS_DIR / 'discover_versions.rs'
    if not discover_file.exists():
        print(f"Warning: discover_versions.rs not found", file=sys.stderr)
        return [(2, 1)]

    content = discover_file.read_text(encoding='utf-8')
    versions = []

    # Parse the supported versions list
    version_pattern = (
        r'protocol_version_major:\s*(\d+),\s*protocol_version_minor:\s*(\d+)'
    )
    for match in re.finditer(version_pattern, content):
        major = int(match.group(1))
        minor = int(match.group(2))
        versions.append((major, minor))

    return versions if versions else [(2, 1)]


def get_operations_by_version() -> Dict[str, Set[str]]:
    """
    Determine which operations are available in each KMIP version.
    Parses actual OASIS KMIP specification HTML files.
    """
    print('Parsing KMIP specifications for operation support...')
    ops_by_version = {}

    for version in ['1.0', '1.1', '1.2', '1.3', '1.4', '2.0', '2.1']:
        print(f"  Parsing KMIP {version}...")
        spec_data = parse_kmip_spec(version)
        ops_by_version[version] = spec_data['operations']
        print(f"    Found {len(spec_data['operations'])} operations")

    return ops_by_version


def determine_baseline_profile_compliance(implemented_ops: Set[str]) -> Dict[str, str]:
    """
    Determine baseline profile compliance based on KMIP profiles spec.

    Returns dict mapping profile names to compliance status.
    """
    # Baseline Server profile requirements (from KMIP Profiles v2.1 Section 4.1)
    baseline_required_ops = {
        'Discover Versions',
        'Query',
        'Create',
        'Register',
        'Get',
        'Destroy',
        'Locate',
        'Activate',
        'Revoke',
    }

    baseline_optional_ops = {
        'Get Attributes',
        'Add Attribute',
        'Delete Attribute',
        'Set Attribute (Modify)',
        'Encrypt',
        'Decrypt',
        'Sign',
        'Signature Verify',
        'MAC',
        'Export',
        'Import',
        'Create Key Pair',
        'Re-key',
        'Re-key Key Pair',
        'DeriveKey',
        'Certify',
        'Validate',
        'Hash',
    }

    profiles = {}

    # Check Baseline Server Profile
    required_missing = baseline_required_ops - implemented_ops
    optional_supported = baseline_optional_ops & implemented_ops

    if not required_missing:
        profiles['Baseline Server'] = (
            f"✅ Compliant (all {len(baseline_required_ops)} required + {len(optional_supported)}/{len(baseline_optional_ops)} optional)"
        )
    else:
        profiles['Baseline Server'] = (
            f"❌ Non-compliant (missing required: {', '.join(sorted(required_missing))})"
        )

    return profiles


def detect_implemented_operations() -> Set[str]:
    """
    Scan the operations directory and return set of implemented operation names.
    Dynamically detects operations by walking the directory structure:
    - .rs files represent single operations
    - directories contain files related to one operation
    """
    ops = set()

    if not OPS_DIR.exists():
        print(f"Warning: Operations directory not found: {OPS_DIR}", file=sys.stderr)
        return ops

    # Files to skip (utility modules, not KMIP operations)
    skip_files = {
        'mod.rs',
        'utils.rs',
        'error.rs',
        'dispatch.rs',
        'message.rs',
        'export_get.rs',  # Helper for export/get operations
        'digest.rs',  # Utility for digest operations
    }

    def name_to_operation(name: str) -> str:
        """Convert a file/directory name to KMIP operation name."""
        # Remove .rs extension if present
        name = name.replace('.rs', '')

        # Special cases for compound names and abbreviations
        special_cases = {
            'activate': 'Activate',
            'add_attribute': 'Add Attribute',
            'certify': 'Certify',
            'create': 'Create',
            'create_key_pair': 'Create Key Pair',
            'decrypt': 'Decrypt',
            'delete_attribute': 'Delete Attribute',
            'derive_key': 'DeriveKey',
            'destroy': 'Destroy',
            'discover_versions': 'Discover Versions',
            'encrypt': 'Encrypt',
            'export': 'Export',
            'get': 'Get',
            'get_attributes': 'Get Attributes',
            'hash': 'Hash',
            'import': 'Import',
            'locate': 'Locate',
            'mac': 'MAC',
            'query': 'Query',
            'register': 'Register',
            'rekey': 'Re-key',
            'rekey_keypair': 'Re-key Key Pair',
            'revoke': 'Revoke',
            'set_attribute': 'Set Attribute (Modify)',
            'sign': 'Sign',
            'signature_verify': 'Signature Verify',
            'validate': 'Validate',
        }

        if name in special_cases:
            return special_cases[name]

        # Generic conversion: snake_case to Title Case
        parts = name.split('_')
        return ' '.join(word.capitalize() for word in parts)

    # Walk through the operations directory
    for item in OPS_DIR.iterdir():
        # Skip hidden files and files in the skip list
        if item.name.startswith('.') or item.name in skip_files:
            continue

        if item.is_file() and item.suffix == '.rs':
            # It's a .rs file - represents a single operation
            op_name = name_to_operation(item.stem)
            ops.add(op_name)
        elif item.is_dir():
            # It's a directory - check if it contains operation-related files
            # A directory represents one operation if it contains actual implementation files
            has_implementation = False
            for subitem in item.iterdir():
                if (
                    subitem.is_file()
                    and subitem.suffix == '.rs'
                    and subitem.name != 'mod.rs'
                ):
                    has_implementation = True
                    break

            if has_implementation:
                op_name = name_to_operation(item.name)
                ops.add(op_name)

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


def get_version_support_for_operation(
    op_name: str, ops_by_version: Dict[str, Set[str]], implemented: bool
) -> Dict[str, str]:
    """
    Determine support status for an operation across KMIP versions.
    Returns dict mapping version to status symbol.
    """
    result = {}
    for version in ['1.0', '1.1', '1.2', '1.3', '1.4', '2.0', '2.1']:
        if op_name in ops_by_version.get(version, set()):
            # Operation exists in this KMIP version
            result[version] = '✅' if implemented else '❌'
        else:
            # Operation doesn't exist in this version
            result[version] = 'N/A'
    return result


def group_version_columns(version_support: Dict[str, str]) -> List[Tuple[str, str]]:
    """
    Group consecutive KMIP versions with identical support status.
    Returns list of (version_range, status) tuples.

    Example: {'1.0': '✅', '1.1': '✅', '1.2': '✅'} -> [('1.0-1.2', '✅')]
    """
    versions = ['1.0', '1.1', '1.2', '1.3', '1.4', '2.0', '2.1']
    if not version_support:
        return []

    groups = []
    start_ver = None
    prev_status = None
    start_idx = 0

    for i, ver in enumerate(versions):
        status = version_support.get(ver, 'N/A')

        if prev_status is None:
            # First version
            start_ver = ver
            start_idx = i
            prev_status = status
        elif status != prev_status:
            # Status changed, save previous group
            end_ver = versions[i - 1]

            if start_ver == end_ver:
                groups.append((start_ver, prev_status))
            else:
                groups.append((f"{start_ver}-{end_ver}", prev_status))

            start_ver = ver
            start_idx = i
            prev_status = status

    # Add final group
    if start_ver:
        end_ver = versions[-1]
        if start_ver == end_ver:
            groups.append((start_ver, prev_status))
        else:
            groups.append((f"{start_ver}-{end_ver}", prev_status))

    return groups


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
    ops_support: Dict[str, str],
    attrs_support: Dict[str, str],
    ops_by_version: Dict[str, Set[str]],
    implemented_ops: Set[str],
    profile_compliance: Dict[str, str],
    server_versions: List[Tuple[int, int]],
    field_support: Dict[str, Dict[str, Set[str]]] = None,
) -> str:
    """Generate the complete support.md content with version-aware tables."""

    # Format server supported versions
    version_str = ', '.join([f"{maj}.{min}" for maj, min in server_versions])

    md = f"""# KMIP support by Cosmian KMS

This page summarizes the KMIP coverage in Cosmian KMS. The support status is
derived from the actual implementation in `crate/server/src/core/operations`.

**Cosmian KMS Server supports KMIP versions:** {version_str}

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated
- N/A Not applicable (operation/attribute not defined in that KMIP version)

## KMIP Baseline Profile Compliance

"""

    # Add profile compliance section
    for profile_name, status in profile_compliance.items():
        md += f"**{profile_name}:** {status}\n\n"

    md += """
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

"""

    # Build operations table with version columns
    # Collect ALL operations from all KMIP version specs (not just a hardcoded list)
    all_operations = set()
    versions = ['1.0', '1.1', '1.2', '1.3', '1.4', '2.0', '2.1']

    for version in versions:
        all_operations.update(ops_by_version.get(version, set()))

    # Sort operations alphabetically
    all_operations = sorted(all_operations)

    print(f"  Found {len(all_operations)} unique operations across all KMIP versions")

    # Build version support matrix
    op_version_matrix = {}
    for op in all_operations:
        implemented = op in implemented_ops
        version_support = get_version_support_for_operation(
            op, ops_by_version, implemented
        )
        op_version_matrix[op] = version_support

    # Create table header with individual version columns
    header_row = '| Operation |'
    separator_row = '| --------- |'
    for version in versions:
        header_row += f' {version} |'
        separator_row += ' :-----: |'

    md += header_row + '\n'
    md += separator_row + '\n'

    # Add operation rows
    for op in all_operations:
        row = f"| {op:<30} |"

        # Add status for each version
        for version in versions:
            status = op_version_matrix[op].get(version, 'N/A')
            row += f' {status:^7} |'

        md += row + '\n'

    md += """
### Methodology

- Operations marked ✅ are backed by a Rust implementation file under `crate/server/src/core/operations`.
- Operations marked ❌ are defined in the KMIP specification but not implemented in Cosmian KMS.
- Operations marked N/A do not exist in that particular KMIP version.
- This documentation is auto-generated by analyzing source code and KMIP specifications.

If you spot a mismatch or want to extend coverage, please open an issue or PR.

### Managed Objects

The following table shows managed object support across all KMIP versions.

"""

    # Build managed objects table with version columns
    managed_objects_list = [
        'Certificate',
        'Symmetric Key',
        'Public Key',
        'Private Key',
        'Split Key',
        'Template',
        'Secret Data',
        'Opaque Object',
        'PGP Key',
    ]

    # Determine implementation status for each object
    implemented_objects = {
        'Certificate': True,
        'Symmetric Key': True,
        'Public Key': True,
        'Private Key': True,
        'Split Key': False,
        'Template': False,  # Deprecated
        'Secret Data': True,
        'Opaque Object': True,
        'PGP Key': False,
    }

    # Build version support matrix for managed objects
    obj_version_matrix = {}
    for obj in managed_objects_list:
        version_support = {}
        for version in versions:
            # Check if object exists in this version's spec
            spec_data = parse_kmip_spec(version)
            obj_in_spec = obj in spec_data.get('managed_objects', set())

            if obj_in_spec:
                # Object exists in spec
                is_implemented = implemented_objects.get(obj, False)
                is_deprecated = obj == 'Template'
                if is_deprecated:
                    version_support[version] = '🚫'
                elif is_implemented:
                    version_support[version] = '✅'
                else:
                    version_support[version] = '❌'
            else:
                # Object doesn't exist in this version
                version_support[version] = 'N/A'

        obj_version_matrix[obj] = version_support

    # Create table header
    header_row = '| Managed Object |'
    separator_row = '| -------------- |'
    for version in versions:
        header_row += f' {version} |'
        separator_row += ' :-----: |'

    md += header_row + '\n'
    md += separator_row + '\n'

    # Add object rows
    for obj in managed_objects_list:
        row = f"| {obj:<14} |"
        for version in versions:
            status = obj_version_matrix[obj].get(version, 'N/A')
            row += f' {status:^7} |'
        md += row + '\n'

    md += """
Notes:

- Opaque Object import support is present (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.
- Template objects are deprecated in newer KMIP versions.

### Base Objects

The following table shows base object support across all KMIP versions.

"""

    # Base objects list
    base_objects_list = [
        'Attribute',
        'Credential',
        'Key Block',
        'Key Value',
        'Key Wrapping Data',
        'Key Wrapping Specification',
        'Transparent Key Structures',
        'Template-Attribute Structures',
        'Extension Information',
        'Data',
        'Data Length',
        'Signature Data',
        'MAC Data',
        'Nonce',
        'Correlation Value',
        'Init Indicator',
        'Final Indicator',
        'RNG Parameter',
        'Profile Information',
        'Validation Information',
        'Capability Information',
        'Authenticated Encryption Additional Data',
        'Authenticated Encryption Tag',
    ]

    # Implementation status for base objects
    implemented_base_objects = {
        'Attribute': True,
        'Credential': True,
        'Key Block': True,
        'Key Value': True,
        'Key Wrapping Data': True,
        'Key Wrapping Specification': True,
        'Transparent Key Structures': True,
        'Template-Attribute Structures': True,
        'Extension Information': True,
        'Data': False,
        'Data Length': False,
        'Signature Data': False,
        'MAC Data': False,
        'Nonce': True,
        'Correlation Value': False,
        'Init Indicator': False,
        'Final Indicator': False,
        'RNG Parameter': True,
        'Profile Information': True,
        'Validation Information': True,
        'Capability Information': True,
        'Authenticated Encryption Additional Data': True,
        'Authenticated Encryption Tag': True,
    }

    # For base objects, we'll assume they're present in all versions
    # (they're fundamental structures)
    header_row = '| Base Object |'
    separator_row = '| ----------- |'
    for version in versions:
        header_row += f' {version} |'
        separator_row += ' :-----: |'

    md += header_row + '\n'
    md += separator_row + '\n'

    for obj in base_objects_list:
        is_implemented = implemented_base_objects.get(obj, False)
        status = '✅' if is_implemented else '❌'
        row = f"| {obj:<40} |"
        for version in versions:
            row += f' {status:^7} |'
        md += row + '\n'

    md += """
Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.
- Base objects are fundamental structures present across all KMIP versions.

### Transparent Key Structures

The following table shows transparent key structure support across all KMIP versions.

"""

    # Transparent key structures
    key_structures_list = [
        'Symmetric Key',
        'DSA Private Key',
        'DSA Public Key',
        'RSA Private Key',
        'RSA Public Key',
        'DH Private Key',
        'DH Public Key',
        'ECDSA Private Key',
        'ECDSA Public Key',
        'ECDH Private Key',
        'ECDH Public Key',
        'ECMQV Private Key',
        'ECMQV Public Key',
        'EC Private Key',
        'EC Public Key',
    ]

    # Implementation status
    implemented_structures = {
        'Symmetric Key': True,
        'DSA Private Key': False,
        'DSA Public Key': False,
        'RSA Private Key': True,
        'RSA Public Key': True,
        'DH Private Key': False,
        'DH Public Key': False,
        'ECDSA Private Key': True,
        'ECDSA Public Key': True,
        'ECDH Private Key': False,
        'ECDH Public Key': False,
        'ECMQV Private Key': False,
        'ECMQV Public Key': False,
        'EC Private Key': True,
        'EC Public Key': True,
    }

    # Build version support matrix
    struct_version_matrix = {}
    for struct in key_structures_list:
        version_support = {}
        for version in versions:
            spec_data = parse_kmip_spec(version)
            struct_in_spec = struct in spec_data.get('key_structures', set())

            if struct_in_spec:
                is_implemented = implemented_structures.get(struct, False)
                version_support[version] = '✅' if is_implemented else '❌'
            else:
                version_support[version] = 'N/A'

        struct_version_matrix[struct] = version_support

    header_row = '| Structure |'
    separator_row = '| --------- |'
    for version in versions:
        header_row += f' {version} |'
        separator_row += ' :-----: |'

    md += header_row + '\n'
    md += separator_row + '\n'

    for struct in key_structures_list:
        row = f"| {struct:<24} |"
        for version in versions:
            status = struct_version_matrix[struct].get(version, 'N/A')
            row += f' {status:^7} |'
        md += row + '\n'

    md += """
Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

### Attributes

"""

    # Attributes table - with version columns
    md += '| Attribute |'
    for version in versions:
        md += f' {version} |'
    md += '\n'

    md += '| --------- |'
    for _ in versions:
        md += ' :-----: |'
    md += '\n'

    # For attributes, show implementation status across all versions
    # (most attributes are present in all versions)
    for attr in sorted(attrs_support.keys()):
        status = attrs_support[attr]
        row = f"| {attr:<35} |"
        for version in versions:
            # Attributes are generally present in all versions
            row += f' {status:^7} |'
        md += row + '\n'

    md += """
Notes:

- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- A ✅ indicates the attribute is used or updated by at least one KMIP operation implementation in `crate/server/src/core/operations`, explicitly excluding the attribute-only handlers (Add/Delete/Get/Set Attribute).
- Most attributes are present across all KMIP versions with some additions in newer versions.
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


def parse_rust_operation_structs(version: str) -> Dict[str, Set[str]]:
    """
    Parse Rust KMIP operation structs to extract field support.
    Returns dict mapping operation names to sets of supported field names.

    Args:
        version: KMIP version like '1.4' or '2.1'

    Returns:
        Dict mapping operation names to sets of field names
    """
    version_dir = ROOT / 'crate' / 'kmip' / 'src' / f'kmip_{version.replace(".", "_")}'
    operations_file = version_dir / 'kmip_operations.rs'

    if not operations_file.exists():
        print(
            f"  Warning: Operations file not found: {operations_file}", file=sys.stderr
        )
        return {}

    operation_fields = {}

    try:
        content = operations_file.read_text(encoding='utf-8')

        # Parse struct definitions using regex
        # Pattern matches: pub struct OperationName { ... }
        struct_pattern = (
            r'(?:^|\n)(?:#\[.*?\]\s*)*pub struct (\w+(?:Response)?)\s*\{([^}]+)\}'
        )

        for match in re.finditer(struct_pattern, content, re.MULTILINE | re.DOTALL):
            struct_name = match.group(1)
            struct_body = match.group(2)

            # Extract field names from the struct body
            # Look for lines like: pub field_name: Type or #[serde(...)] \n pub field_name: Type
            # Match field declarations, handling attributes and pub keywords
            lines = struct_body.split('\n')
            fields = set()

            for line in lines:
                line = line.strip()
                # Skip comments, attributes, and empty lines
                if (
                    not line
                    or line.startswith('//')
                    or line.startswith('#[')
                    or line.startswith('/*')
                ):
                    continue

                # Match: pub field_name: Type, or field_name: Type,
                field_match = re.match(r'(?:pub\s+)?(\w+)\s*:\s*', line)
                if field_match:
                    field_name = field_match.group(1)
                    # Skip type names and keywords that might appear
                    if field_name not in (
                        'serde',
                        'skip_serializing_if',
                        'rename_all',
                        'pub',
                    ):
                        fields.add(field_name)

            if fields:
                operation_fields[struct_name] = fields

        return operation_fields

    except Exception as e:
        print(f"  Warning: Error parsing {operations_file}: {e}", file=sys.stderr)
        return {}


def get_operation_field_support(versions: List[str]) -> Dict[str, Dict[str, Set[str]]]:
    """
    Get operation field support across all KMIP versions.

    Args:
        versions: List of KMIP versions like ['1.0', '1.1', ..., '2.1']

    Returns:
        Dict mapping version -> operation name -> set of field names
    """
    print('Parsing Rust operation structs for field-level support...')

    field_support_by_version = {}

    # Map versions to actual implementation files
    # 1.0-1.3 don't have separate implementations, they use 1.4
    # 2.0 uses 2.1
    version_to_impl = {
        '1.0': '1.4',
        '1.1': '1.4',
        '1.2': '1.4',
        '1.3': '1.4',
        '1.4': '1.4',
        '2.0': '2.1',
        '2.1': '2.1',
    }

    parsed_impls = {}  # Cache parsed implementations

    for version in versions:
        impl_version = version_to_impl.get(version)
        if not impl_version:
            continue

        # Parse implementation if not already cached
        if impl_version not in parsed_impls:
            print(f"  Parsing KMIP {impl_version} operation structs...")
            parsed_impls[impl_version] = parse_rust_operation_structs(impl_version)

        field_support_by_version[version] = parsed_impls[impl_version]

    return field_support_by_version


def main() -> int:
    """Main entry point."""
    print('Analyzing KMS implementation...')

    # Get server supported versions
    server_versions = get_supported_versions()
    print(
        f"  Server supports KMIP versions: {', '.join([f'{maj}.{min}' for maj, min in server_versions])}"
    )

    # Detect implemented operations
    ops = detect_implemented_operations()
    print(f"  Found {len(ops)} implemented operations")

    # Parse attributes
    attrs = parse_attributes()
    print(f"  Found {len(attrs)} defined attributes")

    # Get operations by version
    ops_by_version = get_operations_by_version()

    # Get operation field support from Rust structs
    versions = ['1.0', '1.1', '1.2', '1.3', '1.4', '2.0', '2.1']
    field_support = get_operation_field_support(versions)

    # Determine baseline profile compliance
    print('Checking baseline profile compliance...')
    profile_compliance = determine_baseline_profile_compliance(ops)
    for profile, status in profile_compliance.items():
        print(f"  {profile}: {status}")

    # Map support
    ops_support = map_operation_support(ops)
    attrs_support = map_attribute_support(attrs)

    # Generate markdown
    print('Generating documentation...')
    support_md = generate_support_markdown(
        ops_support,
        attrs_support,
        ops_by_version,
        ops,
        profile_compliance,
        server_versions,
        field_support,
    )

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

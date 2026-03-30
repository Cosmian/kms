#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate per-XML-file markdown tables summarizing the sequence of KMIP operations
from the conformance XML vectors and append them to the specifications README.

For each step, the table shows:
- Operation (from RequestMessage/BatchItem)
- Details (best-effort request summary)
- Expected Status (from the paired ResponseMessage)
- Client Correlation (ClientCorrelationValue from the RequestHeader)
"""
from __future__ import annotations

import sys
from pathlib import Path
import argparse
import xml.etree.ElementTree as ET

# Repository root (the folder containing this scripts/ directory)
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_XML_DIR = ROOT / 'crate/kmip/src/kmip_2_1/specifications/XML'
DEFAULT_README = ROOT / 'crate/kmip/src/kmip_2_1/specifications/README.md'


def attr_val(elem: ET.Element | None, name: str = 'value') -> str | None:
    if elem is None:
        return None
    return elem.attrib.get(name)


def has(elem: ET.Element, tag: str) -> bool:
    return elem.find(tag) is not None


def text_list(elem: ET.Element, tag: str) -> list[str]:
    return [attr_val(e) or '' for e in elem.findall(tag)]


def summarize_request(op: str, payload: ET.Element | None) -> str:
    if payload is None:
        return '-'

    # Common helpers
    uid = attr_val(payload.find('UniqueIdentifier'))
    if op in {
        'Get',
        'Destroy',
        'GetAttributes',
        'GetAttributeList',
        'AddAttribute',
        'ModifyAttribute',
        'DeleteAttribute',
    }:
        return f"UID={uid or 'last'}"

    if op in {'Register', 'Create'}:
        obj_type = attr_val(payload.find('ObjectType'))
        alg = attr_val(payload.find('CryptographicAlgorithm'))
        length = attr_val(payload.find('CryptographicLength'))
        usage = attr_val(payload.find('CryptographicUsageMask'))
        parts = []
        if obj_type:
            parts.append(f'ObjectType={obj_type}')
        if alg:
            parts.append(f'Alg={alg}')
        if length:
            parts.append(f'Len={length}')
        if usage:
            parts.append(f'Usage={usage}')
        return '; '.join(parts) or '-'

    if op == 'CreateKeyPair':
        alg = attr_val(payload.find('CryptographicAlgorithm'))
        length = attr_val(payload.find('CryptographicLength'))
        parts = []
        if alg:
            parts.append(f'Alg={alg}')
        if length:
            parts.append(f'Len={length}')
        return '; '.join(parts) or '-'

    if op == 'Locate':
        name = attr_val(payload.find('Attributes/Name/NameValue'))
        if name:
            return f'Name={name}'
        # Fallback: count attributes
        attrs = payload.find('Attributes')
        count = len(list(attrs)) if attrs is not None else 0
        return f'Attributes={count}'

    if op in {'Encrypt', 'Decrypt'}:
        flags = []
        if has(payload, 'AuthenticatedEncryptionAdditionalData'):
            flags.append('AAD')
        if has(payload, 'IVCounterNonce'):
            flags.append('IV')
        if has(payload, 'AuthenticationTag'):
            flags.append('Tag')
        if has(payload, 'InitIndicator'):
            flags.append('Init')
        if has(payload, 'FinalIndicator'):
            flags.append('Final')
        if payload.find('CorrelationValue') is not None:
            flags.append('Corr')
        return ', '.join(flags) or '-'

    if op in {'MAC', 'MACVerify', 'Sign', 'SignatureVerify'}:
        flags = []
        if has(payload, 'InitIndicator'):
            flags.append('Init')
        if has(payload, 'FinalIndicator'):
            flags.append('Final')
        if payload.find('CorrelationValue') is not None:
            flags.append('Corr')
        return ', '.join(flags) or '-'

    if op == 'PKCS_11':
        func = attr_val(payload.find('Function'))
        return f'Function={func}' if func else '-'

    if op == 'Interop':
        fn = attr_val(payload.find('InteropFunction'))
        ident = attr_val(payload.find('InteropIdentifier'))
        pieces = []
        if fn:
            pieces.append(fn)
        if ident:
            pieces.append(ident)
        return ': '.join(pieces) or '-'

    # Default: nothing special extracted
    return '-'


def extract_operations(xml_path: Path) -> list[tuple[str, str, str, str]]:
    """
    Return list of (operation, details, expected_result_status, client_correlation_value)
    in request order for this XML file.

    - operation, details are derived from RequestMessage/BatchItem.
    - expected_result_status is taken from the matching ResponseMessage/BatchItem/ResultStatus (or ResponseMessage/ResultStatus).
    - client_correlation_value is taken from RequestMessage/RequestHeader/ClientCorrelationValue when present.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Collect requests and responses in order
    requests = list(root.findall('RequestMessage'))
    responses = list(root.findall('ResponseMessage'))

    steps: list[tuple[str, str, str, str]] = []

    # Helper to extract result status from a ResponseMessage element
    def extract_status(resp: ET.Element | None) -> str:
        if resp is None:
            return '-'
        # Prefer per-batch item status
        rs = resp.find('BatchItem/ResultStatus')
        if rs is None:
            rs = resp.find('ResultStatus')
        return attr_val(rs) or '-'

    # Iterate pairing by index; if responses fewer than requests, missing ones become "-"
    for idx, req in enumerate(requests):
        batch = req.find('BatchItem')
        if batch is None:
            continue
        op_el = batch.find('Operation')
        if op_el is None:
            continue
        op = attr_val(op_el) or '-'
        payload = batch.find('RequestPayload')
        details = summarize_request(op, payload)

        # ClientCorrelationValue from RequestHeader
        ccv = attr_val(req.find('RequestHeader/ClientCorrelationValue')) or '-'

        # Expected status from parallel ResponseMessage
        resp = responses[idx] if idx < len(responses) else None
        status = extract_status(resp)

        steps.append((op, details, status, ccv))
    return steps


def find_xml_files(xml_dir: Path) -> list[Path]:
    files: list[Path] = []
    for sub in ('mandatory', 'optional'):
        for p in sorted((xml_dir / sub).glob('*.xml')):
            files.append(p)
    return files


def infer_version_label(xml_dir: Path) -> str:
    s = str(xml_dir)
    if 'kmip_2_1' in s:
        return 'KMIP 2.1'
    if 'kmip_1_4' in s:
        return 'KMIP 1.4'
    return 'KMIP'


def default_overview(version_label: str, xml_dir: Path) -> str:
    return f"""
# {version_label} XML Specifications – Test Flow Overview

This directory contains the {version_label} conformance test vectors (XML) organized per profile:

- `XML/mandatory/` – Mandatory profile test cases
- `XML/optional/` – Optional profile test cases

They originate from the OASIS KMIP Profiles repository of test cases. Our test harness parses each XML into structured KMIP requests/responses and executes them against the KMS, validating both behavior and payloads.

## How the XML runner works

High-level loop per XML file:

1. Parse the XML into a `KmipXmlDoc` with RequestMessage(s)
   and expected ResponseMessage(s).
2. For each request in order:
   - Apply placeholder substitutions (e.g., `$UNIQUE_IDENTIFIER_0`, `$NOW`).
   - Inject cached values as required by later operations:
     - UID (ID Placeholder) from prior responses
     - AEAD artifacts (IV/Nonce, Tag, AAD) and correlation values
     - Sign/MAC outputs for verification requests
   - Send the request and capture the actual response.
   - Compare with expected response, allowing tolerated flexibilities
     (timestamps, RandomIV, allowed orderings, etc.).
   - Update caches (last UID, AEAD artifacts by AAD, correlation,
     last Signature/MAC).
3. Ensure request and response counts match and finalize invariants.

## End-to-end flow steps (what we validate)

| # | Operation | Relevant request fields we track | Response validation focus | Cache and side-effects |
|---:|---|---|---|---|
| 1 | Interop (Begin/End) | InteropIdentifier | ResultStatus=Success | None |
| 2 | Log | LogMessage | ResultStatus=Success | None |
| 3 | Register | ObjectType; Object (KeyBlock/KeyValue); Attributes (Algorithm, Length, UsageMask, Name) | UniqueIdentifier returned; ObjectType and key material/attributes echoed when applicable | Set ID Placeholder (last UID) |
| 4 | Create | ObjectType; Attributes (Algorithm, Length, UsageMask) | UniqueIdentifier; created attributes | Set ID Placeholder |
| 5 | CreateKeyPair | Common/Private/Public Attributes | Private/Public Key UIDs | Set ID Placeholder to Private Key UID |
| 6 | Get | UniqueIdentifier; KeyFormatType/Wrap params (optional) | ObjectType; object payload (KeyBlock); echoed UID | None |
| 7 | Export | UniqueIdentifier; KeyFormatType/Wrap params | ObjectType; Attributes; Object | None |
| 8 | Import | Object (e.g., key/cert); Attributes (optional) | UniqueIdentifier | Set ID Placeholder |
| 9 | Locate | Attributes or Names used to search | One or more UniqueIdentifier values | Update last UID (when single result) |
| 10 | SetAttribute | UniqueIdentifier; Attribute | UniqueIdentifier | None |
| 11 | Add/Modify/DeleteAttribute | UniqueIdentifier; Attribute/Reference | UniqueIdentifier | None |
| 12 | GetAttributes | UniqueIdentifier; AttributeReference (optional) | Attributes/values present | None |
| 13 | Activate | UniqueIdentifier | UniqueIdentifier | None |
| 14 | Revoke | UniqueIdentifier; RevocationReason | UniqueIdentifier | None |
| 15 | Validate | UniqueIdentifier(s) or Certificate; ValidityTime | ValidateResponse payload | None |
| 16 | Encrypt | UID; CryptoParams; Data; IV?; AAD?; init/final?; corr? | Ciphertext; IV (RandomIV); Tag; Corr | Cache AAD→(IV,Tag,CV); last enc artifacts |
| 17 | Decrypt | UID; CryptoParams; Data; IV; Tag; AAD; init/final; corr | Plaintext; Corr (multipart) | Clear enc artifacts on completion |
| 18 | MAC / MACVerify | UniqueIdentifier; Data; AAD; init/final; correlation | MAC value (for MAC); verification result for MACVerify | Cache last MAC for MACVerify |
| 19 | Sign / SignatureVerify | UniqueIdentifier; Data/Hash; Algorithm params | Signature (for Sign); verification result for SignatureVerify | Cache last Signature for SignatureVerify |
| 20 | PKCS11/PKCS11Response | Function; InputParameters; CorrelationValue | ReturnCode; OutputParameters; CorrelationValue | Cache last PKCS#11 correlation value |
| 21 | DiscoverVersions/Query/Hash/DeriveKey | Operation-specific inputs | Response payload structure | None |
| 22 | Destroy | UniqueIdentifier; extensions (remove/cascade when supported) | UniqueIdentifier | None |

---
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Generate per-file KMIP XML README tables.'
    )
    parser.add_argument(
        '--xml-dir',
        type=Path,
        default=DEFAULT_XML_DIR,
        help='Path to specifications/XML directory',
    )
    parser.add_argument(
        '--readme', type=Path, default=DEFAULT_README, help='Path to README.md to write'
    )
    args = parser.parse_args()

    xml_dir: Path = args.xml_dir
    readme: Path = args.readme

    files = find_xml_files(xml_dir)
    if not files:
        print(f'No XML files found under {xml_dir}', file=sys.stderr)
        return 1

    lines: list[str] = []
    lines.append('\n## Per-file summaries\n')
    lines.append(
        '\nEach table lists the RequestMessage operations in order. Details are best-effort and include common inputs like UID, ObjectType/Alg/Len, or flags (AAD/IV/Tag/Init/Final/Corr). Additional columns include the expected ResultStatus from the corresponding ResponseMessage and the ClientCorrelationValue from the RequestHeader when present.\n'
    )

    for xml in files:
        # If the XML is within the expected xml_dir, make a concise relative path including mandatory/optional
        try:
            rel = xml.relative_to(xml_dir)
        except Exception:
            rel = xml.name
        steps = extract_operations(xml)
        lines.append(f'\n### {rel.as_posix()}\n')
        lines.append(
            '\n| Step | Operation | Details | Expected Status | Client Correlation |\n|---:|---|---|---|---|\n'
        )
        for i, (op, details, status, ccv) in enumerate(steps, start=1):
            # Escape vertical bars in details if any
            safe_details = (details or '-').replace('|', '\\|')
            safe_status = (status or '-').replace('|', '\\|')
            safe_ccv = (ccv or '-').replace('|', '\\|')
            lines.append(
                f'| {i} | {op} | {safe_details} | {safe_status} | {safe_ccv} |\n'
            )

    # Prepare README content (add overview if missing/creating new file)
    original = readme.read_text(encoding='utf-8') if readme.exists() else ''
    # Remove any previous generated section to avoid duplication
    marker = '\n## Per-file summaries\n'
    if marker in original:
        original = original.split(marker, 1)[0].rstrip()
    else:
        # If no README existed or no marker found, include a default overview header
        version_label = infer_version_label(xml_dir)
        header = default_overview(version_label, xml_dir)
        if not original:
            original = header.strip() + '\n'
        else:
            # README exists but doesn't have the marker; keep its content as-is
            pass

    new_content = original.rstrip() + '\n' + ''.join(lines)
    readme.parent.mkdir(parents=True, exist_ok=True)
    readme.write_text(new_content, encoding='utf-8')
    print(f'Updated {readme} with per-file tables for {len(files)} XML files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

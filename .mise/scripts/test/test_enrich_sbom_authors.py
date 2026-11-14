#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression: SBOM components built by enrich_sbom_authors.py must satisfy the CycloneDX 1.6 schema.

Cargo `license` values are SPDX expressions ("MIT OR Apache-2.0"); putting them under
`license.id` made every server/ckms SBOM fail `cyclonedx validate`.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.mise/scripts/sbom/enrich_sbom_authors.py'
SCHEMA = ROOT / '.mise/scripts/sbom/schema/bom-1.6.schema.json'


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EnrichSbomLicenseTests(unittest.TestCase):
    def test_cargo_license_strings_produce_schema_valid_components(self) -> None:
        # Needs jsonschema: its absence must fail loudly, never skip the check.
        from jsonschema import Draft7Validator

        enrich = load(SCRIPT, 'enrich_sbom_authors')
        licenses = ['MIT OR Apache-2.0', 'MIT/Apache-2.0', 'MIT', '']
        components = [
            enrich._make_cdx_component(
                {
                    'purl': f'pkg:cargo/c{i}@1.0.0',
                    'name': f'c{i}',
                    'version': '1.0.0',
                    'description': '',
                    'license': lic,
                    'authors': '',
                    'repository': '',
                }
            )
            for i, lic in enumerate(licenses)
        ]
        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.6',
            'version': 1,
            'serialNumber': 'urn:uuid:00000000-0000-4000-8000-000000000000',
            'components': components,
        }
        validator = Draft7Validator(json.loads(SCHEMA.read_text(encoding='utf-8')))
        errors = [e.message for e in validator.iter_errors(bom)]
        self.assertEqual(errors, [])
        self.assertEqual(
            components[1]['licenses'], [{'expression': 'MIT OR Apache-2.0'}]
        )


if __name__ == '__main__':
    unittest.main()

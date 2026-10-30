#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression checks for the CBOM generator: scan root, schema conformance, FIPS flags, OIDs."""

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.mise/scripts/sbom/generate_cbom.py'
VALIDATOR = ROOT / '.mise/scripts/sbom/validate_cbom.py'
PQC_MOD = ROOT / 'crate/crypto/src/crypto/pqc/mod.rs'
PKI_DOC = ROOT / 'documentation/docs/use_cases/pki.md'
OFFICIAL_SCHEMA = ROOT / '.mise/scripts/sbom/schema/bom-1.6.schema.json'

# Crates absent from the default (FIPS) build: `cargo tree -i <crate>` finds no package
# without `--features non-fips`. A catalogue entry using one of them cannot be FIPS.
NON_FIPS_ONLY_LIBS = {
    'ml-kem',
    'cosmian_cover_crypt',
    'cosmian_openssl_provider',
    'cosmian_rust_curve25519_provider',
}


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateCbomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = load(SCRIPT, 'generate_cbom')
        cls.validator = load(VALIDATOR, 'validate_cbom')
        # The source scan is exercised by its own test; the others only need the structure.
        scan, cls.generator.find_in_sources = (
            cls.generator.find_in_sources,
            lambda *_: True,
        )
        try:
            cls.cbom = cls.generator.build_cbom(ROOT, '0.0.0', lib_versions={})
        finally:
            cls.generator.find_in_sources = scan
        cls.assets = {
            c['bom-ref']: c
            for c in cls.cbom['components']
            if c['type'] == 'cryptographic-asset'
        }

    def test_source_scan_runs_against_the_repository(self) -> None:
        # With the scan root pointing at .mise/scripts, every pattern matched vacuously.
        generator = load(SCRIPT, 'generate_cbom_scan')
        self.assertTrue((generator.REPO_ROOT / 'Cargo.toml').is_file())
        generator.ALGORITHMS = [
            {
                'bom_ref': 'algo-bogus',
                'name': 'Bogus',
                'primitive': 'hash',
                'key_size': None,
                'classical_security': 0,
                'nist_pqc_level': 0,
                'fips': False,
                'functions': ['digest'],
                'implementing_libs': ['openssl'],
                'usage': 'regression probe',
                'patterns': [r'zz_no_such_algorithm_zz'],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'cbom.json'
            argv, sys.argv = sys.argv, ['generate_cbom.py', '-o', str(output)]
            try:
                generator.main()
            finally:
                sys.argv = argv
            components = {
                c['bom-ref']: c for c in json.loads(output.read_text())['components']
            }
        found = {p['name']: p['value'] for p in components['algo-bogus']['properties']}
        self.assertEqual(found['cosmian:found-in-source'], 'false')

    def test_every_pqc_algorithm_name_in_the_code_has_a_catalogue_entry(self) -> None:
        names = re.findall(
            r'=> Ok\("((?:ML-KEM|ML-DSA|SLH-DSA)-[A-Za-z0-9-]+|X\d+MLKEM\d+)"\)',
            PQC_MOD.read_text(encoding='utf-8'),
        )
        self.assertGreaterEqual(
            len(names), 20
        )  # guards against the regex silently matching nothing
        catalogued = [a['name'] for a in self.generator.ALGORITHMS]
        missing = [n for n in names if not any(c.startswith(n) for c in catalogued)]
        self.assertEqual(missing, [])

    def test_generated_cbom_passes_the_validator_structural_pass(self) -> None:
        self.assertEqual(self.validator.validate_structural(self.cbom), [])

    def test_generated_cbom_has_no_schema_errors(self) -> None:
        # Needs jsonschema: its absence must fail loudly, never skip the check.
        self.assertEqual(self.validator.validate_schema(self.cbom), [])

    def test_a_missing_jsonschema_package_is_an_error_not_a_pass(self) -> None:
        saved = sys.modules.get('jsonschema')
        sys.modules['jsonschema'] = None  # makes `import jsonschema` raise ImportError
        try:
            errors = self.validator.validate_schema(self.cbom)
        finally:
            if saved is None:
                del sys.modules['jsonschema']
            else:
                sys.modules['jsonschema'] = saved
        self.assertEqual(len(errors), 1)
        self.assertIn('jsonschema', errors[0])

    def test_certification_requires_the_validated_openssl_provider(self) -> None:
        for algo in self.generator.ALGORITHMS:
            levels = self.assets[algo['bom_ref']]['cryptoProperties'][
                'algorithmProperties'
            ]['certificationLevel']
            certified = (
                algo['fips'] is not False and 'openssl' in algo['implementing_libs']
            )
            self.assertEqual(bool(levels), certified, algo['bom_ref'])

    def test_validator_vocabularies_match_the_official_schema(self) -> None:
        schema = json.loads(OFFICIAL_SCHEMA.read_text(encoding='utf-8'))
        props = schema['definitions']['cryptoProperties']['properties'][
            'algorithmProperties'
        ]['properties']
        enum = lambda key: set(
            props[key].get('enum') or props[key]['items']['enum']
        )  # noqa: E731
        v = self.validator
        self.assertEqual(enum('primitive'), v.VALID_PRIMITIVES)
        self.assertEqual(enum('mode'), v.VALID_MODES)
        self.assertEqual(enum('padding'), v.VALID_PADDINGS)
        self.assertEqual(enum('cryptoFunctions'), v.VALID_CRYPTO_FUNCTIONS)
        self.assertEqual(enum('certificationLevel'), v.VALID_CERTIFICATION_LEVELS)
        self.assertEqual(set(props), v.ALLOWED_ALGORITHM_PROPERTIES)

    def test_values_missing_from_the_schema_are_kept_exactly(self) -> None:
        def exact(ref: str) -> dict[str, str]:
            props = self.assets[ref]['properties']
            return {
                p['name']: p['value'] for p in props if p['name'].startswith('cosmian:')
            }

        xts = self.assets['algo-aes-256-xts']['cryptoProperties']['algorithmProperties']
        self.assertEqual(
            (xts['mode'], exact('algo-aes-256-xts')['cosmian:mode']), ('other', 'xts')
        )
        kw = self.assets['algo-aes-kw']['cryptoProperties']['algorithmProperties']
        self.assertEqual(kw['cryptoFunctions'], ['encrypt', 'decrypt'])
        self.assertEqual(
            exact('algo-aes-kw')['cosmian:crypto-functions'], 'wrap,unwrap'
        )
        pss = self.assets['algo-rsassa-pss-2048']['cryptoProperties'][
            'algorithmProperties'
        ]
        self.assertEqual(
            (pss['padding'], exact('algo-rsassa-pss-2048')['cosmian:padding']),
            ('other', 'pss'),
        )

    def test_algorithms_built_on_non_fips_only_crates_are_not_marked_fips(self) -> None:
        wrong = [
            a['bom_ref']
            for a in self.generator.ALGORITHMS
            if a['fips'] is not False
            and NON_FIPS_ONLY_LIBS & set(a['implementing_libs'])
        ]
        self.assertEqual(wrong, [])

    def test_oids_in_the_pki_guide_match_the_catalogue(self) -> None:
        catalogued = {
            a['name']: a['oid'] for a in self.generator.ALGORITHMS if a.get('oid')
        }
        rows = re.findall(
            r'^\| ((?:ML-DSA|SLH-DSA|ML-KEM)-[A-Za-z0-9-]+)\s*\| `([0-9.]+)`',
            PKI_DOC.read_text(encoding='utf-8'),
            re.MULTILINE,
        )
        self.assertGreaterEqual(len(rows), 18)  # 3 ML-DSA + 12 SLH-DSA + 3 ML-KEM
        self.assertEqual([(n, o) for n, o in rows if catalogued.get(n) != o], [])


if __name__ == '__main__':
    unittest.main()

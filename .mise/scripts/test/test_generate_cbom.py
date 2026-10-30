#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression checks for the CBOM generator: source scan root and catalogue coverage."""

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.mise/scripts/sbom/generate_cbom.py'
PQC_MOD = ROOT / 'crate/crypto/src/crypto/pqc/mod.rs'


def load_generator():
    spec = importlib.util.spec_from_file_location('generate_cbom', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateCbomTests(unittest.TestCase):
    def test_source_scan_runs_against_the_repository(self) -> None:
        # With the scan root pointing at .mise/scripts, every pattern matched vacuously.
        generator = load_generator()
        self.assertTrue((generator.REPO_ROOT / 'Cargo.toml').is_file())
        generator.ALGORITHMS.append(
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
        )
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
        generator = load_generator()
        names = re.findall(
            r'=> Ok\("((?:ML-KEM|ML-DSA|SLH-DSA)-[A-Za-z0-9-]+|X\d+MLKEM\d+)"\)',
            PQC_MOD.read_text(encoding='utf-8'),
        )
        self.assertGreaterEqual(
            len(names), 20
        )  # guards against the regex silently matching nothing
        catalogued = [a['name'] for a in generator.ALGORITHMS]
        missing = [n for n in names if not any(c.startswith(n) for c in catalogued)]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()

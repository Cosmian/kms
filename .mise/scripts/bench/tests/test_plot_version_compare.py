# -*- coding: utf-8 -*-
"""Focused tests for the PKCS#11 overhead report pipeline."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'plot_version_compare.py'
FIXTURES = Path(__file__).parent / 'fixtures'
SPEC = importlib.util.spec_from_file_location('plot_version_compare', SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f'Cannot import {SCRIPT}')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Pkcs11OverheadReportTests(unittest.TestCase):
    """Exercise full, missing, and partial overhead inputs."""

    def test_full_schema_renders_tiers_deltas_and_phase_boundaries(self) -> None:
        data = MODULE.parse_pkcs11_overhead_json(FIXTURES / 'pkcs11_overhead_full.json')

        lines = MODULE._render_pkcs11_overhead_section({'5.24.0': data}, ['5.24.0'])
        report = '\n'.join(lines)

        self.assertIn('## PKCS#11 Ed25519 signing overhead', report)
        self.assertIn('[87.0 µs](https://docs.cosmian.com/', report)
        self.assertIn('pre-serialized full `RequestMessage`', report)
        self.assertIn('machine-local', report)
        self.assertIn('payload: **256 bytes**', report)
        self.assertIn('binary request: **128 bytes**', report)
        self.assertIn('| `pkcs11` | Bare Sign raw HTTP | 120.0 µs |', report)
        self.assertIn(
            '| `pkcs11` | Typed binary-TTLV message Sign (bracketed mean) | 110.0 µs |',
            report,
        )
        self.assertNotIn('`typed-binary-message-sign-before`', report)
        self.assertNotIn('`typed-binary-message-sign-after`', report)
        self.assertNotIn('`pkcs11-one-call-before`', report)
        self.assertNotIn('`pkcs11-one-call-after`', report)
        self.assertIn(
            '| Published-equivalent full-message raw HTTP | +20.0 µs | +20.0% |',
            report,
        )
        self.assertIn('#### Internal phase boundaries', report)
        self.assertIn('must not be summed', report)
        self.assertIn('approximate upper bounds from log2', report)
        self.assertIn(
            '| C_SignMessage body | Inclusive boundary | 180.0 µs |',
            report,
        )
        self.assertIn('| Per-session lock wait | Leaf timing | 9.0 µs |', report)

    def test_missing_and_partial_data_are_tolerated(self) -> None:
        missing = MODULE.parse_pkcs11_overhead_json(FIXTURES / 'does_not_exist.json')
        partial = MODULE.parse_pkcs11_overhead_json(
            FIXTURES / 'pkcs11_overhead_partial.json'
        )

        self.assertEqual({}, missing)
        self.assertEqual(1, len(partial['tiers']))
        self.assertEqual(1, len(partial['phases']))
        self.assertEqual(
            [],
            MODULE._render_pkcs11_overhead_section({'5.24.0': missing}, ['5.24.0']),
        )
        report = '\n'.join(
            MODULE._render_pkcs11_overhead_section({'5.24.0': partial}, ['5.24.0'])
        )
        self.assertIn('PKCS#11 v3 C_SignMessage', report)
        self.assertIn('Per-session lock wait', report)
        self.assertNotIn('invalid-mean', report)
        self.assertNotIn('invalid-count', report)

    def test_missing_tier_and_phase_arrays_produce_empty_data(self) -> None:
        minimal = (
            '{"schema_version": 1, "algorithm": "eddsa-ed25519",'
            ' "payload_bytes": 256}'
        )
        path = Path('minimal-pkcs11-overhead.json')

        with (
            patch.object(Path, 'exists', return_value=True),
            patch.object(Path, 'read_text', return_value=minimal),
        ):
            data = MODULE.parse_pkcs11_overhead_json(path)

        self.assertEqual([], data['tiers'])
        self.assertEqual([], data['phases'])

    def test_oversized_numbers_are_ignored_without_crashing(self) -> None:
        oversized = (
            '{"schema_version":1,"algorithm":"eddsa-ed25519","tiers":['
            '{"name":"huge","mean_ns":' + ('9' * 5000) + '}],"phases":[]}'
        )
        path = Path('oversized-pkcs11-overhead.json')

        with (
            patch.object(Path, 'exists', return_value=True),
            patch.object(Path, 'read_text', return_value=oversized),
        ):
            data = MODULE.parse_pkcs11_overhead_json(path)

        self.assertEqual({}, data)

    def test_overhead_section_is_pkcs11_only(self) -> None:
        data = MODULE.parse_pkcs11_overhead_json(FIXTURES / 'pkcs11_overhead_full.json')
        common = (
            Path('unused'),
            ['5.24.0'],
            {'5.24.0': []},
            {'5.24.0': {}},
            [],
            [],
        )

        with patch.object(Path, 'write_text') as write_text:
            MODULE.generate_report(
                *common,
                pkcs11_overhead_data={'5.24.0': data},
                is_pkcs11=False,
            )
        self.assertNotIn(
            'PKCS#11 Ed25519 signing overhead', write_text.call_args.args[0]
        )

        with patch.object(Path, 'write_text') as write_text:
            MODULE.generate_report(
                *common,
                pkcs11_overhead_data={'5.24.0': data},
                is_pkcs11=True,
            )
        self.assertIn('PKCS#11 Ed25519 signing overhead', write_text.call_args.args[0])


if __name__ == '__main__':
    unittest.main()

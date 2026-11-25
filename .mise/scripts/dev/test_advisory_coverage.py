#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests of .mise/scripts/sbom/check_advisory_coverage.py (issue #1498, finding F-048).

Run: python3 -m unittest discover -s .mise/scripts/dev -p 'test_advisory_coverage.py'   (or `mise run dev:ci-security`)
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sbom'))
import check_advisory_coverage as cov  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
ID = 'RUSTSEC-2026-0001'
CLEAN_AUDIT = {
    'vulnerabilities': {'found': False, 'count': 0, 'list': []},
    'warnings': {},
}


def vex_statement(status='not_affected', purl='pkg:cargo/foo@1.0.0', **extra):
    st = {
        'vulnerability': {'name': ID, 'aliases': ['GHSA-xxxx']},
        'products': [{'@id': purl}],
        'status': status,
    }
    if status == 'not_affected':
        st['justification'] = 'vulnerable_code_not_in_execute_path'
    st.update(extra)
    return st


class AnsiTreeTest(unittest.TestCase):
    def test_colored_cargo_tree_output_is_parsed(self) -> None:
        text = 'windows-sys v0.61.2|Win32,default \x1b[33m\x1b[2m(*)\x1b[39m\x1b[22m\n'
        self.assertEqual(
            cov.parse_tree(text), [('windows-sys', '0.61.2', {'Win32', 'default'})]
        )


class Workspace:
    """A throw-away repository root with the four files the checker reads."""

    def __init__(
        self,
        test: unittest.TestCase,
        locked=(('foo', '1.0.0'),),
        statements=None,
        deny=(ID,),
        audit=(ID,),
    ):
        self.root = Path(tempfile.mkdtemp(prefix='advisory-test-'))
        test.addCleanup(
            lambda: __import__('shutil').rmtree(self.root, ignore_errors=True)
        )
        (self.root / 'Cargo.lock').write_text(
            ''.join(
                f'[[package]]\nname = "{n}"\nversion = "{v}"\n\n' for n, v in locked
            )
        )
        quoted = lambda ids: ', '.join(f'"{i}"' for i in ids)  # noqa: E731
        (self.root / 'deny.toml').write_text(
            f'[advisories]\nignore = [{quoted(deny)}]\n'
        )
        (self.root / '.cargo').mkdir()
        (self.root / '.cargo' / 'audit.toml').write_text(
            f'[advisories]\nignore = [{quoted(audit)}]\n'
        )
        (self.root / 'sbom').mkdir()
        (self.root / 'sbom' / 'openvex.json').write_text(
            json.dumps(
                {'statements': [vex_statement()] if statements is None else statements}
            )
        )


def tree(*lines: str) -> str:
    return '\n'.join(lines) + '\n'


class PolicyTest(unittest.TestCase):
    def policy(self, **kw) -> list[str]:
        return cov.check_policy(Workspace(self, **kw).root)

    def test_consistent_policy_is_clean(self) -> None:
        self.assertEqual(self.policy(), [])

    def test_real_repository_policy_is_clean(self) -> None:
        self.assertEqual(cov.check_policy(REPO), [])

    def test_vulnerable_lock_only_packages_fail(self) -> None:
        for name, version in (
            ('quinn-proto', '0.11.18'),
            ('quinn-udp', '0.5.15'),
            ('rustix', '1.1.4'),
        ):
            with self.subTest(name=name):
                errors = self.policy(locked=(('foo', '1.0.0'), (name, version)))
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(f'{name} {version}', errors[0])

    def test_patched_versions_pass(self) -> None:
        locked = (
            ('foo', '1.0.0'),
            ('quinn-proto', '0.11.19'),
            ('quinn-udp', '0.5.16'),
            ('rustix', '1.1.6'),
        )
        self.assertEqual(self.policy(locked=locked), [])

    def test_ignore_lists_must_match(self) -> None:
        errors = self.policy(audit=())
        self.assertTrue(any('ignore lists differ' in e for e in errors), errors)

    def test_ignored_advisory_without_vex_fails(self) -> None:
        errors = self.policy(statements=[])
        self.assertTrue(any('no OpenVEX statement' in e for e in errors), errors)

    def test_vex_alias_covers_the_advisory(self) -> None:
        st = vex_statement()
        st['vulnerability'] = {'name': 'GHSA-xxxx', 'aliases': [ID]}
        self.assertEqual(self.policy(statements=[st]), [])

    def test_stale_vex_version_fails(self) -> None:
        errors = self.policy(statements=[vex_statement(purl='pkg:cargo/foo@0.9.0')])
        self.assertTrue(any('stale product' in e for e in errors), errors)

    def test_contradictory_statements_fail(self) -> None:
        errors = self.policy(
            statements=[
                vex_statement(),
                vex_statement('under_investigation', status_notes='n'),
            ]
        )
        self.assertTrue(any('contradictory' in e for e in errors), errors)

    def test_missing_status_evidence_fails(self) -> None:
        for st in (
            {**vex_statement(), 'justification': ''},
            vex_statement('under_investigation'),
            vex_statement('affected'),
        ):
            with self.subTest(status=st['status']):
                self.assertTrue(self.policy(statements=[st]))

    def test_under_investigation_with_notes_is_kept(self) -> None:
        self.assertEqual(
            self.policy(
                statements=[
                    vex_statement('under_investigation', status_notes='assessing')
                ]
            ),
            [],
        )


class GraphTest(unittest.TestCase):
    def graph(self, text: str) -> tuple[list[str], list[str]]:
        return cov.check_graph('fips', cov.parse_tree(text))

    def test_cargo_tree_line_shapes_parse(self) -> None:
        pkgs = cov.parse_tree(
            tree(
                'ckms v5.29.0 (/work/crate/clients/ckms)|default,non-fips',
                'serde_derive v1.0.0 (proc-macro) (/x)|default',
                'reqwest v0.12.28|json,cookies (*)',
                'cc v1.0.0|',
            )
        )
        self.assertEqual(
            [p[0] for p in pkgs], ['ckms', 'serde_derive', 'reqwest', 'cc']
        )
        self.assertEqual(pkgs[2][2], {'json', 'cookies'})

    def test_malformed_or_empty_tree_is_rejected(self) -> None:
        for text in ('', 'garbage line\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                cov.parse_tree(text)

    def test_runtime_quinn_family_fails(self) -> None:
        for name in ('quinn', 'quinn-proto', 'quinn-udp'):
            with self.subTest(name=name):
                errors, _ = self.graph(tree(f'{name} v0.11.19|rustls'))
                self.assertEqual(len(errors), 1)

    def test_reqwest_http3_fails(self) -> None:
        errors, _ = self.graph(tree('reqwest v0.12.28|json,http3'))
        self.assertTrue(any('http3' in e for e in errors), errors)

    def test_patched_runtime_rustix_is_labeled_production_not_dev_only(self) -> None:
        errors, notes = self.graph(tree('rustix v1.1.6|std'))
        self.assertEqual(errors, [])
        self.assertEqual(notes, ['  [production] fips: rustix 1.1.6 (patched)'])

    def test_vulnerable_runtime_rustix_fails(self) -> None:
        errors, _ = self.graph(tree('rustix v1.1.4|std'))
        self.assertEqual(len(errors), 1)


class AuditTest(unittest.TestCase):
    @staticmethod
    def report(name='rustix', version='1.1.4', kind_warning=False) -> str:
        entry = {'advisory': {'id': ID}, 'package': {'name': name, 'version': version}}
        if kind_warning:
            return json.dumps(
                {
                    'vulnerabilities': {'found': False, 'list': []},
                    'warnings': {'unmaintained': [entry]},
                }
            )
        return json.dumps(
            {
                'vulnerabilities': {'found': True, 'count': 1, 'list': [entry]},
                'warnings': {},
            }
        )

    def test_clean_report_passes(self) -> None:
        self.assertEqual(cov.check_audit(json.dumps(CLEAN_AUDIT), 0, set()), ([], []))

    def test_lock_only_vulnerability_fails_with_accurate_label(self) -> None:
        errors, lines = cov.check_audit(self.report(), 1, set())
        self.assertEqual(len(errors), 1)
        self.assertIn('lock-only/non-runtime', lines[0])
        self.assertIn('does not waive', errors[0])

    def test_runtime_vulnerability_is_labeled_production(self) -> None:
        errors, lines = cov.check_audit(self.report(), 1, {'rustix'})
        self.assertEqual(len(errors), 1)
        self.assertIn('[production]', lines[0])

    def test_informational_warning_is_labeled_not_failed(self) -> None:
        errors, lines = cov.check_audit(self.report(kind_warning=True), 0, set())
        self.assertEqual(errors, [])
        self.assertIn('unmaintained', lines[0])

    def test_malformed_report_fails(self) -> None:
        for text in (
            '',
            '{',
            '{}',
            '[]',
            json.dumps({'vulnerabilities': {'found': True, 'list': []}}),
        ):
            with self.subTest(text=text):
                errors, _ = cov.check_audit(text, 0, set())
                self.assertEqual(len(errors), 1)

    def test_failed_audit_without_findings_fails(self) -> None:
        errors, _ = cov.check_audit(json.dumps(CLEAN_AUDIT), 2, set())
        self.assertEqual(len(errors), 1)


class CliTest(unittest.TestCase):
    def run_cli(self, *argv: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            try:
                return cov.main(list(argv))
            except SystemExit as exc:
                return int(exc.code)

    def files(self, audit: str, tree_text: str, **kw) -> list[str]:
        root = Workspace(self, **kw).root
        (root / 'audit.json').write_text(audit)
        (root / 'fips.txt').write_text(tree_text)
        return [
            '--root',
            str(root),
            '--audit-json',
            str(root / 'audit.json'),
            '--production-tree',
            str(root / 'fips.txt'),
        ]

    def test_clean_run_passes(self) -> None:
        self.assertEqual(
            self.run_cli(*self.files(json.dumps(CLEAN_AUDIT), tree('foo v1.0.0|'))), 0
        )

    def test_missing_report_fails(self) -> None:
        args = self.files(json.dumps(CLEAN_AUDIT), tree('foo v1.0.0|'))
        Path(args[3]).unlink()
        self.assertEqual(self.run_cli(*args), 1)

    def test_full_mode_requires_inputs(self) -> None:
        self.assertEqual(self.run_cli('--root', str(Workspace(self).root)), 2)

    def test_policy_only_needs_just_the_root(self) -> None:
        self.assertEqual(
            self.run_cli('--root', str(Workspace(self).root), '--policy-only'), 0
        )


if __name__ == '__main__':
    unittest.main()

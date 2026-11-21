#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests of ci_changes.py against the real .github/ci-paths.toml.

Each scenario simulates a pull request touching one area and asserts the exact set of CI units that run.
Run: python3 -m unittest discover -s .mise/scripts/dev -p 'test_ci_changes.py'   (or `mise run dev:ci-changes --self-test`)
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import ci_changes  # noqa: E402

CFG = ci_changes.load_config(ci_changes.CONFIG)
EVERYTHING = set(CFG.units)

# Units that run on any crate/** change (compile-wide jobs and whole-workspace unit-test runners).
WORKSPACE = {
    'cargo-clippy',
    'cargo-machete',
    'no-nix',
    'cargo-publish-dry-run',
    'db:sqlite',
    'windows-cargo-test',
}
# Units that additionally run on any change of code linked into the server.
SERVER_WIDE = WORKSPACE | {'forward-proxy', 'xks-remote', 'spire'}
DB_LEGS = {'db:psql', 'db:mysql', 'db:mariadb', 'db:percona', 'db:redis', 'db:openbao'}
KMIP_INTEROP = {
    'interop:ase',
    'interop:db2',
    'interop:edb-tde',
    'interop:iris',
    'interop:kmip-go',
    'interop:kmipkit',
    'interop:openbao-kmip',
    'interop:pykmip',
}


def leaves(leaf: str, *variants: str) -> list[dict[str, str]]:
    return [{'leaf': leaf, 'variant': v} for v in variants]


BOTH = ('fips', 'non-fips')
# Every leg, in ci-paths.toml unit order (what `ci_changes.py --all` emits).
FULL_DB = [
    *leaves('sqlite', *BOTH),
    *leaves('psql', *BOTH),
    *leaves('mysql', *BOTH),
    *leaves('mariadb', *BOTH),
    *leaves('percona', *BOTH),
    *leaves('redis', 'non-fips'),
    *leaves('openbao', *BOTH),
]
FULL_INTEROP = [
    *leaves('ase', 'non-fips'),
    *leaves('db2', 'non-fips'),
    *leaves('edb-tde', 'non-fips'),
    *leaves('iris', 'non-fips'),
    *leaves('jose', 'non-fips'),
    *leaves('kmip-go', *BOTH),
    *leaves('kmipkit', 'non-fips'),
    *leaves('openbao', *BOTH),
    *leaves('openbao-auth-verifier', *BOTH),
    *leaves('openbao-kmip', *BOTH),
    *leaves('pykmip', 'non-fips'),
    *leaves('ssh-secrets', *BOTH),
]


def run(*files: str) -> set[str]:
    """Units that run for a PR changing `files`."""
    skipped, _ = ci_changes.classify(CFG, list(files))
    return EVERYTHING - set(skipped)


class DocsAndIgnored(unittest.TestCase):
    def test_changelog_and_root_readme_run_nothing(self) -> None:
        self.assertEqual(run('CHANGELOG/x.md', 'README.md'), set())

    def test_documentation_and_ai_instruction_files_run_only_the_doc_build(
        self,
    ) -> None:
        for path in (
            'documentation/docs/index.md',
            'documentation/book.toml',
            'AGENTS.md',
            '.github/skills/foo/SKILL.md',
            '.github/instructions/rust.instructions.md',
            '.mise/scripts/docs/check_ai_docs.py',
        ):
            with self.subTest(path=path):
                self.assertEqual(run(path), {'build-documentation'})

    def test_packaging_and_release_files_run_nothing(self) -> None:
        self.assertEqual(
            run(
                'pkg/deb/control',
                'nix/docker.nix',
                '.github/workflows/release.yml',
                '.mise/tasks/package/deb',
            ),
            set(),
        )


class Ui(unittest.TestCase):
    def test_ui_source(self) -> None:
        self.assertEqual(run('ui/src/App.tsx'), {'ui', 'windows-ui'})

    def test_ui_playwright_test(self) -> None:
        self.assertEqual(run('ui/tests/e2e/keys.spec.ts'), {'ui', 'windows-ui'})

    def test_wasm_crate_runs_workspace_and_ui(self) -> None:
        self.assertEqual(
            run('crate/clients/wasm/src/lib.rs'), WORKSPACE | {'ui', 'windows-ui'}
        )

    def test_ui_does_not_touch_rust_jobs(self) -> None:
        self.assertFalse(run('ui/src/App.tsx') & WORKSPACE)


class RustCoreCrates(unittest.TestCase):
    def test_server_operation(self) -> None:
        self.assertEqual(
            run('crate/server/src/core/operations/encrypt.rs'), SERVER_WIDE
        )

    def test_crypto(self) -> None:
        self.assertEqual(run('crate/crypto/src/openssl/mod.rs'), SERVER_WIDE)

    def test_kmip_runs_only_kmip_interop_clients(self) -> None:
        self.assertEqual(run('crate/kmip/src/lib.rs'), SERVER_WIDE | KMIP_INTEROP)

    def test_kmip_endpoint(self) -> None:
        self.assertEqual(
            run('crate/server/src/routes/kmip/mod.rs'), SERVER_WIDE | KMIP_INTEROP
        )

    def test_ckms_client(self) -> None:
        self.assertEqual(run('crate/clients/ckms/src/main.rs'), SERVER_WIDE)

    def test_core_change_skips_feature_suites(self) -> None:
        ran = run('crate/server/src/core/operations/encrypt.rs')
        self.assertFalse(
            ran
            & ({'ui', 'hsm', 'pkcs11', 'obs', 'pki', 'cloud', 'interop:jose'} | DB_LEGS)
        )


class Database(unittest.TestCase):
    def test_shared_sql_runs_every_backend(self) -> None:
        self.assertEqual(
            run('crate/server_database/src/stores/sql/query.sql'),
            SERVER_WIDE | DB_LEGS,
        )

    def test_postgres_store_only(self) -> None:
        self.assertEqual(
            run('crate/server_database/src/stores/sql/pgsql.rs'),
            WORKSPACE | {'db:psql', 'db:openbao', 'interop:ssh-secrets'},
        )

    def test_mysql_store_runs_all_three_mysql_flavours(self) -> None:
        self.assertEqual(
            run('crate/server_database/src/stores/sql/mysql.rs'),
            WORKSPACE
            | {
                'db:mysql',
                'db:mariadb',
                'db:percona',
                'db:openbao',
                'interop:ssh-secrets',
            },
        )

    def test_redis_store_only(self) -> None:
        self.assertEqual(
            run('crate/server_database/src/stores/redis/findex.rs'),
            WORKSPACE | {'db:redis'},
        )

    def test_db_change_skips_non_db_suites(self) -> None:
        ran = run('crate/server_database/src/stores/sql/query.sql')
        self.assertFalse(ran & {'ui', 'hsm', 'pkcs11', 'windows-ui', 'interop:iris'})

    def test_db_task_script_runs_its_leg_only(self) -> None:
        self.assertEqual(run('.mise/tasks/test/db/psql'), {'db:psql'})


class FeatureCrates(unittest.TestCase):
    def test_hsm_vendor_crate(self) -> None:
        self.assertEqual(
            run('crate/hsm/utimaco/src/lib.rs'),
            WORKSPACE | {'hsm', 'windows-hsm-idemia'},
        )

    def test_pkcs11_client(self) -> None:
        self.assertEqual(
            run('crate/clients/pkcs11/module/src/pkcs11.rs'),
            WORKSPACE | {'pkcs11', 'hsm', 'interop:ase', 'windows-cng-ksp'},
        )

    def test_aws_xks_route(self) -> None:
        self.assertEqual(
            run('crate/server/src/routes/aws_xks/mod.rs'),
            WORKSPACE | {'cloud', 'xks-remote'},
        )

    def test_google_cse_route(self) -> None:
        self.assertEqual(
            run('crate/server/src/routes/google_cse/mod.rs'), WORKSPACE | {'cloud'}
        )

    def test_est_route(self) -> None:
        self.assertEqual(
            run('crate/server/src/routes/est/mod.rs'),
            WORKSPACE | {'pki', 'windows-est'},
        )

    def test_certificate_core(self) -> None:
        self.assertEqual(
            run('crate/server/src/core/certificate/validate.rs'),
            SERVER_WIDE | {'pki'},
        )

    def test_audit_core(self) -> None:
        self.assertEqual(
            run('crate/server/src/core/audit/mod.rs'), SERVER_WIDE | {'obs'}
        )

    def test_kv_route(self) -> None:
        self.assertEqual(
            run('crate/server/src/routes/kv/mod.rs'),
            SERVER_WIDE | {'db:openbao', 'interop:openbao', 'interop:ssh-secrets'},
        )

    def test_jose_route(self) -> None:
        self.assertEqual(
            run('crate/server/src/routes/jose/mod.rs'),
            WORKSPACE | {'interop:jose'},
        )

    def test_certificates_cli_action(self) -> None:
        self.assertEqual(
            run('crate/clients/clap/src/actions/certificates/certify.rs'),
            SERVER_WIDE | {'pki'},
        )


class TestScripts(unittest.TestCase):
    def test_interop_script_runs_only_its_suite(self) -> None:
        self.assertEqual(run('.mise/scripts/test/test_iris.sh'), {'interop:iris'})

    def test_hsm_task_script(self) -> None:
        self.assertIn('hsm', run('.mise/tasks/test/hsm/softhsm'))


class CiWorkflows(unittest.TestCase):
    def test_workflow_only_pr_runs_direct_units_and_never_db_sqlite(self) -> None:
        self.assertEqual(
            run(
                '.github/ci-paths.toml',
                '.github/workflows/main.yml',
                '.github/workflows/test_all.yml',
                '.github/workflows/test-group.yml',
                '.github/workflows/test-db.yml',
                '.github/workflows/test-interop.yml',
                '.github/workflows/test_windows.yml',
                '.mise/scripts/dev/ci_changes.py',
            ),
            {
                'cargo-clippy',
                'cargo-machete',
                'forward-proxy',
                'build-documentation',
                'cargo-publish-dry-run',
                'xks-remote',
                'interop:pykmip',
            },
        )

    def test_classifier_config_change_runs_nothing(self) -> None:
        self.assertEqual(run('.github/ci-paths.toml'), set())

    def test_forward_proxy_workflow(self) -> None:
        self.assertEqual(run('.github/workflows/forward_proxy.yml'), {'forward-proxy'})

    def test_rust_only_workflows_run_nothing(self) -> None:
        self.assertEqual(
            run('.github/workflows/no-nix.yml', '.github/workflows/test_windows.yml'),
            set(),
        )

    def test_no_nix_and_windows_cargo_test_need_rust_source(self) -> None:
        for path in (
            '.github/workflows/main.yml',
            '.github/workflows/test_all.yml',
            '.github/workflows/test-interop.yml',
            '.mise/tasks/test/db/psql',
            '.mise/tasks/test/interop/pykmip',
            'ui/src/App.tsx',
            'documentation/docs/index.md',
            'vcpkg.json',
            '.github/actions/windows-vs-ninja/action.yml',
            '.mise/scripts/windows/cargo_test.ps1',
            '.mise/scripts/windows/test_ui.ps1',
        ):
            with self.subTest(path=path):
                self.assertFalse(run(path) & {'no-nix', 'windows-cargo-test'})

    def test_xks_remote_runs_on_xks_related_rust_source(self) -> None:
        # The job builds and deploys cosmian_kms, so the route, its config and the server wiring all trigger it.
        for path in (
            'crate/server/src/routes/aws_xks/sigv4.rs',
            'crate/server/src/routes/aws_xks/encrypt_decrypt/encrypt_.rs',
            'crate/server/src/config/params/server_params.rs',
            'crate/server/src/config/command_line/clap_config.rs',
            'crate/server/src/start_kms_server.rs',
            'crate/server/src/middlewares/auth_verifier/token.rs',
            'crate/server/src/core/operations/key_ops/crypto_op.rs',
        ):
            with self.subTest(path=path):
                self.assertIn('xks-remote', run(path))

    def test_db_and_group_wrappers_run_nothing(self) -> None:
        self.assertEqual(
            run('.github/workflows/test-db.yml', '.github/workflows/test-group.yml'),
            set(),
        )


class Matrices(unittest.TestCase):
    """outputs(): the legs and caller flags main.yml feeds to test_all.yml."""

    def out(self, *files: str) -> dict[str, str]:
        skipped, _ = ci_changes.classify(CFG, list(files))
        return ci_changes.outputs(CFG, skipped)

    def test_everything_runs_every_leg_in_toml_order(self) -> None:
        for out in (self.out(), ci_changes.outputs(CFG, [])):
            self.assertEqual(json.loads(out['db-matrix']), FULL_DB)
            self.assertEqual(json.loads(out['interop-matrix']), FULL_INTEROP)
            self.assertEqual((len(FULL_DB), len(FULL_INTEROP)), (13, 17))
            self.assertEqual((out['run-test'], out['run-windows']), ('true', 'true'))

    def test_workflow_only_pr(self) -> None:
        out = self.out(
            '.github/ci-paths.toml',
            '.github/workflows/main.yml',
            '.github/workflows/test_all.yml',
            '.github/workflows/test-group.yml',
            '.github/workflows/test-db.yml',
            '.github/workflows/test-interop.yml',
            '.github/workflows/test_windows.yml',
            '.mise/scripts/dev/ci_changes.py',
        )
        self.assertEqual(json.loads(out['db-matrix']), [])
        self.assertEqual(
            json.loads(out['interop-matrix']), leaves('pykmip', 'non-fips')
        )
        self.assertEqual((out['run-test'], out['run-windows']), ('true', 'false'))

    def test_pg_store_change_keeps_only_the_legs_it_triggers(self) -> None:
        out = self.out('crate/server_database/src/stores/sql/pgsql.rs')
        self.assertEqual(
            json.loads(out['db-matrix']),
            [
                *leaves('sqlite', *BOTH),
                *leaves('psql', *BOTH),
                *leaves('openbao', *BOTH),
            ],
        )
        self.assertEqual(
            json.loads(out['interop-matrix']), leaves('ssh-secrets', *BOTH)
        )
        self.assertEqual((out['run-test'], out['run-windows']), ('true', 'true'))

    def test_ui_change_has_no_legs_but_still_runs_the_callers(self) -> None:
        out = self.out('ui/src/App.tsx')
        self.assertEqual(out['db-matrix'], '[]')
        self.assertEqual(out['interop-matrix'], '[]')
        self.assertEqual((out['run-test'], out['run-windows']), ('true', 'true'))

    def test_change_that_triggers_no_unit_skips_both_callers(self) -> None:
        out = self.out('clippy.toml')
        self.assertEqual((out['run-test'], out['run-windows']), ('false', 'false'))


class Wiring(unittest.TestCase):
    """Every unit is gated where the workflows test it, and its caller group lists it (else it would never run)."""

    GATE = re.compile(
        r"contains\(fromJSON\((?:needs\.changes\.outputs\.skip|inputs\.skip-units \|\| '\[\]')\), '([a-z0-9:-]+)'\)"
    )

    def gated(self, name: str) -> set[str]:
        text = (ci_changes.REPO / '.github' / 'workflows' / name).read_text()
        return set(self.GATE.findall(text))

    def test_units_callers_and_workflows_agree(self) -> None:
        m, t, w = (
            self.gated(n) for n in ('main.yml', 'test_all.yml', 'test_windows.yml')
        )
        v = set(CFG.variants)
        self.assertEqual(m | t | w | v, EVERYTHING)
        self.assertEqual(len(m) + len(t) + len(w) + len(v), len(EVERYTHING))
        self.assertEqual(set(CFG.callers['test']), t | v)
        self.assertEqual(set(CFG.callers['windows']), w)


class FailSafe(unittest.TestCase):
    def test_empty_diff_runs_everything(self) -> None:
        self.assertEqual(run(), EVERYTHING)

    def test_unknown_path_runs_everything(self) -> None:
        self.assertEqual(run('brand/new.txt'), EVERYTHING)

    def test_unknown_path_among_ignored_files_runs_everything(self) -> None:
        self.assertEqual(run('README.md', 'brand/new.txt'), EVERYTHING)

    def test_full_patterns_run_everything(self) -> None:
        for path in (
            'Cargo.lock',
            'Cargo.toml',
            'rust-toolchain.toml',
            'mise.toml',
            '.mise/lib/common.sh',
            '.github/actions/install-mise/action.yml',
            'crate/crypto/build.rs',
            'test_data',
        ):
            with self.subTest(path=path):
                self.assertEqual(run(path), EVERYTHING)

    def test_one_full_file_overrides_ignored_ones(self) -> None:
        self.assertEqual(run('README.md', 'Cargo.lock'), EVERYTHING)


class MixedChanges(unittest.TestCase):
    def test_ui_plus_docs(self) -> None:
        self.assertEqual(
            run('ui/src/App.tsx', 'documentation/docs/index.md'),
            {'ui', 'windows-ui', 'build-documentation'},
        )

    def test_union_of_independent_areas(self) -> None:
        self.assertEqual(
            run('ui/src/App.tsx', 'crate/server_database/src/stores/redis/findex.rs'),
            WORKSPACE | {'ui', 'windows-ui', 'db:redis'},
        )

    def test_core_plus_ui_is_server_wide_plus_ui(self) -> None:
        self.assertEqual(
            run('crate/crypto/src/lib.rs', 'ui/src/App.tsx'),
            SERVER_WIDE | {'ui', 'windows-ui'},
        )


# One file per unit that triggers it (and not by way of `full`).
UNIT_SAMPLES = {
    'build-documentation': 'documentation/docs/index.md',
    'cargo-clippy': 'clippy.toml',
    'cargo-machete': 'crate/server/src/lib.rs',
    'no-nix': 'crate/server/src/lib.rs',
    'forward-proxy': '.github/workflows/forward_proxy.yml',
    'cargo-publish-dry-run': '.github/workflows/cargo-publish.yml',
    'xks-remote': 'crate/server/src/routes/aws_xks/mod.rs',
    'db:sqlite': '.mise/tasks/test/db/sqlite',
    'db:psql': 'crate/server_database/src/stores/sql/pgsql.rs',
    'db:mysql': 'crate/server_database/src/stores/sql/mysql.rs',
    'db:mariadb': '.mise/tasks/test/db/mariadb',
    'db:percona': '.mise/tasks/test/db/percona',
    'db:redis': 'crate/server_database/src/stores/redis/findex.rs',
    'db:openbao': '.mise/scripts/test/openbao/bao_verifier.sh',
    'cloud': 'crate/server/src/routes/google_cse/mod.rs',
    'hsm': 'crate/hsm/utimaco/src/lib.rs',
    'pkcs11': 'crate/clients/pkcs11/module/src/pkcs11.rs',
    'obs': 'crate/server/src/core/otel_metrics.rs',
    'pki': 'crate/server/src/routes/est/mod.rs',
    'spire': '.mise/tasks/test/spire/_default',
    'ui': 'ui/src/App.tsx',
    'interop:ase': '.mise/tasks/test/interop/ase',
    'interop:db2': '.mise/tasks/test/interop/db2',
    'interop:edb-tde': '.mise/tasks/test/interop/edb-tde',
    'interop:iris': '.mise/tasks/test/interop/iris',
    'interop:jose': 'crate/server/src/routes/jose/mod.rs',
    'interop:kmip-go': '.mise/tasks/test/interop/kmip-go',
    'interop:kmipkit': '.mise/tasks/test/interop/kmipkit',
    'interop:openbao': '.mise/tasks/test/interop/openbao',
    'interop:openbao-auth-verifier': '.mise/tasks/test/interop/openbao-auth-verifier',
    'interop:openbao-kmip': '.mise/tasks/test/interop/openbao-kmip',
    'interop:pykmip': '.mise/tasks/test/interop/pykmip',
    'interop:ssh-secrets': '.mise/tasks/test/interop/ssh-secrets',
    'windows-cargo-test': 'crate/server/src/lib.rs',
    'windows-ui': '.mise/scripts/windows/test_ui.ps1',
    'windows-cng-ksp': '.mise/scripts/windows/test_cng_ksp.ps1',
    'windows-hsm-idemia': '.mise/scripts/windows/test_hsm_idemia.ps1',
    'windows-est': '.mise/scripts/windows/test_est_windows.ps1',
}


class ConfigIntegrity(unittest.TestCase):
    def test_samples_cover_every_unit(self) -> None:
        # A new or renamed unit fails here until it has a sample that triggers it.
        self.assertEqual(set(UNIT_SAMPLES), EVERYTHING)

    def test_every_unit_is_reachable_without_running_everything(self) -> None:
        for unit, path in UNIT_SAMPLES.items():
            with self.subTest(unit=unit):
                ran = run(path)
                self.assertIn(unit, ran)
                self.assertNotEqual(ran, EVERYTHING, f'{path} hits full or an orphan')

    def test_classify_reports_skipped_units_sorted_and_disjoint_from_run(self) -> None:
        skipped, _ = ci_changes.classify(CFG, ['ui/src/App.tsx'])
        self.assertEqual(skipped, sorted(skipped))
        self.assertFalse(set(skipped) & {'ui', 'windows-ui'})


def load(toml: str) -> ci_changes.Config:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'ci-paths.toml'
        path.write_text(textwrap.dedent(toml))
        return ci_changes.load_config(path)


MINI = """
    full = '^Cargo\\.lock$'
    ignore = '\\.md$'
    [sets]
    core = '^lib/(?!feature/)'
    [units.a]
    sets = ["core"]
    [units.b]
    files = '^lib/feature/'
    [units.c]
    sets = ["core"]
    files = '''
      ^extra/   # comments and whitespace are ignored (re.VERBOSE)
    | ^more/
    '''
"""


class ClassifyEngine(unittest.TestCase):
    """classify() semantics on a small inline config: the fail-safe branches decide whether CI is skipped."""

    def setUp(self) -> None:
        self.cfg = load(MINI)

    def skipped(self, *files: str) -> list[str]:
        return ci_changes.classify(self.cfg, list(files))[0]

    def test_empty_diff_skips_nothing(self) -> None:
        self.assertEqual(self.skipped(), [])

    def test_full_hit_skips_nothing_even_with_ignored_files(self) -> None:
        self.assertEqual(self.skipped('README.md', 'Cargo.lock'), [])

    def test_orphan_skips_nothing(self) -> None:
        self.assertEqual(self.skipped('lib/feature/x.rs', 'orphan.bin'), [])

    def test_ignored_only_skips_everything(self) -> None:
        self.assertEqual(self.skipped('README.md'), ['a', 'b', 'c'])

    def test_negative_lookahead_carves_feature_path_out_of_the_set(self) -> None:
        self.assertEqual(self.skipped('lib/feature/x.rs'), ['a', 'c'])

    def test_set_path_triggers_every_unit_using_the_set(self) -> None:
        self.assertEqual(self.skipped('lib/core.rs'), ['b'])

    def test_unit_files_pattern_is_verbose_alternation(self) -> None:
        self.assertEqual(self.skipped('more/x', 'README.md'), ['a', 'b'])
        self.assertEqual(self.skipped('extra/x'), ['a', 'b'])

    def test_union_over_changed_files_and_sorted_result(self) -> None:
        self.assertEqual(self.skipped('lib/feature/x.rs', 'extra/y'), ['a'])

    def test_rename_old_and_new_path_both_count(self) -> None:
        self.assertEqual(self.skipped('lib/core.rs', 'lib/feature/core.rs'), [])


class LoadConfig(unittest.TestCase):
    def rejects(self, toml: str) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            load(toml)

    def test_unknown_set_is_rejected(self) -> None:
        self.rejects("full = 'x'\nignore = 'y'\n[units.a]\nsets = ['nope']\n")

    def test_unit_without_sets_or_files_is_rejected(self) -> None:
        self.rejects("full = 'x'\nignore = 'y'\n[units.a]\n")

    def test_unknown_unit_key_is_rejected(self) -> None:
        self.rejects("full = 'x'\nignore = 'y'\n[units.a]\nfile = 'x'\n")

    def test_missing_full_is_rejected(self) -> None:
        self.rejects("ignore = 'y'\n[units.a]\nfiles = 'x'\n")

    def test_invalid_regex_is_rejected(self) -> None:
        self.rejects("full = '('\nignore = 'y'\n[units.a]\nfiles = 'x'\n")

    def test_non_string_pattern_is_rejected_with_its_key(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            load("full = 1\nignore = 'y'\n[units.a]\nfiles = 'x'\n")
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn('full: expected a regex string', err.getvalue())

    def test_invalid_regex_message_names_the_key(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            load("full = 'x'\nignore = 'y'\n[units.a]\nfiles = '('\n")
        self.assertIn('units.a.files: invalid regex', err.getvalue())

    def test_missing_ignore_and_units_are_rejected(self) -> None:
        self.rejects("full = 'x'\n[units.a]\nfiles = 'x'\n")
        self.rejects("full = 'x'\nignore = 'y'\n")

    def test_set_may_be_used_by_several_units_and_units_keep_file_order(self) -> None:
        cfg = load(MINI)
        self.assertEqual(list(cfg.units), ['a', 'b', 'c'])
        self.assertEqual(len(cfg.units['a']), 1)  # set only
        self.assertEqual(len(cfg.units['b']), 1)  # files only
        self.assertEqual(len(cfg.units['c']), 2)  # set + files

    def test_variants_are_required_on_matrix_units_and_only_there(self) -> None:
        self.rejects(
            "full = 'x'\nignore = 'y'\n[units.a]\nfiles = 'x'\nvariants = ['fips']\n"
        )
        self.rejects("full = 'x'\nignore = 'y'\n[units.'db:x']\nfiles = 'x'\n")

    def test_invalid_variants_are_rejected(self) -> None:
        for bad in ("['fips', 'fips']", '[]', "['x']"):
            with self.subTest(variants=bad):
                self.rejects(
                    f"full = 'x'\nignore = 'y'\n[units.'db:x']\nfiles = 'x'\nvariants = {bad}\n"
                )

    def test_unit_with_only_variants_is_rejected(self) -> None:
        self.rejects("full = 'x'\nignore = 'y'\n[units.'db:x']\nvariants = ['fips']\n")

    def test_bad_callers_are_rejected(self) -> None:
        head = "full = 'x'\nignore = 'y'\n[units.a]\nfiles = 'x'\n[callers]\n"
        self.rejects(head + "t = ['nope*']\n")
        self.rejects(head + "t = 'a'\n")

    def test_callers_expand_patterns_in_unit_order(self) -> None:
        cfg = load(
            "full = 'x'\nignore = 'y'\n[units.'db:b']\nfiles = 'x'\nvariants = ['fips']\n"
            "[units.a]\nfiles = 'x'\n[units.'db:c']\nfiles = 'x'\nvariants = ['fips']\n"
            "[callers]\nt = ['db:*', 'a']\n"
        )
        self.assertEqual(cfg.callers['t'], ['db:b', 'a', 'db:c'])


# Temp repos must not see the runner's or the developer's git config (signing, hooks, identity) nor write the
# `changes` step's real $GITHUB_OUTPUT.
GIT_ENV = {
    **{k: v for k, v in os.environ.items() if k != 'GITHUB_OUTPUT'},
    'GIT_CONFIG_GLOBAL': os.devnull,
    'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_AUTHOR_NAME': 't',
    'GIT_AUTHOR_EMAIL': 't@t',
    'GIT_COMMITTER_NAME': 't',
    'GIT_COMMITTER_EMAIL': 't@t',
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ['git', '-c', 'commit.gpgsign=false', *args],
        cwd=repo,
        env=GIT_ENV,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def commit_files(repo: Path, message: str, **files: str | None) -> None:
    """Write (or delete, when the content is None) `files` (keys use `__` for `/`) and commit."""
    for name, content in files.items():
        path = repo / name.replace('__', '/')
        if content is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    git(repo, 'add', '-A')
    git(repo, 'commit', '-q', '-m', message)


class ChangedFiles(unittest.TestCase):
    """changed_files() lists what the PR branch changes since it forked from the base, as `git diff` sees it."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, 'init', '-q', '-b', 'main')
        commit_files(self.repo, 'base', a_txt='1', b_txt='same content\n' * 20)
        git(self.repo, 'switch', '-q', '-c', 'feature')
        patcher = mock.patch.object(ci_changes, 'REPO', self.repo)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_modified_added_and_deleted_files(self) -> None:
        commit_files(self.repo, 'pr', a_txt='2', c__d_txt='new')
        commit_files(self.repo, 'pr2', b_txt=None)
        self.assertEqual(
            ci_changes.changed_files('main', 'feature'), ['a_txt', 'b_txt', 'c/d_txt']
        )

    def test_rename_lists_old_and_new_path(self) -> None:
        git(self.repo, 'mv', 'b_txt', 'moved_txt')
        git(self.repo, 'commit', '-q', '-m', 'rename')
        self.assertEqual(
            ci_changes.changed_files('main', 'feature'), ['b_txt', 'moved_txt']
        )

    def test_changes_made_on_the_base_after_the_fork_are_ignored(self) -> None:
        commit_files(self.repo, 'pr', a_txt='2')
        git(self.repo, 'switch', '-q', 'main')
        commit_files(self.repo, 'base moves on', base_only_txt='x')
        git(self.repo, 'switch', '-q', 'feature')
        self.assertEqual(ci_changes.changed_files('main', 'feature'), ['a_txt'])

    def test_no_change_is_an_empty_list(self) -> None:
        self.assertEqual(ci_changes.changed_files('main', 'feature'), [])

    def test_head_caret_one_is_the_pr_merge_commit_base(self) -> None:
        # In CI the checkout is the test merge commit: HEAD^1 is the base tip, HEAD the merge.
        commit_files(self.repo, 'pr', a_txt='2')
        git(self.repo, 'switch', '-q', 'main')
        git(self.repo, 'merge', '-q', '--no-ff', '-m', 'merge', 'feature')
        self.assertEqual(ci_changes.changed_files('HEAD^1', 'HEAD'), ['a_txt'])

    def test_unknown_ref_raises(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            ci_changes.changed_files('does-not-exist', 'feature')


class Main(unittest.TestCase):
    """main(): console report, `skip=` line and the $GITHUB_OUTPUT file the workflows read."""

    def run_main(
        self, files: list[str], *argv: str, output: Path | None
    ) -> tuple[str, mock.MagicMock]:
        env = {} if output is None else {'GITHUB_OUTPUT': str(output)}
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, env),
            mock.patch.object(sys, 'argv', ['ci_changes.py', *argv]),
            mock.patch.object(ci_changes, 'changed_files', return_value=files) as cf,
            contextlib.redirect_stdout(out),
        ):
            if output is None:
                os.environ.pop('GITHUB_OUTPUT', None)
            ci_changes.main()
        return out.getvalue(), cf

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.output = Path(tmp.name) / 'github_output'

    def test_report_lists_files_reason_and_every_unit(self) -> None:
        text, _ = self.run_main(['ui/src/App.tsx'], output=self.output)
        lines = text.splitlines()
        self.assertEqual(lines[0], 'Changed files (1):')
        self.assertEqual(lines[1], '  ui/src/App.tsx')
        self.assertEqual(lines[2], f'2 of {len(EVERYTHING)} units triggered')
        marks = {line[5:]: line[:4] for line in lines[3:-5]}
        self.assertEqual(set(marks), EVERYTHING)
        self.assertEqual(
            {u for u, m in marks.items() if m == 'RUN '}, {'ui', 'windows-ui'}
        )
        self.assertTrue(all(m in ('RUN ', 'SKIP') for m in marks.values()))

    def test_output_lines_are_compact_json_in_order_and_appended_to_github_output(
        self,
    ) -> None:
        text, _ = self.run_main(['ui/src/App.tsx'], output=self.output)
        written = self.output.read_text().splitlines()
        self.assertEqual(written, text.splitlines()[-5:])
        self.assertEqual(
            [line.split('=', 1)[0] for line in written],
            ['skip', 'db-matrix', 'interop-matrix', 'run-test', 'run-windows'],
        )
        self.assertNotIn(' ', written[0])
        skipped = json.loads(written[0].removeprefix('skip='))
        self.assertEqual(skipped, sorted(EVERYTHING - {'ui', 'windows-ui'}))

    def test_github_output_is_appended_not_overwritten(self) -> None:
        self.output.write_text('other=1\n')
        self.run_main(['ui/src/App.tsx'], output=self.output)
        lines = self.output.read_text().splitlines()
        self.assertEqual(lines[0], 'other=1')
        self.assertTrue(lines[1].startswith('skip='))

    def test_without_github_output_only_prints(self) -> None:
        text, _ = self.run_main(['ui/src/App.tsx'], output=None)
        self.assertTrue(text.splitlines()[-5].startswith('skip=['))
        self.assertFalse(self.output.exists())

    def assert_runs_everything(self, lines: list[str]) -> None:
        got = dict(line.split('=', 1) for line in lines)
        self.assertEqual(got['skip'], '[]')
        self.assertEqual(json.loads(got['db-matrix']), FULL_DB)
        self.assertEqual(json.loads(got['interop-matrix']), FULL_INTEROP)
        self.assertEqual((got['run-test'], got['run-windows']), ('true', 'true'))

    def test_empty_diff_reports_run_everything(self) -> None:
        text, _ = self.run_main([], output=self.output)
        self.assertIn('Changed files (0):', text)
        self.assertIn('empty diff: run everything', text)
        self.assert_runs_everything(self.output.read_text().splitlines())
        self.assertNotIn('SKIP', text)

    def test_full_match_reports_run_everything(self) -> None:
        text, _ = self.run_main(['Cargo.lock', 'README.md'], output=self.output)
        self.assertIn('Cargo.lock matches full: run everything', text)
        self.assert_runs_everything(self.output.read_text().splitlines())

    def test_orphan_reports_run_everything(self) -> None:
        text, _ = self.run_main(['brand/new.txt'], output=self.output)
        self.assertIn('brand/new.txt matches no unit and is not ignored', text)
        self.assert_runs_everything(self.output.read_text().splitlines())

    def test_all_flag_runs_everything_without_git(self) -> None:
        out = io.StringIO()
        with (
            mock.patch.object(
                ci_changes,
                'changed_files',
                side_effect=AssertionError('git was called'),
            ),
            mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(self.output)}),
            mock.patch.object(sys, 'argv', ['ci_changes.py', '--all']),
            contextlib.redirect_stdout(out),
        ):
            ci_changes.main()
        self.assertIn('not a pull request: run everything', out.getvalue())
        self.assert_runs_everything(self.output.read_text().splitlines())

    def test_docs_only_skips_every_unit(self) -> None:
        text, _ = self.run_main(['README.md'], output=self.output)
        got = dict(line.split('=', 1) for line in self.output.read_text().splitlines())
        self.assertEqual(json.loads(got['skip']), sorted(EVERYTHING))
        self.assertEqual((got['db-matrix'], got['interop-matrix']), ('[]', '[]'))
        self.assertEqual((got['run-test'], got['run-windows']), ('false', 'false'))
        self.assertNotIn('RUN ', text)

    def test_default_refs_are_the_pr_merge_commit_parent_and_head(self) -> None:
        _, cf = self.run_main(['README.md'], output=self.output)
        cf.assert_called_once_with('HEAD^1', 'HEAD')

    def test_base_and_head_flags_are_forwarded(self) -> None:
        _, cf = self.run_main(
            ['README.md'],
            '--base',
            'origin/develop',
            '--head',
            'f00',
            output=self.output,
        )
        cf.assert_called_once_with('origin/develop', 'f00')


class CommandLine(unittest.TestCase):
    def test_script_runs_as_a_program(self) -> None:
        script = Path(ci_changes.__file__)
        done = subprocess.run(
            [sys.executable, str(script), '--base', 'HEAD', '--head', 'HEAD'],
            cwd=ci_changes.REPO,
            env=GIT_ENV,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn('empty diff: run everything', done.stdout)
        self.assertIn('skip=[]', done.stdout.splitlines())

    def test_unknown_flag_is_rejected(self) -> None:
        script = Path(ci_changes.__file__)
        done = subprocess.run(
            [sys.executable, str(script), '--nope'],
            env=GIT_ENV,
            capture_output=True,
            text=True,
        )
        self.assertEqual(done.returncode, 2)


if __name__ == '__main__':
    unittest.main()

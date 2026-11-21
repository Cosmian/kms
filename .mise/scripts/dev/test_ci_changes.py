#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests of ci_changes.py against the real .github/ci-paths.toml.

Each scenario simulates a pull request touching one area and asserts the exact set of CI units that run.
Run: python3 -m unittest discover -s .mise/scripts/dev -p 'test_ci_changes.py'   (or `mise run dev:ci-changes --self-test`)
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import textwrap
import sys
import unittest
from pathlib import Path

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


def run(*files: str) -> set[str]:
    """Units that run for a PR changing `files`."""
    skipped, _ = ci_changes.classify(CFG, list(files))
    return EVERYTHING - set(skipped)


class DocsAndIgnored(unittest.TestCase):
    def test_docs_only_runs_nothing(self) -> None:
        self.assertEqual(
            run(
                'documentation/docs/index.md',
                'CHANGELOG/x.md',
                'README.md',
                '.github/skills/foo/SKILL.md',
            ),
            set(),
        )

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
            run('ui/src/App.tsx', 'documentation/docs/index.md'), {'ui', 'windows-ui'}
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
    'windows-cargo-test': '.mise/scripts/windows/cargo_test.ps1',
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


if __name__ == '__main__':
    unittest.main()

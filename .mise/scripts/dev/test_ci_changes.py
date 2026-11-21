#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests of ci_changes.py against the real .github/ci-paths.toml.

Each scenario simulates a pull request touching one area and asserts the exact set of CI units that run.
Run: python3 -m unittest discover -s .mise/scripts/dev -p 'test_ci_changes.py'   (or `mise run dev:ci-changes --self-test`)
"""

from __future__ import annotations

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
    def test_workflow_only_pr_runs_one_leg_per_workflow(self) -> None:
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
                'no-nix',
                'forward-proxy',
                'cargo-publish-dry-run',
                'xks-remote',
                'db:sqlite',
                'interop:pykmip',
                'windows-cargo-test',
            },
        )

    def test_classifier_config_change_runs_nothing(self) -> None:
        self.assertEqual(run('.github/ci-paths.toml'), set())

    def test_forward_proxy_workflow(self) -> None:
        self.assertEqual(run('.github/workflows/forward_proxy.yml'), {'forward-proxy'})


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


class ConfigIntegrity(unittest.TestCase):
    def test_every_unit_is_reachable(self) -> None:
        # A unit no changed file can trigger would silently never run on PRs.
        samples = {
            'cargo-clippy': 'clippy.toml',
            'ui': 'ui/src/App.tsx',
            'db:psql': 'crate/server_database/src/stores/sql/pgsql.rs',
            'interop:jose': 'crate/server/src/routes/jose/mod.rs',
            'windows-est': 'crate/server/src/routes/est/mod.rs',
        }
        for unit, path in samples.items():
            with self.subTest(unit=unit):
                self.assertIn(unit, run(path))

    def test_classify_reports_skipped_units_sorted_and_disjoint_from_run(self) -> None:
        skipped, _ = ci_changes.classify(CFG, ['ui/src/App.tsx'])
        self.assertEqual(skipped, sorted(skipped))
        self.assertFalse(set(skipped) & {'ui', 'windows-ui'})


if __name__ == '__main__':
    unittest.main()

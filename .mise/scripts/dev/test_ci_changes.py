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
SERVER_WIDE = WORKSPACE | {'forward-proxy', 'spire'}
# Strict units: never forced by `full` or an unmatched path (see ci-paths.toml).
WINDOWS_PLATFORM = {
    'windows-ui',
    'windows-cng-ksp',
    'windows-hsm-idemia',
    'windows-est',
}
STRICT = {
    'cargo-clippy',
    'cargo-machete',
    'no-nix',
    'cargo-publish-dry-run',
    'windows-cargo-test',
} | WINDOWS_PLATFORM
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


def leg(
    suite: str,
    *variants: str,
    runner: str = 'ubuntu-24.04',
    setup: str = 'nix',
    bench: str = '',
    timeout: int = 360,
    lock: str = '',
    environment: str = '',
) -> list[dict[str, object]]:
    return [
        {
            'suite': suite,
            'variant': v,
            'runner': runner,
            'setup': setup,
            'bench': bench,
            'timeout': timeout,
            'lock': lock,
            'environment': environment,
        }
        for v in variants or ('',)
    ]


def written_legs(output: Path) -> list[dict[str, object]]:
    """The legs of the `suites-matrix=` line main() appended to the $GITHUB_OUTPUT file `output`."""
    line = output.read_text().splitlines()[-1]
    return json.loads(line.removeprefix('suites-matrix='))


BOTH = ('fips', 'non-fips')
SOFT_HSMS = 'softhsm2 utimaco crypt2pay-simulator'
WIN = {'runner': 'windows-2022', 'setup': 'windows'}
XKS = leg(
    'xks-remote',
    'non-fips',
    timeout=30,
    lock='xks-remote',
    environment='xks-remote-approval',
)
NO_NIX = [  # runner-major, then variant
    g
    for runner in ('ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15')
    for g in leg('no-nix', *BOTH, runner=runner, setup='plain')
]
# Every pull-request leg of an upstream PR, in ci-paths.toml unit order (what an empty diff emits).
FULL_SUITES = [
    *leg('cargo-clippy', setup='plain'),
    *leg('cargo-machete', setup='plain'),
    *NO_NIX,
    *leg('forward-proxy', 'non-fips', setup='plain'),
    *leg('build-documentation', setup='plain'),
    *leg('cargo-publish-dry-run', setup='plain'),
    *XKS,
    *leg('db:sqlite', *BOTH),
    *leg('db:psql', *BOTH),
    *leg('db:mysql', *BOTH),
    *leg('db:mariadb', *BOTH),
    *leg('db:percona', *BOTH),
    *leg('db:redis', 'non-fips'),
    *leg('db:openbao', *BOTH),
    *leg('cloud', *BOTH),
    *leg('hsm', 'fips', bench=SOFT_HSMS),
    *leg('hsm', 'non-fips', bench=SOFT_HSMS + ' kryoptic'),
    *leg('pkcs11', 'non-fips'),
    *leg('obs', *BOTH),
    *leg('pki', *BOTH),
    *leg('pki-macos', 'fips', runner='macos-15', setup='plain', timeout=60),
    *leg('spire', 'non-fips'),
    *leg('ui', *BOTH),
    *leg('interop:ase', 'non-fips'),
    *leg('interop:db2', 'non-fips'),
    *leg('interop:edb-tde', 'non-fips'),
    *leg('interop:iris', 'non-fips'),
    *leg('interop:jose', 'non-fips'),
    *leg('interop:kmip-go', *BOTH),
    *leg('interop:kmipkit', 'non-fips'),
    *leg('interop:openbao', *BOTH),
    *leg('interop:openbao-auth-verifier', *BOTH),
    *leg('interop:openbao-kmip', *BOTH),
    *leg('interop:pykmip', 'non-fips'),
    *leg('interop:ssh-secrets', *BOTH),
    *leg('windows-cargo-test', **WIN),
    *leg('windows-ui', **WIN),
    *leg('windows-cng-ksp', **WIN),
    *leg('windows-hsm-idemia', 'non-fips', 'fips', timeout=120, **WIN),
    *leg('windows-est', timeout=60, **WIN),
]


# The one leg per setup path a change to the shared CI setup (ci_setup) runs (plain Linux, nix, macOS, Windows).
SETUP_PROBES = {'forward-proxy', 'interop:pykmip', 'pki-macos', 'windows-est'}
# Units whose own steps are the composite action .github/actions/legs/<unit>/.
LEG_ACTIONS = {
    'build-documentation',
    'cargo-clippy',
    'cargo-machete',
    'cargo-publish-dry-run',
    'forward-proxy',
    'no-nix',
    'pki-macos',
    'windows-cargo-test',
    'windows-cng-ksp',
    'windows-est',
    'windows-hsm-idemia',
    'windows-ui',
    'xks-remote',
}


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
            (SERVER_WIDE | DB_LEGS)
            - {'cargo-clippy', 'cargo-machete'},  # SQL is not Rust source
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
            WORKSPACE | {'pki', 'pki-macos', 'windows-est'},
        )

    def test_certificate_core(self) -> None:
        self.assertEqual(
            run('crate/server/src/core/certificate/validate.rs'),
            SERVER_WIDE | {'pki', 'pki-macos'},
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
            SERVER_WIDE | {'pki', 'pki-macos'},
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
                '.github/workflows/test_windows.yml',
                '.mise/scripts/dev/ci_changes.py',
            ),
            # only the shared setup (test_all.yml, test-group.yml) triggers legs: the setup probes
            SETUP_PROBES,
        )

    def test_strict_units_run_only_on_their_inputs(self) -> None:
        crate_rust = {'cargo-clippy', 'cargo-machete', 'no-nix'}
        build = {'no-nix', 'cargo-publish-dry-run', 'windows-cargo-test'}
        self.assertEqual(
            run('crate/server/src/core/mod.rs') & STRICT, crate_rust | build
        )
        self.assertEqual(run('crate/server/kms_template.toml') & STRICT, build)
        for path in (  # inputs the build and test jobs consume besides crate/
            'test_data',
            'Cargo.lock',
            '.config/nextest.toml',
            'crate/server_database/src/stores/sql/query.sql',
        ):
            with self.subTest(path=path):
                self.assertTrue(build <= run(path))
        for path in (
            '.github/workflows/main.yml',
            '.github/workflows/test_all.yml',
            'crate/server/README.md',
            'ui/src/App.tsx',
        ):
            with self.subTest(path=path):
                self.assertFalse(run(path) & (STRICT - WINDOWS_PLATFORM))

    def test_clippy_runs_only_on_rust_changes(self) -> None:
        for path in (
            'crate/server/src/core/mod.rs',
            'crate/server/Cargo.toml',
            'clippy.toml',
        ):
            with self.subTest(path=path):
                self.assertIn('cargo-clippy', run(path))
        for path in (
            '.github/workflows/main.yml',
            'crate/server/kms_template.toml',
            'crate/server/README.md',
            'ui/src/App.tsx',
        ):
            with self.subTest(path=path):
                self.assertNotIn('cargo-clippy', run(path))

    def test_classifier_config_change_runs_nothing(self) -> None:
        self.assertEqual(run('.github/ci-paths.toml'), set())

    def test_removed_job_workflows_run_nothing(self) -> None:
        # their jobs are legs of test-group.yml now: deleting them must not run everything
        self.assertEqual(
            run(
                '.github/workflows/forward_proxy.yml',
                '.github/workflows/no-nix.yml',
                '.github/workflows/test_windows.yml',
            ),
            set(),
        )

    def test_no_nix_and_windows_cargo_test_need_rust_source(self) -> None:
        for path in (
            '.github/workflows/main.yml',
            '.github/workflows/test_all.yml',
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

    def test_xks_remote_runs_only_on_xks_owned_source(self) -> None:
        for path in (
            'crate/server/src/routes/aws_xks/sigv4.rs',
            'crate/server/src/routes/aws_xks/encrypt_decrypt/encrypt_.rs',
            '.mise/scripts/test/test_xks_remote.sh',
        ):
            with self.subTest(path=path):
                self.assertIn('xks-remote', run(path))
        # server code that merely mentions or wires XKS, and unrelated server changes, do not
        for path in (
            'crate/server/src/start_kms_server.rs',
            'crate/server/src/config/params/server_params.rs',
            'crate/server/src/core/operations/key_ops/crypto_op.rs',
            'crate/kmip/src/lib.rs',
        ):
            with self.subTest(path=path):
                self.assertNotIn('xks-remote', run(path))

    def test_removed_suite_wrappers_run_nothing(self) -> None:
        # deleting them must not fall through to the run-everything fail-safe
        self.assertEqual(
            run('.github/workflows/test-db.yml', '.github/workflows/test-interop.yml'),
            set(),
        )

    def test_shared_ci_setup_runs_one_leg_per_setup_path(self) -> None:
        for path in (
            '.github/workflows/test-group.yml',
            '.github/workflows/test_all.yml',
            *(
                f'.github/actions/{a}/action.yml'
                for a in (
                    'install-rust',
                    'install-mise',
                    'setup-nix',
                    'setup-nix-mise',
                    'cache-openssl-buildrs',
                    'cleanup-runner',
                    'build-static-openssl',
                    'windows-vs-ninja',
                )
            ),
        ):
            with self.subTest(path=path):
                self.assertEqual(run(path), SETUP_PROBES)

    def test_other_ci_files_run_nothing(self) -> None:
        for path in (
            *(f'.github/actions/legs/{u}/action.yml' for u in LEG_ACTIONS | {'db'}),
            '.github/workflows/main.yml',
            '.github/workflows/cargo-publish.yml',
            '.github/workflows/ansible.yml',
            '.github/workflows/ansible-galaxy-publish.yml',
            '.github/workflows/brand-new.yml',
            '.github/actions/brand-new/action.yml',
        ):
            with self.subTest(path=path):
                self.assertEqual(run(path), set())


class Matrices(unittest.TestCase):
    """outputs(): the legs main.yml feeds to test_all.yml."""

    def legs(self, files: list[str], **kwargs: object) -> list[dict[str, object]]:
        skipped, _ = ci_changes.classify(CFG, files)
        out = ci_changes.outputs(CFG, skipped, **kwargs)
        self.assertEqual(list(out), ['suites-matrix'])
        return json.loads(out['suites-matrix'])

    def everything(self, event: str, **kwargs: object) -> list[dict[str, object]]:
        return json.loads(
            ci_changes.outputs(CFG, [], event=event, **kwargs)['suites-matrix']
        )

    def test_everything_runs_every_leg_in_toml_order(self) -> None:
        for legs in (self.legs([]), self.everything('pull_request')):
            self.assertEqual(legs, FULL_SUITES)
            self.assertEqual(len(legs), 61)

    def test_no_nix_legs_come_runner_major(self) -> None:
        legs = [g for g in FULL_SUITES if g['suite'] == 'no-nix']
        self.assertEqual(
            [(g['runner'], g['variant']) for g in legs],
            [
                ('ubuntu-24.04', 'fips'),
                ('ubuntu-24.04', 'non-fips'),
                ('ubuntu-24.04-arm', 'fips'),
                ('ubuntu-24.04-arm', 'non-fips'),
                ('macos-15', 'fips'),
                ('macos-15', 'non-fips'),
            ],
        )

    def test_workflow_only_pr(self) -> None:
        legs = self.legs(
            [
                '.github/ci-paths.toml',
                '.github/workflows/main.yml',
                '.github/workflows/test_all.yml',
                '.github/workflows/test-group.yml',
                '.mise/scripts/dev/ci_changes.py',
            ]
        )
        self.assertEqual(
            legs,
            [g for g in FULL_SUITES if g['suite'] in SETUP_PROBES],
        )

    def test_pg_store_change_keeps_only_the_legs_it_triggers(self) -> None:
        legs = self.legs(['crate/server_database/src/stores/sql/pgsql.rs'])
        self.assertEqual(
            legs,
            [
                *leg('cargo-clippy', setup='plain'),
                *leg('cargo-machete', setup='plain'),
                *NO_NIX,
                *leg('cargo-publish-dry-run', setup='plain'),
                *leg('db:sqlite', *BOTH),
                *leg('db:psql', *BOTH),
                *leg('db:openbao', *BOTH),
                *leg('interop:ssh-secrets', *BOTH),
                *leg('windows-cargo-test', **WIN),
            ],
        )

    def test_ui_change_runs_the_ui_and_windows_ui_legs(self) -> None:
        self.assertEqual(
            self.legs(['ui/src/App.tsx']),
            [
                *leg('ui', *BOTH),
                *leg('windows-ui', **WIN),
            ],
        )

    def test_only_hsm_running_keeps_its_bench_models_per_variant(self) -> None:
        out = ci_changes.outputs(CFG, sorted(EVERYTHING - {'hsm'}))
        self.assertEqual(
            json.loads(out['suites-matrix']),
            [
                *leg('hsm', 'fips', bench=SOFT_HSMS),
                *leg('hsm', 'non-fips', bench=SOFT_HSMS + ' kryoptic'),
            ],
        )

    def test_change_that_triggers_no_unit_has_no_legs(self) -> None:
        out = ci_changes.outputs(CFG, ci_changes.classify(CFG, ['README.md'])[0])
        self.assertEqual(out['suites-matrix'], '[]')

    def test_nightly_runs_every_unit_but_xks(self) -> None:
        legs = self.everything('schedule')
        suites = {g['suite'] for g in legs}
        self.assertEqual(len(legs), 62)
        self.assertEqual(suites, set(EVERYTHING) - {'xks-remote'})
        self.assertEqual(
            [g['lock'] for g in legs if g['suite'].startswith('hsm:')],
            ['hsm-crypt2pay', 'hsm-proteccio'],
        )

    def test_tag_runs_the_real_publish_instead_of_the_dry_run(self) -> None:
        legs = self.everything('tag')
        suites = {g['suite'] for g in legs}
        self.assertEqual(len(legs), 62)
        self.assertEqual(suites, set(EVERYTHING) - {'cargo-publish-dry-run'})
        self.assertIn('xks-remote', suites)

    def test_dispatch_runs_every_leg(self) -> None:
        legs = self.everything('workflow_dispatch')
        self.assertEqual(len(legs), 63)
        self.assertEqual({g['suite'] for g in legs}, set(EVERYTHING))

    def test_nightly_of_a_fork_repository(self) -> None:
        legs = self.everything('schedule', secrets=False)
        suites = {g['suite'] for g in legs}
        self.assertEqual(len(legs), 58)
        self.assertFalse(suites & {'cloud', 'hsm:crypt2pay', 'hsm:proteccio'})
        self.assertTrue(suites >= {'cargo-publish-dry-run', 'windows-est'})

    def test_fork_pull_request(self) -> None:
        legs = self.legs([], secrets=False, fork_pr=True)
        suites = {g['suite'] for g in legs}
        self.assertEqual(len(legs), 51)
        self.assertFalse(suites & {'cloud', 'xks-remote', 'cargo-publish-dry-run'})
        self.assertFalse({u for u in suites if u.startswith('windows-')})

    def test_dependabot_pull_request_keeps_the_rust_and_docs_units(self) -> None:
        legs = self.legs([], dependabot=True)
        self.assertEqual(len(legs), 10)
        self.assertEqual(
            {g['suite'] for g in legs},
            {
                'cargo-clippy',
                'cargo-machete',
                'no-nix',
                'forward-proxy',
                'build-documentation',
            },
        )


class Wiring(unittest.TestCase):
    """Every unit has a way to run: a mise task, or steps of its own in test-group.yml (else its leg would run nothing)."""

    def test_units_with_their_own_steps_are_exactly_the_non_nix_ones(self) -> None:
        text = (
            ci_changes.REPO / '.github' / 'workflows' / 'test-group.yml'
        ).read_text()
        steps = set(re.findall(r"inputs\.suite == '([a-z0-9:-]+)'", text))
        self.assertEqual(
            steps, {u for u, l in CFG.legs.items() if l.setup != 'nix'} | {'xks-remote'}
        )

    def test_each_unit_with_own_steps_calls_its_leg_action(self) -> None:
        text = (
            ci_changes.REPO / '.github' / 'workflows' / 'test-group.yml'
        ).read_text()
        calls = set(
            re.findall(
                r"^\s+- if: inputs\.suite == '([a-z0-9-]+)'\n\s+uses: \./\.github/actions/legs/\1$",
                text,
                re.M,
            )
        )
        self.assertEqual(calls, LEG_ACTIONS)
        self.assertEqual(
            LEG_ACTIONS,
            {u for u, l in CFG.legs.items() if l.setup != 'nix'} | {'xks-remote'},
        )
        self.assertIn('uses: ./.github/actions/legs/db\n', text)
        for unit in LEG_ACTIONS | {'db'}:
            with self.subTest(unit=unit):
                self.assertTrue(
                    (
                        ci_changes.REPO
                        / '.github'
                        / 'actions'
                        / 'legs'
                        / unit
                        / 'action.yml'
                    ).is_file()
                )

    def test_every_nix_unit_runs_an_existing_mise_task(self) -> None:
        tasks = ci_changes.REPO / '.mise' / 'tasks' / 'test'
        for unit, legs in CFG.legs.items():
            if legs.setup == 'nix' and unit != 'xks-remote':
                with self.subTest(unit=unit):
                    self.assertTrue((tasks / unit.replace(':', '/')).exists())


class FailSafe(unittest.TestCase):
    def test_empty_diff_runs_everything(self) -> None:
        self.assertEqual(run(), EVERYTHING)

    def test_unknown_path_runs_everything_but_strict_units(self) -> None:
        self.assertEqual(run('brand/new.txt'), EVERYTHING - CFG.strict)

    def test_unknown_path_among_ignored_files_runs_everything_but_strict_units(
        self,
    ) -> None:
        self.assertEqual(run('README.md', 'brand/new.txt'), EVERYTHING - CFG.strict)

    def test_strict_units_are_never_forced_by_full_or_unknown_paths(self) -> None:
        self.assertEqual(CFG.strict, STRICT)
        for path in (
            'mise.toml',
            'shell.nix',
            '.mise/lib/common.sh',
            'brand/new.txt',
        ):
            with self.subTest(path=path):
                self.assertFalse(run(path) & STRICT)
        for path in ('Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml'):
            with self.subTest(path=path):
                self.assertTrue(
                    {'cargo-clippy', 'no-nix', 'windows-cargo-test'} <= run(path)
                )

    def test_full_patterns_run_everything(self) -> None:
        for path in (
            'Cargo.lock',
            'rust-toolchain.toml',
        ):
            with self.subTest(
                path=path
            ):  # Rust inputs, but machete only reads manifests
                self.assertEqual(
                    run(path), EVERYTHING - {'cargo-machete'} - WINDOWS_PLATFORM
                )
        self.assertEqual(  # the tests read it; lint and manifests do not
            run('test_data'),
            EVERYTHING - {'cargo-clippy', 'cargo-machete'} - WINDOWS_PLATFORM,
        )
        for path in ('Cargo.toml', 'crate/crypto/build.rs'):
            with self.subTest(path=path):
                self.assertEqual(run(path), EVERYTHING - WINDOWS_PLATFORM)
        for path in (
            'mise.toml',
            '.mise/lib/common.sh',
        ):
            with self.subTest(path=path):
                self.assertEqual(run(path), EVERYTHING - CFG.strict)

    def test_one_full_file_overrides_ignored_ones(self) -> None:
        self.assertEqual(run('README.md', 'Cargo.lock'), run('Cargo.lock'))


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
    'forward-proxy': '.github/scripts/squid/squid.conf',
    'cargo-publish-dry-run': 'crate/server/kms_template.toml',
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
    'hsm:crypt2pay': 'crate/hsm/crypt2pay/src/lib.rs',
    'hsm:proteccio': 'crate/hsm/proteccio/src/lib.rs',
    'pkcs11': 'crate/clients/pkcs11/module/src/pkcs11.rs',
    'obs': 'crate/server/src/core/otel_metrics.rs',
    'pki': 'crate/server/src/routes/est/mod.rs',
    'pki-macos': 'crate/server/src/routes/est/mod.rs',
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
                self.assertNotEqual(ran, EVERYTHING, f"{path} hits full or an orphan")

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

    def test_bench_must_map_variants_of_the_unit(self) -> None:
        head = "full = 'x'\nignore = 'y'\n[units.h]\nfiles = 'x'\n"
        self.rejects(head + "bench = {fips = 'a'}\n")  # no variants
        self.rejects(head + "variants = ['fips']\nbench = {non-fips = 'a'}\n")
        self.rejects(head + "variants = ['fips']\nbench = {fips = 1}\n")

    def test_invalid_variants_are_rejected(self) -> None:
        for bad in ("['fips', 'fips']", '[]', "['x']"):
            with self.subTest(variants=bad):
                self.rejects(
                    f"full = 'x'\nignore = 'y'\n[units.'db:x']\nfiles = 'x'\nvariants = {bad}\n"
                )

    def test_unit_with_only_variants_is_rejected(self) -> None:
        self.rejects("full = 'x'\nignore = 'y'\n[units.'db:x']\nvariants = ['fips']\n")

    def test_invalid_strict_is_rejected(self) -> None:
        head = "full = 'x'\nignore = 'y'\n[sets]\ns = 'z'\n[units.a]\n"
        self.rejects(head + "files = 'x'\nstrict = false\n")

    def test_invalid_leg_keys_are_rejected(self) -> None:
        head = "full = 'x'\nignore = 'y'\n[units.a]\nfiles = 'x'\n"
        for bad in (
            "setup = 'docker'",
            "setup = 'windows'",  # default ubuntu runner
            "setup = 'nix'\nrunners = ['macos-15']",
            "setup = 'windows'\nrunners = ['windows-2022', 'ubuntu-24.04']",
            'timeout = 0',
            'timeout = 400',
            'timeout = true',
            'events = []',
            "events = ['push']",
            "events = ['tag', 'tag']",
            'upstream = false',
            'no-fork-pr = false',
            'dependabot = false',
            "lock = ''",
            "environment = ''",
            'runners = []',
            "runners = ['ubuntu-24.04', 'ubuntu-24.04']",
        ):
            with self.subTest(bad=bad):
                self.rejects(head + bad + '\n')

    def test_leg_defaults_and_overrides(self) -> None:
        cfg = load(
            "full = 'x'\nignore = 'y'\n[units.a]\nfiles = 'x'\n"
            "[units.b]\nfiles = 'x'\nsetup = 'plain'\nrunners = ['macos-15']\nvariants = ['fips']\n"
            "timeout = 60\nlock = 'l'\nenvironment = 'e'\nevents = ['tag']\nupstream = true\n"
            'no-fork-pr = true\ndependabot = true\n'
        )
        a, b = cfg.legs['a'], cfg.legs['b']
        self.assertEqual(
            (a.variants, a.runners, a.setup, a.timeout, a.lock, a.environment),
            (('',), ('ubuntu-24.04',), 'nix', 360, '', ''),
        )
        self.assertEqual(a.events, frozenset(ci_changes.EVENTS))
        self.assertFalse(a.upstream or a.no_fork_pr or a.dependabot)
        self.assertEqual(
            (b.variants, b.runners, b.setup, b.timeout, b.lock, b.environment),
            (('fips',), ('macos-15',), 'plain', 60, 'l', 'e'),
        )
        self.assertEqual(b.events, frozenset({'tag'}))
        self.assertTrue(b.upstream and b.no_fork_pr and b.dependabot)


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
    """main(): console report and the `suites-matrix=` line of the $GITHUB_OUTPUT file the workflows read."""

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

    def run_all(self, *argv: str) -> tuple[str, list[dict[str, object]]]:
        """`--all` run: the diff must never be read. Returns the report and the written legs."""
        out = io.StringIO()
        with (
            mock.patch.object(
                ci_changes,
                'changed_files',
                side_effect=AssertionError('git was called'),
            ),
            mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(self.output)}),
            mock.patch.object(sys, 'argv', ['ci_changes.py', '--all', *argv]),
            contextlib.redirect_stdout(out),
        ):
            ci_changes.main()
        return out.getvalue(), written_legs(self.output)

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.output = Path(tmp.name) / 'github_output'

    def test_report_lists_files_reason_and_every_unit(self) -> None:
        text, _ = self.run_main(['ui/src/App.tsx'], output=self.output)
        lines = text.splitlines()
        self.assertEqual(lines[0], 'Changed files (1):')
        self.assertEqual(lines[1], '  ui/src/App.tsx')
        self.assertEqual(lines[2], f"2 of {len(EVERYTHING)} units triggered")
        marks = {line[5:]: line[:4] for line in lines[3:-1]}
        self.assertEqual(set(marks), EVERYTHING)
        self.assertEqual(
            {u for u, m in marks.items() if m == 'RUN '}, {'ui', 'windows-ui'}
        )
        self.assertTrue(all(m in ('RUN ', 'SKIP') for m in marks.values()))

    def test_output_is_one_compact_json_line_appended_to_github_output(self) -> None:
        text, _ = self.run_main(['ui/src/App.tsx'], output=self.output)
        written = self.output.read_text().splitlines()
        self.assertEqual(written, text.splitlines()[-1:])
        self.assertTrue(written[0].startswith('suites-matrix=['))
        self.assertNotIn(' ', written[0])
        self.assertEqual(
            [(g['suite'], g['variant']) for g in written_legs(self.output)],
            [('ui', 'fips'), ('ui', 'non-fips'), ('windows-ui', '')],
        )

    def test_github_output_is_appended_not_overwritten(self) -> None:
        self.output.write_text('other=1\n')
        self.run_main(['ui/src/App.tsx'], output=self.output)
        lines = self.output.read_text().splitlines()
        self.assertEqual(lines[0], 'other=1')
        self.assertTrue(lines[1].startswith('suites-matrix='))

    def test_without_github_output_only_prints(self) -> None:
        text, _ = self.run_main(['ui/src/App.tsx'], output=None)
        self.assertTrue(text.splitlines()[-1].startswith('suites-matrix=['))
        self.assertFalse(self.output.exists())

    def test_empty_diff_reports_run_everything(self) -> None:
        text, _ = self.run_main([], output=self.output)
        self.assertIn('Changed files (0):', text)
        self.assertIn('empty diff: run everything', text)
        self.assertEqual(written_legs(self.output), FULL_SUITES)
        # only the real HSMs have no pull-request leg
        skipped = {l[5:] for l in text.splitlines() if l.startswith('SKIP')}
        self.assertEqual(skipped, {'hsm:crypt2pay', 'hsm:proteccio'})

    def test_full_match_runs_every_non_strict_unit(self) -> None:
        text, _ = self.run_main(['mise.toml', 'README.md'], output=self.output)
        self.assertIn('mise.toml matches full: run everything', text)
        self.assertEqual(
            {g['suite'] for g in written_legs(self.output)},
            {g['suite'] for g in FULL_SUITES} - STRICT,
        )

    def test_orphan_runs_every_non_strict_unit(self) -> None:
        text, _ = self.run_main(['brand/new.txt'], output=self.output)
        self.assertIn('brand/new.txt matches no unit and is not ignored', text)
        self.assertEqual(
            {g['suite'] for g in written_legs(self.output)},
            {g['suite'] for g in FULL_SUITES} - STRICT,
        )

    def test_nightly_never_reads_the_diff_and_skips_xks(self) -> None:
        text, legs = self.run_all('--event', 'schedule')
        self.assertIn('not a pull request: run everything', text)
        self.assertEqual(len(legs), 62)
        self.assertNotIn('xks-remote', {g['suite'] for g in legs})
        self.assertIn('RUN  hsm:proteccio', text)
        self.assertIn('SKIP xks-remote', text)

    def test_nightly_without_secrets_keeps_windows_but_not_upstream_units(self) -> None:
        _, legs = self.run_all('--event', 'schedule', '--no-secrets')
        suites = {g['suite'] for g in legs}
        self.assertEqual(len(legs), 58)
        self.assertIn('windows-cargo-test', suites)
        self.assertFalse(suites & {'cloud', 'hsm:crypt2pay', 'hsm:proteccio'})

    def test_tag_and_dispatch_runs(self) -> None:
        _, tag = self.run_all('--event', 'tag')
        _, dispatch = self.run_all('--event', 'workflow_dispatch')
        self.assertEqual((len(tag), len(dispatch)), (62, 63))

    def test_fork_pr_without_secrets_drops_cloud_and_windows(self) -> None:
        self.run_main(
            ['ui/src/App.tsx'], '--no-secrets', '--fork-pr', output=self.output
        )
        self.assertEqual({g['suite'] for g in written_legs(self.output)}, {'ui'})

    def test_dependabot_keeps_only_its_units(self) -> None:
        self.run_main([], '--dependabot', output=self.output)
        self.assertEqual(len(written_legs(self.output)), 10)

    def test_inconsistent_flags_exit_with_status_2(self) -> None:
        for argv in (
            ['--all'],
            ['--all', '--event', 'tag', '--dependabot'],
            ['--all', '--event', 'tag', '--fork-pr'],
            ['--event', 'tag'],
        ):
            with self.subTest(argv=argv):
                with (
                    mock.patch.object(sys, 'argv', ['ci_changes.py', *argv]),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as ctx,
                ):
                    ci_changes.main()
                self.assertEqual(ctx.exception.code, 2)

    def test_docs_only_runs_nothing(self) -> None:
        text, _ = self.run_main(['README.md'], output=self.output)
        self.assertEqual(self.output.read_text(), 'suites-matrix=[]\n')
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
        self.assertEqual(
            json.loads(done.stdout.splitlines()[-1].removeprefix('suites-matrix=')),
            FULL_SUITES,
        )

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

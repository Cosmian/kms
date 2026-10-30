#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exercise HSM image preparation without Nix, Kubernetes, or HSM credentials."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
TASK = ROOT / '.mise/tasks/test/k8s/hsm'
MOCK = """#!/usr/bin/env bash
set -euo pipefail
cmd="${0##*/}"
printf '%s\t%s\t%s\n' "$cmd" "${FORCE_REBUILD:-}" "$*" >> "$COMMAND_LOG"
case "$cmd" in
  mise) exit "${BUILD_EXIT:-0}" ;;
  minikube) exit "${LOAD_EXIT:-0}" ;;
  kubectl)
    [ "$1" != cluster-info ] || exit 0
    exit 77 # Stop before namespace creation or HSM configuration.
    ;;
  mktemp)
    mkdir -p "$TEST_ROOT/work"
    printf '%s\n' "$TEST_ROOT/work"
    ;;
  helm | rm | sudo) exit 0 ;;
esac
"""


class HsmImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.log = self.work / 'commands.log'
        for name in ('mise', 'minikube', 'kubectl', 'helm', 'mktemp', 'rm', 'sudo'):
            path = self.work / name
            path.write_text(MOCK)
            path.chmod(0o755)

    def run_task(
        self,
        model: str = 'proteccio',
        variant: str = 'fips',
        build: bool = True,
        **extra: str,
    ) -> tuple[subprocess.CompletedProcess, str]:
        env = os.environ.copy()
        for name in ('usage_image_tag', 'KMS_IMAGE_TAG', 'FORCE_REBUILD'):
            env.pop(name, None)
        env.update(
            MISE_CONFIG_ROOT=str(ROOT),
            HOME=str(self.work),
            PATH=f"{self.work}{os.pathsep}{env['PATH']}",
            TEST_ROOT=str(self.work),
            COMMAND_LOG=str(self.log),
            usage_model=model,
            usage_variant=variant,
            usage_build_image=str(build).lower(),
        )
        env.update(extra)
        self.log.write_text('')
        result = subprocess.run(
            ['bash', str(TASK)],
            env=env,
            text=True,
            capture_output=True,
            check=False,  # The mock cluster deliberately stops the real task.
        )
        return result, self.log.read_text()

    def test_preparation_failures_stop_before_deployment(self) -> None:
        for overrides, code in (({'BUILD_EXIT': '42'}, 42), ({'LOAD_EXIT': '43'}, 43)):
            with self.subTest(overrides=overrides):
                result, commands = self.run_task(**overrides)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertNotIn('delete namespace', commands)
                if code == 42:
                    self.assertNotIn('minikube\t', commands)

    def test_build_rejects_a_release_tag_override(self) -> None:
        result, commands = self.run_task(usage_image_tag='released-tag')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('cannot be combined', result.stdout + result.stderr)
        self.assertNotIn('mise\t', commands)
        self.assertNotIn('minikube\t', commands)


if __name__ == '__main__':
    unittest.main()

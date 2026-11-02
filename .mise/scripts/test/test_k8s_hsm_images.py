#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exercise local HSM image loading without Docker, Kubernetes, or HSM credentials."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
TASK = ROOT / '.mise/tasks/test/k8s/hsm'
IMAGE = 'registry.invalid/kms:test-tag'  # docker and minikube are mocked: only the form matters
MOCK = """#!/usr/bin/env bash
set -euo pipefail
cmd="${0##*/}"
printf '%s\t%s\n' "$cmd" "$*" >> "$COMMAND_LOG"
case "$cmd" in
  docker) exit "${DOCKER_EXIT:-0}" ;;
  minikube) exit "${LOAD_EXIT:-0}" ;;
  kubectl)
    [ "$1" != cluster-info ] || exit 0
    exit 77 # Stop before namespace creation or HSM configuration.
    ;;
  mktemp)
    mkdir -p "$TEST_ROOT/work"
    if [ "${1:-}" = -d ]; then printf '%s\n' "$TEST_ROOT/work"; else printf '%s\n' "$TEST_ROOT/image.tar"; fi
    ;;
  helm | rm | sudo) exit 0 ;;
esac
"""


class HsmLocalImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.log = self.work / 'commands.log'
        for name in ('docker', 'minikube', 'kubectl', 'helm', 'mktemp', 'rm', 'sudo'):
            path = self.work / name
            path.write_text(MOCK)
            path.chmod(0o755)

    def run_task(
        self, image: str = IMAGE, **extra: str
    ) -> tuple[subprocess.CompletedProcess, str]:
        env = os.environ.copy()
        for name in ('usage_image_tag', 'KMS_IMAGE_TAG'):
            env.pop(name, None)
        env.update(
            MISE_CONFIG_ROOT=str(ROOT),
            HOME=str(self.work),
            PATH=f"{self.work}{os.pathsep}{env['PATH']}",
            TEST_ROOT=str(self.work),
            COMMAND_LOG=str(self.log),
            usage_model='proteccio',
            usage_variant='fips',
            usage_local_image=image,
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

    def test_load_failures_stop_before_deployment(self) -> None:
        for overrides in ({'DOCKER_EXIT': '42'}, {'LOAD_EXIT': '43'}):
            with self.subTest(overrides=overrides):
                result, commands = self.run_task(**overrides)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('Could not load', result.stdout + result.stderr)
                self.assertNotIn('delete namespace', commands)

    def test_rejects_a_release_tag_override(self) -> None:
        result, commands = self.run_task(usage_image_tag='released-tag')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('cannot be combined', result.stdout + result.stderr)
        self.assertNotIn('docker\t', commands)
        self.assertNotIn('minikube\timage', commands)

    def test_rejects_an_image_without_a_tag(self) -> None:
        # A registry port must not be mistaken for the tag.
        for image in ('ghcr.io/cosmian/kms-fips', 'localhost:5000/cosmian/kms-fips'):
            with self.subTest(image=image):
                result, commands = self.run_task(image)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(
                    'must be <repository>:<tag>', result.stdout + result.stderr
                )
                self.assertNotIn('docker\t', commands)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Integration tests of .mise/scripts/release/push_package.sh against a real localhost sshd.

The sshd forces the production command (`rrsync -wo -munge -no-del -no-lock <root>`) on the test key, exactly as the
package server does for the kms-ci-upload account. A `ssh` shim placed first on PATH redirects the production
host name to the isolated endpoint (HostName/Port/HostKeyAlias only): host-key verification, key handling and
rsync options are the ones the script uses in production.

Needs Linux with sshd, ssh-keygen, rsync >= 3.2.3 and rrsync; skipped otherwise.
Run: python3 -m unittest discover -s .mise/scripts/dev -p 'test_package_upload.py'   (or `mise run dev:ci-security`)
"""

from __future__ import annotations

import getpass
import os
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / '.mise' / 'scripts' / 'release' / 'push_package.sh'
PROD_HOST = 'package.cosmian.com'
SSHD = shutil.which('sshd') or '/usr/sbin/sshd'
RRSYNC = shutil.which('rrsync') or '/usr/bin/rrsync'
SSH = shutil.which('ssh')


def _rsync_ok() -> bool:
    try:
        out = subprocess.run(
            ['rsync', '--version'], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return False
    match = re.search(r'version\s+(\d+)\.(\d+)', out)
    return (
        bool(match)
        and (int(match[1]), int(match[2])) >= (3, 2)
        and not out.startswith('openrsync')
    )


READY = all(
    [
        os.path.exists(SSHD),
        os.path.exists(RRSYNC),
        SSH,
        shutil.which('ssh-keygen'),
        _rsync_ok(),
    ]
)


def keygen(path: Path) -> str:
    subprocess.run(
        ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', str(path)],
        check=True,
    )
    return (
        path.with_suffix('.pub').read_text()
        if path.with_suffix('.pub').exists()
        else Path(f'{path}.pub').read_text()
    )


class RequirementsTest(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get('REQUIRE_SSH_TESTS'), 'REQUIRE_SSH_TESTS is not set'
    )
    def test_tooling_is_installed_when_required(self) -> None:
        self.assertTrue(
            READY,
            'CI must run the SSH tests: sshd, ssh-keygen, rsync >= 3.2.3 and rrsync are required',
        )


@unittest.skipUnless(
    READY, 'needs Linux with sshd, ssh-keygen, rsync >= 3.2.3 and rrsync'
)
class PackageUploadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix='push-package-test-'))
        cls.root = cls.tmp / 'upload-root'
        cls.root.mkdir()
        host_key = cls.tmp / 'host'
        host_pub = keygen(host_key).split()
        cls.known_hosts = f'{PROD_HOST} {host_pub[0]} {host_pub[1]}\n'
        other_pub = keygen(cls.tmp / 'other_host').split()
        cls.wrong_known_hosts = f'{PROD_HOST} {other_pub[0]} {other_pub[1]}\n'
        cls.key_path = cls.tmp / 'client'
        client_pub = keygen(cls.key_path).strip()
        cls.key = cls.key_path.read_text()
        cls.unauthorized_key = cls.tmp / 'stranger'
        keygen(cls.unauthorized_key)
        cls.unauthorized_key = cls.unauthorized_key.read_text()
        (cls.tmp / 'authorized_keys').write_text(
            f'restrict,command="{RRSYNC} -wo -munge -no-del -no-lock {cls.root}" {client_pub}\n'
        )
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            cls.port = s.getsockname()[1]
        (cls.tmp / 'sshd_config').write_text(
            textwrap.dedent(
                f"""\
            Port {cls.port}
            ListenAddress 127.0.0.1
            HostKey {host_key}
            PidFile {cls.tmp / 'sshd.pid'}
            AuthorizedKeysFile {cls.tmp / 'authorized_keys'}
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            UsePAM no
            StrictModes no
            PermitRootLogin yes
            AllowTcpForwarding yes
            LogLevel ERROR
            """
            )
        )
        cls.sshd = subprocess.Popen([SSHD, '-D', '-f', str(cls.tmp / 'sshd_config')])
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError('sshd did not start')
        # ssh shim: map the production endpoint to the local sshd, nothing else.
        cls.bin = cls.tmp / 'bin'
        cls.bin.mkdir()
        shim = cls.bin / 'ssh'
        shim.write_text(
            textwrap.dedent(
                f"""\
            #!/bin/bash
            pre=()
            while [ $# -gt 0 ]; do
              case "$1" in
                -F) pre+=("$1" "$2"); shift 2 ;;
                -l) shift 2 ;;
                *) break ;;
              esac
            done
            exec {SSH} "${{pre[@]}}" -o HostName=127.0.0.1 -o Port={cls.port} -o HostKeyAlias={PROD_HOST} \\
              -l {getpass.getuser()} "$@"
            """
            )
        )
        shim.chmod(0o755)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.sshd.terminate()
        cls.sshd.wait(timeout=10)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self) -> None:
        shutil.rmtree(self.root)
        self.root.mkdir()
        self.work = Path(tempfile.mkdtemp(prefix='work-', dir=self.tmp))
        self.scratch = Path(tempfile.mkdtemp(prefix='scratch-', dir=self.tmp))
        self.out = self.work / 'github_output'

    def push(
        self, *, key=None, known_hosts=None, cwd=None, **env: str
    ) -> subprocess.CompletedProcess:
        full = {
            'PATH': f'{self.bin}:{os.environ["PATH"]}',
            'HOME': str(self.work),
            'TMPDIR': str(self.scratch),
            'KNOWN_HOSTS': self.known_hosts if known_hosts is None else known_hosts,
            'SSH_PRIVATE_KEY': self.key if key is None else key,
            'GITHUB_OUTPUT': str(self.out),
            'GITHUB_REF': 'refs/tags/1.2.3',
            'GITHUB_REF_NAME': '1.2.3',
        }
        full.update(env)
        return subprocess.run(
            ['bash', str(SCRIPT)],
            env=full,
            cwd=cwd or self.work,
            capture_output=True,
            text=True,
        )

    def assertPushOk(self, proc: subprocess.CompletedProcess) -> None:
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def assertPushFails(self, proc: subprocess.CompletedProcess) -> None:
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(
            list(self.root.rglob('*')), [], 'a failed push must not write anything'
        )
        self.assertFalse(
            self.out.exists() and self.out.read_text(), 'no success output on failure'
        )
        self.assertEqual(
            list(self.scratch.iterdir()), [], 'temporary SSH material must be removed'
        )

    def write(self, rel: str, data: bytes) -> None:
        p = self.work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    # ── success paths ────────────────────────────────────────────────────────
    def test_flat_files_land_at_tag_path(self) -> None:
        self.write('dist/a.deb', b'\x00deb\xff')
        self.write('dist/b.txt', b'text')
        proc = self.push(
            SUBDIR='deb/amd64/fips/static', FILES='dist/*.deb\n./dist/b.txt\n'
        )
        self.assertPushOk(proc)
        dest = self.root / '1.2.3/deb/amd64/fips/static'
        self.assertEqual((dest / 'a.deb').read_bytes(), b'\x00deb\xff')
        self.assertEqual((dest / 'b.txt').read_bytes(), b'text')
        self.assertEqual(
            self.out.read_text(),
            'remote-dir=/mnt/package/kms/1.2.3/deb/amd64/fips/static\n',
        )

    def test_branch_with_slash_uses_last_build(self) -> None:
        self.write('x.zip', b'zip')
        proc = self.push(
            SUBDIR='monitoring',
            FILES='x.zip',
            GITHUB_REF='refs/pull/1/merge',
            GITHUB_HEAD_REF='feat/security-1498',
        )
        self.assertPushOk(proc)
        self.assertEqual(
            (self.root / 'last_build/feat/security-1498/monitoring/x.zip').read_bytes(),
            b'zip',
        )

    def test_directory_contents_with_version_override(self) -> None:
        self.write('report/load/a.svg', b'<svg/>')
        self.write('report/report.md', b'# r')
        proc = self.push(
            SUBDIR='benchmarks',
            DIRECTORY='report',
            VERSION_DIR='develop',
            GITHUB_REF='refs/heads/develop',
        )
        self.assertPushOk(proc)
        dest = self.root / 'develop/benchmarks'
        self.assertEqual((dest / 'load/a.svg').read_bytes(), b'<svg/>')
        self.assertEqual((dest / 'report.md').read_bytes(), b'# r')
        self.assertFalse(
            (dest / 'report').exists(),
            'contents are uploaded, not the directory itself',
        )

    def test_colon_in_name_is_not_a_remote_host(self) -> None:
        self.write('host:file.txt', b'x')
        self.assertPushOk(self.push(SUBDIR='s', FILES='host:file.txt'))
        self.assertEqual((self.root / '1.2.3/s/host:file.txt').read_bytes(), b'x')

    # ── failure paths ────────────────────────────────────────────────────────
    def test_missing_key_fails(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(self.push(SUBDIR='s', FILES='f', key=' '[:0]))

    def test_unauthorized_key_fails(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(
            self.push(SUBDIR='s', FILES='f', key=self.unauthorized_key)
        )

    def test_missing_host_pin_fails(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(self.push(SUBDIR='s', FILES='f', known_hosts=' '[:0]))

    def test_mismatched_host_pin_fails(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(
            self.push(SUBDIR='s', FILES='f', known_hosts=self.wrong_known_hosts)
        )

    def test_unmatched_glob_fails(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(self.push(SUBDIR='s', FILES='f\nnope/*.deb'))

    def test_empty_directory_fails(self) -> None:
        (self.work / 'empty/sub').mkdir(parents=True)
        self.assertPushFails(self.push(SUBDIR='s', DIRECTORY='empty'))

    def test_files_and_directory_together_fail(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(self.push(SUBDIR='s', FILES='f', DIRECTORY='.'))

    def test_traversal_fails(self) -> None:
        self.write('f', b'1')
        for subdir, version in (
            ('../x', ''),
            ('a/../../x', ''),
            ('/abs', ''),
            ('a//b', ''),
            ('s', '..'),
            ('s', 'a/./b'),
        ):
            with self.subTest(subdir=subdir, version=version):
                self.assertPushFails(
                    self.push(SUBDIR=subdir, FILES='f', VERSION_DIR=version)
                )

    def test_traversal_via_ref_name_fails(self) -> None:
        self.write('f', b'1')
        self.assertPushFails(
            self.push(
                SUBDIR='s',
                FILES='f',
                GITHUB_REF='refs/tags/../../x',
                GITHUB_REF_NAME='../../x',
            )
        )

    def test_symlink_upload_fails(self) -> None:
        (self.work / 'secret').write_text('s')
        (self.work / 'link').symlink_to('secret')
        self.assertPushFails(self.push(SUBDIR='s', FILES='link'))

    def test_symlink_inside_directory_fails(self) -> None:
        self.write('d/ok', b'1')
        (self.work / 'd/link').symlink_to('/etc/passwd')
        self.assertPushFails(self.push(SUBDIR='s', DIRECTORY='d'))

    def test_duplicate_basename_fails(self) -> None:
        self.write('a/x', b'1')
        self.write('b/x', b'2')
        self.assertPushFails(self.push(SUBDIR='s', FILES='a/x\nb/x'))

    # ── what the pinned key can do besides uploading ─────────────────────────
    def raw_ssh_config(self) -> Path:
        cfg = self.work / 'ssh_config'
        key = self.work / 'raw_key'
        key.write_text(self.key)
        key.chmod(0o600)
        known = self.work / 'raw_known_hosts'
        known.write_text(self.known_hosts)
        cfg.write_text(
            f'Host {PROD_HOST}\n  IdentityFile {key}\n  IdentitiesOnly yes\n  BatchMode yes\n'
            f'  StrictHostKeyChecking yes\n  UserKnownHostsFile {known}\n  GlobalKnownHostsFile /dev/null\n'
        )
        return cfg

    def run_raw(self, args: list[str]) -> subprocess.CompletedProcess:
        env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}'}
        return subprocess.run(
            args, env=env, cwd=self.work, capture_output=True, text=True, timeout=60
        )

    def test_key_cannot_run_commands_read_forward_delete_or_escape(self) -> None:
        self.write('f', b'1')
        self.assertPushOk(self.push(SUBDIR='s', FILES='f'))
        cfg = self.raw_ssh_config()
        ssh = ['ssh', '-F', str(cfg), '-l', 'kms-ci-upload', PROD_HOST]
        rsh = f'ssh -F {cfg}'

        proc = self.run_raw([*ssh, 'id'])
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('uid=', proc.stdout)

        marker = self.work / 'forward-ok'
        proc = self.run_raw([*ssh, '-R', '0:127.0.0.1:1', 'true'])
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(marker.exists())

        dl = self.work / 'download'
        dl.mkdir()
        proc = self.run_raw(
            ['rsync', '-r', '-e', rsh, f'kms-ci-upload@{PROD_HOST}:1.2.3/s/', f'{dl}/']
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(list(dl.iterdir()), [], 'read/download must be refused')

        empty = self.work / 'empty'
        empty.mkdir()
        proc = self.run_raw(
            [
                'rsync',
                '-r',
                '--delete',
                '-e',
                rsh,
                f'{empty}/',
                f'kms-ci-upload@{PROD_HOST}:1.2.3/s/',
            ]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue((self.root / '1.2.3/s/f').exists(), 'delete must be refused')

        outside = self.tmp / 'outside'
        outside.mkdir(exist_ok=True)
        (self.work / 'payload').write_text('p')
        for dest in ('../outside/', '/tmp/', '/../outside/'):
            self.run_raw(
                [
                    'rsync',
                    '-r',
                    '-e',
                    rsh,
                    str(self.work / 'payload'),
                    f'kms-ci-upload@{PROD_HOST}:{dest}',
                ]
            )
        self.assertEqual(
            list(outside.iterdir()),
            [],
            'writes outside the upload root must be refused',
        )
        self.assertFalse(Path('/tmp/payload').exists())


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Release-credential isolation checks (issue #1498, finding F-012).

Three things live here:

  --probe CHECKOUT   (used by the release/generation/verification jobs, after their setup steps)
                     Builds a dependency-free Cargo workspace whose build script and proc macro run
                     `--inspect CHECKOUT` from inside cargo/rustc, i.e. with exactly the environment real
                     dependency code gets. Fails when a release credential is visible. The job environment is
                     deliberately NOT sanitized first.
  --inspect CHECKOUT Fails when the inherited environment or the Git config of CHECKOUT (root and submodules)
                     holds a release credential. Prints names and locations, never values.
  (no flag)          unittest suite: the probe itself, `cargo publish --no-verify`, and the Git-only publisher
                     scripts (.mise/scripts/release/{make_generated_patch,commit_generated,push_generated}.sh).

Run: python3 -m unittest discover -s .mise/scripts/dev -p 'test_release_security.py'   (or `mise run dev:ci-security`)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
REPO = HERE.parents[3]
RELEASE_SCRIPTS = REPO / '.mise' / 'scripts' / 'release'

CREDENTIAL_ENV = re.compile(
    r'^(PAT_TOKEN|CRATES_IO(_TOKEN)?|CARGO_REGISTRY_TOKEN|CARGO_REGISTRIES_.+_TOKEN|PACKAGE_COSMIAN_SSH_PRIVATE_KEY'
    r'|SSH_PRIVATE_KEY|GH_TOKEN|GITHUB_TOKEN)$',
    re.IGNORECASE,
)
TOKEN_URL = re.compile(r'://[^/@\s]+@')
SECRET_KEY_MATERIAL = re.compile(r'BEGIN [A-Z ]*PRIVATE KEY')


# ── inspection (runs inside build scripts and proc macros) ───────────────────
def git_config_files(checkout: Path) -> list[Path]:
    git_dir = checkout / '.git'
    if git_dir.is_file():  # worktree / submodule checkout: `gitdir: <path>`
        git_dir = (checkout / git_dir.read_text().split(':', 1)[1].strip()).resolve()
    files = [git_dir / 'config'] if (git_dir / 'config').exists() else []
    modules = git_dir / 'modules'
    if modules.is_dir():
        files += sorted(p for p in modules.rglob('config') if p.is_file())
    return files


def redacted(key: str) -> str:
    """A config key can itself carry the token (`url.https://user:TOKEN@host/.insteadOf`)."""
    return TOKEN_URL.sub('://<redacted>@', key)


def global_git_configs(environ: dict[str, str]) -> list[Path]:
    """User-level Git configs Git itself would read (a token persisted there outlives any checkout)."""
    if environ.get('GIT_CONFIG_GLOBAL'):
        return [Path(environ['GIT_CONFIG_GLOBAL'])]
    home = Path(environ.get('HOME') or Path.home())
    xdg = Path(environ.get('XDG_CONFIG_HOME') or home / '.config')
    return [p for p in (home / '.gitconfig', xdg / 'git' / 'config') if p.is_file()]


def cargo_credential_files(environ: dict[str, str]) -> list[Path]:
    """Files `cargo login` writes registry tokens to."""
    home = Path(
        environ.get('CARGO_HOME') or Path(environ.get('HOME') or Path.home()) / '.cargo'
    )
    return [
        p
        for p in (home / 'credentials.toml', home / 'credentials')
        if p.is_file() and p.stat().st_size
    ]


def inspect(checkout: Path, environ: dict[str, str]) -> list[str]:
    """Names and locations of exposed credentials; never values."""
    findings = []
    for name, value in environ.items():
        if CREDENTIAL_ENV.match(name) and value:
            findings.append(f"environment variable {name} is set")
        elif SECRET_KEY_MATERIAL.search(value):
            findings.append(f"environment variable {name} holds private key material")
        elif (
            re.fullmatch(r'GIT_CONFIG_VALUE_\d+', name)
            and 'authorization' in value.lower()
        ):
            findings.append(
                f"environment variable {name} carries a Git authorization header"
            )
        elif re.fullmatch(r'GIT_CONFIG_KEY_\d+', name) and re.search(
            r'extraheader|credential', value, re.I
        ):
            findings.append(
                f"environment variable {name} configures Git credentials ({value})"
            )
    for path in cargo_credential_files(environ):
        findings.append(f"Cargo registry credentials file {path}")
    for config in git_config_files(checkout) + global_git_configs(environ):
        listing = subprocess.run(
            ['git', 'config', '-f', str(config), '--list'],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        for line in listing.splitlines():
            key, _, value = line.partition('=')
            if re.search(r'extraheader', key, re.I) or re.match(
                r'credential(\..+)?\.(helper|username)$', key, re.I
            ):
                findings.append(f"Git config {redacted(key)} in {config}")
            elif key.endswith('.url') and TOKEN_URL.search(value):
                findings.append(f"Git config {key} embeds credentials in {config}")
            elif key.startswith('url.') and TOKEN_URL.search(key):
                findings.append(
                    f"Git config {redacted(key)} embeds credentials in {config}"
                )
    return findings


def run_inspect(checkout: Path) -> int:
    findings = inspect(checkout, dict(os.environ))
    for finding in findings:
        print(f"RELEASE CREDENTIAL EXPOSED: {finding}", file=sys.stderr)
    return 1 if findings else 0


# ── probe workspace ──────────────────────────────────────────────────────────
def write_probe_workspace(root: Path, checkout: Path, markers: Path) -> None:
    py, script = json.dumps(sys.executable), json.dumps(str(HERE))
    co = json.dumps(str(checkout))

    def body(marker: str) -> str:
        return (
            f'let status = std::process::Command::new({py}).args([{script}, "--inspect", {co}])'
            f'.status().expect("cannot run the inspector");\n'
            f'    std::fs::write({json.dumps(str(markers / marker))}, "ran").expect("marker");\n'
            f'    assert!(status.success(), "release credential visible to {marker}");'
        )

    (root / 'macro' / 'src').mkdir(parents=True)
    (root / 'lib' / 'src').mkdir(parents=True)
    (root / 'Cargo.toml').write_text(
        '[workspace]\nresolver = "2"\nmembers = ["macro", "lib"]\n'
    )
    (root / 'macro' / 'Cargo.toml').write_text(
        '[package]\nname = "probe-macro"\nversion = "0.0.0"\nedition = "2021"\n[lib]\nproc-macro = true\n'
    )
    (root / 'macro' / 'src' / 'lib.rs').write_text(
        '#[proc_macro]\npub fn probe(_: proc_macro::TokenStream) -> proc_macro::TokenStream {\n'
        f'    {body("proc-macro")}\n    proc_macro::TokenStream::new()\n}}\n'
    )
    (root / 'lib' / 'Cargo.toml').write_text(
        '[package]\nname = "probe-lib"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n'
        '[dependencies]\nprobe-macro = { path = "../macro" }\n'
    )
    (root / 'lib' / 'build.rs').write_text(
        f'fn main() {{\n    {body("build-script")}\n}}\n'
    )
    (root / 'lib' / 'src' / 'lib.rs').write_text('probe_macro::probe!();\n')


def run_probe(checkout: Path) -> int:
    if not shutil.which('cargo'):
        print('probe: cargo not found', file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix='release-probe-') as tmp:
        root, markers = Path(tmp) / 'ws', Path(tmp) / 'markers'
        markers.mkdir()
        write_probe_workspace(root, checkout.resolve(), markers)
        # Inherit the environment untouched: sanitizing it would defeat the probe.
        proc = subprocess.run(
            [
                'cargo',
                'build',
                '--offline',
                '--manifest-path',
                str(root / 'Cargo.toml'),
            ],
            env={**os.environ, 'CARGO_TARGET_DIR': str(Path(tmp) / 'target')},
            capture_output=True,
            text=True,
        )
        ran = sorted(p.name for p in markers.iterdir())
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            print(f"probe FAILED (executed: {ran})", file=sys.stderr)
            return 1
        if ran != ['build-script', 'proc-macro']:
            print(
                f"probe invalid: expected the build script and the proc macro to run, got {ran}",
                file=sys.stderr,
            )
            return 1
    print(
        'probe OK: dependency build code ran (build script + proc macro) and saw no release credential'
    )
    return 0


# ── tests ────────────────────────────────────────────────────────────────────
def _git(
    cwd: Path, *args: str, env: dict | None = None, check: bool = True
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['git', *args],
        cwd=cwd,
        env={**GIT_ENV, **(env or {})},
        capture_output=True,
        text=True,
        check=check,
    )


GIT_ENV = {
    **os.environ,
    'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_AUTHOR_NAME': 'test',
    'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'test',
    'GIT_COMMITTER_EMAIL': 'test@example.invalid',
}


def _network() -> bool:
    try:
        socket.create_connection(('index.crates.io', 443), timeout=3).close()
        return True
    except OSError:
        return False


class InspectTest(unittest.TestCase):
    """Credentials persisted OUTSIDE the checkout (user Git config, `cargo login` file) are found too."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix='inspect-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.checkout = self.tmp / 'checkout'
        self.checkout.mkdir()
        _git(self.checkout, 'init', '-q')
        self.env = {
            'HOME': str(self.tmp / 'home'),
            'CARGO_HOME': str(self.tmp / 'home' / '.cargo'),
        }
        (self.tmp / 'home').mkdir()

    def test_clean_home_has_no_findings(self) -> None:
        self.assertEqual(inspect(self.checkout, self.env), [])

    def test_global_git_config_credentials_are_found(self) -> None:
        cases = {
            'insteadOf with token': 'url.https://x-access-token:s3cret@github.com/.insteadof=https://github.com/',
            'extraheader': 'http.https://github.com/.extraheader=AUTHORIZATION: basic czNjcmV0',
        }
        for label, line in cases.items():
            with self.subTest(label):
                key, _, value = line.partition('=')
                (self.tmp / 'home' / '.gitconfig').unlink(missing_ok=True)
                _git(
                    self.tmp,
                    'config',
                    '--file',
                    str(self.tmp / 'home' / '.gitconfig'),
                    key,
                    value,
                )
                findings = inspect(self.checkout, self.env)
                self.assertEqual(len(findings), 1, findings)
                self.assertNotIn('s3cret', ' '.join(findings))

    def test_cargo_login_file_is_found(self) -> None:
        creds = self.tmp / 'home' / '.cargo'
        creds.mkdir()
        (creds / 'credentials.toml').write_text('[registry]\ntoken = "cio-s3cret"\n')
        findings = inspect(self.checkout, self.env)
        self.assertEqual(len(findings), 1, findings)
        self.assertNotIn('s3cret', ' '.join(findings))


@unittest.skipUnless(shutil.which('cargo'), 'cargo is required')
class ProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix='probe-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.checkout = self.tmp / 'checkout'
        self.checkout.mkdir()
        _git(self.checkout, 'init', '-q')
        _git(
            self.checkout,
            'remote',
            'add',
            'origin',
            'https://github.com/Cosmian/kms.git',
        )
        modules = self.checkout / '.git' / 'modules' / 'test_data'
        modules.mkdir(parents=True)
        (modules / 'config').write_text(
            '[remote "origin"]\n\turl = https://github.com/Cosmian/test_data.git\n'
        )

    def probe(self, **env: str) -> subprocess.CompletedProcess:
        clean = {
            k: v
            for k, v in os.environ.items()
            if not CREDENTIAL_ENV.match(k) and not k.startswith('GIT_CONFIG_')
        }
        clean['CARGO_HOME'] = str(self.tmp / 'cargo-home')
        clean['GIT_CONFIG_GLOBAL'] = os.devnull
        return subprocess.run(
            [sys.executable, str(HERE), '--probe', str(self.checkout)],
            env={**clean, **env},
            capture_output=True,
            text=True,
        )

    def assertExposed(
        self, proc: subprocess.CompletedProcess, needle: str, secret: str
    ) -> None:
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(needle, proc.stdout + proc.stderr)
        self.assertNotIn(
            secret,
            proc.stdout + proc.stderr,
            'the credential value must never be printed',
        )

    def test_clean_environment_passes_with_both_executors_running(self) -> None:
        proc = self.probe()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('build script + proc macro', proc.stdout)

    def test_dummy_credentials_fail_without_leaking_the_value(self) -> None:
        for name in (
            'PAT_TOKEN',
            'CARGO_REGISTRY_TOKEN',
            'PACKAGE_COSMIAN_SSH_PRIVATE_KEY',
        ):
            with self.subTest(name=name):
                self.assertExposed(
                    self.probe(**{name: 'dummy-secret-value-123'}),
                    name,
                    'dummy-secret-value-123',
                )

    def test_git_authorization_header_in_environment_fails(self) -> None:
        proc = self.probe(
            GIT_CONFIG_COUNT='1',
            GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
            GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ZHVtbXktc2VjcmV0',
        )
        self.assertExposed(proc, 'GIT_CONFIG_VALUE_0', 'ZHVtbXktc2VjcmV0')

    def test_persisted_checkout_credentials_fail(self) -> None:
        cases = {
            'extraheader': (
                'http.https://github.com/.extraheader',
                'AUTHORIZATION: basic c2VjcmV0',
            ),
            'credential helper': ('credential.helper', '!echo secret'),
            'tokenized remote': (
                'remote.origin.url',
                'https://x-access-token:s3cret@github.com/Cosmian/kms.git',
            ),
        }
        for label, (key, value) in cases.items():
            with self.subTest(label):
                _git(self.checkout, 'config', '--local', key, value)
                proc = self.probe()
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertNotIn(value, proc.stdout + proc.stderr)
                self.assertNotIn('s3cret', proc.stdout + proc.stderr)
                _git(self.checkout, 'config', '--local', '--unset-all', key)
                _git(
                    self.checkout,
                    'remote',
                    'set-url',
                    'origin',
                    'https://github.com/Cosmian/kms.git',
                )

    def test_submodule_credentials_fail(self) -> None:
        cfg = self.checkout / '.git' / 'modules' / 'test_data' / 'config'
        cfg.write_text(
            '[remote "origin"]\n\turl = https://x-access-token:s3cret@github.com/Cosmian/test_data.git\n'
        )
        proc = self.probe()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('test_data', proc.stdout + proc.stderr)
        self.assertNotIn('s3cret', proc.stdout + proc.stderr)


@unittest.skipUnless(
    shutil.which('cargo') and _network(), 'cargo and crates.io access are required'
)
class NoVerifyPublishTest(unittest.TestCase):
    """`cargo publish --no-verify` must package without executing the crate's build script."""

    def fixture(self) -> tuple[Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix='publish-test-'))
        self.addCleanup(shutil.rmtree, tmp, True)
        marker = tmp / 'build-script-ran'
        crate = tmp / 'crate'
        (crate / 'src').mkdir(parents=True)
        (crate / 'Cargo.toml').write_text(
            '[package]\nname = "release-isolation-fixture"\nversion = "0.0.1"\nedition = "2021"\n'
            'description = "fixture"\nlicense = "MIT"\n[workspace]\n'
        )
        (crate / 'build.rs').write_text(
            f'fn main() {{ std::fs::write({json.dumps(str(marker))}, "ran").unwrap(); }}\n'
        )
        (crate / 'src' / 'lib.rs').write_text('')
        return crate, marker

    def publish(self, crate: Path, *flags: str) -> None:
        env = {**os.environ, 'CARGO_TARGET_DIR': str(crate.parent / 'target')}
        proc = subprocess.run(
            ['cargo', 'publish', '--dry-run', '--allow-dirty', *flags],
            cwd=crate,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_no_verify_runs_no_build_script_but_verification_does(self) -> None:
        crate, marker = self.fixture()
        self.publish(crate, '--no-verify')
        self.assertFalse(
            marker.exists(),
            'publish --no-verify must not execute dependency/build code',
        )
        self.publish(crate)
        self.assertTrue(
            marker.exists(),
            'control: normal verification compiles and runs the build script',
        )


class PublisherTest(unittest.TestCase):
    """The Git-only publisher: data patch in, exact-path commit out, before any credential is used."""

    ALLOWED = 'gen/out.txt\ngen/new.txt\nREADME.md\n'
    TOKEN = 'dummy-pat-value-9f2c'

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix='publisher-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.remote = self.tmp / 'remote.git'
        _git(self.tmp, 'init', '-q', '--bare', '-b', 'main', str(self.remote))
        seed = self.tmp / 'seed'
        _git(self.tmp, 'clone', '-q', str(self.remote), str(seed))
        self.write(seed, 'README.md', 'readme\n')
        self.write(seed, 'gen/out.txt', 'one\ntwo\nthree\n')
        self.write(seed, '.github/workflows/w.yml', 'name: w\n')
        self.write(seed, '.gitmodules', '')
        _git(seed, 'add', '-A')
        _git(seed, 'commit', '-qm', 'seed')
        _git(seed, 'push', '-q', 'origin', 'HEAD:main')
        self.base = self.remote_sha('main')
        self.n = 0

    @staticmethod
    def write(root: Path, rel: str, text: str) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def remote_sha(self, ref: str) -> str:
        return _git(self.remote, 'rev-parse', f"refs/heads/{ref}").stdout.strip()

    def remote_file(self, ref: str, rel: str) -> str:
        return _git(self.remote, 'show', f"refs/heads/{ref}:{rel}").stdout

    def clone(self, label: str, sha: str) -> Path:
        self.n += 1
        work = self.tmp / f"{label}-{self.n}"
        _git(self.tmp, 'clone', '-q', str(self.remote), str(work))
        _git(work, 'checkout', '-q', sha)
        return work

    def generate(
        self, change, paths: str | None = None, base: str | None = None
    ) -> Path:
        """Run `change(workdir)` in a builder checkout and capture its patch artifact."""
        base = base or self.base
        work = self.clone('builder', base)
        change(work)
        out = self.tmp / f"artifact-{self.n}"
        env = {'PATHS': paths or self.ALLOWED, 'OUT_DIR': str(out), 'BASE_SHA': base}
        proc = subprocess.run(
            ['bash', str(RELEASE_SCRIPTS / 'make_generated_patch.sh')],
            cwd=work,
            env={**GIT_ENV, **env},
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return out

    def publish(
        self,
        artifact: Path,
        *,
        base: str | None = None,
        ref: str = 'main',
        paths: str | None = None,
    ):
        """commit_generated.sh then push_generated.sh. Returns (stage_failed|None, combined output, checkout)."""
        base = base or self.base
        work = self.clone('publisher', base)
        trusted = self.tmp / f"trusted-{self.n}"
        trusted.mkdir()
        (trusted / 'allowed.txt').write_text(paths or self.ALLOWED)
        shutil.copy(RELEASE_SCRIPTS / 'validate_generated_changes.py', trusted)
        out_file = self.tmp / f"gh-output-{self.n}"
        env = {
            'BASE_SHA': base,
            'ARTIFACT_DIR': str(artifact),
            'ALLOWED_FILE': str(trusted / 'allowed.txt'),
            'VALIDATOR': str(trusted / 'validate_generated_changes.py'),
            'MESSAGE': 'build: generated [skip ci]',
            'GITHUB_OUTPUT': str(out_file),
        }
        apply = subprocess.run(
            ['bash', str(RELEASE_SCRIPTS / 'commit_generated.sh')],
            cwd=work,
            env={**GIT_ENV, **env},
            capture_output=True,
            text=True,
        )
        output = apply.stdout + apply.stderr
        if apply.returncode != 0:
            return 'apply', output, work
        changed = 'changed=true' in (out_file.read_text() if out_file.exists() else '')
        push = subprocess.run(
            ['bash', str(RELEASE_SCRIPTS / 'push_generated.sh')],
            cwd=work,
            env={
                **GIT_ENV,
                'REF': ref,
                'BASE_SHA': base,
                'CHANGED': 'true' if changed else 'false',
                'PAT_TOKEN': self.TOKEN,
                'REMOTE_URL': str(self.remote),
            },
            capture_output=True,
            text=True,
        )
        output += push.stdout + push.stderr
        self.assertNotIn(self.TOKEN, output, 'the token must never be printed')
        self.assertNotIn(
            self.TOKEN,
            (work / '.git' / 'config').read_text(),
            'the token must not be persisted',
        )
        return (None if push.returncode == 0 else 'push'), output, work

    # ── accepted ─────────────────────────────────────────────────────────────
    def test_allowed_change_is_committed_exactly(self) -> None:
        art = self.generate(lambda w: self.write(w, 'gen/out.txt', 'one\nTWO\nthree\n'))
        stage, out, _ = self.publish(art)
        self.assertIsNone(stage, out)
        self.assertEqual(self.remote_file('main', 'gen/out.txt'), 'one\nTWO\nthree\n')
        changed = _git(
            self.remote, 'diff', '--name-only', self.base, 'refs/heads/main'
        ).stdout.split()
        self.assertEqual(changed, ['gen/out.txt'])

    def test_new_allowed_file_is_included(self) -> None:
        art = self.generate(lambda w: self.write(w, 'gen/new.txt', 'fresh\n'))
        stage, out, _ = self.publish(art)
        self.assertIsNone(stage, out)
        self.assertEqual(self.remote_file('main', 'gen/new.txt'), 'fresh\n')

    def test_empty_patch_is_a_no_op(self) -> None:
        art = self.generate(lambda w: None)
        self.assertEqual((art / 'changes.patch').read_text(), '')
        stage, out, _ = self.publish(art)
        self.assertIsNone(stage, out)
        self.assertEqual(self.remote_sha('main'), self.base)

    def test_missing_branch_is_created_from_base(self) -> None:
        art = self.generate(lambda w: self.write(w, 'README.md', 'bumped\n'))
        stage, out, _ = self.publish(art, ref='release/1.2.3')
        self.assertIsNone(stage, out)
        self.assertEqual(self.remote_file('release/1.2.3', 'README.md'), 'bumped\n')
        self.assertEqual(self.remote_sha('main'), self.base)

    def test_empty_patch_still_creates_a_missing_branch(self) -> None:
        stage, out, _ = self.publish(self.generate(lambda w: None), ref='release/1.2.3')
        self.assertIsNone(stage, out)
        self.assertEqual(self.remote_sha('release/1.2.3'), self.base)

    def test_unrelated_remote_progress_is_rebased_over(self) -> None:
        art = self.generate(lambda w: self.write(w, 'gen/out.txt', 'one\ntwo\nTHREE\n'))
        other = self.clone('other', self.base)
        self.write(other, 'other.txt', 'x\n')
        _git(other, 'add', '-A')
        _git(other, 'commit', '-qm', 'other')
        _git(other, 'push', '-q', 'origin', 'HEAD:main')
        stage, out, _ = self.publish(art)
        self.assertIsNone(stage, out)
        self.assertEqual(self.remote_file('main', 'other.txt'), 'x\n')
        self.assertEqual(self.remote_file('main', 'gen/out.txt'), 'one\ntwo\nTHREE\n')

    # ── rejected before any credential is used ───────────────────────────────
    def assertRejected(self, art: Path, **kw) -> None:
        stage, out, _ = self.publish(art, **kw)
        self.assertEqual(stage, 'apply', out)
        self.assertEqual(
            self.remote_sha('main'),
            self.base,
            'a rejected patch must not reach the remote',
        )
        self.assertNotIn('Pushed', out)

    def test_unlisted_files_are_rejected(self) -> None:
        for rel in ('.github/workflows/w.yml', '.gitmodules', 'scripts/new.sh'):
            with self.subTest(rel=rel):
                self.assertRejected(
                    self.generate(
                        lambda w: self.write(w, rel, 'evil\n'),
                        paths=self.ALLOWED + rel + '\n',
                    )
                )

    def test_listed_by_the_producer_but_not_by_the_caller_is_rejected(self) -> None:
        art = self.generate(
            lambda w: self.write(w, '.github/workflows/w.yml', 'evil\n'),
            paths='.github/workflows/w.yml\n',
        )
        self.assertRejected(art)

    def test_symlink_is_rejected(self) -> None:
        art = self.generate(lambda w: (w / 'gen/new.txt').symlink_to('/etc/passwd'))
        self.assertRejected(art)

    def test_symlink_replacing_a_regular_file_is_rejected(self) -> None:
        def change(w: Path) -> None:
            (w / 'README.md').unlink()
            (w / 'README.md').symlink_to('/etc/passwd')

        self.assertRejected(self.generate(change))

    def test_deletion_is_rejected(self) -> None:
        self.assertRejected(self.generate(lambda w: (w / 'gen/out.txt').unlink()))

    def test_rename_is_rejected(self) -> None:
        self.assertRejected(
            self.generate(lambda w: (w / 'gen/out.txt').rename(w / 'gen/new.txt'))
        )

    def test_mode_change_is_rejected(self) -> None:
        self.assertRejected(self.generate(lambda w: (w / 'README.md').chmod(0o755)))

    def test_missing_artifact_is_rejected(self) -> None:
        self.assertRejected(self.tmp / 'no-such-artifact')

    def test_artifact_without_base_sha_is_rejected(self) -> None:
        art = self.generate(lambda w: self.write(w, 'README.md', 'x\n'))
        (art / 'base-sha.txt').unlink()
        self.assertRejected(art)

    def test_artifact_from_another_commit_is_rejected(self) -> None:
        art = self.generate(lambda w: self.write(w, 'README.md', 'x\n'))
        (art / 'base-sha.txt').write_text('0' * 40 + '\n')
        self.assertRejected(art)

    def test_wrong_requested_base_sha_is_rejected(self) -> None:
        art = self.generate(lambda w: self.write(w, 'README.md', 'x\n'))
        other = self.clone('other', self.base)
        self.write(other, 'other.txt', 'x\n')
        _git(other, 'add', '-A')
        _git(other, 'commit', '-qm', 'other')
        _git(other, 'push', '-q', 'origin', 'HEAD:refs/heads/side')
        self.assertRejected(art, base=_git(other, 'rev-parse', 'HEAD').stdout.strip())

    # ── the base commit must belong to the repository history ────────────────
    def lineage(self, sha: str, ref: str = 'main') -> subprocess.CompletedProcess:
        work = self.clone('lineage', self.base)
        return subprocess.run(
            ['bash', str(RELEASE_SCRIPTS / 'check_base_lineage.sh')],
            cwd=work,
            env={**GIT_ENV, 'REF': ref, 'BASE_SHA': sha, 'DEFAULT_BRANCH': 'main'},
            capture_output=True,
            text=True,
        )

    def push_side_commit(self) -> str:
        other = self.clone('other', self.base)
        self.write(other, 'evil.txt', 'x\n')
        _git(other, 'add', '-A')
        _git(other, 'commit', '-qm', 'side')
        _git(other, 'push', '-q', 'origin', 'HEAD:refs/heads/side')
        return _git(other, 'rev-parse', 'HEAD').stdout.strip()

    def test_base_on_the_default_branch_is_accepted_for_a_new_branch(self) -> None:
        proc = self.lineage(self.base, ref='release/9.9.9')
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_unrelated_commit_is_rejected_as_base(self) -> None:
        proc = self.lineage(self.push_side_commit())
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertIn('not reachable', proc.stderr)

    def test_unknown_commit_is_rejected_as_base(self) -> None:
        self.assertNotEqual(self.lineage('1' * 40).returncode, 0)

    # ── only the generated commit lands on an existing branch ────────────────
    def test_existing_branch_receives_only_the_generated_commit(self) -> None:
        other = self.clone('other', self.base)
        _git(other, 'push', '-q', 'origin', 'HEAD:refs/heads/rel')
        self.write(other, 'other.txt', 'x\n')
        _git(other, 'add', '-A')
        _git(other, 'commit', '-qm', 'develop moved on')
        _git(other, 'push', '-q', 'origin', 'HEAD:main')
        new_base = self.remote_sha('main')
        art = self.generate(
            lambda w: self.write(w, 'gen/out.txt', 'one\ntwo\nNEW\n'), base=new_base
        )
        stage, out, _ = self.publish(art, base=new_base, ref='rel')
        self.assertIsNone(stage, out)
        self.assertEqual(
            _git(
                self.remote, 'rev-list', '--count', f"{self.base}..rel"
            ).stdout.strip(),
            '1',
        )
        self.assertNotIn(
            'other.txt',
            _git(self.remote, 'ls-tree', '--name-only', 'refs/heads/rel').stdout,
        )
        self.assertEqual(self.remote_file('rel', 'gen/out.txt'), 'one\ntwo\nNEW\n')

    # ── never rewrites remote history ────────────────────────────────────────
    def test_conflicting_remote_edit_fails_without_force_push(self) -> None:
        art = self.generate(
            lambda w: self.write(w, 'gen/out.txt', 'one\nGENERATED\nthree\n')
        )
        other = self.clone('other', self.base)
        self.write(other, 'gen/out.txt', 'one\nCONCURRENT\nthree\n')
        _git(other, 'commit', '-qam', 'concurrent')
        _git(other, 'push', '-q', 'origin', 'HEAD:main')
        tip = self.remote_sha('main')
        stage, out, _ = self.publish(art)
        self.assertEqual(stage, 'push', out)
        self.assertEqual(self.remote_sha('main'), tip)
        self.assertEqual(
            self.remote_file('main', 'gen/out.txt'), 'one\nCONCURRENT\nthree\n'
        )


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--probe':
        sys.exit(run_probe(Path(sys.argv[2])))
    if len(sys.argv) == 3 and sys.argv[1] == '--inspect':
        sys.exit(run_inspect(Path(sys.argv[2])))
    unittest.main()

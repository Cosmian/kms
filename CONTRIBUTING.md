# Contributing to Cosmian KMS

- [Contributing to Cosmian KMS](#contributing-to-cosmian-kms)
    - [Issues](#issues)
        - [Reporting an Issue](#reporting-an-issue)
        - [Issue Lifecycle](#issue-lifecycle)
    - [Pull Requests](#pull-requests)
        - [Changelog Entries](#changelog-entries)
    - [Contributing to the UI](#contributing-to-the-ui)
    - [Setting up Rust to work on Cosmian KMS](#setting-up-rust-to-work-on-cosmian-kms)
    - [Supply-chain / dependency policy](#supply-chain--dependency-policy)
    - [Testing](#testing)
    - [Contributor License Agreement](#contributor-license-agreement)
    - [Code of Conduct](#code-of-conduct)
    - [Getting Help](#getting-help)

---

Please note: We take Cosmian KMS's security and our users' trust very seriously. If you believe you have found a
security issue in Cosmian KMS, please read our [security policy](SECURITY.md) and responsibly disclose by contacting
us at [tech@cosmian.com](mailto:tech@cosmian.com).

First: if you're unsure or afraid of anything, just ask or submit the issue or pull request anyways. You won't be
yelled at for giving it your best effort. The worst that can happen is that you'll be politely asked to change
something. We appreciate any sort of contributions, and don't want a wall of rules to get in the way of that.

That said, if you want to ensure that a pull request is likely to be merged, talk to us! You can find out our thoughts
and ensure that your contribution won't clash or be obviated by Cosmian KMS's normal direction. A great way to do this
is via [GitHub Issues](https://github.com/Cosmian/kms/issues) or [GitHub Discussions](https://github.com/Cosmian/kms/discussions).

## Issues

This section will cover what we're looking for in terms of reporting issues.

By addressing all the points we're looking for, it raises the chances we can quickly merge or address your contributions.

### Reporting an Issue

• Make sure you test against the latest released version. It is possible we already fixed the bug you're experiencing.
Even better is if you can test against the `develop` branch, as bugs are regularly fixed but new versions are only
released periodically.

• Provide steps to reproduce the issue, and if possible include the expected results as well as the actual results.
Please provide text, not screen shots!

• If you are seeing an internal Cosmian KMS error (a status code of 5xx), please be sure to post relevant parts of
(or the entire) Cosmian KMS log, as often these errors are logged on the server but not reported to the user.

• If you experienced a panic, please create a [gist](https://gist.github.com/) of the entire generated crash log for
us to look at. Double check no sensitive items were in the log.

• Respond as promptly as possible to any questions made by the Cosmian KMS team to your issue.

### Issue Lifecycle

1. The issue is reported.

2. The issue is verified and categorized by a Cosmian KMS collaborator. Categorization is done via tags. For example,
   bugs are marked as "bugs".

3. Unless it is critical, the issue may be left for a period of time (sometimes many weeks), giving outside
   contributors -- maybe you!? -- a chance to address the issue.

4. The issue is addressed in a pull request or commit. The issue will be referenced in the commit message so that the
   code that fixes it is clearly linked.

5. The issue is closed.

6. Issues that are not reproducible and/or not gotten responses for a long time are stale issues. In order to provide
   faster responses and better engagement with the community, we strive to keep the issue tracker clean and the issue
   count low. In this regard, our current policy is to close stale issues after 30 days.

Closed issues will still be indexed and available for future viewers. If users feel that the issue is still relevant,
we encourage reopening them.

## Pull Requests

When submitting a PR you should reference an existing issue. If no issue already exists, please create one. This can be
skipped for trivial PRs like fixing typos.

Creating an issue in advance of working on the PR can help to avoid duplication of effort, e.g. maybe we know of
existing related work. Or it may be that we can provide guidance that will help with your approach.

Your pull request should have a description of what it accomplishes, how it does so, and why you chose the approach you
did. PRs should include unit tests that validate correctness and the existing tests must pass. Follow-up work to fix
tests does not need a fresh issue filed.

Someone will do a first pass review on your PR making sure it follows the guidelines in this document. If it doesn't
we'll mark the PR incomplete and ask you to follow up on the missing requirements.

### Changelog Entries

Create a file `CHANGELOG/<your-branch-name-with-slashes-replaced-by-underscores>.md` and add a one-line summary of
your change. For example, for branch `fix/my-bug` create `CHANGELOG/fix_my-bug.md`.

Use one of these section headers: `Features`, `Bug Fixes`, `Build`, `Refactor`, `Documentation`, `Testing`, `CI`,
`Security`. Group related entries under a sub-feature or component if applicable. See existing files in
[CHANGELOG/](CHANGELOG/) for examples.

## Contributing to the UI

The UI is a React 19 + TypeScript + Vite app located in `ui/`. It mirrors the `ckms` CLI — every CLI feature should
have a corresponding UI action.

For new features, open an issue first describing the use case and approach - A Cosmian KMS collaborator will review it and might assist you in coding the feature if it's accepted. Bug fixes can go straight to a PR.

All three test layers must pass before merging (E2E Playwright, Vitest integration, Vitest unit). See
[§8.1 UI-specific rules](AGENTS.md#81-ui-specific-rules) in AGENTS.md for how to run them.

## Setting up Rust to work on Cosmian KMS

If you have never worked with Rust before, you will have to complete the following steps:

1. Install Rust using [rustup](https://rustup.rs/)
2. Install the required stable toolchain: `rustup toolchain install 1.97.0`
3. Install required components: `rustup component add rustfmt clippy --toolchain 1.97.0`
4. Build the project: `cargo build --release`

For build commands and local setup, see [Quick start](README.md#-quick-start) in the README. For Nix-based
reproducible builds and CI, see [§2 Build & test cheatsheet](AGENTS.md#build--test-cheatsheet) and
[§8.6 Nix packaging](AGENTS.md#86-nix-packaging) in AGENTS.md.

If you are using an AI coding assistant that does not natively support `AGENTS.md` (e.g. Claude Code, at the time of
writing), create a symbolic link so it picks up the agent instructions automatically:

```sh
ln -s AGENTS.md CLAUDE.md
```

## Coding Standards

These rules are non-negotiable and apply to every contribution:

| Rule                        | Detail                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| **No `.unwrap()`**          | Use `?` propagation in production code; never ignore errors in tests                       |
| **No inline feature flags** | `#[cfg(feature = "non-fips")]` at function/module level only, never inside a function body |
| **Unsafe code**             | Every `unsafe` block requires a `// SAFETY:` comment explaining the invariant              |
| **Clippy**                  | Zero warnings — fix them; `#[allow]` requires an inline comment explaining why             |
| **Tests**                   | Unit tests go in a `#[cfg(test)]` submodule in the same file                               |
| **Docs**                    | All public items require `///` doc comments                                                |
| **Pre-commit hooks**        | Must pass — never use `--no-verify`                                                        |
| **Commit scope**            | Minimal, focused changes — don't refactor unrelated code alongside a bug fix               |

For detailed Rust design patterns and idiomatic conventions specific to this codebase, see
[`.github/skills/rust-patterns/SKILL.md`](.github/skills/rust-patterns/SKILL.md).
For FIPS gating rules, multi-standard algorithm compliance, and key lifecycle, see
[`.github/skills/cryptography-review/SKILL.md`](.github/skills/cryptography-review/SKILL.md).
For React/TypeScript/WASM conventions, see
[`.github/skills/react-ant-patterns/SKILL.md`](.github/skills/react-ant-patterns/SKILL.md).

---

## Supply-chain / dependency policy

- **Rust dependencies** — after adding or bumping a crate, run `cargo vet check`. If it fails, either add an
  exemption (`cargo vet add-exemption <crate> <version>`) with a reason, or record a real audit
  (`cargo vet certify`). The `cargo-vet` CI job blocks the merge otherwise. Existing exemptions for build-time code
  (`-sys`, proc-macro, `build.rs` crates) are tagged `priority: build-time code` in `supply-chain/config.toml` and are
  the audit backlog.
  Dependabot opens **security** PRs only for Cargo (version-update PRs are disabled in `.github/dependabot.yml`):
  it cannot edit `supply-chain/`, so a maintainer must run `cargo vet check` (without `--locked`: it fetches imported
  Mozilla/Google/… audits into `supply-chain/imports.lock`, which may already cover the bumped version), then add an
  exemption for what is still reported (`cargo vet suggest` lists it) on the PR branch before merging. Routine bumps
  are done by hand (`cargo update -p <crate> --precise <version>`).
- **Python test dependencies** — edit the human-authored `.in` file next to the requirements (for example
  `.mise/scripts/test/requirements-jose.in`), then regenerate the hash-pinned lockfile with
  `pip-compile --generate-hashes --output-file=<name>.txt <name>.in` and commit both. Never hand-edit the `.txt`;
  install sites use `pip install --require-hashes`. The `jose` and `cef` lockfiles are compiled with Python 3.9 because
  `.mise/scripts/common.sh` puts the macOS Command Line Tools `python3` first in `PATH`; the other lockfiles are
  compiled with Python 3.12 (the CI `ubuntu-24.04` interpreter) and need Python ≥ 3.10. Check each result with
  `pip-audit -r <name>.txt`; the `python-dependency-audit` CI job runs it on every lockfile.
- **Go test dependencies** — `.mise/scripts/kmip-go/go.mod` pins the Go `toolchain`; the `govulncheck` CI job
  (`govulncheck -test ./...`) must report no vulnerabilities.
- **GitHub Actions** — every `uses:` reference must be a full 40-character commit SHA followed by a `# <tag>`
  comment (local `./.github/actions/...` paths excepted). Dependabot (`github-actions` ecosystem) bumps these
  automatically.
- **Docker base images** in `.mise/scripts/docker/**` must be pinned by digest (`FROM image:tag@sha256:...`).
- **Bootstrap installers** — never pipe a remote script into a shell. Download it, verify its SHA-256, then run it
  (see `.github/actions/install-mise/action.yml`), or use a version pinned by a git submodule.

Pre-commit hooks enforce the policy locally (`.pre-commit-config.yaml`): `cargo-vet`, `github-actions-sha-pin`,
`docker-base-image-digest-pin` and `no-curl-pipe-shell` run on commit; `pip-audit-lockfiles` and `govulncheck`
(which need `pip-audit` and `govulncheck` installed, and network access) run on `pre-push`.

Reference: [`supply-chain/config.toml`](supply-chain/config.toml), [`.github/dependabot.yml`](.github/dependabot.yml),
[`.github/workflows/main_base.yml`](.github/workflows/main_base.yml), and the pre-existing
[`.cargo/audit.toml`](.cargo/audit.toml) / [`deny.toml`](deny.toml).

---

## Testing

Before submitting a pull request, please ensure that:

• All existing tests pass: `cargo test --workspace --lib`
• Your code is properly formatted: `cargo fmt --check`
• Your code passes clippy lints: `cargo clippy --workspace --all-targets --all-features`
• If you've added new functionality, include appropriate unit and/or integration tests

For database-specific testing, you may need to set up local database instances. See
[§2 Database test environment](AGENTS.md#database-test-environment) in AGENTS.md for details.

If you have access to LLM coding tools, we recommend to use the [kms-adversarial-test](.github/skills/kms-adversarial-test) skill before considering work as finished, as it operates as last human-like sanity check.

## Contributor License Agreement

We require that all contributors sign our Contributor License Agreement ("CLA") before we can accept the contribution.

[Learn more about the CLA and sign it here](CLA.md)

## Code of Conduct

This project adheres to the principles of respectful and inclusive collaboration. We expect all contributors to:

• Be respectful and constructive in discussions
• Focus on the technical aspects of contributions
• Help maintain a welcoming environment for all contributors
• Report any behavior that violates these principles to [tech@cosmian.com](mailto:tech@cosmian.com)

## Getting Help

If you need help with your contribution:

• Check the [documentation](documentation/) for technical guides
• Search existing [issues](https://github.com/Cosmian/kms/issues) for similar problems
• Open a new issue with the "question" label
• Contact us at [tech@cosmian.com](mailto:tech@cosmian.com) for general inquiries

Thank you for contributing to Cosmian KMS!

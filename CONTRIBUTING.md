# Contributing to Cosmian KMS

- [Contributing to Cosmian KMS](#contributing-to-cosmian-kms)
  - [Issues](#issues)
    - [Reporting an Issue](#reporting-an-issue)
    - [Issue Lifecycle](#issue-lifecycle)
  - [Pull Requests](#pull-requests)
    - [Changelog Entries](#changelog-entries)
  - [Contributing to the UI](#contributing-to-the-ui)
  - [Setting up Rust to work on Cosmian KMS](#setting-up-rust-to-work-on-cosmian-kms)
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
[§8 Web UI & Playwright E2E tests](AGENTS.md#8-web-ui--playwright-e2e-tests) in AGENTS.md for how to run them.

## Setting up Rust to work on Cosmian KMS

If you have never worked with Rust before, you will have to complete the following steps:

1. Install Rust using [rustup](https://rustup.rs/)
2. Install the required stable toolchain: `rustup toolchain install 1.90.0`
3. Install required components: `rustup component add rustfmt clippy --toolchain 1.90.0`
4. Build the project: `cargo build --release`

For build commands and local setup, see [Quick start](README.md#-quick-start) in the README. For Nix-based
reproducible builds and CI, see [§1 Build & test cheatsheet](AGENTS.md#1-build--test-cheatsheet) and
[§13 Nix packaging](AGENTS.md#13-nix-packaging) in AGENTS.md.

If you are using an AI coding assistant that does not natively support `AGENTS.md` (e.g. Claude Code, at the time of
writing), create a symbolic link so it picks up the agent instructions automatically:

```sh
ln -s AGENTS.md CLAUDE.md
```

## Testing

Before submitting a pull request, please ensure that:

• All existing tests pass: `cargo test --workspace --lib`
• Your code is properly formatted: `cargo fmt --check`
• Your code passes clippy lints: `cargo clippy --workspace --all-targets --all-features`
• If you've added new functionality, include appropriate unit and/or integration tests

For database-specific testing, you may need to set up local database instances. See
[§1 Database test environment](AGENTS.md#database-test-environment) in AGENTS.md for details.

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

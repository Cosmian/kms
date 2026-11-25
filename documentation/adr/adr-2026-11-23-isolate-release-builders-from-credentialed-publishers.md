---
title: "ADR-2026-11-23: Isolate release builders from credentialed publishers"
status: "Accepted"
date: "2026-11-23"
authors: "Release maintainers, package-server administrators, supply-chain reviewers"
tags: ["architecture", "decision", "ci", "supply-chain", "security"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-11-23: Isolate release builders from credentialed publishers

## Status

Accepted

## Context

Issue #1498 (findings F-012, F-016, F-048). Release jobs ran dependency code (build scripts, proc macros, generators) in the same job, on the same runner and with the same checkout as long-lived credentials:

- `release.yml`, `nix-update-hashes.yml` and `update-generated-docs.yml` checked out with `PAT_TOKEN` (persisted in `.git/config`), then compiled or generated.
- `cargo-publish.yml` compiled the workspace (`cargo publish` verifies by building) in the step that held `CARGO_REGISTRY_TOKEN`.
- Eight publish jobs mounted the host's `/home/cosmian/.ssh/id_rsa` (a full shell-capable key) into mutable `cosmian/docker_doc_ci` containers on self-hosted runners.
- `Cargo.lock` carried versions flagged by RUSTSEC-2026-0523/0524 (`quinn-proto`), 0538 (`quinn-udp`) and 0486 (`rustix`) with no evidence of which were reachable.

## Decision

1. **Builders hold no credential.** Jobs that compile, run generators or install dependencies check out with `persist-credentials: false`, read-only `GITHUB_TOKEN`, and receive no PAT, registry token or upload key. Each runs `test_release_security.py --probe`, which builds a throw-away build script and proc macro that fail when a release credential or credential-bearing Git config is visible.
2. **Builders emit data, publishers apply it.** A builder uploads `changes.patch` + `base-sha.txt`. `commit-generated.yml` (Git only, no toolchain) takes its helper scripts from its own commit (never from `base-sha`), requires `base-sha` to be reachable from the target or default branch, checks out that commit, applies the patch, accepts only added/modified regular files at the caller's exact paths (`validate_generated_changes.py`), commits with hooks and signing off, transplants the single generated commit (`rebase --onto base-sha`) onto the branch tip and pushes without force. `PAT_TOKEN` appears in the last step only, as `GIT_CONFIG_*` environment of the network commands. `sync-branches` stays Git-only with the same command-scoped authentication.
3. **Crates are published without executing dependency code.** `cargo-publish.yml` has `verify` (full `--dry-run` compile, no credential) and `publish` (fresh runner, tags only, environment `crates-io` with required reviewers and the only copy of `CRATES_IO`, `--no-verify`). Cargo repackages the same commit; the verifier's tarballs are not reused.
4. **Package uploads use a dedicated write-only key.** The eight publish jobs run on hosted `ubuntu-24.04`, environment `package-publish`, with `secrets.PACKAGE_COSMIAN_SSH_PRIVATE_KEY`. The server pins that key to `restrict,command="rrsync -wo -munge -no-del -no-lock /mnt/package/kms"`: no shell, read, delete, forwarding or path outside the root. `push_package.sh` replaces scp/ssh/tar with rsync, validates every path component, refuses symlinks and unmatched globs, and keeps strict pinned host-key checking.
5. **Advisories are checked against the shipped graph.** The three vulnerable packages are updated in the lock file (targeted `cargo update --precise`; no new ignore). `check_advisory_coverage.py` fails on a vulnerable lock entry anywhere, on the QUIC stack or reqwest HTTP/3 in either production graph, on a vulnerable `rustix` in the runtime graph, and on any inconsistency between `deny.toml`, `.cargo/audit.toml` and `sbom/openvex.json`. Lock-only versus runtime is a label, never a waiver.

## Consequences

### Positive

- **POS-001**: A compromised dependency or generator cannot read the PAT, the registry token or the upload key; the job boundary, not a cleanup step, enforces it.
- **POS-002**: The upload key can only write inside `/mnt/package/kms`; it cannot delete or read, and is rotatable in GitHub without touching a runner host.
- **POS-003**: Generated-file commits are restricted to explicit paths and plain files; workflows, scripts and `.gitmodules` cannot be changed through the patch channel.
- **POS-004**: Regression tests cover the probe, `--no-verify` behavior, the patch validator and a real sshd + rrsync upload.

### Negative

- **NEG-001**: More jobs and a data hand-off; a builder compromise can still alter the contents of allowed generated files. Isolation does not prove package contents benign.
- **NEG-002**: Administrators must create the `crates-io` and `package-publish` environments, the `kms-ci-upload` account/key, and expose `PAT_TOKEN`/`CRATES_IO`; the YAML cannot create them.
- **NEG-003**: Hosted runners must reach `package.cosmian.com`; otherwise an administrator-provisioned ephemeral uploader with the same isolation is needed.
- **NEG-004**: A retry no longer deletes and recreates `release/<version>`: an existing branch is rebased onto (identical bump dropped) or the run fails on conflict.
- **NEG-005**: `rustix` is a genuine runtime dependency (`tempfile` through `native-tls` and `dialoguer`), contrary to the issue's assumption; the fix is the patched version, enforced by the checker, not removal.

## Alternatives Considered

### Sanitize the environment inside the job

- **ALT-001 Description**: Unset secrets before compiling and re-inject them afterwards.
- **ALT-002 Rejection Reason**: Persisted checkout credentials, background processes and cached state survive inside one job; a boundary at job level is verifiable.

### Keep the host key and restrict it in a mutable container

- **ALT-003 Description**: Pin the container image and keep mounting the host SSH key.
- **ALT-004 Rejection Reason**: The key stays shell-capable and host-resident; any job that mounts it can run commands on the package server.

### GitHub App / OIDC instead of long-lived secrets

- **ALT-005 Description**: Short-lived tokens for Git and crates.io trusted publishing.
- **ALT-006 Rejection Reason**: Out of scope for this issue; the chosen design keeps existing secrets and SSH authentication (maintainer decision).

### Upload `.crate` files verified earlier

- **ALT-007 Description**: Hand verified tarballs from the builder to the publisher.
- **ALT-008 Rejection Reason**: `cargo publish --no-verify` repackages source, so the artifact would not be what is uploaded; the same immutable commit is used instead.

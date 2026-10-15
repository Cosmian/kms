# Supply-chain hardening (Rust, Python, Go, Docker, GitHub Actions)

## Security

- Adopt `cargo-vet` (`supply-chain/`), importing the Mozilla, Google and Bytecode Alliance audits; existing third-party
  crates are recorded as exemptions, with build-time code (`-sys`, proc-macro, `build.rs`) tagged
  `priority: build-time code` as the manual-audit backlog. New `cargo-vet` CI job in `main_base.yml`.
- Hash-pin all Python test/docs requirements (`.in` source + `pip-compile --generate-hashes` `.txt` lockfile, installed
  with `--require-hashes`) and add a `pip-audit` CI job. Bump `cryptography` in the JOSE test requirements to `50.x`
  (CVE-2026-69247).
- Add a `govulncheck` CI job for `.mise/scripts/kmip-go` and pin its Go `toolchain` to a release containing the
  standard-library fixes.
- Pin the `ubuntu:22.04` base image of the SAP ASE test image by digest.
- Pin every GitHub Actions `uses:` reference (including `dtolnay/rust-toolchain@master`, `jlumbroso/free-disk-space@main`
  and the `Cosmian/reusable_*` workflows) to a full commit SHA.
- Pin the mdBook installer: it now runs from the pinned `documentation/theme` submodule instead of `curl`-ing doc-theme `main`.
  Still open in that script (doc-theme repo): `curl | sh` rustup fallback when `cargo` is missing, and `--locked` only on `mdbook`.
  The mise and pyenv installers are SHA-256 verified before execution.
- Extend Dependabot to `cargo`, `pip`, `gomod` and `docker`.
- Add pre-commit hooks for the policy (`cargo-vet`, `github-actions-sha-pin`, `docker-base-image-digest-pin`,
  `no-curl-pipe-shell`; `pip-audit-lockfiles` and `govulncheck` on pre-push) and exclude generated lockfiles from
  `requirements-txt-fixer` and `typos`.
- Document the policy in `CONTRIBUTING.md`.

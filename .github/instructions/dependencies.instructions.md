---
name: 'Third-Party Dependencies'
description: 'Vet every new or bumped third-party dependency (Cargo, pnpm, Python, Go, Docker images, GitHub Actions, installers) against the supply-chain policy of issue #1265'
applyTo: '**/Cargo.toml, Cargo.lock, supply-chain/**, deny.toml, .cargo/audit.toml, ui/package.json, ui/pnpm-lock.yaml, crate/clients/wasm/package.json, **/requirements*.in, **/requirements*.txt, **/go.mod, **/go.sum, **/Dockerfile*, .github/dependabot.yml, .github/workflows/**, .github/actions/**'
---

# Third-party dependencies (supply chain)

Dependency code runs before anyone reviews it: `build.rs` and proc-macros on `cargo build`/`check`/`test` and when rust-analyzer opens
the project, npm lifecycle scripts on `pnpm install`, Vite/PostCSS/Tailwind plugins on `pnpm build`, `setup.py` of Python sdists. One
malicious package at any depth can exfiltrate every credential of the developer or CI machine (issue #1265). Treat every added or bumped
crate, package, module, base image, action and installer as untrusted code.

`CONTRIBUTING.md` ("Supply-chain / dependency policy") is the human-facing policy; this file is the agent checklist.

## 1. All ecosystems

- [ ] Reuse first: the standard library, an existing `[workspace.dependencies]` entry of the root `Cargo.toml`, a package already in `ui/package.json`, or a helper of `.mise/lib/common.sh`. Add a dependency only when none of them does the job.
- [ ] Depend on a released version from the official registry (crates.io, npm, PyPI, the Go module proxy, the image's registry, a GitHub release asset). Never a git branch or URL dependency, a fork, `latest` or `*`.
- [ ] Bump only what the task needs (`cargo update -p <crate> --precise <version>`, `pnpm update <pkg>`). A whole-tree update (`cargo update`, `pnpm update`, `go get -u ./...`) is its own reviewed PR.
- [ ] Never pipe a download into an interpreter (`curl … | sh`, `wget … | bash`).
- [ ] Never hand-edit generated files: Python `.txt` lockfiles (`pip-compile`), `supply-chain/imports.lock` (`cargo vet`), `sbom/` (`mise run sbom:generate`, run by the packaging and release workflows).
- [ ] Submodules (`authentication`, `documentation/theme`, `kmip`, `test_data`, `.github/reusable_scripts`) are separate repositories: change their dependencies there. Bumping a submodule pointer here is a dependency bump: review the upstream commits (`git diff --submodule=log`).
- [ ] List every new or bumped direct dependency in the PR description (or the final summary when there is no PR): ecosystem, name, version, why it is needed, whether it ships build-time code, and each exemption, allowlist or override entry added for it.

## 2. Rust (Cargo)

Gates: `cargo deny check` (CI job `cargo-deny` in `.github/workflows/main_base.yml`, pre-commit hook `cargo-deny`), `cargo machete` (CI job `cargo-machete`, pre-commit hook `cargo-machete`), `cargo vet check --locked` (CI job `cargo-vet`, pre-commit hook `cargo-vet`).

- [ ] Declare the crate once in `[workspace.dependencies]` of the root `Cargo.toml` with an explicit version (`default-features = false` when it has default features); member crates use `<crate> = { workspace = true }`, adding `features = [...]` as needed (`toml.instructions.md`).
- [ ] crates.io only: no `git =`, no `path =` outside the workspace, no `[patch.crates-io]` (`deny.toml` `[sources]` has `allow-git = []`).
- [ ] FIPS-mode cryptography goes through OpenSSL (`rust-crypto.instructions.md`). A crate implementing a cryptographic primitive needs `/cryptography-review` first and, unless that review approves it for FIPS builds, is `optional = true` and enabled only through `dep:<crate>` in the member crate's `non-fips` feature (pattern: `crate/crypto/Cargo.toml`).
- [ ] The crate's license is in the `allow` list of `deny.toml` `[licenses]`. Never extend that list, add a `[[licenses.clarify]]`, or add an advisory ignore without explicit user approval; an approved ignore is `{ id = "RUSTSEC-…", reason = "…" }` in `deny.toml` plus the same ID in `.cargo/audit.toml`.
- [ ] `cargo deny check` passes. Run it yourself: its pre-commit hook only fires when `.rs` files change.
- [ ] `cargo machete` reports no unused dependency; a false positive goes into `[package.metadata.cargo-machete] ignored = [...]` of that crate's `Cargo.toml`.
- [ ] `cargo vet check --locked` prints `Vetting Succeeded`. For each `<crate>:<version> missing ["<criteria>"]` line it prints instead:
    1. Run `cargo vet check` once without `--locked`: it fetches newer Mozilla, Google and Bytecode Alliance audits into `supply-chain/imports.lock` and prunes exemptions they make unused. Keep the resulting `supply-chain/` changes either way; never revert them with `git checkout`.
    2. For each line still printed, classify the crate. It is build-time code when its name ends in `-sys`, or when `cargo metadata --format-version 1 --locked | jq -r '.packages[] | select(.name=="<crate>" and .version=="<version>") | [.targets[].kind[]] | unique | join(",")'` contains `proc-macro` or `custom-build`.
    3. Record an exemption with the printed criteria:
        - build-time code: `cargo vet add-exemption <crate> <version> --criteria <criteria> --notes "priority: build-time code (sys/proc-macro/build.rs) — needs manual audit, tracked as backlog per issue #1265"`
        - otherwise: `cargo vet add-exemption <crate> <version> --criteria <criteria> --notes "<why the workspace needs it> — unaudited, pending review"`
    4. Re-run `cargo vet check --locked` until it prints `Vetting Succeeded`.
- [ ] Change `supply-chain/` only through the `cargo vet` commands above. Never run `cargo vet certify` (it records a human audit under the git user's name), `cargo vet trust` or `cargo vet regenerate exemptions` (it silently exempts everything new), and never edit `[imports.*]`/`[policy.*]` of `supply-chain/config.toml` or `[[trusted.*]]` of `supply-chain/audits.toml`: those are human decisions.
- [ ] `Cargo.lock` changed → also `lockfile-hashes.instructions.md` (Nix vendor hashes).

## 3. JavaScript (pnpm, `ui/`)

`ui/` is the only npm project of this repository (`"packageManager": "pnpm@10.17.1"`, lockfile `ui/pnpm-lock.yaml`). `crate/clients/wasm/package.json` is the wasm-pack input manifest (only `repository`): never add npm dependencies to it.

No CI gate covers npm yet (open tasks of #1265), so these checks are mandatory for agents. Run them from `ui/`:

- [ ] Release-age cooldown: the version was published at least 7 days ago. List the eligible versions:

    ```bash
    pnpm view <pkg> time --json | jq -r '(now - 7*86400 | todate) as $c | to_entries[] | select((.key | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and .value < $c) | "\(.value) \(.key)"' | sort | tail -5
    ```

    Then `pnpm add <pkg>@<version>` (`pnpm add -D` for build and test tooling). Never an unversioned `pnpm add <pkg>` or `@latest`.
- [ ] Install scripts: pnpm 10 runs dependency lifecycle scripts only for packages listed in `pnpm.onlyBuiltDependencies` of `ui/package.json`. Leave packages reported under "Ignored build scripts" ignored and never run `pnpm approve-builds`; add an allowlist entry only when the feature cannot work without the script, and justify it in the PR.
- [ ] Fix a vulnerable transitive package with a `pnpm.overrides` entry in the style of the existing ones (`"ws": ">=8.20.1"`) and cite the advisory ID in the commit message.
- [ ] `pnpm install --frozen-lockfile` succeeds with the committed `ui/pnpm-lock.yaml`.
- [ ] `pnpm audit` reports no advisory whose path goes through a package you added or bumped.
- [ ] `pnpm run check:dedup` (knip) does not report the new package as unused.
- [ ] `ui/pnpm-lock.yaml` changed → also `lockfile-hashes.instructions.md` (`ui.pnpm.{linux,darwin}.sha256`).

## 4. Python (test and docs helpers)

Lockfiles: `.mise/scripts/test/requirements-*.{in,txt}` and `.mise/scripts/docs/requirements.{in,txt}`. Gates: CI job `python-dependency-audit` (`.github/workflows/main_base.yml`), pre-push hook `pip-audit-lockfiles`.

- [ ] Prefer the standard library (`python.instructions.md`).
- [ ] Edit only the human-written `.in` file: `==` pin or bounded range (`>=X,<Y`), with a comment for any CVE-driven floor (pattern: `.mise/scripts/test/requirements-jose.in`).
- [ ] Regenerate the `.txt` with the exact `pip-compile --generate-hashes …` command recorded in its header, from the repository root, under the Python version that header names; commit both files.
- [ ] `pip-audit -r <file>.txt` reports no known vulnerability.
- [ ] Test and docs scripts install with `pip install --require-hashes -r <file>.txt`, never `pip install <pkg>`.
- [ ] A new lockfile: add it to the `for f in` list of the `python-dependency-audit` job and to `[files] extend-exclude` of `_typos.toml` (unless an existing entry already matches it). Outside `.mise/scripts/test/` and `.mise/scripts/docs/`, also add its directory to the `pip` entry of `.github/dependabot.yml` and widen the `files:` regex of the `pip-audit-lockfiles` hook and the `exclude:` regex of the `requirements-txt-fixer` hook in `.pre-commit-config.yaml`.

## 5. Go (`.mise/scripts/kmip-go`)

Gates: CI job `govulncheck` (`.github/workflows/main_base.yml`), pre-push hook `govulncheck`.

- [ ] From the module directory: `go get <module>@vX.Y.Z` (never `@latest`), `go mod tidy`, `go mod verify`; commit `go.mod` and `go.sum`.
- [ ] Bump the `toolchain` line only to a Go release that fixes a standard-library vulnerability reported by govulncheck.
- [ ] `govulncheck -test ./...` reports no vulnerability.
- [ ] A new Go module: add a `gomod` entry to `.github/dependabot.yml`, a govulncheck run to `.github/workflows/main_base.yml`, and its path to the `govulncheck` hook of `.pre-commit-config.yaml`.

## 6. Docker base images

Gate: pre-commit hook `docker-base-image-digest-pin` (Dockerfiles under `.mise/scripts/docker/` and `.mise/scripts/edb_tde/`). Product images are built by Nix (`nix/docker.nix`), not from Dockerfiles.

- [ ] Every `FROM` is `image:tag@sha256:<digest>`, with the multi-arch index digest printed on the `Digest:` line of `docker buildx imagetools inspect <image>:<tag>`.
- [ ] A Dockerfile in a new directory: add the directory to the `docker` entry of `.github/dependabot.yml` and widen the hook's `files:` regex.

## 7. GitHub Actions and CI tooling

Gate: pre-commit hook `github-actions-sha-pin`; Dependabot (`github-actions`) keeps the pins current.

- [ ] Reuse an action already pinned under `.github/` (copy its `uses:` line).
- [ ] A new action or reusable workflow is `uses: <owner>/<repo>[/<path>]@<40-hex commit SHA> # <tag or branch>`; resolve the SHA with `GH_PAGER=cat gh api repos/<owner>/<repo>/commits/<tag or branch> --jq .sha`. Local `./.github/...` references are exempt.
- [ ] A tool installed by a step pins an exact version: `cargo install --locked <tool>@<x.y.z>`, `go install <module>@vX.Y.Z`, `pip install <tool>==<x.y.z>`, `npm install -g <tool>@<x.y.z>` (pattern: the supply-chain jobs of `.github/workflows/main_base.yml`).
- [ ] Least-privilege `permissions:` (`github-actions.instructions.md`). Never give release, signing or registry secrets to a job that installs or builds third-party code; publish from a separate job.

## 8. Downloaded installers and binaries

Gate: pre-commit hook `no-curl-pipe-shell` (workflows, actions, `.mise/`, `scripts/`).

- [ ] Download from an immutable, versioned URL (a release asset, never a "latest" endpoint) to a file, verify its SHA-256, then run it. Pattern: `.github/actions/install-mise/action.yml` (`sha256sum -c`); in mise scripts use `compute_sha256` from `.mise/lib/common.sh`.
- [ ] Put the command that recomputes the hash in a comment next to it.

## Known non-conforming code (do not copy)

- `.mise/scripts/edb_tde/Dockerfile.edb`: tag-only `FROM` (the digest needs `EDB_SUBSCRIPTION_TOKEN`; excluded from the digest hook).
- `.mise/scripts/pykmip/setup_pykmip.sh`: unpinned `pip install PyKMIP`, with a `git+https://github.com/OpenKMIP/PyKMIP.git` fallback.
- `.mise/tasks/build/ui` and `.mise/scripts/windows/windows_ui.ps1`: `pnpm install` without `--frozen-lockfile`.
- `documentation/theme/scripts/setup-mdbook.sh` (submodule): `curl | sh` rustup fallback when `cargo` is missing; `cargo install` without `--locked` for `mdbook-admonish`, `mdbook-mermaid` and `mdbook-linkcheck`.

> Rule 4.19 of `/kms-sync-rules`. Lock-file hash sync: `lockfile-hashes.instructions.md` (rule 4.11).

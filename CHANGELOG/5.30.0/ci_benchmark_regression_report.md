## Features

### Benchmark regression report between two published versions

- Add `mise run bench:compare <base_version> <new_version> [threshold]`: downloads the `ckms_bench` report published
  on package.cosmian.com for both versions and compares every load-test point (encryption, signature, ...) and every
  Criterion median 1 to 1. Default threshold 5%; only regressions are listed unless `--all` is given; a Criterion
  slowdown whose confidence interval overlaps the baseline is reported as noise; benchmarks present in one version
  only are listed, and `--fail` exits non-zero on a regression or on an encryption/signature gap.

## Bug Fixes

### Benchmark workflow

- `benchmark.yml`: install Nix (`setup-nix`) before the `bench:hsm` / `bench:pkcs11` steps, which re-exec inside
  `nix-shell` and failed on the benchmark runner with "Nix is required for this task".
- `benchmark.yml`: when `server_version` is set, run only `bench:load`. The HSM and PKCS#11 tasks benchmark the
  checked-out code, so their reports were published under the released version's directory.

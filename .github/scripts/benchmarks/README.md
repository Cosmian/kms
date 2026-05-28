# `.github/scripts/benchmarks/` — Benchmark scripts

This directory contains all scripts for running, generating, and regression-gating
Cosmian KMS benchmarks. Scripts fall into two groups:

- **Local scripts** — build the KMS server from source, spin up a temporary process,
  and run `ckms bench` against it.
- **Docker scripts** (`docker/`) — pull published KMS Docker images from
  `ghcr.io/cosmian/kms` and run `ckms bench` against them, enabling cross-version
  comparisons without a local build.

---

## Local scripts

All four local scripts source `common.sh` (this directory) which in turn sources the
parent `.github/scripts/common.sh`. Callers only need `source "${SCRIPT_DIR}/common.sh"`.

### `common.sh` — Shared benchmark helpers

A Bash library sourced by all local benchmark scripts. Provides:

| Function | Description |
|---|---|
| `bench_build_binaries [release]` | `cargo build` server + CLI; exports `KMS_BIN`, `CKMS_BIN`, `CARGO_TARGET_DIR`. Pass `release` for a `--release` build; default is `debug`. |
| `bench_start_server <port> <tmp_dir>` | Write a minimal SQLite/HTTP `kms.toml`, start the server, and wait for it to be ready. Exports `KMS_PID`. |
| `bench_register_cleanup` | Register an `EXIT` trap that kills the KMS process and removes `TMP_DIR`. Reads globals `KMS_PID` and `TMP_DIR`. |
| `bench_write_md <out> <port> <md> <title>` | Collect date / KMS version / `lscpu` output and write a Markdown documentation file combining machine info with the Criterion report. |

Not intended to be run directly.

---

### `bench_ci.sh` — CI smoke-test

**Purpose**: lightweight smoke-test used in CI.

**Workflow**:

1. Builds the KMS server + `ckms` CLI (`cargo build`).
2. Starts a temporary KMS server (SQLite, plain HTTP) on a configurable port.
3. Runs `ckms bench --speed sanity --format json` to verify every benchmark operation
   succeeds end-to-end.
4. Optionally saves or loads a Criterion baseline for regression comparison.
5. Stops the server and cleans up.

**Environment variables** (all optional):

| Variable             | Default   | Description                                          |
|----------------------|-----------|------------------------------------------------------|
| `BENCH_SAVE_BASELINE`| —         | Save Criterion results under this baseline name.     |
| `BENCH_LOAD_BASELINE`| —         | Compare against this previously saved baseline.      |
| `BENCH_SPEED`        | `sanity`  | Speed mode passed to `ckms bench`.                   |
| `BENCH_FORMAT`       | `json`    | Output format passed to `ckms bench`.                |
| `BENCH_PORT`         | `19997`   | Port for the temporary KMS server.                   |

**Usage**:

```bash
bash .github/scripts/benchmarks/bench_ci.sh
# or with a FIPS/non-FIPS variant (forwarded to common.sh's init_build_env):
bash .github/scripts/benchmarks/bench_ci.sh --variant non-fips
```

---

### `bench_regression.sh` — Regression gate

**Purpose**: download reference benchmark results from `package.cosmian.com`, run the
current branch's benchmarks, and fail if the average regression exceeds a threshold.

**Workflow**:

1. Downloads `https://package.cosmian.com/kms/<version>/benchmarks.json` as the
   reference (graceful fallback if unavailable).
2. Builds the KMS server + `ckms` CLI in **release** mode.
3. Starts a temporary KMS server and runs `ckms bench --format json`.
4. Computes per-benchmark delta: `(current − reference) / reference × 100 %`.
5. Fails with a detailed report if the global average exceeds `REGRESSION_THRESHOLD`.

**Environment variables** (all optional):

| Variable               | Default                                         | Description                                        |
|------------------------|-------------------------------------------------|----------------------------------------------------|
| `VARIANT`              | `fips`                                          | `fips` or `non-fips` — sets `FEATURES_FLAG`.       |
| `BENCH_SPEED`          | `quick`                                         | Speed mode: `sanity`, `quick`, or `normal`.        |
| `BENCH_PORT`           | `19998`                                         | Port for the temporary KMS server.                 |
| `REGRESSION_THRESHOLD` | `10`                                            | Maximum allowed average regression (%).            |
| `REFERENCE_URL`        | `https://package.cosmian.com/kms/<ver>/benchmarks.json` | Override the reference URL.           |
| `CARGO_TARGET_DIR`     | `./target`                                      | Override the Cargo target directory.               |

**Requirements**: `cargo`, `curl`, `jq`, `bc`.

**Usage**:

```bash
bash .github/scripts/benchmarks/bench_regression.sh
REGRESSION_THRESHOLD=5 bash .github/scripts/benchmarks/bench_regression.sh --variant non-fips
```

---

### `bench_run.sh` — Full benchmark run (local, generates docs)

**Purpose**: self-contained script that builds the KMS server + `ckms` CLI, starts a
temporary SQLite KMS server on plain HTTP, runs `ckms bench --mode all --speed quick
--format markdown`, and writes the results to `documentation/docs/benchmarks.md`.

**Produces**: `documentation/docs/benchmarks.md`

**Environment variables** (all optional):

| Variable          | Default                               | Description                                   |
|-------------------|---------------------------------------|-----------------------------------------------|
| `VARIANT`         | `non-fips` (via `init_build_env`)     | `fips` or `non-fips` — sets features flag.   |
| `BENCH_MODE`      | `all`                                 | Benchmark mode passed to `ckms bench`.        |
| `BENCH_SPEED`     | `quick`                               | Speed mode: `sanity`, `quick`, or `normal`.   |
| `BENCH_PORT`      | `19996`                               | Port for the temporary KMS server.            |
| `OUT_MD`          | `documentation/docs/benchmarks.md`   | Output markdown path.                         |
| `CARGO_TARGET_DIR`| `./target`                            | Override Cargo target directory.              |

**Requirements**: `cargo` (builds binaries automatically).

**Usage**:

```bash
bash .github/scripts/benchmarks/bench_run.sh --variant non-fips
# Or with custom mode/speed:
BENCH_MODE=encrypt BENCH_SPEED=normal bash .github/scripts/benchmarks/bench_run.sh
```

---

### `bench_run_load.sh` — Load-test benchmark run (local, generates docs)

**Purpose**: identical to `bench_run.sh` but invokes `ckms bench --load` to measure
throughput (req/s) and latency percentiles at increasing concurrency levels, writing
results to `documentation/docs/benchmarks_load_tests.md`.

Builds the KMS server + `ckms` CLI from source, starts a temporary SQLite KMS server
on plain HTTP (no TLS, no auth), runs the load sweep, and optionally generates an HTML
gnuplot report.

**Produces**:

- `documentation/docs/benchmarks_load_tests.md`
- `documentation/docs/benchmarks_load_tests.html` (only when `gnuplot` is available)

**Environment variables** (all optional):

| Variable            | Default                                              | Description                                          |
|---------------------|------------------------------------------------------|------------------------------------------------------|
| `VARIANT`           | `fips` (via `init_build_env`)                        | `fips` or `non-fips` — sets features flag.          |
| `BENCH_MODE`        | `all`                                                | Benchmark mode passed to `ckms bench`.              |
| `BENCH_TIME`        | `5`                                                  | Seconds per concurrency level.                       |
| `BENCH_CONCURRENCY` | `1,2,4,8,16,32`                                      | Comma-separated concurrency sweep levels.            |
| `BENCH_PORT`        | `19995`                                              | Port for the temporary KMS server.                   |
| `OUT_MD`            | `documentation/docs/benchmarks_load_tests.md`        | Output markdown path.                                |
| `CARGO_TARGET_DIR`  | `./target`                                           | Override Cargo target directory.                     |

**Requirements**: `cargo` (builds binaries automatically).

**Usage**:

```bash
bash .github/scripts/benchmarks/bench_run_load.sh --variant non-fips
# Or with a focused mode and longer sweep:
BENCH_MODE=encrypt BENCH_TIME=10 bash .github/scripts/benchmarks/bench_run_load.sh
```

---

## Docker scripts (`docker/`)

These scripts pull published KMS images from `ghcr.io/cosmian/kms` and run `ckms bench`
against them. No local Rust build of the server is required. They are useful for:

- tracking performance across released versions,
- generating side-by-side comparison reports,
- validating that a new release does not regress vs the previous one.

### `docker/docker_helpers.sh` — Shared helpers

A Bash library sourced by the two Docker benchmark scripts. Provides:

| Function                    | Description                                                          |
|-----------------------------|----------------------------------------------------------------------|
| `docker_write_ckms_conf`    | Write a minimal `ckms` config pointing at the local Docker KMS.      |
| `docker_resolve_image_tag`  | Resolve a `MAJOR.MINOR` tag, falling back to `MAJOR.MINOR.0`.       |
| `docker_wait_kms_ready`     | Poll `GET /version` until the containerised KMS is accepting traffic. |

Not intended to be run directly.

---

### `docker/bench_docker.sh` — Docker benchmark runs

**Purpose**: pull one or more KMS Docker images, run `ckms bench` against each, and
optionally produce a two-version comparison report.

**Modes**:

| Invocation                             | Behaviour                                                    |
|----------------------------------------|--------------------------------------------------------------|
| `./bench_docker.sh 5.17`      | Single version — run benchmarks, save Criterion baseline.    |
| `./bench_docker.sh 5.12..5.17`| Range — one report per minor version.                        |
| `./bench_docker.sh 5.14 5.17` | Diff — baseline vs compare, side-by-side markdown output.   |
| `./bench_docker.sh`           | Defaults to version `5.17`.                                  |

**Produces**: `documentation/docs/benchmarks/docker/benchmarks-<v1>-vs-<v2>.md`
(in two-version mode).

**Environment variables** (all optional):

| Variable              | Default                    | Description                                                |
|-----------------------|----------------------------|------------------------------------------------------------|
| `IMAGE_REPO`          | `ghcr.io/cosmian/kms`      | Docker image registry/repository.                          |
| `HOST_PORT`           | `9998`                     | Host port mapped from the container.                       |
| `BENCH_MODE`          | `all`                      | Benchmark mode.                                            |
| `EXTRA_ARGS`          | `--speed quick`            | Extra arguments passed to `ckms bench`.                    |
| `OUT_DIR`             | `documentation/docs/benchmarks/docker` | Output directory for markdown reports.       |
| `MAX_MINOR_PER_MAJOR` | `29`                       | Upper bound when expanding cross-major version ranges.     |
| `CKMS_CARGO_ARGS`     | `--release --features non-fips` | Cargo args used to run `ckms`.                       |

**Requirements**: `cargo`, `docker`.

**Usage** (from repo root):

```bash
bash .github/scripts/benchmarks/docker/bench_docker.sh 5.17
bash .github/scripts/benchmarks/docker/bench_docker.sh 5.14 5.17
bash .github/scripts/benchmarks/docker/bench_docker.sh 5.12..5.17
```

---

### `docker/bench_docker_load.sh` — Docker load-test benchmark runs

**Purpose**: identical to `run_benchmarks_docker.sh` but uses `ckms bench --load` to
measure concurrent throughput. Requires exactly one or two version arguments.

**Modes**:

| Invocation                                          | Behaviour                                       |
|-----------------------------------------------------|-------------------------------------------------|
| `./bench_docker_load.sh 5.18`        | Single version report.                          |
| `./bench_docker_load.sh 5.17 5.18`   | Diff — baseline vs compare.                     |

**Produces**: `documentation/docs/benchmarks/docker/load-tests-<v1>-vs-<v2>.md`

**Environment variables** (all optional):

| Variable          | Default                    | Description                                                |
|-------------------|----------------------------|------------------------------------------------------------|
| `IMAGE_REPO`      | `ghcr.io/cosmian/kms`      | Docker image registry/repository.                          |
| `HOST_PORT`       | `9998`                     | Host port mapped from the container.                       |
| `BENCH_MODE`      | `all`                      | Benchmark mode.                                            |
| `EXTRA_ARGS`      | `--time 5`                 | Extra arguments passed to `ckms bench`.                    |
| `OUT_DIR`         | `documentation/docs/benchmarks/docker` | Output directory for markdown reports.       |
| `CKMS_CARGO_ARGS` | `--release --features non-fips` | Cargo args used to run `ckms`.                       |

**Requirements**: `cargo`, `docker`, `python3`, `curl`.

**Usage** (from repo root):

```bash
bash .github/scripts/benchmarks/docker/bench_docker_load.sh 5.18
bash .github/scripts/benchmarks/docker/bench_docker_load.sh 5.17 5.18
```

---

## Directory layout

```text
.github/scripts/benchmarks/
├── README.md                             ← this file
├── bench_ci.sh                           ← CI smoke-test (build + run + optional baseline)
├── bench_regression.sh                   ← regression gate vs package.cosmian.com reference
├── bench_run.sh                          ← full local run → documentation/docs/benchmarks.md
├── bench_run_load.sh                     ← load test run → documentation/docs/benchmarks_load_tests.md
└── docker/
    ├── docker_helpers.sh                 ← shared Bash helpers (not run directly)
    ├── bench_docker.sh                   ← Docker-based benchmark run / comparison
    └── bench_docker_load.sh              ← Docker-based load-test run / comparison
```

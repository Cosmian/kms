#!/usr/bin/env bash
# bench_run_flamegraph.sh — Core implementation for `mise bench:flamegraph`.
#
# The benchmark (`crate/test_kms_server/benches/http_throughput.rs`) starts its own
# in-process KMS server for each worker count, so no separate server process is needed.
#
# Produces (per operation × worker count, e.g. "aes_gcm_enc_w4"):
#   <OUT_MD_DIR>/<op>_w<N>.svg                 (interactive flamegraph)
#   <OUT_MD_DIR>/<op>_w<N>.png                 (static render for the doc, via rsvg-convert)
#   <OUT_MD_DIR>/flamegraph/                   (Criterion HTML report, copied here)
#   <OUT_MD_DIR>/cpu_scaling.md                (updated with fresh results)
#   target/criterion/kms_bench/*/report/       (Criterion HTML report source)
#
# All configuration is passed via environment variables (set by the MISE task
# or exported by the caller).  See .mise/tasks/bench/flamegraph for the CLI.
#
# ENV (all optional):
#   VARIANT           fips or non-fips  (default: non-fips)
#   WORKER_COUNTS     Space-separated worker counts to sweep  (default: "1 2 4 8")
#   PROFILE_TIME      Seconds to record per flamegraph  (default: 15)
#   BENCH_OPERATIONS  Comma-separated Criterion bench IDs, one flamegraph series each
#                     (default: "aes_gcm_enc,rsa_oaep_dec,ecdsa_sign")
#   PERF_FREQ         perf sampling frequency in Hz  (default: 500)
#   SKIP_FLAMEGRAPH   Set to 1 to skip flamegraph generation (throughput bench only)
#   SKIP_THROUGHPUT   Set to 1 to skip the throughput bench (flamegraphs only)
#   OUT_MD            Output markdown path  (default: documentation/docs/benchmarks/cpu_scaling.md)
#   CARGO_TARGET_DIR  Override cargo target directory

set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT:-${_SCRIPT_DIR}/../..}/.mise/lib/common.sh"

# Default to non-fips for benchmarks.
: "${VARIANT:=non-fips}"

# kms_init_env sets FEATURES_FLAG, VARIANT_NAME, etc.
# Always call — FEATURES_FLAG is a bash array that does not survive `exec`,
# so we cannot rely on the mise task's prior invocation.
kms_init_env "${VARIANT}" "static"

REPO_ROOT="$(get_repo_root)"
cd "${REPO_ROOT}"

require_cmd cargo "Cargo is required. Install Rust (rustup) and retry."

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
export CARGO_TARGET_DIR

WORKER_COUNTS="${WORKER_COUNTS:-1 2 4 8}"
PROFILE_TIME="${PROFILE_TIME:-15}"
BENCH_OPERATIONS="${BENCH_OPERATIONS:-aes_gcm_enc,rsa_oaep_dec,ecdsa_sign}"
# 500 Hz instead of cargo-flamegraph's default 997 Hz.
# At 997 Hz × 8 worker threads the ring buffer (256 pages = 1 MB) can fill faster
# than the kernel drains it, producing "lost N chunks" warnings and incomplete traces.
# 500 Hz halves ring-buffer pressure with negligible impact on flamegraph resolution.
PERF_FREQ="${PERF_FREQ:-500}"
SKIP_FLAMEGRAPH="${SKIP_FLAMEGRAPH:-0}"
SKIP_THROUGHPUT="${SKIP_THROUGHPUT:-0}"
OUT_MD="${OUT_MD:-${REPO_ROOT}/documentation/docs/benchmarks/cpu_scaling.md}"
FLAMEGRAPH_DIR="$(dirname "${OUT_MD}")"

# Normalises an operation ID to a safe file-system slug (lower-case, underscores).
slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_' | sed 's/^_*//; s/_*$//'
}

# Shared path builders so the generation loop and the markdown-writing loop
# below can never drift apart on the file naming convention.
# Images go into flamegraph/<op>/w<N>/ so each operation × worker count is
# self-contained alongside its Criterion report (base/new/report).
flamegraph_svg_path() { echo "${FLAMEGRAPH_DIR}/flamegraph/$(slugify "$1")/w$2/$(slugify "$1")_w$2.svg"; }
flamegraph_png_path() { echo "${FLAMEGRAPH_DIR}/flamegraph/$(slugify "$1")/w$2/$(slugify "$1")_w$2.png"; }
# Relative path suitable for markdown links (from cpu_scaling.md's directory).
flamegraph_md_relpath() { echo "flamegraph/$(slugify "$1")/w$2"; }

print_header "KMS CPU Scaling Flamegraph Benchmark"
echo "  Variant       : ${VARIANT}"
echo "  Worker counts : ${WORKER_COUNTS}"
echo "  Profile time  : ${PROFILE_TIME}s per worker count"
echo "  perf frequency: ${PERF_FREQ} Hz"
echo "  Operations    : ${BENCH_OPERATIONS}"
echo "  Output        : ${OUT_MD}"

# ── Detect OS — flamegraph requires Linux perf ───────────────────────────────
OS="$(uname -s)"
if [ "${OS}" != "Linux" ] && [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  echo "WARNING: flamegraph generation requires Linux perf. Disabling flamegraphs."
  SKIP_FLAMEGRAPH=1
fi

# ── Check / install prerequisites ────────────────────────────────────────────
if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  if ! command -v perf >/dev/null 2>&1; then
    echo "ERROR: 'perf' not found. Install linux-perf (apt-get install linux-perf) and retry."
    echo "       Or set SKIP_FLAMEGRAPH=1 to run the throughput bench only."
    exit 1
  fi

  if ! cargo flamegraph --version >/dev/null 2>&1; then
    echo "cargo-flamegraph not found — installing..."
    cargo install flamegraph --locked
  fi

  # rsvg-convert renders the flamegraph SVGs to PNG for the docs page.
  # ImageMagick's `convert` silently falls back to a blank bitmap when it
  # cannot find a working SVG delegate, producing fully-black PNGs — always  # typos:ignore
  # invoke rsvg-convert directly instead of relying on `convert`.
  if ! command -v rsvg-convert >/dev/null 2>&1; then
    echo "ERROR: 'rsvg-convert' not found. Install it (e.g. apt-get install librsvg2-bin) and retry."
    echo "       Or set SKIP_FLAMEGRAPH=1 to run the throughput bench only."
    exit 1
  fi

  # Relax perf permissions if needed (requires sudo; best-effort).
  PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "2")"
  if [ "${PARANOID}" -gt "0" ]; then
    echo "Setting perf_event_paranoid to -1 (requires sudo)..."
    echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid >/dev/null
    echo 0 | sudo tee /proc/sys/kernel/kptr_restrict >/dev/null
  fi
fi

# ── Determine cargo feature flags ────────────────────────────────────────────
# FEATURES_FLAG is set by kms_init_env (e.g. (--features non-fips) or empty).

# Force frame pointers in all Rust code for accurate stack unwinding.
# Combined with DWARF unwinding in perf, this eliminates most [unknown] frames.
export RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes"

# ── Ensure OpenSSL is built with debug symbols for perf ────────────────────────
# build.rs (crate/crypto/build.rs) builds OpenSSL 3.6.2 automatically.
# For flamegraphs we need DWARF debug symbols (-g) so perf can resolve
# OpenSSL frames instead of showing [unknown].  Export CFLAGS so that
# build.rs's `./Configure` inherits it, and delete the cached non-debug build
# (plus build.rs's own output) to force a rebuild.
if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  ARCH="$(uname -m)"
  OPENSSL_FIPS_PREFIX="${CARGO_TARGET_DIR}/openssl-3.6.2-linux-${ARCH}"
  OPENSSL_NON_FIPS_PREFIX="${CARGO_TARGET_DIR}/openssl-non-fips-3.6.2-linux-${ARCH}"

  if [ "${VARIANT}" = "fips" ]; then
    OPENSSL_BUILD_PREFIX="${OPENSSL_FIPS_PREFIX}"
  else
    OPENSSL_BUILD_PREFIX="${OPENSSL_NON_FIPS_PREFIX}"
  fi

  if [ -f "${OPENSSL_BUILD_PREFIX}/lib/libcrypto.a" ]; then
    echo "── Removing cached OpenSSL build (will rebuild with -g for debug symbols) ──"
    rm -rf "${OPENSSL_BUILD_PREFIX}"
  fi

  # Delete build.rs's cached output so cargo re-runs build.rs.
  # Without this cargo skips the build script (none of its rerun-if inputs changed)
  # and links against a stale/missing OpenSSL.
  find "${CARGO_TARGET_DIR}/release/build" -maxdepth 1 \
    -name "cosmian_kms_crypto-*" -exec rm -rf {} + 2>/dev/null || true
  find "${CARGO_TARGET_DIR}/debug/build" -maxdepth 1 \
    -name "cosmian_kms_crypto-*" -exec rm -rf {} + 2>/dev/null || true

  export CFLAGS="-g -O2"
  echo "   CFLAGS=${CFLAGS}  (build.rs will build OpenSSL with debug symbols)"
fi

# ── Run throughput benchmark ──────────────────────────────────────────────────
THROUGHPUT_OUTPUT="${CARGO_TARGET_DIR}/http_throughput_bench.txt"

if [ "${SKIP_THROUGHPUT}" != "1" ]; then
  echo ""
  echo "── Running HTTP throughput benchmark ────────────────────────────────"
  echo "   (worker sweep: ${WORKER_COUNTS}; all three operations)"
  CARGO_PROFILE_BENCH_DEBUG=true \
    cargo bench \
    --bench http_throughput \
    -p test_kms_server \
    "${FEATURES_FLAG[@]}" \
    -- \
    --output-format bencher \
    2>&1 | tee "${THROUGHPUT_OUTPUT}"
  echo ""
  echo "    Throughput bench complete. Criterion HTML: ${CARGO_TARGET_DIR}/criterion/"

  # ── Copy Criterion HTML report to docs ────────────────────────────────────
  # Must happen BEFORE flamegraph generation so flamegraph images land inside
  # the established per-operation/wN/ directory structure alongside Criterion data.
  CRITERION_SRC="${CARGO_TARGET_DIR}/criterion/kms_bench"
  CRITERION_DOCS_DIR="${FLAMEGRAPH_DIR}/flamegraph"
  if [ -d "${CRITERION_SRC}" ]; then
    echo ""
    echo "── Copying Criterion report to docs ─────────────────────────────────"
    rm -rf "${CRITERION_DOCS_DIR}"
    cp -r "${CRITERION_SRC}" "${CRITERION_DOCS_DIR}"
    # Fix cross-report links: Criterion built them relative to target/criterion/kms_bench/.
    # After copying to flamegraph/, strip the kms_bench/ path component so all
    # inter-report navigation works from the new location.
    # Process 3-level prefix (../../../kms_bench/) before 2-level (../../kms_bench/)
    # to avoid partial double-substitution.
    find "${CRITERION_DOCS_DIR}" -name "*.html" \
      -exec sed -i 's|\.\./\.\./\.\./kms_bench/|../../|g' {} +
    find "${CRITERION_DOCS_DIR}" -name "*.html" \
      -exec sed -i 's|\.\./\.\./kms_bench/|../|g' {} +
    print_success "Criterion report: ${CRITERION_DOCS_DIR}"
  fi
fi

# ── Run flamegraph per worker count ──────────────────────────────────────────
mkdir -p "${FLAMEGRAPH_DIR}"

if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  echo ""
  echo "── Generating flamegraphs ────────────────────────────────────────────"

  # Remove stale flamegraph images from previous runs inside per-operation wN dirs.
  for operation in $(echo "${BENCH_OPERATIONS}" | tr ',' ' '); do
    for workers in ${WORKER_COUNTS}; do
      rm -f "$(flamegraph_svg_path "${operation}" "${workers}")" \
        "$(flamegraph_png_path "${operation}" "${workers}")"
    done
  done

  IFS=',' read -r -a OPERATIONS_ARRAY <<<"${BENCH_OPERATIONS}"
  for operation in "${OPERATIONS_ARRAY[@]}"; do
    for workers in ${WORKER_COUNTS}; do
      SVG_OUT="$(flamegraph_svg_path "${operation}" "${workers}")"
      PNG_OUT="$(flamegraph_png_path "${operation}" "${workers}")"
      mkdir -p "$(dirname "${SVG_OUT}")"
      BENCH_FILTER="${operation}/w${workers}"
      echo ""
      echo "   ${operation} — ${workers} worker(s)  →  ${SVG_OUT}"
      # The -c/--cmd argument to cargo-flamegraph is appended token-by-token to
      # `Command::new("perf")` — do NOT include "perf" itself at the start.
      # The default args string is "record -F {freq} --call-graph dwarf,64000 -g";
      # we use DWARF unwinding for maximum accuracy:
      #
      #   record                    → perf sub-command (required)
      #   --call-graph dwarf,32768  → DWARF-based unwinding: resolves frames in system
      #                               libraries (glibc, OpenSSL) that lack frame pointers.
      #                               32 KB stack dump per sample (default 8 KB is often
      #                               too shallow for deep async stacks).
      #   -F ${PERF_FREQ}           → sampling rate; 500 Hz avoids ring-buffer overflow
      #   -g                        → enable call-graph recording
      PERF_CMD="record --call-graph dwarf,32768 -F ${PERF_FREQ} -g"
      CARGO_PROFILE_BENCH_DEBUG=true \
        cargo flamegraph \
        --bench http_throughput \
        -p test_kms_server \
        "${FEATURES_FLAG[@]}" \
        --output "${SVG_OUT}" \
        --no-inline \
        -c "${PERF_CMD}" \
        -- \
        --bench \
        "${BENCH_FILTER}" \
        --profile-time "${PROFILE_TIME}" ||
        echo "    WARNING: flamegraph for ${operation} / ${workers} workers failed (non-fatal)"
      if [ -f "${SVG_OUT}" ]; then
        echo "    Written: ${SVG_OUT}"
        rsvg-convert --width 2400 --keep-aspect-ratio --output "${PNG_OUT}" "${SVG_OUT}" &&
          echo "    Written: ${PNG_OUT}" ||
          echo "    WARNING: PNG render for ${operation} / ${workers} workers failed (non-fatal)"
      fi
    done
  done
fi

# ── Collect results for markdown ─────────────────────────────────────────────
BENCH_DATE="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
LSCPU_OUTPUT="$(lscpu 2>/dev/null || echo "lscpu not available")"
CPUINFO_OUTPUT="$(awk '/^processor/ && seen{exit} /^processor/{seen=1} {print}' /proc/cpuinfo 2>/dev/null ||
  echo "/proc/cpuinfo not available")"
KMS_VERSION="$(grep -A20 '^\[workspace\.package\]' "${REPO_ROOT}/Cargo.toml" |
  grep '^version' | head -1 | sed 's/version = "\(.*\)"/\1/' || echo "unknown")"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"

# Build throughput table from bencher-format output (lines: "test <name> ... bench: N ns/iter")
THROUGHPUT_TABLE=""
if [ -f "${THROUGHPUT_OUTPUT}" ]; then
  THROUGHPUT_TABLE="$(awk -v conc=16 '
    /^test .* bench:/ {
      name = $0
      sub(/^test /, "", name)
      sub(/ bench:.*/, "", name)
      sub(/[[:space:]]*\.\.\.[[:space:]]*$/, "", name)

      if (match($0, /bench:[[:space:]]*[0-9,]+[[:space:]]*ns\/iter/)) {
        ns = substr($0, RSTART, RLENGTH)
        gsub(/bench:[[:space:]]*/, "", ns)
        gsub(/[[:space:]]*ns\/iter/, "", ns)
        gsub(/,/, "", ns)
        if (ns + 0 > 0) {
          rps = int((1e9 / (ns + 0)) * conc)
          printf "| %s | %s |\n", name, rps
        }
      }
    }
  ' "${THROUGHPUT_OUTPUT}" 2>/dev/null || true)"
fi

# Build flamegraph links section, grouped by operation then worker count.
# PNGs (rendered via rsvg-convert) are embedded directly so they display in the  # typos:ignore
# rendered docs site and in GitHub's markdown preview; the SVG is linked
# alongside for interactive zoom/search in a browser.
FLAMEGRAPH_SECTION=""
if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  FLAMEGRAPH_SECTION="
## Flamegraphs

Generated by \`cargo-flamegraph\` / Linux \`perf\` during a \`${PROFILE_TIME}\`-second profiling window,
for each operation and worker count. Click a PNG's caption link to open the interactive SVG
(zoom, search) in a browser.

"
  for operation in "${OPERATIONS_ARRAY[@]}"; do
    OP_HAS_IMAGES=0
    OP_SECTION="### \`${operation}\`
"
    for workers in ${WORKER_COUNTS}; do
      PNG_OUT="$(flamegraph_png_path "${operation}" "${workers}")"
      SVG_OUT="$(flamegraph_svg_path "${operation}" "${workers}")"
      if [ ! -f "${PNG_OUT}" ]; then
        continue
      fi
      OP_HAS_IMAGES=1
      REL_DIR="$(flamegraph_md_relpath "${operation}" "${workers}")"
      PNG_REL="${REL_DIR}/$(slugify "${operation}")_w${workers}.png"
      SVG_REL="${REL_DIR}/$(slugify "${operation}")_w${workers}.svg"
      OP_SECTION+="
#### ${workers} worker(s)

![flamegraph ${operation} ${workers} workers](${PNG_REL})

[Open interactive SVG](${SVG_REL})
"
    done
    [ "${OP_HAS_IMAGES}" = "1" ] && FLAMEGRAPH_SECTION+="
${OP_SECTION}"
  done
fi

# ── Write documentation ───────────────────────────────────────────────────────
mkdir -p "$(dirname "${OUT_MD}")"
cat >"${OUT_MD}" <<MDEOF
# CPU Scaling & Flamegraph Analysis

This page documents the multi-CPU scaling characteristics of the Cosmian KMS and explains how to
reproduce the results and generate flamegraphs yourself.

## Why this matters

A KMS deployed in production must handle concurrent cryptographic requests from many clients at the
same time. To justify a multi-core deployment (and to rule out serialisation bottlenecks such as
global mutexes or single-threaded database queues), we measure:

1. **Throughput scaling** – how req/s grows as the number of actix-web worker threads increases
   from 1 → 2 → 4 → 8.
2. **CPU hotspot profile** – a flamegraph confirming that the dominant cost is the cryptographic
   operation itself, not infrastructure overhead (routing, serialisation, database, locks).

## Methodology

### Server worker count

The KMS exposes a \`--server-workers N\` / \`KMS_SERVER_WORKERS\` configuration option that pins
the number of actix-web OS threads. Setting it explicitly makes the bench deterministic regardless
of the host's logical CPU count.

\`\`\`toml
# kms.toml  – leave unset to default to one thread per logical CPU
# server_workers = 8
\`\`\`

### Benchmark design

The \`http_throughput\` Criterion bench (located at
\`crate/test_kms_server/benches/http_throughput.rs\`) exercises three representative KMIP operations:

| Operation | Why chosen |
|-----------|-----------|
| AES-256-GCM encrypt | Lightweight, high-frequency – reveals OS-thread dispatch overhead |
| RSA-2048 OAEP decrypt | CPU-heavy asymmetric – shows scaling of the OpenSSL thread pool |
| ECDSA P-256 sign | CPU-heavy, short messages – reveals lock contention on key material |

For each worker count in \`{1, 2, 4, 8}\`:

1. A fresh in-process KMS is started with \`server_workers = N\` and SQLite on \`/dev/shm\` (tmpfs).
2. Cryptographic keys are pre-created (not timed).
3. **16 concurrent** \`reqwest\` HTTP tasks are dispatched per Criterion iteration via
   \`iter_custom + join_all\`, so the server is always saturated.
4. Criterion reports wall-clock throughput in **elements/s** (= concurrent requests per second).

### Flamegraph generation

Flamegraphs are recorded with
[\`cargo-flamegraph\`](https://github.com/flamegraph-rs/flamegraph) (Linux \`perf\` back-end) and
rendered to PNG with [\`rsvg-convert\`](https://gitlab.gnome.org/GNOME/librsvg) (part of
\`librsvg2-bin\`). They are generated for all three operations above at 1, 2, 4, and 8 workers.

> **Why \`rsvg-convert\` and not \`convert\`/ImageMagick?** ImageMagick delegates SVG rasterisation
> to \`rsvg-convert\` internally; if that binary is missing, \`convert\` silently falls back to a
> blank canvas, producing fully-black PNGs. Always invoke \`rsvg-convert\` directly.  # typos:ignore

To reproduce locally (Linux only, requires \`perf\` and \`rsvg-convert\`):

\`\`\`bash
# Install cargo-flamegraph and rsvg-convert once
cargo install flamegraph --locked
sudo apt-get install -y librsvg2-bin

# Allow perf for unprivileged processes (revert after benchmarking)
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
echo 0   | sudo tee /proc/sys/kernel/kptr_restrict

# Build and profile – SVG lands next to this file
CARGO_PROFILE_BENCH_DEBUG=true \\
cargo flamegraph \\
  --bench http_throughput \\
  -p test_kms_server \\
  --features non-fips \\
  --output documentation/docs/benchmarks/flamegraph/ecdsa_sign/w8/ecdsa_sign_w8.svg \\
  -- \\
  --bench \\
  "ecdsa_sign/w8" \\
  --profile-time 15

# Render the interactive SVG to a static PNG for the docs page
rsvg-convert --width 2400 --keep-aspect-ratio --output documentation/docs/benchmarks/flamegraph/ecdsa_sign/w8/ecdsa_sign_w8.png \\
  documentation/docs/benchmarks/flamegraph/ecdsa_sign/w8/ecdsa_sign_w8.svg
\`\`\`

## Running the throughput benchmark

\`\`\`bash
# Non-FIPS mode (all three operations)
cargo bench --bench http_throughput -p test_kms_server --features non-fips

# FIPS mode
cargo bench --bench http_throughput -p test_kms_server
\`\`\`

Criterion writes an HTML report to \`target/criterion/kms_bench/\` (also copied to \`flamegraph/\` here).

## Interpreting the results

### What near-linear scaling looks like

If the KMS scales well, throughput doubles when the worker count doubles:

| Workers | Expected throughput (relative) |
|---------|-------------------------------|
| 1       | 1× baseline                    |
| 2       | ~1.9×                          |
| 4       | ~3.6×                          |
| 8       | ~6–7× (NUMA / HT effects)      |

Sub-linear but monotonically increasing throughput is normal and expected:

- HTTP keep-alive and connection pooling overhead does not scale perfectly.
- SQLite WAL mode serialises writes but allows concurrent reads.
- OpenSSL's FIPS provider has per-context locking.

Flat or decreasing throughput would indicate a bottleneck worth investigating.

### Reading a flamegraph

A flamegraph shows where CPU time is spent, stacked by call depth.

- **Wide frames at the top** = the dominant cost; you want to see \`openssl\` / \`ring\` /
  \`cosmian_kms_crypto\` here.
- **Wide frames in the middle** = infrastructure cost; \`actix-rt\`, \`tokio\`, \`serde_json\`,
  \`sqlx\` are expected but should be narrow compared to crypto.
- **Wide frames at the bottom** = system calls; \`syscall\`, \`epoll_wait\` width grows with
  I/O wait (not CPU saturation).

If \`std::sync::Mutex\` or \`parking_lot::Mutex\` frames appear wide, that signals lock contention
and is a regression signal worth investigating.

## CI integration

The \`flamegraph.yml\` GitHub Actions workflow runs:

- **On demand** via \`workflow_dispatch\` (configurable worker counts and profile time).
- **Weekly** (Monday 03:00 UTC) against the default branch.
- **On pull requests** that touch \`http_config.rs\`, \`start_kms_server.rs\`, or the bench itself.

Artifacts uploaded per run:

| Artifact | Contents |
|----------|----------|
| \`criterion-http-throughput-<run_id>\` | Criterion HTML report with throughput charts |
| \`flamegraph-svgs-<run_id>\` | SVG flamegraphs per worker count |
| \`http-throughput-output-<run_id>\` | Raw bench output (bencher format) |

---

## Results

> Generated: ${BENCH_DATE}
> KMS version: ${KMS_VERSION} (commit: ${GIT_COMMIT})
> Variant: ${VARIANT}

## Machine Info

\`\`\`
${LSCPU_OUTPUT}
\`\`\`

<details>
<summary>/proc/cpuinfo (first core)</summary>

\`\`\`
${CPUINFO_OUTPUT}
\`\`\`

</details>

## Throughput Results

Benchmark: \`http_throughput\` Criterion bench, 16 concurrent tasks per iteration,
worker sweep: \`${WORKER_COUNTS}\`.

| Benchmark | ~req/s |
|-----------|--------|
${THROUGHPUT_TABLE:-| (no throughput data — run without --skip-throughput) | — |}

## How to Reproduce

\`\`\`bash
# Full run (throughput + flamegraphs for the default worker sweep)
mise bench:flamegraph

# Throughput only (no perf/flamegraph)
mise bench:flamegraph --skip-flamegraph

# Flamegraph for 8 workers only (skip throughput bench)
mise bench:flamegraph --workers 8 --skip-throughput

# Choose variant
mise bench:flamegraph --variant ${VARIANT}
\`\`\`
${FLAMEGRAPH_SECTION}
## Criterion Report

The full interactive Criterion HTML report is in [\`flamegraph/\`](flamegraph/report/index.html).
It is structured in four levels:

| Path | Contents |
|------|----------|
| \`flamegraph/report/\` | Group overview — all $(echo "${BENCH_OPERATIONS}" | tr ',' '\n' | wc -l | tr -d ' ') operations × $(echo "${WORKER_COUNTS}" | wc -w | tr -d ' ') worker counts |
| \`flamegraph/<operation>/report/\` | Per-operation summary — throughput curve across worker counts |
| \`flamegraph/<operation>/<workers>/report/\` | Individual benchmark — timing distribution, regression analysis |
| \`flamegraph/<operation>/<workers>/\` | Flamegraph SVG + PNG — CPU hotspot profile for this operation at this concurrency |

Each \`<operation>/<workers>/\` directory is self-contained:
- \`base/\` / \`new/\` — Criterion raw measurement data (JSON)
- \`report/\` — Criterion HTML report (timing distribution, regression analysis)
- \`*.svg\` / \`*.png\` — flamegraph (generated by \`cargo-flamegraph\`)
MDEOF

print_success "Written: ${OUT_MD}"
